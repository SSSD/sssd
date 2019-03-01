/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <talloc.h>
#include <tevent.h>

#include "sbus/sbus_request.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

static errno_t
dp_failover_list_services_ldap(struct be_ctx *be_ctx,
                               const char **services,
                               int *_count)
{
    struct be_svc_data *svc;
    int count;

    count = 0;
    DLIST_FOR_EACH(svc, be_ctx->be_fo->svcs) {
        services[count] = talloc_strdup(services, svc->name);
        if (services[count] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            return ENOMEM;
        }
        count++;
    }

    *_count = count;

    return EOK;
}

static errno_t
dp_failover_list_services_ad(struct be_ctx *be_ctx,
                             struct sss_domain_info *domain,
                             const char **services,
                             int *_count)
{
    char *fo_svc_name = NULL;
    struct be_svc_data *svc;
    errno_t ret;
    int count;

    fo_svc_name = talloc_asprintf(services, "sd_%s", domain->name);
    if (fo_svc_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    count = 0;
    DLIST_FOR_EACH(svc, be_ctx->be_fo->svcs) {
        /* Drop each sd_gc_* since this service is not used with AD at all,
         * we only connect to AD_GC for global catalog. */
        if (strncasecmp(svc->name, "sd_gc_", strlen("sd_gc_")) == 0) {
            continue;
        }

        /* Drop all subdomain services for different domain. */
        if (strncasecmp(svc->name, "sd_", strlen("sd_")) == 0) {
            if (!IS_SUBDOMAIN(domain)) {
                continue;
            }

            if (strcasecmp(svc->name, fo_svc_name) != 0) {
                continue;
            }
        }

        if (IS_SUBDOMAIN(domain)) {
            /* Drop AD since we connect to subdomain.com for LDAP. */
            if (strcasecmp(svc->name, "AD") == 0) {
                continue;
            }
        }

        services[count] = talloc_strdup(services, svc->name);
        if (services[count] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            ret = ENOMEM;
            goto done;
        }
        count++;
    }

    *_count = count;

    ret = EOK;

done:
    talloc_free(fo_svc_name);
    return ret;
}

static errno_t
dp_failover_list_services_ipa(struct be_ctx *be_ctx,
                              struct sss_domain_info *domain,
                              const char **services,
                              int *_count)
{
    struct be_svc_data *svc;
    char *fo_svc_name = NULL;
    char *fo_gc_name = NULL;
    errno_t ret;
    int count;

    fo_svc_name = talloc_asprintf(services, "sd_%s", domain->name);
    if (fo_svc_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    fo_gc_name = talloc_asprintf(services, "sd_gc_%s", domain->name);
    if (fo_gc_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    count = 0;
    DLIST_FOR_EACH(svc, be_ctx->be_fo->svcs) {
        /* Drop all subdomain services for different domain. */
        if (strncasecmp(svc->name, "sd_", strlen("sd_")) == 0) {
            if (!IS_SUBDOMAIN(domain)) {
                continue;
            }

            if (strcasecmp(svc->name, fo_svc_name) != 0
                    && strcasecmp(svc->name, fo_gc_name) != 0) {
                continue;
            }
        }

        services[count] = talloc_strdup(services, svc->name);
        if (services[count] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            return ENOMEM;
        }
        count++;
    }

    *_count = count;

    ret = EOK;

done:
    talloc_free(fo_svc_name);
    talloc_free(fo_gc_name);

    return ret;
}

enum dp_fo_svc_type {
    DP_FO_SVC_LDAP = 0,
    DP_FO_SVC_AD = 1,
    DP_FO_SVC_IPA = 1 << 1,
    DP_FO_SVC_MIXED = DP_FO_SVC_AD | DP_FO_SVC_IPA
};

errno_t
dp_failover_list_services(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct be_ctx *be_ctx,
                          const char *domname,
                          const char ***_services)
{
    enum dp_fo_svc_type svc_type = DP_FO_SVC_LDAP;
    struct sss_domain_info *domain;
    struct be_svc_data *svc;
    const char **services;
    int num_services;
    errno_t ret;

    if (SBUS_REQ_STRING_IS_EMPTY(domname)) {
        domain = be_ctx->domain;
    } else {
        domain = find_domain_by_name(be_ctx->domain, domname, false);
        if (domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }
    }

    /**
     * Returning list of failover services is currently rather difficult
     * since there is only one failover context for the whole backend.
     *
     * The list of services for the given domain depends on whether it is
     * a master domain or a subdomain and whether we are using IPA, AD or
     * LDAP backend.
     *
     * For LDAP we just return everything we have.
     * For AD master domain we return AD, AD_GC.
     * For AD subdomain we return subdomain.com, AD_GC.
     * For IPA in client mode we return IPA.
     * For IPA in server mode we return IPA for master domain and
     * subdomain.com, gc_subdomain.com for subdomain.
     *
     * We also return everything else for all cases if any other service
     * such as kerberos is configured separately.
     */

    /* Allocate enough space. */
    num_services = 0;
    DLIST_FOR_EACH(svc, be_ctx->be_fo->svcs) {
        num_services++;

        if (strcasecmp(svc->name, "AD") == 0) {
            svc_type |= DP_FO_SVC_AD;
        } else if (strcasecmp(svc->name, "IPA") == 0) {
            svc_type |= DP_FO_SVC_IPA;
        }
    }

    services = talloc_zero_array(mem_ctx, const char *, num_services + 1);
    if (services == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        return ENOMEM;
    }

    /* Fill the list. */
    switch (svc_type) {
    case DP_FO_SVC_LDAP:
    case DP_FO_SVC_MIXED:
        ret = dp_failover_list_services_ldap(be_ctx, services, &num_services);
        break;
    case DP_FO_SVC_AD:
        ret = dp_failover_list_services_ad(be_ctx, domain,
                                           services, &num_services);
        break;
    case DP_FO_SVC_IPA:
        ret = dp_failover_list_services_ipa(be_ctx, domain,
                                            services, &num_services);
        break;
    default:
        ret = ERR_INTERNAL;
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create service list [%d]: %s\n",
              ret, sss_strerror(ret));
        talloc_free(services);
        return ret;
    }

    *_services = services;

    return EOK;
}

errno_t
dp_failover_active_server(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct be_ctx *be_ctx,
                          const char *service_name,
                          const char **_server)
{
    struct be_svc_data *svc;
    bool found = false;

    DLIST_FOR_EACH(svc, be_ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get server name\n");
        return ENOENT;
    }

    *_server = svc->last_good_srv == NULL ? "" : svc->last_good_srv;

    return EOK;
}

errno_t
dp_failover_list_servers(TALLOC_CTX *mem_ctx,
                         struct sbus_request *sbus_req,
                         struct be_ctx *be_ctx,
                         const char *service_name,
                         const char ***_servers)
{
    struct be_svc_data *svc;
    const char **servers;
    bool found = false;
    size_t count;

    DLIST_FOR_EACH(svc, be_ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get server list\n");
        return ENOENT;
    }

    servers = fo_svc_server_list(sbus_req, svc->fo_service, &count);
    if (servers == NULL) {
        return ENOMEM;
    }

    *_servers = servers;

    return EOK;
}
