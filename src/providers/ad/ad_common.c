/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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
#include <ctype.h>

#include "providers/ad/ad_common.h"
#include "providers/ad/ad_opts.h"
#include "providers/dp_dyndns.h"

struct ad_server_data {
    bool gc;
};

errno_t ad_set_search_bases(struct sdap_options *id_opts);
static errno_t ad_set_sdap_options(struct ad_options *ad_opts,
                                   struct sdap_options *id_opts);

static struct sdap_options *
ad_create_default_sdap_options(TALLOC_CTX *mem_ctx)
{
    struct sdap_options *id_opts;
    errno_t ret;

    id_opts = talloc_zero(mem_ctx, struct sdap_options);
    if (!id_opts) {
        return NULL;
    }

    ret = dp_copy_defaults(id_opts,
                           ad_def_ldap_opts,
                           SDAP_OPTS_BASIC,
                           &id_opts->basic);
    if (ret != EOK) {
        goto fail;
    }

    /* Get sdap option maps */

    /* General Attribute Map */
    ret = sdap_copy_map(id_opts,
                       ad_2008r2_attr_map,
                       SDAP_AT_GENERAL,
                       &id_opts->gen_map);
    if (ret != EOK) {
        goto fail;
    }

    /* User map */
    ret = sdap_copy_map(id_opts,
                       ad_2008r2_user_map,
                       SDAP_OPTS_USER,
                       &id_opts->user_map);
    if (ret != EOK) {
        goto fail;
    }
    id_opts->user_map_cnt = SDAP_OPTS_USER;

    /* Group map */
    ret = sdap_copy_map(id_opts,
                       ad_2008r2_group_map,
                       SDAP_OPTS_GROUP,
                       &id_opts->group_map);
    if (ret != EOK) {
        goto fail;
    }

    /* Netgroup map */
    ret = sdap_copy_map(id_opts,
                       ad_netgroup_map,
                       SDAP_OPTS_NETGROUP,
                       &id_opts->netgroup_map);
    if (ret != EOK) {
        goto fail;
    }

    /* Services map */
    ret = sdap_copy_map(id_opts,
                       ad_service_map,
                       SDAP_OPTS_SERVICES,
                       &id_opts->service_map);
    if (ret != EOK) {
        goto fail;
    }

    return id_opts;

fail:
    talloc_free(id_opts);
    return NULL;
}

struct ad_options *
ad_create_default_options(TALLOC_CTX *mem_ctx)
{
    struct ad_options *ad_options;
    errno_t ret;

    ad_options = talloc_zero(mem_ctx, struct ad_options);
    if (ad_options == NULL) return NULL;

    ret = dp_copy_defaults(ad_options,
                           ad_basic_opts,
                           AD_OPTS_BASIC,
                           &ad_options->basic);
    if (ret != EOK) {
        talloc_free(ad_options);
        return NULL;
    }

    ad_options->id = ad_create_default_sdap_options(ad_options);
    if (ad_options->id == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD LDAP options\n");
        talloc_free(ad_options);
        return NULL;
    }

    return ad_options;
}

static errno_t
set_common_ad_trust_opts(struct ad_options *ad_options,
                         const char *realm,
                         const char *ad_domain,
                         const char *hostname)
{
    errno_t ret;

    ret = dp_opt_set_string(ad_options->basic, AD_KRB5_REALM, realm);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set AD krb5 realm\n");
        return ret;
    }

    ret = dp_opt_set_string(ad_options->basic, AD_DOMAIN, ad_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set AD domain\n");
        return ret;
    }

    ret = dp_opt_set_string(ad_options->basic, AD_HOSTNAME, hostname);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set AD hostname\n");
        return ret;
    }

    return EOK;
}

struct ad_options *
ad_create_2way_trust_options(TALLOC_CTX *mem_ctx,
                             const char *realm,
                             const char *ad_domain,
                             const char *hostname)
{
    struct ad_options *ad_options;
    errno_t ret;

    ad_options = ad_create_default_options(mem_ctx);
    if (ad_options == NULL) return NULL;

    ret = set_common_ad_trust_opts(ad_options, realm, ad_domain, hostname);
    if (ret != EOK) {
        talloc_free(ad_options);
        return NULL;
    }

    ret = ad_set_sdap_options(ad_options, ad_options->id);
    if (ret != EOK) {
        talloc_free(ad_options);
        return NULL;
    }

    return ad_options;
}

struct ad_options *
ad_create_1way_trust_options(TALLOC_CTX *mem_ctx,
                             const char *ad_domain,
                             const char *hostname,
                             const char *keytab,
                             const char *sasl_authid)
{
    struct ad_options *ad_options;
    const char *realm;
    errno_t ret;

    ad_options = ad_create_default_options(mem_ctx);
    if (ad_options == NULL) return NULL;

    realm = get_uppercase_realm(ad_options, ad_domain);
    if (!realm) {
        talloc_free(ad_options);
        return NULL;
    }

    ret = set_common_ad_trust_opts(ad_options, realm,
                                   ad_domain, hostname);
    if (ret != EOK) {
        talloc_free(ad_options);
        return NULL;
    }

    /* Set AD_KEYTAB to the special 1way keytab */
    ret = dp_opt_set_string(ad_options->basic, AD_KEYTAB, keytab);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set trust keytab\n");
        talloc_free(ad_options);
        return NULL;
    }

    /* Set SDAP_SASL_AUTHID to the trust principal */
    ret = dp_opt_set_string(ad_options->id->basic,
                            SDAP_SASL_AUTHID, sasl_authid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set SASL authid\n");
        talloc_free(ad_options);
        return NULL;
    }

    ret = ad_set_sdap_options(ad_options, ad_options->id);
    if (ret != EOK) {
        talloc_free(ad_options);
        return NULL;
    }

    return ad_options;
}

static errno_t
ad_create_sdap_options(TALLOC_CTX *mem_ctx,
                       struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct sdap_options **_id_opts)
{
    struct sdap_options *id_opts;
    errno_t ret;

    id_opts = talloc_zero(mem_ctx, struct sdap_options);
    if (!id_opts) {
        ret = ENOMEM;
        goto done;
    }

    ret = dp_get_options(id_opts, cdb, conf_path,
                         ad_def_ldap_opts,
                         SDAP_OPTS_BASIC,
                         &id_opts->basic);
    if (ret != EOK) {
        goto done;
    }

    /* Get sdap option maps */

    /* General Attribute Map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_2008r2_attr_map,
                       SDAP_AT_GENERAL,
                       &id_opts->gen_map);
    if (ret != EOK) {
        goto done;
    }

    /* User map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_2008r2_user_map,
                       SDAP_OPTS_USER,
                       &id_opts->user_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_extend_map_with_list(id_opts, id_opts,
                                    SDAP_USER_EXTRA_ATTRS,
                                    id_opts->user_map,
                                    SDAP_OPTS_USER,
                                    &id_opts->user_map,
                                    &id_opts->user_map_cnt);
    if (ret != EOK) {
        goto done;
    }

    /* Group map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_2008r2_group_map,
                       SDAP_OPTS_GROUP,
                       &id_opts->group_map);
    if (ret != EOK) {
        goto done;
    }

    /* Netgroup map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_netgroup_map,
                       SDAP_OPTS_NETGROUP,
                       &id_opts->netgroup_map);
    if (ret != EOK) {
        goto done;
    }

    /* Services map */
    ret = sdap_get_map(id_opts,
                       cdb, conf_path,
                       ad_service_map,
                       SDAP_OPTS_SERVICES,
                       &id_opts->service_map);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
    *_id_opts = id_opts;
done:
    return ret;
}

errno_t
ad_get_common_options(TALLOC_CTX *mem_ctx,
                      struct confdb_ctx *cdb,
                      const char *conf_path,
                      struct sss_domain_info *dom,
                      struct ad_options **_opts)
{
    errno_t ret;
    int gret;
    struct ad_options *opts = NULL;
    char *domain;
    char *server;
    char *realm;
    char *ad_hostname;
    char hostname[HOST_NAME_MAX + 1];
    char *case_sensitive_opt;
    const char *opt_override;

    opts = talloc_zero(mem_ctx, struct ad_options);
    if (!opts) return ENOMEM;

    ret = dp_get_options(opts, cdb, conf_path,
                         ad_basic_opts,
                         AD_OPTS_BASIC,
                         &opts->basic);
    if (ret != EOK) {
        goto done;
    }

    /* If the AD domain name wasn't explicitly set, assume that it
     * matches the SSSD domain name
     */
    domain = dp_opt_get_string(opts->basic, AD_DOMAIN);
    if (!domain) {
        ret = dp_opt_set_string(opts->basic, AD_DOMAIN, dom->name);
        if (ret != EOK) {
            goto done;
        }
        domain = dom->name;
    }

    /* Did we get an explicit server name, or are we discovering it? */
    server = dp_opt_get_string(opts->basic, AD_SERVER);
    if (!server) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No AD server set, will use service discovery!\n");
    }

    /* Set the machine's hostname to the local host name if it
     * wasn't explicitly specified.
     */
    ad_hostname = dp_opt_get_string(opts->basic, AD_HOSTNAME);
    if (ad_hostname == NULL) {
        gret = gethostname(hostname, HOST_NAME_MAX);
        if (gret != 0) {
            ret = errno;
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "gethostname failed [%s].\n",
                   strerror(ret));
            goto done;
        }
        hostname[HOST_NAME_MAX] = '\0';
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Setting ad_hostname to [%s].\n", hostname);
        ret = dp_opt_set_string(opts->basic, AD_HOSTNAME, hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Setting ad_hostname failed [%s].\n",
                   strerror(ret));
            goto done;
        }
    }


    /* Always use the upper-case AD domain for the kerberos realm */
    realm = get_uppercase_realm(opts, domain);
    if (!realm) {
        ret = ENOMEM;
        goto done;
    }

    ret = dp_opt_set_string(opts->basic, AD_KRB5_REALM, realm);
    if (ret != EOK) {
        goto done;
    }

    /* Active Directory is always case-insensitive */
    ret = confdb_get_string(cdb, mem_ctx, conf_path,
                            CONFDB_DOMAIN_CASE_SENSITIVE, "false",
                            &case_sensitive_opt);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "condb_get_string failed.\n");
        goto done;
    }

    if (strcasecmp(case_sensitive_opt, "true") == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Warning: AD domain can not be set as case-sensitive.\n");
        dom->case_sensitive = false;
        dom->case_preserve = false;
    } else if (strcasecmp(case_sensitive_opt, "false") == 0) {
        dom->case_sensitive = false;
        dom->case_preserve = false;
    } else if (strcasecmp(case_sensitive_opt, "preserving") == 0) {
        dom->case_sensitive = false;
        dom->case_preserve = true;
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for %s\n", CONFDB_DOMAIN_CASE_SENSITIVE);
        goto done;
    }

    opt_override = dom->case_preserve ? "preserving" : "false";

    /* Set this in the confdb so that the responders pick it
     * up when they start up.
     */
    ret = confdb_set_string(cdb, conf_path, "case_sensitive", opt_override);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not set domain option case_sensitive: [%s]\n",
               strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Setting domain option case_sensitive to [%s]\n", opt_override);

    ret = EOK;
    *_opts = opts;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }
    return ret;
}

static void
ad_resolve_callback(void *private_data, struct fo_server *server);

static errno_t
_ad_servers_init(struct ad_service *service,
                 struct be_ctx *bectx,
                 const char *fo_service,
                 const char *fo_gc_service,
                 const char *servers,
                 const char *ad_domain,
                 bool primary)
{
    size_t i;
    errno_t ret = 0;
    char **list;
    struct ad_server_data *sdata;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Split the server list */
    ret = split_on_separator(tmp_ctx, servers, ',', true, true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse server list!\n");
        goto done;
    }

    /* Add each of these servers to the failover service */
    for (i = 0; list[i]; i++) {
        if (be_fo_is_srv_identifier(list[i])) {
            if (!primary) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to add server [%s] to failover service: "
                       "SRV resolution only allowed for primary servers!\n",
                       list[i]);
                continue;
            }

            sdata = talloc(service, struct ad_server_data);
            if (sdata == NULL) {
                ret = ENOMEM;
                goto done;
            }
            sdata->gc = true;

            ret = be_fo_add_srv_server(bectx, fo_gc_service, "gc",
                                       ad_domain, BE_FO_PROTO_TCP,
                                       false, sdata);
            if (ret != EOK) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Failed to add service discovery to failover: [%s]\n",
                      strerror(ret));
                goto done;
            }

            sdata = talloc(service, struct ad_server_data);
            if (sdata == NULL) {
                ret = ENOMEM;
                goto done;
            }
            sdata->gc = false;

            ret = be_fo_add_srv_server(bectx, fo_service, "ldap",
                                       ad_domain, BE_FO_PROTO_TCP,
                                       false, sdata);
            if (ret != EOK) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Failed to add service discovery to failover: [%s]\n",
                      strerror(ret));
                goto done;
            }

            DEBUG(SSSDBG_CONF_SETTINGS, "Added service discovery for AD\n");
            continue;
        }

        /* It could be ipv6 address in square brackets. Remove
         * the brackets if needed. */
        ret = remove_ipv6_brackets(list[i]);
        if (ret != EOK) {
            goto done;
        }

        sdata = talloc(service, struct ad_server_data);
        if (sdata == NULL) {
            ret = ENOMEM;
            goto done;
        }
        sdata->gc = true;

        ret = be_fo_add_server(bectx, fo_gc_service, list[i], 0, sdata, primary);
        if (ret && ret != EEXIST) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add server\n");
            goto done;
        }

        sdata = talloc(service, struct ad_server_data);
        if (sdata == NULL) {
            ret = ENOMEM;
            goto done;
        }
        sdata->gc = false;

        ret = be_fo_add_server(bectx, fo_service, list[i], 0, sdata, primary);
        if (ret && ret != EEXIST) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to add server\n");
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Added failover server %s\n", list[i]);
    }
done:
    talloc_free(tmp_ctx);
    return ret;
}

static inline errno_t
ad_primary_servers_init(struct ad_service *service,
                        struct be_ctx *bectx, const char *servers,
                        const char *fo_service, const char *fo_gc_service,
                        const char *ad_domain)
{
    return _ad_servers_init(service, bectx, fo_service,
                            fo_gc_service, servers, ad_domain, true);
}

static inline errno_t
ad_backup_servers_init(struct ad_service *service,
                        struct be_ctx *bectx, const char *servers,
                        const char *fo_service, const char *fo_gc_service,
                        const char *ad_domain)
{
    return _ad_servers_init(service, bectx, fo_service,
                            fo_gc_service, servers, ad_domain, false);
}

static int ad_user_data_cmp(void *ud1, void *ud2)
{
    struct ad_server_data *sd1, *sd2;

    sd1 = talloc_get_type(ud1, struct ad_server_data);
    sd2 = talloc_get_type(ud2, struct ad_server_data);
    if (sd1 == NULL || sd2 == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No user data\n");
        return sd1 == sd2 ? 0 : 1;
    }

    if (sd1->gc == sd2->gc) {
        return 0;
    }

    return 1;
}

static void ad_online_cb(void *pvt)
{
    struct ad_service *service = talloc_get_type(pvt, struct ad_service);

    if (service == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid private pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "The AD provider is online\n");
}

errno_t
ad_failover_init(TALLOC_CTX *mem_ctx, struct be_ctx *bectx,
                 const char *primary_servers,
                 const char *backup_servers,
                 const char *krb5_realm,
                 const char *ad_service,
                 const char *ad_gc_service,
                 const char *ad_domain,
                 struct ad_service **_service)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ad_service *service;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    service = talloc_zero(tmp_ctx, struct ad_service);
    if (!service) {
        ret = ENOMEM;
        goto done;
    }

    service->sdap = talloc_zero(service, struct sdap_service);
    service->gc = talloc_zero(service, struct sdap_service);
    if (!service->sdap || !service->gc) {
        ret = ENOMEM;
        goto done;
    }

    service->sdap->name = talloc_strdup(service->sdap, ad_service);
    service->gc->name = talloc_strdup(service->gc, ad_gc_service);
    if (!service->sdap->name || !service->gc->name) {
        ret = ENOMEM;
        goto done;
    }

    service->krb5_service = talloc_zero(service, struct krb5_service);
    if (!service->krb5_service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(bectx, ad_service, ad_user_data_cmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create failover service!\n");
        goto done;
    }

    ret = be_fo_add_service(bectx, ad_gc_service, ad_user_data_cmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create GC failover service!\n");
        goto done;
    }

    service->krb5_service->name = talloc_strdup(service->krb5_service,
                                                ad_service);
    if (!service->krb5_service->name) {
        ret = ENOMEM;
        goto done;
    }
    service->sdap->kinit_service_name = service->krb5_service->name;
    service->gc->kinit_service_name = service->krb5_service->name;

    if (!krb5_realm) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No Kerberos realm set\n");
        ret = EINVAL;
        goto done;
    }
    service->krb5_service->realm =
        talloc_strdup(service->krb5_service, krb5_realm);
    if (!service->krb5_service->realm) {
        ret = ENOMEM;
        goto done;
    }

    if (!primary_servers) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No primary servers defined, using service discovery\n");
        primary_servers = BE_SRV_IDENTIFIER;
    }

    ret = ad_primary_servers_init(service, bectx,
                                  primary_servers, ad_service,
                                  ad_gc_service, ad_domain);
    if (ret != EOK) {
        goto done;
    }

    if (backup_servers) {
        ret = ad_backup_servers_init(service, bectx,
                                     backup_servers, ad_service,
                                     ad_gc_service, ad_domain);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = be_add_online_cb(bectx, bectx, ad_online_cb, service, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up AD online callback\n");
        goto done;
    }

    ret = be_fo_service_add_callback(mem_ctx, bectx, ad_service,
                                     ad_resolve_callback, service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to add failover callback! [%s]\n", strerror(ret));
        goto done;
    }

    ret = be_fo_service_add_callback(mem_ctx, bectx, ad_gc_service,
                                     ad_resolve_callback, service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to add failover callback! [%s]\n", strerror(ret));
        goto done;
    }

    *_service = talloc_steal(mem_ctx, service);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void
ad_resolve_callback(void *private_data, struct fo_server *server)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ad_service *service;
    struct resolv_hostent *srvaddr;
    struct sockaddr_storage *sockaddr;
    char *address;
    const char *safe_address;
    char *new_uri;
    int new_port;
    const char *srv_name;
    struct ad_server_data *sdata = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        return;
    }

    sdata = fo_get_server_user_data(server);
    if (fo_is_srv_lookup(server) == false && sdata == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No user data?\n");
        ret = EINVAL;
        goto done;
    }

    service = talloc_get_type(private_data, struct ad_service);
    if (!service) {
        ret = EINVAL;
        goto done;
    }

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No hostent available for server (%s)\n",
               fo_get_server_str_name(server));
        ret = EINVAL;
        goto done;
    }

    address = resolv_get_string_address(tmp_ctx, srvaddr);
    if (address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "resolv_get_string_address failed.\n");
        ret = EIO;
        goto done;
    }

    srv_name = fo_get_server_name(server);
    if (srv_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not get server host name\n");
        ret = EINVAL;
        goto done;
    }

    new_uri = talloc_asprintf(service->sdap, "ldap://%s", srv_name);
    if (!new_uri) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to copy URI\n");
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_CONF_SETTINGS, "Constructed uri '%s'\n", new_uri);

    sockaddr = resolv_get_sockaddr_address(tmp_ctx, srvaddr, LDAP_PORT);
    if (sockaddr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "resolv_get_sockaddr_address failed.\n");
        ret = EIO;
        goto done;
    }

    /* free old one and replace with new one */
    talloc_zfree(service->sdap->uri);
    service->sdap->uri = new_uri;
    talloc_zfree(service->sdap->sockaddr);
    service->sdap->sockaddr = talloc_steal(service->sdap, sockaddr);

    talloc_zfree(service->gc->uri);
    talloc_zfree(service->gc->sockaddr);
    if (sdata && sdata->gc) {
        new_port = fo_get_server_port(server);
        new_port = (new_port == 0) ? AD_GC_PORT : new_port;

        service->gc->uri = talloc_asprintf(service->gc, "%s:%d",
                                           new_uri, new_port);

        service->gc->sockaddr = resolv_get_sockaddr_address(service->gc,
                                                            srvaddr,
                                                            new_port);
    } else {
        /* Make sure there always is an URI even if we know that this
         * server doesn't support GC. That way the lookup would go through
         * just not return anything
         */
        service->gc->uri = talloc_strdup(service->gc, service->sdap->uri);
        service->gc->sockaddr = talloc_memdup(service->gc, service->sdap->sockaddr,
                                              sizeof(struct sockaddr_storage));
    }

    if (!service->gc->uri) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to append to URI\n");
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_CONF_SETTINGS, "Constructed GC uri '%s'\n", service->gc->uri);

    if (service->gc->sockaddr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "resolv_get_sockaddr_address failed.\n");
        ret = EIO;
        goto done;
    }

    /* Only write kdcinfo files for local servers */
    if ((sdata == NULL || sdata->gc == false) &&
        service->krb5_service->write_kdcinfo) {
        /* Write krb5 info files */
        safe_address = sss_escape_ip_address(tmp_ctx,
                                            srvaddr->family,
                                            address);
        if (safe_address == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_escape_ip_address failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = write_krb5info_file(service->krb5_service->realm, safe_address,
                                SSS_KRB5KDC_FO_SRV);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                "write_krb5info_file failed, authentication might fail.\n");
        }
    }

    ret = EOK;
done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error: [%s]\n", strerror(ret));
    }
    talloc_free(tmp_ctx);
    return;
}

static errno_t
ad_set_sdap_options(struct ad_options *ad_opts,
                    struct sdap_options *id_opts)
{
    errno_t ret;
    char *krb5_realm;
    char *keytab_path;

    /* We only support Kerberos password policy with AD, so
     * force that on.
     */
    ret = dp_opt_set_string(id_opts->basic,
                            SDAP_PWD_POLICY,
                            PWD_POL_OPT_MIT);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set password policy\n");
        goto done;
    }

    /* Set the Kerberos Realm for GSSAPI */
    krb5_realm = dp_opt_get_string(ad_opts->basic, AD_KRB5_REALM);
    if (!krb5_realm) {
        /* Should be impossible, this is set in ad_get_common_options() */
        DEBUG(SSSDBG_FATAL_FAILURE, "No Kerberos realm\n");
        ret = EINVAL;
        goto done;
    }

    ret = dp_opt_set_string(id_opts->basic, SDAP_KRB5_REALM, krb5_realm);
    if (ret != EOK) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Option %s set to %s\n",
           id_opts->basic[SDAP_KRB5_REALM].opt_name,
           krb5_realm);

    keytab_path = dp_opt_get_string(ad_opts->basic, AD_KEYTAB);
    if (keytab_path) {
        ret = dp_opt_set_string(id_opts->basic, SDAP_KRB5_KEYTAB,
                                keytab_path);
        if (ret != EOK) goto done;
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Option %s set to %s\n",
               id_opts->basic[SDAP_KRB5_KEYTAB].opt_name,
               keytab_path);
    }

    ret = sdap_set_sasl_options(id_opts,
                                dp_opt_get_string(ad_opts->basic,
                                                  AD_HOSTNAME),
                                dp_opt_get_string(ad_opts->basic,
                                                  AD_KRB5_REALM),
                                keytab_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set the SASL-related options\n");
        goto done;
    }

    /* fix schema to AD  */
    id_opts->schema_type = SDAP_SCHEMA_AD;

    ad_opts->id = id_opts;
    ret = EOK;
done:
    return ret;
}

errno_t
ad_get_id_options(struct ad_options *ad_opts,
                  struct confdb_ctx *cdb,
                  const char *conf_path,
                  struct sdap_options **_opts)
{
    struct sdap_options *id_opts;
    errno_t ret;

    ret = ad_create_sdap_options(ad_opts, cdb, conf_path, &id_opts);
    if (ret != EOK) {
        return ENOMEM;
    }

    ret = ad_set_sdap_options(ad_opts, id_opts);
    if (ret != EOK) {
        talloc_free(id_opts);
        return ret;
    }

    ret = sdap_domain_add(id_opts,
                          ad_opts->id_ctx->sdap_id_ctx->be->domain,
                          NULL);
    if (ret != EOK) {
        talloc_free(id_opts);
        return ret;
    }

    /* Set up search bases if they were assigned explicitly */
    ret = ad_set_search_bases(id_opts);
    if (ret != EOK) {
        talloc_free(id_opts);
        return ret;
    }

    *_opts = id_opts;
    return EOK;
}

errno_t
ad_get_autofs_options(struct ad_options *ad_opts,
                      struct confdb_ctx *cdb,
                      const char *conf_path)
{
    errno_t ret;

    /* autofs maps */
    ret = sdap_get_map(ad_opts->id,
                       cdb,
                       conf_path,
                       ad_autofs_mobject_map,
                       SDAP_OPTS_AUTOFS_MAP,
                       &ad_opts->id->autofs_mobject_map);
    if (ret != EOK) {
        return ret;
    }

    ret = sdap_get_map(ad_opts->id,
                       cdb,
                       conf_path,
                       ad_autofs_entry_map,
                       SDAP_OPTS_AUTOFS_ENTRY,
                       &ad_opts->id->autofs_entry_map);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t
ad_set_search_bases(struct sdap_options *id_opts)
{
    errno_t ret;
    char *default_search_base;
    size_t o;
    const int search_base_options[] = { SDAP_USER_SEARCH_BASE,
                                        SDAP_GROUP_SEARCH_BASE,
                                        SDAP_NETGROUP_SEARCH_BASE,
                                        SDAP_SERVICE_SEARCH_BASE,
                                        -1 };

    /* AD servers provide defaultNamingContext, so we will
     * rely on that to specify the search base unless it has
     * been specifically overridden.
     */

    default_search_base =
            dp_opt_get_string(id_opts->basic, SDAP_SEARCH_BASE);

    if (default_search_base) {
        /* set search bases if they are not */
        for (o = 0; search_base_options[o] != -1; o++) {
            if (NULL == dp_opt_get_string(id_opts->basic,
                                          search_base_options[o])) {
                ret = dp_opt_set_string(id_opts->basic,
                                        search_base_options[o],
                                        default_search_base);
                if (ret != EOK) {
                    goto done;
                }
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "Option %s set to %s\n",
                       id_opts->basic[search_base_options[o]].opt_name,
                       dp_opt_get_string(id_opts->basic,
                                         search_base_options[o]));
            }
        }
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Search base not set. SSSD will attempt to discover it later, "
               "when connecting to the LDAP server.\n");
    }

    /* Default search */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_SEARCH_BASE,
                                 &id_opts->sdom->search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* User search */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_USER_SEARCH_BASE,
                                 &id_opts->sdom->user_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Group search base */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_GROUP_SEARCH_BASE,
                                 &id_opts->sdom->group_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Netgroup search */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_NETGROUP_SEARCH_BASE,
                                 &id_opts->sdom->netgroup_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Service search */
    ret = sdap_parse_search_base(id_opts, id_opts->basic,
                                 SDAP_SERVICE_SEARCH_BASE,
                                 &id_opts->sdom->service_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    ret = EOK;
done:
    return ret;
}

errno_t
ad_get_auth_options(TALLOC_CTX *mem_ctx,
                    struct ad_options *ad_opts,
                    struct be_ctx *bectx,
                    struct dp_option **_opts)
{
    errno_t ret;
    struct dp_option *krb5_options;
    const char *ad_servers;
    const char *krb5_realm;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Get krb5 options */
    ret = dp_get_options(tmp_ctx, bectx->cdb, bectx->conf_path,
                         ad_def_krb5_opts, KRB5_OPTS,
                         &krb5_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not read Kerberos options from the configuration\n");
        goto done;
    }

    ad_servers = dp_opt_get_string(ad_opts->basic, AD_SERVER);

    /* Force the krb5_servers to match the ad_servers */
    ret = dp_opt_set_string(krb5_options, KRB5_KDC, ad_servers);
    if (ret != EOK) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Option %s set to %s\n",
           krb5_options[KRB5_KDC].opt_name,
           ad_servers);

    /* Set krb5 realm */
    /* Set the Kerberos Realm for GSSAPI */
    krb5_realm = dp_opt_get_string(ad_opts->basic, AD_KRB5_REALM);
    if (!krb5_realm) {
        /* Should be impossible, this is set in ad_get_common_options() */
        DEBUG(SSSDBG_FATAL_FAILURE, "No Kerberos realm\n");
        ret = EINVAL;
        goto done;
    }

    /* Force the kerberos realm to match the AD_KRB5_REALM (which may have
     * been upper-cased in ad_common_options()
     */
    ret = dp_opt_set_string(krb5_options, KRB5_REALM, krb5_realm);
    if (ret != EOK) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Option %s set to %s\n",
           krb5_options[KRB5_REALM].opt_name,
           krb5_realm);

    /* Set flag that controls whether we want to write the
     * kdcinfo files at all
     */
    ad_opts->service->krb5_service->write_kdcinfo = \
        dp_opt_get_bool(krb5_options, KRB5_USE_KDCINFO);
    DEBUG(SSSDBG_CONF_SETTINGS, "Option %s set to %s\n",
          krb5_options[KRB5_USE_KDCINFO].opt_name,
          ad_opts->service->krb5_service->write_kdcinfo ? "true" : "false");

    *_opts = talloc_steal(mem_ctx, krb5_options);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t ad_get_dyndns_options(struct be_ctx *be_ctx,
                              struct ad_options *ad_opts)
{
    errno_t ret;

    ret = be_nsupdate_init(ad_opts, be_ctx, ad_dyndns_opts,
                           &ad_opts->dyndns_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot initialize AD dyndns opts [%d]: %s\n",
               ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}


struct ad_id_ctx *
ad_id_ctx_init(struct ad_options *ad_opts, struct be_ctx *bectx)
{
    struct sdap_id_ctx *sdap_ctx;
    struct ad_id_ctx *ad_ctx;

    ad_ctx = talloc_zero(ad_opts, struct ad_id_ctx);
    if (ad_ctx == NULL) {
        return NULL;
    }
    ad_ctx->ad_options = ad_opts;

    sdap_ctx = sdap_id_ctx_new(ad_ctx, bectx, ad_opts->service->sdap);
    if (sdap_ctx == NULL) {
        talloc_free(ad_ctx);
        return NULL;
    }
    ad_ctx->sdap_id_ctx = sdap_ctx;
    ad_ctx->ldap_ctx = sdap_ctx->conn;

    ad_ctx->gc_ctx = sdap_id_ctx_conn_add(sdap_ctx, ad_opts->service->gc);
    if (ad_ctx->gc_ctx == NULL) {
        talloc_free(ad_ctx);
        return NULL;
    }

    return ad_ctx;
}

struct sdap_id_conn_ctx *
ad_get_dom_ldap_conn(struct ad_id_ctx *ad_ctx, struct sss_domain_info *dom)
{
    struct sdap_id_conn_ctx *conn;
    struct sdap_domain *sdom;
    struct ad_id_ctx *subdom_id_ctx;

    sdom = sdap_domain_get(ad_ctx->sdap_id_ctx->opts, dom);
    if (sdom == NULL || sdom->pvt == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No ID ctx available for [%s].\n",
                                    dom->name);
        return NULL;
    }
    subdom_id_ctx = talloc_get_type(sdom->pvt, struct ad_id_ctx);
    conn = subdom_id_ctx->ldap_ctx;

    if (IS_SUBDOMAIN(sdom->dom) == true && conn != NULL) {
        /* Regardless of connection types, a subdomain error must not be
         * allowed to set the whole back end offline, rather report an error
         * and let the caller deal with it (normally disable the subdomain
         */
        conn->ignore_mark_offline = true;
    }

    return conn;
}

struct sdap_id_conn_ctx **
ad_gc_conn_list(TALLOC_CTX *mem_ctx, struct ad_id_ctx *ad_ctx,
                struct sss_domain_info *dom)
{
    struct sdap_id_conn_ctx **clist;
    int cindex = 0;

    clist = talloc_zero_array(mem_ctx, struct sdap_id_conn_ctx *, 3);
    if (clist == NULL) return NULL;

    /* Always try GC first */
    if (dp_opt_get_bool(ad_ctx->ad_options->basic, AD_ENABLE_GC)) {
        clist[cindex] = ad_ctx->gc_ctx;
        clist[cindex]->ignore_mark_offline = true;
        cindex++;
    }

    clist[cindex] = ad_get_dom_ldap_conn(ad_ctx, dom);

    return clist;
}

struct sdap_id_conn_ctx **
ad_ldap_conn_list(TALLOC_CTX *mem_ctx,
                  struct ad_id_ctx *ad_ctx,
                  struct sss_domain_info *dom)
{
    struct sdap_id_conn_ctx **clist;

    clist = talloc_zero_array(mem_ctx, struct sdap_id_conn_ctx *, 2);
    if (clist == NULL) {
        return NULL;
    }

    clist[0] = ad_get_dom_ldap_conn(ad_ctx, dom);

    clist[1] = NULL;
    return clist;
}

struct sdap_id_conn_ctx **
ad_user_conn_list(struct ad_id_ctx *ad_ctx,
                  struct sss_domain_info *dom)
{
    struct sdap_id_conn_ctx **clist;
    int cindex = 0;

    clist = talloc_zero_array(ad_ctx, struct sdap_id_conn_ctx *, 3);
    if (clist == NULL) {
        return NULL;
    }

    /* Try GC first for users from trusted domains, but go to LDAP
     * for users from non-trusted domains to get all POSIX attrs
     */
    if (dp_opt_get_bool(ad_ctx->ad_options->basic, AD_ENABLE_GC)
            && IS_SUBDOMAIN(dom)) {
        clist[cindex] = ad_ctx->gc_ctx;
        clist[cindex]->ignore_mark_offline = true;
        cindex++;
    }

    /* Users from primary domain can be just downloaded from LDAP.
     * The domain's LDAP connection also works as a fallback
     */
    clist[cindex] = ad_get_dom_ldap_conn(ad_ctx, dom);

    return clist;
}
