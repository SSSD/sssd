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

#include <popt.h>
#include <stdio.h>

#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/sssctl/sssctl.h"
#include "sbus/sssd_dbus.h"
#include "responder/ifp/ifp_iface.h"

#define SSS_SIFP_ATTR_SUBDOMAIN "subdomain"

errno_t domain_is_subdomain_check(sss_sifp_ctx *sifp_ctx,
                                  char *domain,
                                  bool *_is_subdom)
{
    bool is_subdom;
    sss_sifp_error error;
    sss_sifp_object *domain_obj;

    error = sss_sifp_fetch_domain_by_name(sifp_ctx, domain, &domain_obj);
    if (error != SSS_SIFP_OK) {
        sssctl_sifp_error(sifp_ctx, error, "Unable to fetch domain by name");
        return EIO;
    }

    error = sss_sifp_find_attr_as_bool(domain_obj->attrs,
                                       SSS_SIFP_ATTR_SUBDOMAIN,
                                       &is_subdom);
    if (error != SSS_SIFP_OK) {
        sssctl_sifp_error(sifp_ctx, error, "Unable to find subdomain attr");
        return EIO;
    }

    *_is_subdom = is_subdom;

    return EOK;
}

errno_t sssctl_domain_list(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt)
{
    sss_sifp_ctx *sifp;
    sss_sifp_error error;
    bool is_subdom;
    char **domains;
    int start = 0;
    int verbose = 0;
    errno_t ret;
    int i;

    /* Parse command line. */
    struct poptOption options[] = {
        {"start", 's', POPT_ARG_NONE, &start, 0, _("Start SSSD if it is not running"), NULL },
        {"verbose", 'v', POPT_ARG_NONE, &verbose, 0, _("Show domain list including primary or trusted domain type"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt(cmdline, options, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    if (!sssctl_start_sssd(start)) {
        return ERR_SSSD_NOT_RUNNING;
    }

    error = sssctl_sifp_init(tool_ctx, &sifp);
    if (error != SSS_SIFP_OK) {
        sssctl_sifp_error(sifp, error, "Unable to connect to the InfoPipe");
        return EFAULT;
    }

    error = sss_sifp_list_domains(sifp, &domains);
    if (error != SSS_SIFP_OK) {
        sssctl_sifp_error(sifp, error, "Unable to get domains list");
        return EIO;
    }

    if (verbose) {
        for (i = 0; domains[i] != NULL; i++) {
            ret = domain_is_subdomain_check(sifp, domains[i], &is_subdom);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Subdomain check failed\n");
                return ret;
            }

            if (is_subdom) {
                printf("Trusted domain: %s\n", domains[i]);
            } else {
                printf("Primary domain: %s\n", domains[i]);
            }
        }

        return EOK;
    }

    for (i = 0; domains[i] != NULL; i++) {
        puts(domains[i]);
    }

    return EOK;
}

static errno_t sssctl_domain_status_online(struct sss_tool_ctx *tool_ctx,
                                           sss_sifp_ctx *sifp,
                                           const char *domain_path)
{
    TALLOC_CTX *tmp_ctx;
    sss_sifp_error error;
    DBusMessage *reply;
    bool is_online;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    error = sssctl_sifp_send(tmp_ctx, sifp, &reply, domain_path,
                             IFACE_IFP_DOMAINS_DOMAIN,
                             IFACE_IFP_DOMAINS_DOMAIN_ISONLINE);
    if (error != SSS_SIFP_OK) {
        sssctl_sifp_error(sifp, error, "Unable to get online status");
        ret = EIO;
        goto done;
    }

    ret = sbus_parse_reply(reply, DBUS_TYPE_BOOLEAN, &is_online);
    if (ret != EOK) {
        goto done;
    }

    printf(_("Online status: %s\n"), is_online ? _("Online") : _("Offline"));

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static const char *proper_service_name(const char *service)
{
    if (strcasecmp(service, "AD_GC") == 0) {
        return "AD Global Catalog";
    } else if (strcasecmp(service, "AD") == 0) {
        return "AD Domain Controller";
    } else if (strncasecmp(service, "sd_gc_", strlen("sd_gc_")) == 0) {
        return "AD Global Catalog";
    } else if (strncasecmp(service, "sd_", strlen("sd_")) == 0) {
        return "AD Domain Controller";
    }

    return service;
}

static errno_t sssctl_domain_status_active_server(struct sss_tool_ctx *tool_ctx,
                                                  sss_sifp_ctx *sifp,
                                                  const char *domain_path)
{
    TALLOC_CTX *tmp_ctx;
    sss_sifp_error error;
    DBusMessage *reply;
    const char *server;
    const char **services;
    int num_services;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    error = sssctl_sifp_send(tmp_ctx, sifp, &reply, domain_path,
                             IFACE_IFP_DOMAINS_DOMAIN,
                             IFACE_IFP_DOMAINS_DOMAIN_LISTSERVICES);
    if (error != SSS_SIFP_OK) {
        sssctl_sifp_error(sifp, error, "Unable to list services");
        ret = EIO;
        goto done;
    }

    ret = sbus_parse_reply(reply, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
                           &services, &num_services);
    if (ret != EOK) {
        goto done;
    }

    printf(_("Active servers:\n"));
    for (i = 0; i < num_services; i++) {
        error = sssctl_sifp_send(tmp_ctx, sifp, &reply, domain_path,
                                 IFACE_IFP_DOMAINS_DOMAIN,
                                 IFACE_IFP_DOMAINS_DOMAIN_ACTIVESERVER,
                                 DBUS_TYPE_STRING, &services[i]);
        if (error != SSS_SIFP_OK) {
            sssctl_sifp_error(sifp, error, "Unable to get active server");
            ret = EIO;
            goto done;
        }

        ret = sbus_parse_reply(reply, DBUS_TYPE_STRING, &server);
        if (ret != EOK) {
            goto done;
        }

        server = SBUS_IS_STRING_EMPTY(server) ? _("not connected") : server;
        printf("%s: %s\n", proper_service_name(services[i]), server);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sssctl_domain_status_server_list(struct sss_tool_ctx *tool_ctx,
                                                sss_sifp_ctx *sifp,
                                                const char *domain_path)
{
    TALLOC_CTX *tmp_ctx;
    sss_sifp_error error;
    DBusMessage *reply;
    const char **servers;
    int num_servers;
    const char **services;
    int num_services;
    errno_t ret;
    int i, j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    error = sssctl_sifp_send(tmp_ctx, sifp, &reply, domain_path,
                             IFACE_IFP_DOMAINS_DOMAIN,
                             IFACE_IFP_DOMAINS_DOMAIN_LISTSERVICES);
    if (error != SSS_SIFP_OK) {
        sssctl_sifp_error(sifp, error, "Unable to list services");
        ret = EIO;
        goto done;
    }

    ret = sbus_parse_reply(reply, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
                           &services, &num_services);
    if (ret != EOK) {
        goto done;
    }

    for (i = 0; i < num_services; i++) {
        printf(_("Discovered %s servers:\n"), proper_service_name(services[i]));
        error = sssctl_sifp_send(tmp_ctx, sifp, &reply, domain_path,
                                 IFACE_IFP_DOMAINS_DOMAIN,
                                 IFACE_IFP_DOMAINS_DOMAIN_LISTSERVERS,
                                 DBUS_TYPE_STRING, &services[i]);
        if (error != SSS_SIFP_OK) {
            sssctl_sifp_error(sifp, error, "Unable to get active server");
            ret = EIO;
            goto done;
        }

        ret = sbus_parse_reply(reply, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
                               &servers, &num_servers);
        if (ret != EOK) {
            goto done;
        }

        if (num_servers == 0) {
            puts(_("None so far.\n"));
            continue;
        }

        for (j = 0; j < num_servers; j++) {
            printf("- %s\n", servers[j]);
        }

        printf("\n");
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct sssctl_domain_status_opts {
    const char *domain;
    int online;
    int last;
    int active;
    int servers;
    int force_start;
};

errno_t sssctl_domain_status(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt)
{
    struct sssctl_domain_status_opts opts = {0};
    sss_sifp_ctx *sifp;
    sss_sifp_error error;
    const char *path;
    bool opt_set;
    errno_t ret;

    /* Parse command line. */
    struct poptOption options[] = {
        {"online", 'o', POPT_ARG_NONE , &opts.online, 0, _("Show online status"), NULL },
        {"active-server", 'a', POPT_ARG_NONE, &opts.active, 0, _("Show information about active server"), NULL },
        {"servers", 'r', POPT_ARG_NONE, &opts.servers, 0, _("Show list of discovered servers"), NULL },
        {"start", 's', POPT_ARG_NONE, &opts.force_start, 0, _("Start SSSD if it is not running"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt_ex(cmdline, options, SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, "DOMAIN", _("Specify domain name."),
                           &opts.domain, &opt_set);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    if (opt_set == false) {
        opts.online = true;
        opts.last = true;
        opts.active = true;
        opts.servers = true;
    }

    path = sbus_opath_compose(tool_ctx, IFP_PATH_DOMAINS, opts.domain);
    if (path == NULL) {
        printf(_("Out of memory!\n"));
        return ENOMEM;
    }

    if (!sssctl_start_sssd(opts.force_start)) {
        return ERR_SSSD_NOT_RUNNING;
    }

    error = sssctl_sifp_init(tool_ctx, &sifp);
    if (error != SSS_SIFP_OK) {
        sssctl_sifp_error(sifp, error, "Unable to connect to the InfoPipe");
        return EFAULT;
    }

    if (opts.online) {
        ret = sssctl_domain_status_online(tool_ctx, sifp, path);
        if (ret != EOK) {
            fprintf(stderr, _("Unable to get online status\n"));
            return ret;
        }

        printf("\n");
    }

    if (opts.active) {
        ret = sssctl_domain_status_active_server(tool_ctx, sifp, path);
        if (ret != EOK) {
            fprintf(stderr, _("Unable to get online status\n"));
            return ret;
        }

        printf("\n");
    }

    if (opts.servers) {
        ret = sssctl_domain_status_server_list(tool_ctx, sifp, path);
        if (ret != EOK) {
            fprintf(stderr, _("Unable to get server list\n"));
            return ret;
        }
    }

    return EOK;
}
