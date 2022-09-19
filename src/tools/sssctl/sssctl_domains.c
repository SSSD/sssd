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
#include <talloc.h>

#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/sssctl/sssctl.h"
#include "sbus/sbus_opath.h"
#include "responder/ifp/ifp_iface/ifp_iface_sync.h"

static errno_t
sssctl_domain_list_get_properties(TALLOC_CTX *mem_ctx,
                                  struct sbus_sync_connection *conn,
                                  const char *path,
                                  const char **_name,
                                  bool *_is_subdom)
{
    errno_t ret;

    if (_name != NULL) {
        ret = sbus_get_ifp_domains_name(mem_ctx, conn, IFP_BUS, path, _name);
        if (ret != EOK) {
            goto done;
        }
    }

    if (_is_subdom != NULL) {
        ret = sbus_get_ifp_domains_subdomain(conn, IFP_BUS, path, _is_subdom);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get domain property [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
    }

    return ret;
}

errno_t sssctl_domain_list(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_sync_connection *conn;
    const char **paths;
    const char *name;
    bool is_subdom;
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

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    conn = sbus_sync_connect_system(tmp_ctx, NULL);
    if (conn == NULL) {
        ERROR("Unable to connect to system bus!\n");
        ret = EIO;
        goto done;
    }

    ret = sbus_call_ifp_ListDomains(tmp_ctx, conn, IFP_BUS, IFP_PATH, &paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to list domains [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
        goto done;
    }

    if (verbose) {
        for (i = 0; paths[i] != NULL; i++) {
            ret = sssctl_domain_list_get_properties(tmp_ctx, conn, paths[i],
                                                    &name, &is_subdom);
            if (ret != EOK) {
                goto done;
            }

            if (is_subdom) {
                printf("Trusted domain: %s\n", name);
            } else {
                printf("Primary domain: %s\n", name);
            }
        }

        return EOK;
    }

    for (i = 0; paths[i] != NULL; i++) {
        ret = sssctl_domain_list_get_properties(tmp_ctx, conn, paths[i],
                                                &name, NULL);
        if (ret != EOK) {
            goto done;
        }

        puts(name);
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
sssctl_domain_status_online(struct sbus_sync_connection *conn,
                            const char *domain_path)
{
    bool is_online;
    errno_t ret;

    ret = sbus_call_ifp_domain_IsOnline(conn, IFP_BUS, domain_path, &is_online);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get domain status [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
        return ret;
    }

    PRINT("Online status: %s\n", is_online ? _("Online") : _("Offline"));

    return EOK;
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

static errno_t
sssctl_domain_status_active_server(struct sbus_sync_connection *conn,
                                   const char *domain_path)
{
    TALLOC_CTX *tmp_ctx;
    const char *server;
    const char **services;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sbus_call_ifp_domain_ListServices(tmp_ctx, conn, IFP_BUS,
                                            domain_path, &services);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get domain services [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
        goto done;
    }

    if (services == NULL) {
        PRINT("This domain has no active servers.\n");
        ret = EOK;
        goto done;
    }

    PRINT("Active servers:\n");
    for (i = 0; services[i] != NULL; i++) {
        ret = sbus_call_ifp_domain_ActiveServer(tmp_ctx, conn, IFP_BUS,
                  domain_path, services[i], &server);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get active server [%d]: %s\n",
                  ret, sss_strerror(ret));
            PRINT_IFP_WARNING(ret);
            goto done;
        }

        /* SBUS_REQ_STRING_DEFAULT handles (server == NULL) case gracefully */
        server = SBUS_REQ_STRING_DEFAULT(server, _("not connected"));
        printf("%s: %s\n", proper_service_name(services[i]), server);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sssctl_domain_status_server_list(struct sbus_sync_connection *conn,
                                 const char *domain_path)
{
    TALLOC_CTX *tmp_ctx;
    const char **servers;
    const char **services;
    errno_t ret;
    int i, j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sbus_call_ifp_domain_ListServices(tmp_ctx, conn, IFP_BUS,
                                            domain_path, &services);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get domain services [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
        goto done;
    }

    if (services == NULL) {
        PRINT("No servers discovered.\n");
        ret = EOK;
        goto done;
    }

    for (i = 0; services[i] != NULL; i++) {
        PRINT("Discovered %s servers:\n", proper_service_name(services[i]));

        ret = sbus_call_ifp_domain_ListServers(tmp_ctx, conn, IFP_BUS,
                  domain_path, services[i], &servers);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get domain servers [%d]: %s\n",
                  ret, sss_strerror(ret));
            PRINT_IFP_WARNING(ret);
            goto done;
        }

        if (servers == NULL || servers[0] == NULL) {
            PRINT("None so far.\n");
            continue;
        }

        for (j = 0; servers[j] != NULL; j++) {
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
    TALLOC_CTX *tmp_ctx = NULL;
    struct sssctl_domain_status_opts opts = {0};
    struct sbus_sync_connection *conn;
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
                           SSS_TOOL_OPT_REQUIRED, &opts.domain, &opt_set);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        goto done;
    }

    if (opt_set == false) {
        opts.online = true;
        opts.last = true;
        opts.active = true;
        opts.servers = true;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    path = sbus_opath_compose(tmp_ctx, IFP_PATH_DOMAINS, opts.domain);
    if (path == NULL) {
        PRINT("Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    if (!sssctl_start_sssd(opts.force_start)) {
        ret = ERR_SSSD_NOT_RUNNING;
        goto done;
    }

    conn = sbus_sync_connect_system(tmp_ctx, NULL);
    if (conn == NULL) {
        ERROR("Unable to connect to system bus!\n");
        ret = EIO;
        goto done;
    }

    if (opts.online) {
        ret = sssctl_domain_status_online(conn, path);
        if (ret != EOK) {
            ERROR("Unable to get online status\n");
            goto done;
        }

        printf("\n");
    }

    if (opts.active) {
        ret = sssctl_domain_status_active_server(conn, path);
        if (ret != EOK) {
            ERROR("Unable to get online status\n");
            goto done;
        }

        printf("\n");
    }

    if (opts.servers) {
        ret = sssctl_domain_status_server_list(conn, path);
        if (ret != EOK) {
            ERROR("Unable to get server list\n");
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    free(discard_const(opts.domain));

    return ret;
}
