/*
   SSSD

   NSS Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include "popt.h"
#include "util/util.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_nc.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"

#define SSS_NSS_PIPE_NAME "nss"

#define DEFAULT_PWFIELD "*"

struct sbus_method monitor_nss_methods[] = {
    { MON_CLI_METHOD_PING, monitor_common_pong },
    { MON_CLI_METHOD_RES_INIT, monitor_common_res_init },
    { MON_CLI_METHOD_ROTATE, monitor_common_rotate_logs },
    { NULL, NULL }
};

struct sbus_interface monitor_nss_interface = {
    MONITOR_INTERFACE,
    MONITOR_PATH,
    SBUS_DEFAULT_VTABLE,
    monitor_nss_methods,
    NULL
};

static int nss_get_config(struct nss_ctx *nctx,
                          struct resp_ctx *rctx,
                          struct confdb_ctx *cdb)
{
    TALLOC_CTX *tmpctx;
    struct sss_domain_info *dom;
    const char *conf_path;
    char *domain, *name;
    char **filter_list = NULL;
    int ret, i;
    bool filter_set;

    tmpctx = talloc_new(nctx);
    if (!tmpctx) return ENOMEM;

    ret = confdb_get_int(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENUM_CACHE_TIMEOUT, 120,
                         &nctx->enum_cache_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_int(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENTRY_NEG_TIMEOUT, 15,
                         &nctx->neg_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_bool(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_FILTER_USERS_IN_GROUPS, true,
                         &nctx->filter_users_in_groups);
    if (ret != EOK) goto done;


    ret = confdb_get_int(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENTRY_CACHE_NOWAIT_PERCENTAGE, 0,
                         &nctx->cache_refresh_percent);
    if (ret != EOK) goto done;
    if (nctx->cache_refresh_percent < 0 ||
        nctx->cache_refresh_percent > 99) {
        DEBUG(0,("Configuration error: entry_cache_nowait_percentage is"
                 "invalid. Disabling feature.\n"));
        nctx->cache_refresh_percent = 0;
    }

    filter_set = false;
    for (dom = rctx->domains; dom; dom = dom->next) {
        conf_path = talloc_asprintf(tmpctx, CONFDB_DOMAIN_PATH_TMPL, dom->name);
        if (!conf_path) {
            ret = ENOMEM;
            goto done;
        }

        talloc_zfree(filter_list);
        ret = confdb_get_string_as_list(cdb, tmpctx, conf_path,
                                        CONFDB_NSS_FILTER_USERS, &filter_list);
        if (ret == ENOENT) continue;
        if (ret != EOK) goto done;
        filter_set = true;

        for (i = 0; (filter_list && filter_list[i]); i++) {
            ret = sss_parse_name(tmpctx, nctx->rctx->names,
                                 filter_list[i], &domain, &name);
            if (ret != EOK) {
                DEBUG(1, ("Invalid name in filterUsers list: [%s] (%d)\n",
                         filter_list[i], ret));
                continue;
            }

            if (domain && strcmp(domain, dom->name)) {
                DEBUG(1, ("Mismatch betwen domain name (%s) and name "
                          "set in FQN  (%s), skipping user %s\n",
                          dom->name, domain, name));
                continue;
            }

            ret = nss_ncache_set_user(nctx->ncache, true, dom->name, name);
            if (ret != EOK) {
                DEBUG(1, ("Failed to store permanent user filter for [%s]"
                          " (%d [%s])\n", filter_list[i],
                          ret, strerror(ret)));
                continue;
            }
        }
    }

    ret = confdb_get_string_as_list(cdb, tmpctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_FILTER_USERS, &filter_list);
    if (ret == ENOENT) {
        if (!filter_set) {
            filter_list = talloc_array(tmpctx, char *, 2);
            if (!filter_list) {
                ret = ENOMEM;
                goto done;
            }
            filter_list[0] = talloc_strdup(tmpctx, "root");
            if (!filter_list[0]) {
                ret = ENOMEM;
                goto done;
            }
            filter_list[1] = NULL;
        }
        ret = EOK;
    }
    else if (ret != EOK) goto done;

    for (i = 0; (filter_list && filter_list[i]); i++) {
        ret = sss_parse_name(tmpctx, nctx->rctx->names,
                             filter_list[i], &domain, &name);
        if (ret != EOK) {
            DEBUG(1, ("Invalid name in filterUsers list: [%s] (%d)\n",
                     filter_list[i], ret));
            continue;
        }
        if (domain) {
            ret = nss_ncache_set_user(nctx->ncache, true, domain, name);
            if (ret != EOK) {
                DEBUG(1, ("Failed to store permanent user filter for [%s]"
                          " (%d [%s])\n", filter_list[i],
                          ret, strerror(ret)));
                continue;
            }
        } else {
            for (dom = rctx->domains; dom; dom = dom->next) {
                ret = nss_ncache_set_user(nctx->ncache, true, dom->name, name);
                if (ret != EOK) {
                   DEBUG(1, ("Failed to store permanent user filter for"
                             " [%s:%s] (%d [%s])\n",
                             dom->name, filter_list[i],
                             ret, strerror(ret)));
                    continue;
                }
            }
        }
    }

    filter_set = false;
    for (dom = rctx->domains; dom; dom = dom->next) {
        conf_path = talloc_asprintf(tmpctx, CONFDB_DOMAIN_PATH_TMPL, dom->name);
        if (!conf_path) {
            ret = ENOMEM;
            goto done;
        }

        talloc_zfree(filter_list);
        ret = confdb_get_string_as_list(cdb, tmpctx, conf_path,
                                        CONFDB_NSS_FILTER_GROUPS, &filter_list);
        if (ret == ENOENT) continue;
        if (ret != EOK) goto done;
        filter_set = true;

        for (i = 0; (filter_list && filter_list[i]); i++) {
            ret = sss_parse_name(tmpctx, nctx->rctx->names,
                                 filter_list[i], &domain, &name);
            if (ret != EOK) {
                DEBUG(1, ("Invalid name in filterGroups list: [%s] (%d)\n",
                         filter_list[i], ret));
                continue;
            }

            if (domain && strcmp(domain, dom->name)) {
                DEBUG(1, ("Mismatch betwen domain name (%s) and name "
                          "set in FQN  (%s), skipping group %s\n",
                          dom->name, domain, name));
                continue;
            }

            ret = nss_ncache_set_group(nctx->ncache, true, dom->name, name);
            if (ret != EOK) {
                DEBUG(1, ("Failed to store permanent group filter for [%s]"
                          " (%d [%s])\n", filter_list[i],
                          ret, strerror(ret)));
                continue;
            }
        }
    }

    ret = confdb_get_string_as_list(cdb, tmpctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_FILTER_GROUPS, &filter_list);
    if (ret == ENOENT) {
        if (!filter_set) {
            filter_list = talloc_array(tmpctx, char *, 2);
            if (!filter_list) {
                ret = ENOMEM;
                goto done;
            }
            filter_list[0] = talloc_strdup(tmpctx, "root");
            if (!filter_list[0]) {
                ret = ENOMEM;
                goto done;
            }
            filter_list[1] = NULL;
        }
        ret = EOK;
    }
    else if (ret != EOK) goto done;

    for (i = 0; (filter_list && filter_list[i]); i++) {
        ret = sss_parse_name(tmpctx, nctx->rctx->names,
                             filter_list[i], &domain, &name);
        if (ret != EOK) {
            DEBUG(1, ("Invalid name in filterGroups list: [%s] (%d)\n",
                     filter_list[i], ret));
            continue;
        }
        if (domain) {
            ret = nss_ncache_set_group(nctx->ncache, true, domain, name);
            if (ret != EOK) {
                DEBUG(1, ("Failed to store permanent group filter for"
                          " [%s] (%d [%s])\n", filter_list[i],
                          ret, strerror(ret)));
                continue;
            }
        } else {
            for (dom = rctx->domains; dom; dom = dom->next) {
                ret = nss_ncache_set_group(nctx->ncache, true, dom->name, name);
                if (ret != EOK) {
                   DEBUG(1, ("Failed to store permanent group filter for"
                             " [%s:%s] (%d [%s])\n",
                             dom->name, filter_list[i],
                             ret, strerror(ret)));
                    continue;
                }
            }
        }
    }

    ret = confdb_get_string(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_PWFIELD, DEFAULT_PWFIELD,
                            &nctx->pwfield);
    if (ret != EOK) goto done;

    ret = 0;
done:
    talloc_free(tmpctx);
    return ret;
}

static struct sbus_method nss_dp_methods[] = {
    { NULL, NULL }
};

struct sbus_interface nss_dp_interface = {
    DP_INTERFACE,
    DP_PATH,
    SBUS_DEFAULT_VTABLE,
    nss_dp_methods,
    NULL
};


static void nss_dp_reconnect_init(struct sbus_connection *conn,
                                  int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(1, ("Reconnected to the Data Provider.\n"));

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "NSS");
        /* all fine */
        if (ret == EOK) return;
    }

    /* Failed to reconnect */
    DEBUG(0, ("Could not reconnect to %s provider.\n",
              be_conn->domain->name));

    /* FIXME: kill the frontend and let the monitor restart it ? */
    /* nss_shutdown(rctx); */
}

int nss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
    struct sss_cmd_table *nss_cmds;
    struct be_conn *iter;
    struct nss_ctx *nctx;
    int ret, max_retries;

    nctx = talloc_zero(mem_ctx, struct nss_ctx);
    if (!nctx) {
        DEBUG(0, ("fatal error initializing nss_ctx\n"));
        return ENOMEM;
    }

    ret = nss_ncache_init(nctx, &nctx->ncache);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing negative cache\n"));
        return ret;
    }

    nss_cmds = get_nss_cmds();

    ret = sss_process_init(nctx, ev, cdb,
                           nss_cmds,
                           SSS_NSS_SOCKET_NAME, NULL,
                           CONFDB_NSS_CONF_ENTRY,
                           NSS_SBUS_SERVICE_NAME,
                           NSS_SBUS_SERVICE_VERSION,
                           &monitor_nss_interface,
                           "NSS", &nss_dp_interface,
                           &nctx->rctx);
    if (ret != EOK) {
        return ret;
    }
    nctx->rctx->pvt_ctx = nctx;

    ret = nss_get_config(nctx, nctx->rctx, cdb);
    if (ret != EOK) {
        DEBUG(0, ("fatal error getting nss config\n"));
        return ret;
    }

    /* Enable automatic reconnection to the Data Provider */
    ret = confdb_get_int(nctx->rctx->cdb, nctx->rctx,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES,
                         3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        return ret;
    }

    for (iter = nctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            nss_dp_reconnect_init, iter);
    }

    DEBUG(1, ("NSS Initialization complete\n"));

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    poptFreeContext(pc);

   /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_nss";

    ret = server_setup("sssd[nss]", 0, CONFDB_NSS_CONF_ENTRY, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    ret = nss_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

