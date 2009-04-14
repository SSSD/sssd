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
#include "util/btreemap.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_sbus.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"

#define SSS_NSS_PIPE_NAME "nss"

static int service_identity(DBusMessage *message, struct sbus_conn_ctx *sconn);
static int service_pong(DBusMessage *message, struct sbus_conn_ctx *sconn);
static int service_reload(DBusMessage *message, struct sbus_conn_ctx *sconn);

struct sbus_method nss_sbus_methods[] = {
    {SERVICE_METHOD_IDENTITY, service_identity},
    {SERVICE_METHOD_PING, service_pong},
    {SERVICE_METHOD_RELOAD, service_reload},
    {NULL, NULL}
};

static int service_identity(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    dbus_uint16_t version = NSS_SBUS_SERVICE_VERSION;
    const char *name = NSS_SBUS_SERVICE_NAME;
    DBusMessage *reply;
    dbus_bool_t ret;

    DEBUG(4,("Sending ID reply: (%s,%d)\n",
             name, version));

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static int service_pong(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply, DBUS_TYPE_INVALID);
    if (!ret) {
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static int service_reload(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    /* Monitor calls this function when we need to reload
     * our configuration information. Perform whatever steps
     * are needed to update the configuration objects.
     */

    /* Send an empty reply to acknowledge receipt */
    return service_pong(message, sconn);
}

static int nss_get_config(struct nss_ctx *nctx,
                          struct resp_ctx *rctx,
                          struct confdb_ctx *cdb)
{
    TALLOC_CTX *tmpctx;
    struct sss_domain_info *dom;
    char *domain, *name;
    char **filter_list;
    int ret, i;

    tmpctx = talloc_new(nctx);
    if (!tmpctx) return ENOMEM;

    ret = confdb_get_int(cdb, nctx, NSS_SRV_CONFIG,
                         "EnumCacheTimeout", 120,
                         &nctx->enum_cache_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_int(cdb, nctx, NSS_SRV_CONFIG,
                         "EntryCacheTimeout", 600,
                         &nctx->enum_cache_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_int(cdb, nctx, NSS_SRV_CONFIG,
                         "EntryNegativeTimeout", 15,
                         &nctx->enum_cache_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_param(cdb, nctx, NSS_SRV_CONFIG,
                           "filterUsers", &filter_list);
    if (ret != EOK) goto done;
    for (i = 0; filter_list[i]; i++) {
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
    talloc_free(filter_list);

    ret = confdb_get_param(cdb, nctx, NSS_SRV_CONFIG,
                           "filterGroups", &filter_list);
    if (ret != EOK) goto done;
    for (i = 0; filter_list[i]; i++) {
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
    talloc_free(filter_list);

done:
    talloc_free(tmpctx);
    return ret;
}

static void nss_shutdown(struct resp_ctx *rctx)
{
    /* TODO: Do clean-up here */

    /* Nothing left to do but exit() */
    exit(0);
}


static void nss_dp_reconnect_init(struct sbus_conn_ctx *sconn, int status, void *pvt)
{
    int ret;
    struct resp_ctx *rctx = talloc_get_type(pvt, struct resp_ctx);

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        /* Add the methods back to the new connection */
        ret = sbus_conn_add_method_ctx(rctx->dp_ctx->scon_ctx,
                                       rctx->dp_ctx->sm_ctx);
        if (ret != EOK) {
            DEBUG(0, ("Could not re-add methods on reconnection.\n"));
            nss_shutdown(rctx);
        }

        DEBUG(1, ("Reconnected to the Data Provider.\n"));
        return;
    }

    /* Handle failure */
    DEBUG(0, ("Could not reconnect to data provider.\n"));
    /* Kill the backend and let the monitor restart it */
    nss_shutdown(rctx);
}


int nss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
    struct sbus_method *nss_dp_methods;
    struct sss_cmd_table *nss_cmds;
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

    nss_dp_methods = get_nss_dp_methods();
    nss_cmds = get_nss_cmds();

    ret = sss_process_init(nctx, ev, cdb,
                           nss_sbus_methods,
                           nss_cmds,
                           SSS_NSS_SOCKET_NAME, NULL,
                           NSS_SRV_CONFIG,
                           nss_dp_methods,
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

    /* FIXME: "retries" is too generic, either get it from a global config
     * or specify these retries are about the sbus connections to DP */
    ret = confdb_get_int(nctx->rctx->cdb, nctx->rctx,
                         nctx->rctx->confdb_service_path,
                         "retries", 3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        return ret;
    }

    sbus_reconnect_init(nctx->rctx->dp_ctx->scon_ctx,
                        max_retries,
                        nss_dp_reconnect_init, nctx->rctx);

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
		{ NULL }
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

    /* set up things like debug , signals, daemonization, etc... */
    ret = server_setup("sssd[nss]", 0, NSS_SRV_CONFIG, &main_ctx);
    if (ret != EOK) return 2;

    ret = nss_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

