/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

    Autofs responder: the responder server

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

#include "util/util.h"
#include "confdb/confdb.h"
#include "monitor/monitor_interfaces.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "responder/autofs/autofs_private.h"

static int autofs_clean_hash_table(struct sbus_request *dbus_req, void *data);

struct mon_cli_iface monitor_autofs_methods = {
    { &mon_cli_iface_meta, 0 },
    .ping = monitor_common_pong,
    .resInit = monitor_common_res_init,
    .shutDown = NULL,
    .goOffline = NULL,
    .resetOffline = NULL,
    .rotateLogs = responder_logrotate,
    .clearMemcache = NULL,
    .clearEnumCache = autofs_clean_hash_table,
    .sysbusReconnect = NULL,
};

static struct data_provider_iface autofs_dp_methods = {
    { &data_provider_iface_meta, 0 },
    .RegisterService = NULL,
    .pamHandler = NULL,
    .sudoHandler = NULL,
    .autofsHandler = NULL,
    .hostHandler = NULL,
    .getDomains = NULL,
    .getAccountInfo = NULL,
};

static errno_t
autofs_get_config(struct autofs_ctx *actx,
                  struct confdb_ctx *cdb)
{
    errno_t ret;

    ret = confdb_get_int(cdb, CONFDB_AUTOFS_CONF_ENTRY,
                         CONFDB_AUTOFS_MAP_NEG_TIMEOUT, 15,
                         &actx->neg_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read %s from configuration [%d]: %s\n",
              CONFDB_AUTOFS_MAP_NEG_TIMEOUT, ret, strerror(ret));
        return ret;
    }

    return EOK;
}

static void
autofs_dp_reconnect_init(struct sbus_connection *conn,
                         int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(SSSDBG_TRACE_FUNC, "Reconnected to the Data Provider.\n");

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "autofs");
        /* all fine */
        if (ret == EOK) {
            handle_requests_after_reconnect(be_conn->rctx);
            return;
        }
    }

    /* Failed to reconnect */
    DEBUG(SSSDBG_FATAL_FAILURE, "Could not reconnect to %s provider.\n",
                                 be_conn->domain->name);
}

static int autofs_clean_hash_table(struct sbus_request *dbus_req, void *data)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);
    struct autofs_ctx *actx =
            talloc_get_type(rctx->pvt_ctx, struct autofs_ctx);
    errno_t ret;

    ret = autofs_orphan_maps(actx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not invalidate maps\n");
        return ret;
    }

    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}

static int
autofs_process_init(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *autofs_cmds;
    struct autofs_ctx *autofs_ctx;
    struct be_conn *iter;
    int ret;
    int hret;
    int max_retries;

    autofs_cmds = get_autofs_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           autofs_cmds,
                           SSS_AUTOFS_SOCKET_NAME, NULL,
                           CONFDB_AUTOFS_CONF_ENTRY,
                           SSS_AUTOFS_SBUS_SERVICE_NAME,
                           SSS_AUTOFS_SBUS_SERVICE_VERSION,
                           &monitor_autofs_methods,
                           "autofs",
                           &autofs_dp_methods.vtable,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_process_init() failed\n");
        return ret;
    }

    autofs_ctx = talloc_zero(rctx, struct autofs_ctx);
    if (!autofs_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing autofs_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = autofs_get_config(autofs_ctx, cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot read autofs configuration\n");
        goto fail;
    }

    autofs_ctx->rctx = rctx;
    autofs_ctx->rctx->pvt_ctx = autofs_ctx;

    /* Enable automatic reconnection to the Data Provider */
    ret = confdb_get_int(autofs_ctx->rctx->cdb,
                         CONFDB_AUTOFS_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES,
                         3, &max_retries);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to set up automatic reconnection\n");
        goto fail;
    }

    for (iter = autofs_ctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            autofs_dp_reconnect_init, iter);
    }

    /* Create the lookup table for setautomntent results */
    hret = sss_hash_create_ex(autofs_ctx, 10, &autofs_ctx->maps, 0, 0, 0, 0,
                              autofs_map_hash_delete_cb, NULL);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to initialize automount maps hash table\n");
        ret = EIO;
        goto fail;
    }

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "schedule_get_domains_tasks failed.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "autofs Initialization complete\n");
    return EOK;

fail:
    talloc_free(rctx);
    return ret;
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

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

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

    DEBUG_INIT(debug_level);

    /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_autofs";

    ret = server_setup("sssd[autofs]", 0, CONFDB_AUTOFS_CONF_ENTRY, &main_ctx);
    if (ret != EOK) {
        return 2;
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE, "Could not set up to exit "
                                  "when parent process does\n");
    }

    ret = autofs_process_init(main_ctx,
                              main_ctx->event_ctx,
                              main_ctx->confdb_ctx);
    if (ret != EOK) {
        return 3;
    }

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
