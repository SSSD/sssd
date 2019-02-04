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
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "responder/autofs/autofs_private.h"
#include "sss_iface/sss_iface_async.h"

static errno_t
autofs_get_config(struct autofs_ctx *actx,
                  struct confdb_ctx *cdb)
{
    errno_t ret;

    ret = confdb_get_int(cdb, CONFDB_AUTOFS_CONF_ENTRY,
                         CONFDB_AUTOFS_MAP_NEG_TIMEOUT, 15,
                         &actx->neg_timeout);
    return ret;
}

static errno_t
autofs_clean_hash_table(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct autofs_ctx *actx)
{
    errno_t ret;

    ret = autofs_orphan_maps(actx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not invalidate maps\n");
    }

    return ret;
}

static errno_t
autofs_register_service_iface(struct autofs_ctx *autofs_ctx,
                              struct resp_ctx *rctx)
{
    errno_t ret;

    SBUS_INTERFACE(iface_svc,
        sssd_service,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_service, resInit, monitor_common_res_init, NULL),
            SBUS_SYNC(METHOD, sssd_service, rotateLogs, responder_logrotate, rctx),
            SBUS_SYNC(METHOD, sssd_service, clearEnumCache, autofs_clean_hash_table, autofs_ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    ret = sbus_connection_add_path(rctx->mon_conn, SSS_BUS_PATH, &iface_svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register service interface"
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    return ret;
}

static int
autofs_process_init(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *autofs_cmds;
    struct autofs_ctx *autofs_ctx;
    int ret;
    int hret;

    autofs_cmds = get_autofs_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           autofs_cmds,
                           SSS_AUTOFS_SOCKET_NAME, -1, NULL, -1,
                           CONFDB_AUTOFS_CONF_ENTRY,
                           SSS_BUS_AUTOFS, SSS_AUTOFS_SBUS_SERVICE_NAME,
                           autofs_connection_setup,
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

    /* Create the lookup table for setautomntent results */
    hret = sss_hash_create_ex(autofs_ctx, 10, &autofs_ctx->maps, 0, 0, 0, 0,
                              autofs_map_hash_delete_cb, NULL);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to initialize automount maps hash table\n");
        ret = EIO;
        goto fail;
    }

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "schedule_get_domains_tasks failed.\n");
        goto fail;
    }

    /* The responder is initialized. Now tell it to the monitor. */
    ret = sss_monitor_service_init(rctx, rctx->ev, SSS_BUS_AUTOFS,
                                   SSS_AUTOFS_SBUS_SERVICE_NAME,
                                   SSS_AUTOFS_SBUS_SERVICE_VERSION,
                                   MT_SVC_SERVICE,
                                   &rctx->last_request_time, &rctx->mon_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error setting up message bus\n");
        goto fail;
    }

    ret = autofs_register_service_iface(autofs_ctx, rctx);
    if (ret != EOK) {
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
    char *opt_logger = NULL;
    struct main_context *main_ctx;
    int ret;
    uid_t uid;
    gid_t gid;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
        SSSD_SERVER_OPTS(uid, gid)
        SSSD_RESPONDER_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    umask(DFL_RSP_UMASK);

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

    /* set up things like debug, signals, daemonization, etc. */
    debug_log_file = "sssd_autofs";

    sss_set_logger(opt_logger);

    ret = server_setup("sssd[autofs]", 0, uid, gid,
                       CONFDB_AUTOFS_CONF_ENTRY, &main_ctx);
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
