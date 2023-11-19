/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include "responder/sudo/sudosrv_private.h"
#include "providers/data_provider.h"
#include "responder/common/negcache.h"
#include "sss_iface/sss_iface_async.h"

int sudo_process_init(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *sudo_cmds;
    struct sudo_ctx *sudo_ctx;
    int ret;

    sudo_cmds = get_sudo_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           sudo_cmds,
                           SSS_SUDO_SOCKET_NAME, SSS_DFL_UMASK,
                           CONFDB_SUDO_CONF_ENTRY,
                           SSS_BUS_SUDO, SSS_SUDO_SBUS_SERVICE_NAME,
                           sss_connection_setup,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_process_init() failed\n");
        return ret;
    }

    sudo_ctx = talloc_zero(rctx, struct sudo_ctx);
    if (!sudo_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing sudo_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    sudo_ctx->rctx = rctx;
    sudo_ctx->rctx->pvt_ctx = sudo_ctx;

    sss_ncache_prepopulate(sudo_ctx->rctx->ncache, sudo_ctx->rctx->cdb, rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "failed to set ncache for sudo's filter_users\n");
        goto fail;
    }

    /* Get sudo_timed option */
    ret = confdb_get_bool(sudo_ctx->rctx->cdb,
                          CONFDB_SUDO_CONF_ENTRY, CONFDB_SUDO_TIMED,
                          CONFDB_DEFAULT_SUDO_TIMED,
                          &sudo_ctx->timed);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading from confdb (%d) [%s]\n",
              ret, strerror(ret));
        goto fail;
    }

    /* Get sudo_inverse_order option */
    ret = confdb_get_bool(sudo_ctx->rctx->cdb,
                          CONFDB_SUDO_CONF_ENTRY, CONFDB_SUDO_INVERSE_ORDER,
                          CONFDB_DEFAULT_SUDO_INVERSE_ORDER,
                          &sudo_ctx->inverse_order);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading from confdb (%d) [%s]\n",
              ret, strerror(ret));
        goto fail;
    }

    /* Get sudo_inverse_order option */
    ret = confdb_get_int(sudo_ctx->rctx->cdb,
                         CONFDB_SUDO_CONF_ENTRY, CONFDB_SUDO_THRESHOLD,
                         CONFDB_DEFAULT_SUDO_THRESHOLD,
                         &sudo_ctx->threshold);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading from confdb (%d) [%s]\n",
              ret, strerror(ret));
        goto fail;
    }

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx, NULL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "schedule_get_domains_tasks failed.\n");
        goto fail;
    }

    /* The responder is initialized. Now tell it to the monitor. */
    ret = sss_monitor_register_service(rctx, rctx->sbus_conn,
                                       SSS_SUDO_SBUS_SERVICE_NAME,
                                       SSS_SUDO_SBUS_SERVICE_VERSION,
                                       MT_SVC_SERVICE);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register to the monitor "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    ret = sss_resp_register_service_iface(rctx);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "SUDO Initialization complete\n");

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
    uid_t uid = 0;
    gid_t gid = 0;

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

    /* set up things like debug, signals, daemonization, etc. */
    debug_log_file = "sssd_sudo";
    DEBUG_INIT(debug_level, opt_logger);

    ret = server_setup("sudo", true, 0, uid, gid, CONFDB_FILE,
                       CONFDB_SUDO_CONF_ENTRY, &main_ctx, true);
    if (ret != EOK) {
        return 2;
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE, "Could not set up to exit "
                                  "when parent process does\n");
    }

    ret = sudo_process_init(main_ctx,
                            main_ctx->event_ctx,
                            main_ctx->confdb_ctx);
    if (ret != EOK) {
        return 3;
    }

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
