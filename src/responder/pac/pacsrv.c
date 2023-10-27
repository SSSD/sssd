/*
   SSSD

   PAC Responder

   Copyright (C) Sumit Bose <sbose@redhat.com> 2011

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
#include <popt.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "responder/pac/pacsrv.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "util/util_sss_idmap.h"
#include "sss_iface/sss_iface_async.h"

#define SSS_PAC_PIPE_NAME "pac"
#define DEFAULT_PAC_FD_LIMIT 8192
#define DEFAULT_ALLOWED_UIDS "0"

int pac_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *pac_cmds;
    struct pac_ctx *pac_ctx;
    int ret;
    enum idmap_error_code err;
    int fd_limit;
    char *uid_str;

    pac_cmds = get_pac_cmds();

    ret = sss_process_init(mem_ctx, ev, cdb,
                           pac_cmds,
                           SSS_PAC_SOCKET_NAME, SCKT_RSP_UMASK,
                           CONFDB_PAC_CONF_ENTRY,
                           SSS_BUS_PAC, PAC_SBUS_SERVICE_NAME,
                           sss_connection_setup,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_process_init() failed\n");
        return ret;
    }

    pac_ctx = talloc_zero(rctx, struct pac_ctx);
    if (!pac_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing pac_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    pac_ctx->rctx = rctx;
    pac_ctx->rctx->pvt_ctx = pac_ctx;

    ret = confdb_get_string(pac_ctx->rctx->cdb, pac_ctx->rctx,
                            CONFDB_PAC_CONF_ENTRY, CONFDB_SERVICE_ALLOWED_UIDS,
                            DEFAULT_ALLOWED_UIDS, &uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get allowed UIDs.\n");
        goto fail;
    }

    ret = csv_string_to_uid_array(pac_ctx->rctx, uid_str,
                                  &pac_ctx->rctx->allowed_uids_count,
                                  &pac_ctx->rctx->allowed_uids);
    talloc_free(uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to set allowed UIDs.\n");
        goto fail;
    }

    err = sss_idmap_init(sss_idmap_talloc, pac_ctx, sss_idmap_talloc_free,
                         &pac_ctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_idmap_init failed.\n");
        ret = EFAULT;
        goto fail;
    }

    /* Set up file descriptor limits */
    ret = confdb_get_int(pac_ctx->rctx->cdb,
                         CONFDB_PAC_CONF_ENTRY,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_PAC_FD_LIMIT,
                         &fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to set up file descriptor limit\n");
        goto fail;
    }
    responder_set_fd_limit(fd_limit);

    ret = confdb_get_int(pac_ctx->rctx->cdb, CONFDB_PAC_CONF_ENTRY,
                         CONFDB_PAC_LIFETIME, 300,
                         &pac_ctx->pac_lifetime);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to setup pac lifetime timeout [%s].\n",
              CONFDB_PAC_LIFETIME);
        goto fail;
    }

    ret = get_pac_check_config(pac_ctx->rctx->cdb, &pac_ctx->pac_check_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get pac_check");
        goto fail;
    }

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx, NULL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "schedule_get_domains_tasks failed.\n");
        goto fail;
    }

    /* The responder is initialized. Now tell it to the monitor. */
    ret = sss_monitor_register_service(rctx, rctx->sbus_conn,
                                       PAC_SBUS_SERVICE_NAME,
                                       PAC_SBUS_SERVICE_VERSION,
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

    DEBUG(SSSDBG_TRACE_FUNC, "PAC Initialization complete\n");

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

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
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
    debug_log_file = "sssd_pac";
    DEBUG_INIT(debug_level, opt_logger);

    ret = server_setup("pac", true, 0, CONFDB_FILE,
                       CONFDB_PAC_CONF_ENTRY, &main_ctx, true);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE, "Could not set up to exit when parent process does\n");
    }

    ret = pac_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
