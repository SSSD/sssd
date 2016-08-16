/*
   SSSD

   Secrets Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016

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

#include "util/util.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <popt.h>

#include "responder/common/responder.h"
#include "responder/secrets/secsrv.h"
#include "resolv/async_resolv.h"

#define DEFAULT_SEC_FD_LIMIT 2048

static int sec_get_config(struct sec_ctx *sctx)
{
    int ret;

    ret = confdb_get_int(sctx->rctx->cdb,
                         sctx->rctx->confdb_service_path,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_SEC_FD_LIMIT,
                         &sctx->fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get file descriptors limit\n");
        goto fail;
    }

    ret = confdb_get_int(sctx->rctx->cdb, sctx->rctx->confdb_service_path,
                         CONFDB_RESPONDER_CLI_IDLE_TIMEOUT,
                         CONFDB_RESPONDER_CLI_IDLE_DEFAULT_TIMEOUT,
                         &sctx->rctx->client_idle_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the client idle timeout [%d]: %s\n",
               ret, strerror(ret));
        goto fail;
    }

    /* Ensure that the client timeout is at least ten seconds */
    if (sctx->rctx->client_idle_timeout < 10) {
        sctx->rctx->client_idle_timeout = 10;
    }

    ret = EOK;

fail:
    return ret;
}

static int sec_responder_ctx_destructor(void *ptr)
{
    struct resp_ctx *rctx = talloc_get_type(ptr, struct resp_ctx);

    /* mark that we are shutting down the responder, so it is propagated
     * into underlying contexts that are freed right before rctx */
    DEBUG(SSSDBG_TRACE_FUNC, "Responder is being shut down\n");
    rctx->shutting_down = true;

    return 0;
}

static int sec_process_init(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sec_ctx *sctx;
    int ret;

    rctx = talloc_zero(mem_ctx, struct resp_ctx);
    if (!rctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing resp_ctx\n");
        return ENOMEM;
    }
    rctx->ev = ev;
    rctx->cdb = cdb;
    rctx->sock_name = SSS_SEC_SOCKET_NAME;
    rctx->confdb_service_path = CONFDB_SEC_CONF_ENTRY;
    rctx->shutting_down = false;

    talloc_set_destructor((TALLOC_CTX*)rctx, sec_responder_ctx_destructor);

    sctx = talloc_zero(rctx, struct sec_ctx);
    if (!sctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing sec_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    sctx->rctx = rctx;
    sctx->rctx->pvt_ctx = sctx;

    ret = sec_get_config(sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error getting secrets config\n");
        goto fail;
    }

    ret = resolv_init(sctx, ev, SEC_NET_TIMEOUT, &sctx->resctx);
    if (ret != EOK) {
        /* not fatal for now */
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize resolver library\n");
    }

    /* Set up file descriptor limits */
    responder_set_fd_limit(sctx->fd_limit);

    ret = activate_unix_sockets(rctx, sec_connection_setup);
    if (ret != EOK) goto fail;

    DEBUG(SSSDBG_TRACE_FUNC, "Secrets Initialization complete\n");

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
    uid_t uid;
    gid_t gid;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_SERVER_OPTS(uid, gid)
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_secrets";

    ret = server_setup("sssd[secrets]", 0, uid, gid, CONFDB_SEC_CONF_ENTRY,
                       &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = sec_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
