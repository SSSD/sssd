/*
    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

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

#include "util/util.h"
#include "confdb/confdb_setup.h"
#include "responder/common/responder.h"


/* Dummy, not used here but required to link to other responder files */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    return NULL;
}

static errno_t update_confdb_update(struct cli_ctx *cctx)
{
    TALLOC_CTX *tmp_ctx;
    struct confdb_ctx *confdb;
    char *path;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    path = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (path == NULL) {
        return ENOMEM;
    }

    ret = confdb_setup(tmp_ctx, path, SSSD_CONFIG_FILE, CONFDB_DEFAULT_CONFIG_DIR, &confdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to setup ConfDB [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = EOK;

    TEVENT_FD_WRITEABLE(cctx->cfde);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int update_confdb_send_data(int fd)
{
    char data = '1';
    ssize_t len;

    errno = 0;
    len = send(fd, &data, 1, 0);
    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return EAGAIN;
        } else {
            return errno;
        }
    }

    if (len == 0) {
        return EIO;
    }

    return EOK;
}

static void update_confdb_send(struct cli_ctx *cctx)
{
    int ret;

    ret = update_confdb_send_data(cctx->cfd);
    if (ret == EAGAIN) {
        /* not all data was sent, loop again */
        return;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to send data, aborting client!\n");
        talloc_free(cctx);

        return;
    }

    /* ok all sent */
    TEVENT_FD_NOT_WRITEABLE(cctx->cfde);
    TEVENT_FD_READABLE(cctx->cfde);

    exit(0);
}

static int update_confdb_recv_data(int fd)
{
    char data;
    ssize_t len;

    errno = 0;
    len = recv(fd, &data, 1, 0);
    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return EAGAIN;
        } else {
            return errno;
        }
    }

    if (len == 0) {
        return ENODATA;
    }

    return EOK;
}

static void update_confdb_recv(struct cli_ctx *cctx)
{
    int ret;

    ret = update_confdb_recv_data(cctx->cfd);
    switch(ret) {
    case ENODATA:
        DEBUG(SSSDBG_TRACE_ALL,
              "Client closed connection\n");
        talloc_free(cctx);
        return;
    case EAGAIN:
        DEBUG(SSSDBG_TRACE_ALL,
              "Interrupted before any data could be read, retry later\n");
        return;
    case EOK:
        /* all fine */
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to receive data (%d, %s), aborting client!\n",
              ret, strerror(ret));
        talloc_free(cctx);
        return;
    }

    TEVENT_FD_NOT_READABLE(cctx->cfde);
    update_confdb_update(cctx);

    return;
}

static void update_confdb_fd_handler(struct tevent_context *ev,
                                     struct tevent_fd *fde,
                                     uint16_t flags, void *ptr)
{
    errno_t ret;
    struct cli_ctx *cctx = talloc_get_type(ptr, struct cli_ctx);

    /* Always reset the idle timer on any activity */
    ret = reset_idle_timer(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not create idle timer for client. "
              "This connection may not auto-terminate\n");
        /* Non-fatal, continue */
    }

    if (flags & TEVENT_FD_READ) {
        update_confdb_recv(cctx);
        return;
    }

    if (flags & TEVENT_FD_WRITE) {
        update_confdb_send(cctx);
        return;
    }
}

static int update_confdb_connection_setup(struct cli_ctx *cctx)
{
    cctx->cfd_handler = update_confdb_fd_handler;

    return EOK;
}

static int update_confdb_ctx_destructor(void *ptr)
{
    struct resp_ctx *rctx = talloc_get_type(ptr, struct resp_ctx);

    /* mark that we are shutting down the service, so it is propagated
     * into underlying contexts that are freed right before rctx */
    DEBUG(SSSDBG_TRACE_FUNC, "Service is being shutdown\n");
    rctx->shutting_down = true;

    return 0;
}

static int update_confdb_process_init(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    int ret;

    rctx = talloc_zero(mem_ctx, struct resp_ctx);
    if (rctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing resp_ctx\n");

        return ENOMEM;
    }

    rctx->ev = ev;
    rctx->cdb = cdb;
    rctx->sock_name = SSS_UPDATE_CONFDB_SOCKET_NAME;
    rctx->shutting_down = false;
    rctx->client_idle_timeout = CONFDB_RESPONDER_CLI_IDLE_DEFAULT_TIMEOUT;

    talloc_set_destructor((TALLOC_CTX *)rctx, update_confdb_ctx_destructor);

    ret = activate_unix_sockets(rctx, update_confdb_connection_setup);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Update ConfDB socket activation complete\n");

    return EOK;

fail:
    talloc_free(rctx);
    return ret;
}

int main (int argc, const char *argv[])
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

    /* set up things like debug, signals, daemonizations, etc ... */
    debug_log_file = "sssd_update_confdb";

    ret = server_setup("update_confdb", 0, 0, 0,
                       CONFDB_UPDATE_CONF_ENTRY, &main_ctx);
    if (ret != EOK) {
        return 2;
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return. */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = update_confdb_process_init(main_ctx,
                                     main_ctx->event_ctx,
                                     main_ctx->confdb_ctx);
    if (ret != EOK) {
        return 3;
    }

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
