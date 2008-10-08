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
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include "ldb.h"
#include "util/util.h"
#include "service.h"
#include "nss/nsssrv.h"
#include "nss/nsssrv_ldb.h"

static void set_nonblocking(int fd)
{
    unsigned v;
    v = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, v | O_NONBLOCK);
}

static void set_close_on_exec(int fd)
{
    unsigned v;
    v = fcntl(fd, F_GETFD, 0);
    fcntl(fd, F_SETFD, v | FD_CLOEXEC);
}

static int client_destructor(struct cli_ctx *ctx)
{
    if (ctx->cfd > 0) close(ctx->cfd);
    return 0;
}

static void client_send(struct event_context *ev, struct cli_ctx *cctx)
{
    int ret;

    ret = nss_packet_send(cctx->creq->out, cctx->cfd);
    if (ret == RES_RETRY) {
        /* not all data was sent, loop again */
        return;
    }
    if (ret != RES_SUCCESS) {
        DEBUG(0, ("Failed to read request, aborting client!\n"));
        talloc_free(cctx);
        return;
    }

    /* ok all sent */
    EVENT_FD_NOT_WRITEABLE(cctx->cfde);
    EVENT_FD_READABLE(cctx->cfde);
    talloc_free(cctx->creq);
    cctx->creq = NULL;
    return;
}

static void client_recv(struct event_context *ev, struct cli_ctx *cctx)
{
    int ret;

    if (!cctx->creq) {
        cctx->creq = talloc_zero(cctx, struct cli_request);
        if (!cctx->creq) {
            DEBUG(0, ("Failed to alloc request, aborting client!\n"));
            talloc_free(cctx);
            return;
        }
    }

    if (!cctx->creq->in) {
        ret = nss_packet_new(cctx->creq, 0, 0, &cctx->creq->in);
        if (ret != RES_SUCCESS) {
            DEBUG(0, ("Failed to alloc request, aborting client!\n"));
            talloc_free(cctx);
            return;
        }
    }

    ret = nss_packet_recv(cctx->creq->in, cctx->cfd);
    switch (ret) {
    case RES_SUCCESS:
        /* do not read anymore */
        EVENT_FD_NOT_READABLE(cctx->cfde);
        /* execute command */
        ret = nss_cmd_execute(cctx);
        if (ret != RES_SUCCESS) {
            DEBUG(0, ("Failed to execute request, aborting client!\n"));
            talloc_free(cctx);
        }
        break;

    case RES_RETRY:
        /* need to read still some data, loop again */
        break;

    default:
        DEBUG(0, ("Failed to read request, aborting client!\n"));
        talloc_free(cctx);
    }

    return;
}

static void client_fd_handler(struct event_context *ev,
                              struct fd_event *fde,
                              uint16_t flags, void *ptr)
{
    struct cli_ctx *cctx = talloc_get_type(ptr, struct cli_ctx);

    if (flags & EVENT_FD_READ) {
        client_recv(ev, cctx);
        return;
    }
    if (flags & EVENT_FD_WRITE) {
        client_send(ev, cctx);
        return;
    }
}

static void accept_fd_handler(struct event_context *ev,
                              struct fd_event *fde,
                              uint16_t flags, void *ptr)
{
    /* accept and attach new event handler */
    struct nss_ctx *nctx = talloc_get_type(ptr, struct nss_ctx);
    struct cli_ctx *cctx;
    socklen_t len;

    cctx = talloc_zero(nctx, struct cli_ctx);
    if (!cctx) {
        struct sockaddr_un addr;
        int fd;
        DEBUG(0, ("Out of memory trying to setup client context!\n"));
        /* accept and close to signal the client we have a problem */
        memset(&addr, 0, sizeof(addr));
        len = sizeof(addr);
        fd = accept(nctx->lfd, (struct sockaddr *)&addr, &len);
        if (fd == -1) {
            return;
        }
        close(fd);
        return;
    }

    len = sizeof(cctx->addr);
    cctx->cfd = accept(nctx->lfd, (struct sockaddr *)&cctx->addr, &len);
    if (cctx->cfd == -1) {
        DEBUG(0, ("Accept failed [%s]", strerror(errno)));
        talloc_free(cctx);
        return;
    }

    cctx->cfde = event_add_fd(ev, cctx, cctx->cfd,
                              EVENT_FD_READ, client_fd_handler, cctx);
    if (!cctx->cfde) {
        close(cctx->cfd);
        talloc_free(cctx);
        DEBUG(0, ("Failed to queue client handler\n"));
    }

    cctx->ev = ev;
    cctx->ldb = nctx->ldb;

    talloc_set_destructor(cctx, client_destructor);

    DEBUG(2, ("Client connected!\n"));

    return;
}

/* create a unix socket and listen to it */
static void set_unix_socket(struct event_context *ev,
                            struct nss_ctx *nctx,
                            const char *sock_name)
{
    struct sockaddr_un addr;

    /* make sure we have no old sockets around */
    unlink(sock_name);

    nctx->lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (nctx->lfd == -1) {
        return;
    }

    set_nonblocking(nctx->lfd);
    set_close_on_exec(nctx->lfd);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_name, sizeof(addr.sun_path));

    if (bind(nctx->lfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        DEBUG(0,("Unable to bind on socket '%s'\n", sock_name));
        goto failed;
    }
    if (listen(nctx->lfd, 10) != 0) {
        DEBUG(0,("Unable to listen on socket '%s'\n", sock_name));
        goto failed;
    }

    nctx->lfde = event_add_fd(ev, nctx, nctx->lfd,
                                 EVENT_FD_READ, accept_fd_handler, nctx);

    return;

failed:
    close(nctx->lfd);
}

void nss_task_init(struct task_server *task)
{
    struct nss_ctx *nctx;
    int ret;

    task_server_set_title(task, "sssd[nsssrv]");

    nctx = talloc_zero(task, struct nss_ctx);
    if (!nctx) {
        task_server_terminate(task, "fatal error initializing nss_ctx\n");
        return;
    }
    nctx->task = task;

    set_unix_socket(task->event_ctx, nctx, SSS_NSS_SOCKET_NAME);

    ret = nss_ldb_init(nctx, task->event_ctx, &nctx->ldb);
    if (ret != RES_SUCCESS) {
        task_server_terminate(task, "fatal error initializing nss_ctx\n");
        return;
    }
}
