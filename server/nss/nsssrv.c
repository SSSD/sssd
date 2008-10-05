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
#include "../events/events.h"
#include "../talloc/talloc.h"
#include "util/util.h"
#include "service.h"
#include "nss/nsssrv.h"

struct nss_ctx {
    struct task_server *task;
    struct fd_event *lfde;
    int lfd;
};

struct cli_ctx {
    int cfd;
    struct fd_event *cfde;
    struct sockaddr_un addr;
    struct cli_request *creq;
};

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

static void client_send(struct event_context *ev, struct cli_ctx *ctx)
{
    int ret;

    ret = nss_packet_send(ctx->creq->out, ctx->cfd);
    if (ret == RES_RETRY) {
        /* not all data was sent, loop again */
        return;
    }
    if (ret != RES_SUCCESS) {
        DEBUG(0, ("Failed to read request, aborting client!\n"));
        talloc_free(ctx);
        return;
    }

    /* ok all sent */
    EVENT_FD_NOT_WRITEABLE(ctx->cfde);
    EVENT_FD_READABLE(ctx->cfde);
    talloc_free(ctx->creq);
    ctx->creq = NULL;
    return;
}

static void client_recv(struct event_context *ev, struct cli_ctx *ctx)
{
    int ret;

    if (!ctx->creq) {
        ctx->creq = talloc_zero(ctx, struct cli_request);
        if (!ctx->creq) {
            DEBUG(0, ("Failed to alloc request, aborting client!\n"));
            talloc_free(ctx);
            return;
        }
    }

    if (!ctx->creq->in) {
        ret = nss_packet_new(ctx->creq, 0, &ctx->creq->in);
        if (ret != RES_SUCCESS) {
            DEBUG(0, ("Failed to alloc request, aborting client!\n"));
            talloc_free(ctx);
            return;
        }
    }

    ret = nss_packet_recv(ctx->creq->in, ctx->cfd);
    switch (ret) {
    case RES_SUCCESS:
        /* do not read anymore */
        EVENT_FD_NOT_READABLE(ctx->cfde);
        /* execute command */
    /*    nss_cmd_execute(ctx); */
        break;

    case RES_RETRY:
        /* need to read still some data, loop again */
        break;

    default:
        DEBUG(0, ("Failed to read request, aborting client!\n"));
        talloc_free(ctx);
    }

    return;
}

static void client_fd_handler(struct event_context *ev,
                              struct fd_event *fde,
                              uint16_t flags, void *ptr)
{
    struct cli_ctx *ctx = talloc_get_type(ptr, struct cli_ctx);

    if (flags & EVENT_FD_READ) {
        client_recv(ev, ctx);
        return;
    }
    if (flags & EVENT_FD_WRITE) {
        client_send(ev, ctx);
        return;
    }
}

static void accept_fd_handler(struct event_context *ev,
                              struct fd_event *fde,
                              uint16_t flags, void *ptr)
{
    /* accept and attach new event handler */
    struct nss_ctx *ctx = talloc_get_type(ptr, struct nss_ctx);
    struct cli_ctx *cctx;
    socklen_t len;

    cctx = talloc_zero(ctx, struct cli_ctx);
    if (!cctx) {
        struct sockaddr_un addr;
        int fd;
        DEBUG(0, ("Out of memory trying to setup client context!\n"));
        /* accept and close to signal the client we have a problem */
        memset(&addr, 0, sizeof(addr));
        len = sizeof(addr);
        fd = accept(ctx->lfd, (struct sockaddr *)&addr, &len);
        if (fd == -1) {
            return;
        }
        close(fd);
        return;
    }

    len = sizeof(cctx->addr);
    cctx->cfd = accept(ctx->lfd, (struct sockaddr *)&cctx->addr, &len);
    if (cctx->cfd == -1) {
        DEBUG(1, ("Accept failed [%s]", strerror(errno)));
        talloc_free(cctx);
        return;
    }

    cctx->cfde = event_add_fd(ev, cctx, cctx->cfd,
                              EVENT_FD_READ, client_fd_handler, cctx);
    if (!cctx->cfde) {
        close(cctx->cfd);
        talloc_free(cctx);
        DEBUG(1, ("Failed to queue client handler\n"));
    }

    talloc_set_destructor(cctx, client_destructor);

    return;
}

/* create a unix socket and listen to it */
static void set_unix_socket(struct event_context *ev,
                            struct nss_ctx *ctx,
                            const char *sock_name)
{
    struct sockaddr_un addr;

    /* make sure we have no old sockets around */
    unlink(sock_name);

    ctx->lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx->lfd == -1) {
        return;
    }

    set_nonblocking(ctx->lfd);
    set_close_on_exec(ctx->lfd);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_name, sizeof(addr.sun_path));

    if (bind(ctx->lfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        DEBUG(0,("Unable to bind on socket '%s'\n", sock_name));
        goto failed;
    }
    if (listen(ctx->lfd, 10) != 0) {
        DEBUG(0,("Unable to listen on socket '%s'\n", sock_name));
        goto failed;
    }

    ctx->lfde = event_add_fd(ev, ctx, ctx->lfd,
                                 EVENT_FD_READ, accept_fd_handler, ctx);

    return;

failed:
    close(ctx->lfd);
}

void nss_task_init(struct task_server *task)
{
    struct nss_ctx *ctx;

    task_server_set_title(task, "sssd[nsssrv]");

    ctx = talloc_zero(task, struct nss_ctx);
    if (!ctx) {
        task_server_terminate(task, "fatal error initializing nss_ctx\n");
        return;
    }
    ctx->task = task;

    set_unix_socket(task->event_ctx, ctx, SSS_NSS_SOCKET_NAME);

}
