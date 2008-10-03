/* 
   SSSD

   Service monitor

   Copyright (C) Simo Sorce			2008

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
#include "util/util.h"
#include "service.h"

struct mt_ctx {
    struct task_server *task;
    struct fd_event *test_fde;
    int test_fd;
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

static void set_test_timed_event(struct event_context *ev,
                                 struct mt_ctx *ctx);

static void test_timed_handler(struct event_context *ev,
                               struct timed_event *te,
                               struct timeval t, void *ptr)
{
    struct mt_ctx *ctx = talloc_get_type(ptr, struct mt_ctx);

    fprintf(stdout, ".");
    fflush(stdout);

    set_test_timed_event(ev, ctx);
}

static void set_test_timed_event(struct event_context *ev,
                                 struct mt_ctx *ctx)
{
    struct timed_event *te = NULL;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    tv.tv_sec += 2;
    tv.tv_usec = 0;
    te = event_add_timed(ev, ctx, tv, test_timed_handler, ctx);
    if (te == NULL) {
        DEBUG(0, ("failed to add event!\n"));
        task_server_terminate(ctx->task, "fatal error initializing service\n");
    }
}

static void test_fd_handler(struct event_context *ev,
                            struct fd_event *fde,
                            uint16_t flags, void *ptr)
{
    /* accept and close */
    struct mt_ctx *ctx = talloc_get_type(ptr, struct mt_ctx);
    struct sockaddr_un addr;
    socklen_t len;
    int fd;

    memset(&addr, 0, sizeof(addr));
    len = sizeof(addr);
    fd = accept(ctx->test_fd, (struct sockaddr *)&addr, &len);
    if (fd == -1) {
        return;
    }

    close(fd);
    return;
}

/* create a unix socket and listen to it */
static void set_test_fd_event(struct event_context *ev,
                              struct mt_ctx *ctx)
{
    struct sockaddr_un addr;
    const char *sock_name = "/tmp/foo/test_sock";

    /* make sure we have no old sockets around */
    unlink(sock_name);

    ctx->test_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx->test_fd == -1) {
        return;
    }

    set_nonblocking(ctx->test_fd);
    set_close_on_exec(ctx->test_fd);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_name, sizeof(addr.sun_path));

    if (bind(ctx->test_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        DEBUG(0,("Unable to bind on socket '%s'\n", sock_name));
        goto failed;
    }
    if (listen(ctx->test_fd, 10) != 0) {
        DEBUG(0,("Unable to listen on socket '%s'\n", sock_name));
        goto failed;
    }

    ctx->test_fde = event_add_fd(ev, ctx, ctx->test_fd,
                                 EVENT_FD_READ, test_fd_handler, ctx);

    return;

failed:
    close(ctx->test_fd);
}

void monitor_task_init(struct task_server *task)
{
    struct mt_ctx *ctx;

    task_server_set_title(task, "sssd[monitor]");

    ctx = talloc_zero(task, struct mt_ctx);
    if (!ctx) {
        task_server_terminate(task, "fatal error initializing mt_ctx\n");
        return;
    }
    ctx->task = task;

    /* without an fd event the event system just exits.
     * We must always have at least one file base event around
     */
    set_test_fd_event(task->event_ctx, ctx);

    /* our test timed event */
    set_test_timed_event(task->event_ctx, ctx);

    fprintf(stdout, "test monitor process started!\n");
}
