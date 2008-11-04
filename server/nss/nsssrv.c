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
#include "ldb.h"
#include "util/util.h"
#include "service.h"
#include "nss/nsssrv.h"
#include "nss/nsssrv_ldb.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus_interfaces.h"

static int provide_identity(DBusMessage *message, void *data, DBusMessage **r);
static int reply_ping(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method nss_sbus_methods[] = {
    {SERVICE_METHOD_IDENTITY, provide_identity},
    {SERVICE_METHOD_PING, reply_ping},
    {NULL, NULL}
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

static void client_send(struct event_context *ev, struct cli_ctx *cctx)
{
    int ret;

    ret = nss_packet_send(cctx->creq->out, cctx->cfd);
    if (ret == EAGAIN) {
        /* not all data was sent, loop again */
        return;
    }
    if (ret != EOK) {
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
        if (ret != EOK) {
            DEBUG(0, ("Failed to alloc request, aborting client!\n"));
            talloc_free(cctx);
            return;
        }
    }

    ret = nss_packet_recv(cctx->creq->in, cctx->cfd);
    switch (ret) {
    case EOK:
        /* do not read anymore */
        EVENT_FD_NOT_READABLE(cctx->cfde);
        /* execute command */
        ret = nss_cmd_execute(cctx);
        if (ret != EOK) {
            DEBUG(0, ("Failed to execute request, aborting client!\n"));
            talloc_free(cctx);
        }
        break;

    case EAGAIN:
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
        DEBUG(1, ("Accept failed [%s]", strerror(errno)));
        talloc_free(cctx);
        return;
    }

    cctx->cfde = event_add_fd(ev, cctx, cctx->cfd,
                              EVENT_FD_READ, client_fd_handler, cctx);
    if (!cctx->cfde) {
        close(cctx->cfd);
        talloc_free(cctx);
        DEBUG(2, ("Failed to queue client handler\n"));
    }

    cctx->ev = ev;
    cctx->lctx = nctx->lctx;

    talloc_set_destructor(cctx, client_destructor);

    DEBUG(2, ("Client connected!\n"));

    return;
}

static int provide_identity(DBusMessage *message, void *data, DBusMessage **r)
{
    dbus_uint16_t version = NSS_SBUS_SERVICE_VERSION;
    const char *name = NSS_SBUS_SERVICE_NAME;
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    *r = reply;
    return EOK;
}

static int reply_ping(DBusMessage *message, void *data, DBusMessage **r)
{
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply, DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    *r = reply;
    return EOK;
}

static int nss_sbus_init(struct nss_ctx *nctx)
{
    struct sbus_method_ctx *cli_sm_ctx;
    struct sbus_method_ctx *srv_sm_ctx;
    struct nss_sbus_ctx *ns_ctx;
    DBusConnection *dbus_conn;
    char *sbus_address;
    int ret;

    ret = confdb_get_string(nctx->cdb, nctx,
                            "config.services.monitor", "sbusAddress",
                            DEFAULT_SBUS_ADDRESS, &sbus_address);
    if (ret != EOK) {
        return ret;
    }

    ns_ctx = talloc(nctx, struct nss_sbus_ctx);
    if (!ns_ctx) {
        return ENOMEM;
    }
    ns_ctx->ev = nctx->ev;

    ret = sbus_new_connection(ns_ctx, ns_ctx->ev,
                              sbus_address,
                              &ns_ctx->scon_ctx, NULL);
    if (ret != EOK) {
        talloc_free(ns_ctx);
        return ret;
    }
    dbus_conn = sbus_get_connection(ns_ctx->scon_ctx);
    dbus_connection_set_exit_on_disconnect(dbus_conn, TRUE);

    /* set up handler for service methods */
    srv_sm_ctx = talloc_zero(ns_ctx, struct sbus_method_ctx);
    if (!srv_sm_ctx) {
        talloc_free(ns_ctx);
        return ENOMEM;
    }
    srv_sm_ctx->interface = talloc_strdup(srv_sm_ctx, SERVICE_INTERFACE);
    srv_sm_ctx->path = talloc_strdup(srv_sm_ctx, SERVICE_PATH);
    if (!srv_sm_ctx->interface || !srv_sm_ctx->path) {
        talloc_free(ns_ctx);
        return ENOMEM;
    }
    srv_sm_ctx->methods = nss_sbus_methods;
    sbus_conn_add_method_ctx(ns_ctx->scon_ctx, srv_sm_ctx);

    /* set up client stuff */
    cli_sm_ctx = talloc(ns_ctx, struct sbus_method_ctx);
    if (!cli_sm_ctx) {
        talloc_free(ns_ctx);
        return ENOMEM;
    }
    cli_sm_ctx->interface = talloc_strdup(cli_sm_ctx, MONITOR_DBUS_INTERFACE);
    cli_sm_ctx->path = talloc_strdup(cli_sm_ctx, MONITOR_DBUS_PATH);
    if (!cli_sm_ctx->interface || !cli_sm_ctx->path) {
        talloc_free(ns_ctx);
        return ENOMEM;
    }
    ns_ctx->sm_ctx = cli_sm_ctx;

    nctx->ns_ctx = ns_ctx;

    return EOK;
}

/* create a unix socket and listen to it */
static int set_unix_socket(struct nss_ctx *nctx)
{
    struct sockaddr_un addr;
    int ret;

    ret = confdb_get_string(nctx->cdb, nctx,
                            "config.services.nss", "unixSocket",
                            SSS_NSS_SOCKET_NAME, &nctx->sock_name);
    if (ret != EOK) {
        return ret;
    }

    nctx->lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (nctx->lfd == -1) {
        return EIO;
    }

    /* Set the umask so that permissions are set right on the socket.
     * It must be readable and writable by anybody on the system. */
    umask(0111);

    set_nonblocking(nctx->lfd);
    set_close_on_exec(nctx->lfd);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, nctx->sock_name, sizeof(addr.sun_path));

    /* make sure we have no old sockets around */
    unlink(nctx->sock_name);

    if (bind(nctx->lfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        DEBUG(0,("Unable to bind on socket '%s'\n", nctx->sock_name));
        goto failed;
    }
    if (listen(nctx->lfd, 10) != 0) {
        DEBUG(0,("Unable to listen on socket '%s'\n", nctx->sock_name));
        goto failed;
    }

    nctx->lfde = event_add_fd(nctx->ev, nctx, nctx->lfd,
                              EVENT_FD_READ, accept_fd_handler, nctx);

	/* we want default permissions on created files to be very strict,
	   so set our umask to 0177 */
	umask(0177);
    return EOK;

failed:
	/* we want default permissions on created files to be very strict,
	   so set our umask to 0177 */
	umask(0177);
    close(nctx->lfd);
    return EIO;
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
    nctx->ev = task->event_ctx;
    nctx->task = task;

    ret = confdb_init(task, task->event_ctx, &nctx->cdb);
    if (ret != EOK) {
        task_server_terminate(task, "fatal error initializing confdb\n");
        return;
    }

    ret = nss_sbus_init(nctx);
    if (ret != EOK) {
        task_server_terminate(task, "fatal error setting up message bus\n");
        return;
    }

    ret = nss_ldb_init(nctx, nctx->ev, nctx->cdb, &nctx->lctx);
    if (ret != EOK) {
        task_server_terminate(task, "fatal error initializing nss_ctx\n");
        return;
    }

    /* after all initializations we are ready to listen on our socket */
    ret = set_unix_socket(nctx);
    if (ret != EOK) {
        task_server_terminate(task, "fatal error initializing socket\n");
        return;
    }
}
