/*
   SSSD

   Service monitor - D-BUS features

   Copyright (C) Stephen Gallagher         2008

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
#include <sys/time.h>
#include "tevent.h"
#include "util/util.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

/* Types */
struct sbus_srv_ctx {
    DBusServer *server;
    /*
     * sd_ctx here describes the object path that will be
     * presented to all clients of this server. Additional
     * connection-specific paths can be specified by the
     * init_fn, which is called every time a new connection
     * is established.
     * There should only be one global object path (for
     * simplicity's sake)
     */
    struct event_context *ev;
    struct sbus_method_ctx *sd_ctx;
    sbus_server_conn_init_fn init_fn;
    void *init_pvt_data;
};

struct sbus_srv_watch_ctx {
    DBusWatch *watch;
    int fd;
    struct fd_event *fde;
    struct sbus_srv_ctx *top;
};

struct dbus_srv_timeout_ctx {
    DBusTimeout *timeout;
    struct timed_event *te;
    struct sbus_srv_ctx *top;
};

static int sbus_server_destructor(void *ctx);

/*
 * dbus_server_read_write_handler
 * Callback for D-BUS to handle messages on a file-descriptor
 */
static void sbus_srv_read_write_handler(struct event_context *ev,
                                           struct fd_event *fde,
                                           uint16_t flags, void *data)
{
    struct sbus_srv_watch_ctx *svw_ctx;
    svw_ctx = talloc_get_type(data, struct sbus_srv_watch_ctx);

    dbus_server_ref(svw_ctx->top->server);
    if (flags & EVENT_FD_READ) {
        dbus_watch_handle(svw_ctx->watch, DBUS_WATCH_READABLE);
    }
    if (flags & EVENT_FD_WRITE) {
        dbus_watch_handle(svw_ctx->watch, DBUS_WATCH_WRITABLE);
    }
    dbus_server_unref(svw_ctx->top->server);
}

/*
 * add_server_watch
 * Set up hooks into the libevents mainloop for
 * D-BUS to add file descriptor-based events
 */
static dbus_bool_t sbus_add_srv_watch(DBusWatch *watch, void *data)
{
    unsigned int flags;
    unsigned int event_flags;
    struct sbus_srv_ctx *dt_ctx;
    struct sbus_srv_watch_ctx *svw_ctx;

    if (!dbus_watch_get_enabled(watch)) {
        return FALSE;
    }

    dt_ctx = talloc_get_type(data, struct sbus_srv_ctx);

    svw_ctx = talloc_zero(dt_ctx, struct sbus_srv_watch_ctx);
    svw_ctx->top = dt_ctx;
    svw_ctx->watch = watch;

    flags = dbus_watch_get_flags(watch);
    svw_ctx->fd = dbus_watch_get_unix_fd(watch);

    event_flags = 0;

    if (flags & DBUS_WATCH_READABLE) {
        event_flags |= EVENT_FD_READ;
    }

    if (flags & DBUS_WATCH_WRITABLE) {
        event_flags |= EVENT_FD_WRITE;
    }
    DEBUG(5,("%lX: %d, %d=%s\n", watch, svw_ctx->fd, event_flags, event_flags==EVENT_FD_READ?"READ":"WRITE"));

    svw_ctx->fde = event_add_fd(dt_ctx->ev, svw_ctx, svw_ctx->fd,
                                event_flags, sbus_srv_read_write_handler,
                                svw_ctx);

    /* Save the event to the watch object so it can be removed later */
    dbus_watch_set_data(svw_ctx->watch, svw_ctx->fde, NULL);

    return TRUE;
}

/*
 * server_watch_toggled
 * Hook for D-BUS to toggle the enabled/disabled state of
 * an event in the mainloop
 */
static void sbus_toggle_srv_watch(DBusWatch *watch, void *data)
{
    if (dbus_watch_get_enabled(watch)) {
        sbus_add_srv_watch(watch, data);
    } else {
        sbus_remove_watch(watch, data);
    }
}

static void sbus_srv_timeout_handler(struct event_context *ev,
                                        struct timed_event *te,
                                        struct timeval t, void *data)
{
    struct dbus_srv_timeout_ctx *svt_ctx;
    svt_ctx = talloc_get_type(data, struct dbus_srv_timeout_ctx);
    dbus_timeout_handle(svt_ctx->timeout);
}

/*
 * add_server_timeout
 * Hook for D-BUS to add time-based events to the mainloop
 */
static dbus_bool_t sbus_add_srv_timeout(DBusTimeout *timeout, void *data)
{
    struct sbus_srv_ctx *dt_ctx;
    struct dbus_srv_timeout_ctx *svt_ctx;
    struct timeval tv;

    if (!dbus_timeout_get_enabled(timeout))
        return TRUE;

    dt_ctx = talloc_get_type(data, struct sbus_srv_ctx);

    svt_ctx = talloc_zero(dt_ctx,struct dbus_srv_timeout_ctx);
    svt_ctx->top = dt_ctx;
    svt_ctx->timeout = timeout;

    tv = _dbus_timeout_get_interval_tv(dbus_timeout_get_interval(timeout));

    svt_ctx->te = event_add_timed(dt_ctx->ev, svt_ctx, tv,
                                  sbus_srv_timeout_handler, svt_ctx);

    /* Save the event to the watch object so it can be removed later */
    dbus_timeout_set_data(svt_ctx->timeout, svt_ctx->te, NULL);

    return TRUE;
}

/*
 * server_timeout_toggled
 * Hook for D-BUS to toggle the enabled/disabled state of a mainloop
 * event
 */
static void sbus_toggle_srv_timeout(DBusTimeout *timeout, void *data)
{
    if (dbus_timeout_get_enabled(timeout)) {
        sbus_add_srv_timeout(timeout, data);
    } else {
        sbus_remove_timeout(timeout, data);
    }
}

/*
 * new_connection_callback
 * Actions to be run upon each new client connection
 * Must either perform dbus_connection_ref() on the
 * new connection or else close the connection with
 * dbus_connection_close()
 */
static void sbus_server_init_new_connection(DBusServer *server,
                                            DBusConnection *conn,
                                            void *data)
{
    struct sbus_srv_ctx *srv_ctx;
    struct sbus_conn_ctx *conn_ctx;
    struct sbus_method_ctx *iter;
    int ret;

    DEBUG(5,("Entering.\n"));
    srv_ctx = talloc_get_type(data, struct sbus_srv_ctx);
    if (srv_ctx == NULL) {
        return;
    }

    DEBUG(5,("Adding connection %lX.\n", conn));
    ret = sbus_add_connection(srv_ctx, srv_ctx->ev, conn,
                              &conn_ctx, SBUS_CONN_TYPE_PRIVATE);
    if (ret != 0) {
        dbus_connection_close(conn);
        DEBUG(5,("Closing connection (failed setup)"));
        return;
    }

    dbus_connection_ref(conn);

    DEBUG(5,("Got a connection\n"));

    /* Set up global methods */
    iter = srv_ctx->sd_ctx;
    while (iter != NULL) {
        sbus_conn_add_method_ctx(conn_ctx, iter);
        iter = iter->next;
    }

    /*
     * Initialize connection-specific features
     * This may set a more detailed destructor, but
     * the default destructor will always be chained
     * to handle connection cleanup.
     * This function (or its callbacks) should also
     * set up connection-specific methods.
     */
    ret = srv_ctx->init_fn(conn_ctx, srv_ctx->init_pvt_data);
    if (ret != EOK) {
        DEBUG(1,("Initialization failed!\n"));
    }
}

/*
 * dbus_new_server
 * Set up a D-BUS server, integrate with the event loop
 * for handling file descriptor and timed events
 */
int sbus_new_server(TALLOC_CTX *mem_ctx,
                    struct event_context *ev, struct sbus_method_ctx *ctx,
                    struct sbus_srv_ctx **server_ctx, const char *address,
                    sbus_server_conn_init_fn init_fn, void *init_pvt_data)
{
    struct sbus_srv_ctx *srv_ctx;
    DBusServer *dbus_server;
    DBusError dbus_error;
    dbus_bool_t dbret;
    char *tmp;

    *server_ctx = NULL;

    /* Set up D-BUS server */
    dbus_error_init(&dbus_error);
    dbus_server = dbus_server_listen(address, &dbus_error);
    if (!dbus_server) {
        DEBUG(1,("dbus_server_listen failed! (name=%s, message=%s)\n",
                 dbus_error.name, dbus_error.message));
        return EIO;
    }

    tmp = dbus_server_get_address(dbus_server);
    DEBUG(3, ("D-BUS Server listening on %s\n", tmp));
    free(tmp);

    srv_ctx = talloc_zero(mem_ctx, struct sbus_srv_ctx);
    if (!srv_ctx) {
        return ENOMEM;
    }

    srv_ctx->ev = ev;
    srv_ctx->server = dbus_server;
    srv_ctx->sd_ctx = ctx;
    srv_ctx->init_fn = init_fn;
    srv_ctx->init_pvt_data = init_pvt_data;

    talloc_set_destructor((TALLOC_CTX *)srv_ctx, sbus_server_destructor);

    /* Set up D-BUS new connection handler */
    dbus_server_set_new_connection_function(srv_ctx->server,
                                            sbus_server_init_new_connection,
                                            srv_ctx, NULL);

    /* Set up DBusWatch functions */
    dbret = dbus_server_set_watch_functions(srv_ctx->server,
                                            sbus_add_srv_watch,
                                            sbus_remove_watch,
                                            sbus_toggle_srv_watch,
                                            srv_ctx, NULL);
    if (!dbret) {
        DEBUG(4, ("Error setting up D-BUS server watch functions"));
        talloc_free(srv_ctx);
        return EIO;
    }

    /* Set up DBusTimeout functions */
    dbret = dbus_server_set_timeout_functions(srv_ctx->server,
                                              sbus_add_srv_timeout,
                                              sbus_remove_timeout,
                                              sbus_toggle_srv_timeout,
                                              srv_ctx, NULL);
    if (!dbret) {
        DEBUG(4,("Error setting up D-BUS server timeout functions"));
        dbus_server_set_watch_functions(srv_ctx->server,
                                        NULL, NULL, NULL, NULL, NULL);
        talloc_free(srv_ctx);
        return EIO;
    }

    *server_ctx = srv_ctx;
    return EOK;
}

static int sbus_server_destructor(void *ctx)
{
    struct sbus_srv_ctx *srv_ctx = talloc_get_type(ctx, struct sbus_srv_ctx);
    dbus_server_disconnect(srv_ctx->server);
    return 0;
}
