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
#include "events.h"
#include "util/util.h"
#include "dbus/dbus.h"
#include "dbus/sssd_dbus.h"
#include "dbus/sssd_dbus_private.h"

/* Types */
struct dbus_server_toplevel_context {
    DBusServer *server;
    struct sssd_dbus_ctx *sd_ctx;
};

struct dbus_server_watch_context {
    DBusWatch *watch;
    int fd;
    struct fd_event *fde;
    struct dbus_server_toplevel_context *top;
};

struct dbus_server_timeout_context {
    DBusTimeout *timeout;
    struct timed_event *te;
    struct dbus_server_toplevel_context *top;
};

/*
 * dbus_server_read_write_handler
 * Callback for D-BUS to handle messages on a file-descriptor
 */
static void dbus_server_read_write_handler(struct event_context *ev,
                                           struct fd_event *fde,
                                           uint16_t flags, void *data)
{
    struct dbus_server_watch_context *svw_ctx;
    svw_ctx = talloc_get_type(data, struct dbus_server_watch_context);

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
static dbus_bool_t add_server_watch(DBusWatch *watch, void *data)
{
    unsigned int flags;
    unsigned int event_flags;
    struct dbus_server_toplevel_context *dt_ctx;
    struct dbus_server_watch_context *svw_ctx;

    if (!dbus_watch_get_enabled(watch)) {
        return FALSE;
    }

    dt_ctx = talloc_get_type(data, struct dbus_server_toplevel_context);

    svw_ctx = talloc_zero(dt_ctx, struct dbus_server_watch_context);
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

    svw_ctx->fde = event_add_fd(dt_ctx->sd_ctx->ev, svw_ctx, svw_ctx->fd,
                                event_flags, dbus_server_read_write_handler,
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
static void toggle_server_watch(DBusWatch *watch, void *data)
{
    if (dbus_watch_get_enabled(watch)) {
        add_server_watch(watch, data);
    } else {
        remove_watch(watch, data);
    }
}

static void dbus_server_timeout_handler(struct event_context *ev,
                                        struct timed_event *te,
                                        struct timeval t, void *data)
{
    struct dbus_server_timeout_context *svt_ctx;
    svt_ctx = talloc_get_type(data, struct dbus_server_timeout_context);
    dbus_timeout_handle(svt_ctx->timeout);
}

/*
 * add_server_timeout
 * Hook for D-BUS to add time-based events to the mainloop
 */
static dbus_bool_t add_server_timeout(DBusTimeout *timeout, void *data)
{
    struct dbus_server_toplevel_context *dt_ctx;
    struct dbus_server_timeout_context *svt_ctx;
    struct timeval tv;

    if (!dbus_timeout_get_enabled(timeout))
        return TRUE;

    dt_ctx = talloc_get_type(data, struct dbus_server_toplevel_context);

    svt_ctx = talloc_zero(dt_ctx,struct dbus_server_timeout_context);
    svt_ctx->top = dt_ctx;
    svt_ctx->timeout = timeout;

    tv = _dbus_timeout_get_interval_tv(dbus_timeout_get_interval(timeout));

    svt_ctx->te = event_add_timed(dt_ctx->sd_ctx->ev, svt_ctx, tv,
                                  dbus_server_timeout_handler, svt_ctx);

    /* Save the event to the watch object so it can be removed later */
    dbus_timeout_set_data(svt_ctx->timeout, svt_ctx->te, NULL);

    return TRUE;
}

/*
 * server_timeout_toggled
 * Hook for D-BUS to toggle the enabled/disabled state of a mainloop
 * event
 */
static void toggle_server_timeout(DBusTimeout *timeout, void *data)
{
    if (dbus_timeout_get_enabled(timeout)) {
        add_server_timeout(timeout, data);
    } else {
        remove_timeout(timeout, data);
    }
}

/* messsage_handler
 * Receive messages and process them
 */
static DBusHandlerResult message_handler(DBusConnection *conn,
                                         DBusMessage *message,
                                         void *user_data)
{
    struct sssd_dbus_ctx *ctx;
    const char *method;
    const char *path;
    const char *msg_interface;
    DBusMessage *reply = NULL;
    int i, ret;

    ctx = talloc_get_type(user_data, struct sssd_dbus_ctx);

    method = dbus_message_get_member(message);
    path = dbus_message_get_path(message);
    msg_interface = dbus_message_get_interface(message);

    if (!method || !path || !msg_interface)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    /* Validate the method interface */
    if (strcmp(msg_interface, ctx->name) != 0)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    /* Validate the D-BUS path */
    if (strcmp(path, ctx->path) == 0) {
        for (i = 0; ctx->methods[i].method != NULL; i++) {
            if (strcmp(method, ctx->methods[i].method) == 0) {
                ret = ctx->methods[i].fn(message, ctx, &reply);
                /* FIXME: check error */
                break;
            }
        }
        /* FIXME: check if we didn't find any matching method */
    }

    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }

    return reply ? DBUS_HANDLER_RESULT_HANDLED :
                   DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/*
 * new_connection_callback
 * Actions to be run upon each new client connection
 * Must either perform dbus_connection_ref() on the
 * new connection or else close the connection with
 * dbus_connection_close()
 */
static void new_connection_callback(DBusServer *server, DBusConnection *conn,
                                    void *data)
{
    struct dbus_server_toplevel_context *dst_ctx;
    DBusObjectPathVTable *monitor_vtable;
    int ret;

    dst_ctx = talloc_get_type(data,struct dbus_server_toplevel_context);

    ret = sssd_add_dbus_connection(dst_ctx->sd_ctx, conn);
    if (ret != 0) {
        dbus_connection_close(conn);
        DEBUG(0,("Closing connection (failed setup)"));
        return;
    }

    dbus_connection_ref(conn);

    DEBUG(3,("Got a connection\n"));

    monitor_vtable = talloc_zero(dst_ctx, DBusObjectPathVTable);

    DEBUG (3,("Initializing D-BUS methods.\n"));
    monitor_vtable->message_function = message_handler;

    dbus_connection_register_object_path(conn, dst_ctx->sd_ctx->path,
                                         monitor_vtable, dst_ctx->sd_ctx);

    DEBUG(3,("D-BUS method initialization complete.\n"));
}

/*
 * dbus_new_server
 * Set up a D-BUS server, integrate with the event loop
 * for handling file descriptor and timed events
 */
int sssd_new_dbus_server(struct sssd_dbus_ctx *ctx, const char *address)
{
    struct dbus_server_toplevel_context *dt_ctx;
    DBusServer *dbus_server;
    DBusError dbus_error;
    dbus_bool_t dbret;

    /* Set up D-BUS server */
    dbus_error_init(&dbus_error);
    dbus_server = dbus_server_listen(address, &dbus_error);
    if (!dbus_server) {
        DEBUG(0,("dbus_server_listen failed! (name=%s, message=%s)\n",
                 dbus_error.name, dbus_error.message));
        return EIO;
    }

    /* TODO: remove debug */
    DEBUG(2, ("D-BUS Server listening on %s\n",
              dbus_server_get_address(dbus_server)));

    dt_ctx = talloc_zero(ctx, struct dbus_server_toplevel_context);
    if (!dt_ctx) {
        /* FIXME: free DBusServer resources */
        return ENOMEM;
    }
    dt_ctx->server = dbus_server;
    dt_ctx->sd_ctx = ctx;

    /* Set up D-BUS new connection handler */
    /* FIXME: set free_data_function */
    dbus_server_set_new_connection_function(dt_ctx->server,
                                            new_connection_callback,
                                            dt_ctx, NULL);

    /* Set up DBusWatch functions */
    dbret = dbus_server_set_watch_functions(dt_ctx->server, add_server_watch,
                                            remove_watch, toggle_server_watch,
                                            dt_ctx, NULL);
    if (!dbret) {
        DEBUG(0, ("Error setting up D-BUS server watch functions"));
        /* FIXME: free DBusServer resources */
        return EIO;
    }

    /* Set up DBusTimeout functions */
    dbret = dbus_server_set_timeout_functions(dt_ctx->server,
                                              add_server_timeout,
                                              remove_timeout,
                                              toggle_server_timeout,
                                              dt_ctx, NULL);
    if (!dbret) {
        DEBUG(0,("Error setting up D-BUS server timeout functions"));
        /* FIXME: free DBusServer resources */
        return EIO;
    }

    return EOK;
}
