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
#include "dbus/dbus.h"
#include "monitor.h"
#include "dbus/sssd_dbus_common.h"
#include "dbus/sssd_dbus_server.h"
#include "dbus/sssd_dbus_client.h"
#include "events.h"
#include "util/util.h"

/*
 * integrate_server_with_event_loop
 * Set up a D-BUS server to use the libevents mainloop
 * for handling file descriptor and timed events
 */
int integrate_server_with_event_loop(struct event_context *event_ctx,
        DBusServer *dbus_server,
        void(*server_connection_setup)(DBusConnection *conn, struct event_context *)) {
    struct dbus_server_toplevel_context *dt_ctx;
    dt_ctx = talloc_zero(event_ctx, struct dbus_server_toplevel_context);
    dt_ctx->ev = event_ctx;
    dt_ctx->server = dbus_server;
    dt_ctx->server_connection_setup = server_connection_setup;

    /* Set up D-BUS new connection handler */
    dbus_server_set_new_connection_function(dt_ctx->server,
            new_connection_callback, dt_ctx, NULL);

    /* Set up DBusWatch functions */
    if (!dbus_server_set_watch_functions(dt_ctx->server, add_server_watch,
            remove_watch, toggle_server_watch, dt_ctx, NULL)) {
        DEBUG(0,("Error setting up D-BUS server watch functions"));
        return -1;
    }

    /* Set up DBusTimeout functions */
    if (!dbus_server_set_timeout_functions(dt_ctx->server, add_server_timeout,
            remove_timeout, toggle_server_timeout, dt_ctx, NULL)) {
        DEBUG(0,("Error setting up D-BUS server timeout functions"));
        return -1;
    }

    return 0;
}

/*
 * new_connection_callback
 * Actions to be run upon each new client connection
 * Must either perform dbus_connection_ref() on the
 * new connection or else close the connection with
 * dbus_connection_close()
 */
void new_connection_callback(DBusServer *server,
        DBusConnection *new_connection, void *data) {

    struct dbus_server_toplevel_context *dst_ctx;
    dst_ctx = talloc_get_type(data,struct dbus_server_toplevel_context);

    if(integrate_connection_with_event_loop(dst_ctx->ev,new_connection) != 0) {
        dbus_connection_close(new_connection);
        DEBUG(0,("Closing connection (failed setup)"));
        return;
    }
    dbus_connection_ref(new_connection);

    /* Run connection setup function */
    DEBUG(3,("Got a connection\n"));
    dst_ctx->server_connection_setup(new_connection, dst_ctx->ev);
    DEBUG(3,("New connection set up.\n"));
}

/*
 * add_server_watch
 * Set up hooks into the libevents mainloop for
 * D-BUS to add file descriptor-based events
 */
dbus_bool_t add_server_watch(DBusWatch *watch, void *data) {
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
    svw_ctx->fde = event_add_fd(svw_ctx->top->ev, svw_ctx, svw_ctx->fd,
            event_flags, dbus_server_read_write_handler, svw_ctx);

    /* Save the event to the watch object so it can be removed later */
    dbus_watch_set_data(svw_ctx->watch,svw_ctx->fde,NULL);

    return TRUE;
}

/*
 * server_watch_toggled
 * Hook for D-BUS to toggle the enabled/disabled state of
 * an event in the mainloop
 */
void toggle_server_watch(DBusWatch *watch, void *data) {
    if (dbus_watch_get_enabled(watch))
        add_server_watch(watch, data);
    else
        remove_watch(watch, data);
}

/*
 * add_server_timeout
 * Hook for D-BUS to add time-based events to the mainloop
 */
dbus_bool_t add_server_timeout(DBusTimeout *timeout, void *data) {
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

    svt_ctx->te = event_add_timed(svt_ctx->top->ev, svt_ctx, tv,
            dbus_server_timeout_handler, svt_ctx);

    /* Save the event to the watch object so it can be removed later */
    dbus_timeout_set_data(svt_ctx->timeout,svt_ctx->te,NULL);

    return TRUE;
}

/*
 * server_timeout_toggled
 * Hook for D-BUS to toggle the enabled/disabled state of a mainloop
 * event
 */
void toggle_server_timeout(DBusTimeout *timeout, void *data) {
    if (dbus_timeout_get_enabled(timeout))
        add_server_timeout(timeout, data);
    else
        remove_timeout(timeout, data);
}

/*
 * dbus_server_read_write_handler
 * Callback for D-BUS to handle messages on a file-descriptor
 */
void dbus_server_read_write_handler(struct event_context *ev, struct fd_event *fde,
        uint16_t flags, void *ptr) {
    struct dbus_server_watch_context *svw_ctx;
    svw_ctx = talloc_get_type(ptr,struct dbus_server_watch_context);

    dbus_server_ref(svw_ctx->top->server);
    if (flags & EVENT_FD_READ) {
        dbus_watch_handle(svw_ctx->watch, DBUS_WATCH_READABLE);
    }
    if (flags & EVENT_FD_WRITE) {
        dbus_watch_handle(svw_ctx->watch, DBUS_WATCH_WRITABLE);
    }
    dbus_server_ref(svw_ctx->top->server);
}

void dbus_server_timeout_handler(struct event_context *ev, struct timed_event *te,
        struct timeval t, void *data) {
    struct dbus_server_timeout_context *svt_ctx;
    svt_ctx = talloc_get_type(data, struct dbus_server_timeout_context);
    dbus_timeout_handle(svt_ctx->timeout);
}
