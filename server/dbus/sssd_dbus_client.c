#include "dbus/sssd_dbus_common.h"
#include "dbus/sssd_dbus_client.h"
#include "util/util.h"
#include <sys/time.h>
#include "events.h"

const char* print_status(int status) {
    switch (status){
    case DBUS_DISPATCH_DATA_REMAINS:
        return "DBUS_DISPATCH_DATA_REMAINS";
    case DBUS_DISPATCH_COMPLETE:
        return "DBUS_DISPATCH_COMPLETE";
    case DBUS_DISPATCH_NEED_MEMORY:
        return "DBUS_DISPATCH_NEED_MEMORY";
    default:
        return "ERROR";
    }
}

void do_dispatch(struct event_context *ev,
                               struct timed_event *te,
                               struct timeval t, void *ptr) {
    struct timed_event *new_event;
    DBusConnection *conn = (DBusConnection *)ptr;

    /* Dispatch only once each time through the mainloop to avoid
     * starving other features
     */
    if(dbus_connection_get_dispatch_status(conn) != DBUS_DISPATCH_COMPLETE) {
        DEBUG(2,("Dispatching.\n"));
        dbus_connection_dispatch(conn);
    }
    /* If other dispatches are waiting, queue up the do_dispatch function
     * for the next loop.
     */
    if(dbus_connection_get_dispatch_status(conn) != DBUS_DISPATCH_COMPLETE) {
        new_event = event_add_timed(ev, ev, t, do_dispatch, conn);
        if (new_event == NULL) {
            DEBUG(0,("Could not add dispatch event!\n"));
            exit(1);
        }
    }
}

/*
 * integrate_connection_with_event_loop
 * Set up a D-BUS connection to use the libevents mainloop
 * for handling file descriptor and timed events
 */
int integrate_connection_with_event_loop(struct event_context *event_ctx,
        DBusConnection *dbus_conn) {
    struct dbus_connection_toplevel_context *dt_ctx;
    dt_ctx = talloc_zero(event_ctx, struct dbus_connection_toplevel_context);
    dt_ctx->ev = event_ctx;
    dt_ctx->conn = dbus_conn;

    /* Set up DBusWatch functions */
    if (!dbus_connection_set_watch_functions(dt_ctx->conn, add_connection_watch,
            remove_watch, toggle_connection_watch, dt_ctx, NULL)) {
        DEBUG(0,("Error setting up D-BUS connection watch functions\n"));
        return -1;
    }

    /* Set up DBusTimeout functions */
    if (!dbus_connection_set_timeout_functions(dt_ctx->conn, add_connection_timeout,
            remove_timeout, toggle_connection_timeout, dt_ctx, NULL)) {
        DEBUG(0,("Error setting up D-BUS server timeout functions\n"));
        return -1;
    }

    /* Set up dispatch handler */
    dbus_connection_set_wakeup_main_function(dt_ctx->conn,
            dbus_connection_wakeup_main, dt_ctx, NULL);

    /* Attempt to dispatch immediately in case of opportunistic
     * services connecting before the handlers were all up.
     * If there are no messages to be dispatched, this will do
     * nothing.
     */
    dbus_connection_wakeup_main(dt_ctx);

    return 0;
}

/*
 * add_connection_watch
 * Set up hooks into the libevents mainloop for
 * D-BUS to add file descriptor-based events
 */
dbus_bool_t add_connection_watch(DBusWatch *watch, void *data) {
    unsigned int flags;
    unsigned int event_flags;
    struct dbus_connection_toplevel_context *dt_ctx;
    struct dbus_connection_watch_context *conn_w_ctx;

    if (!dbus_watch_get_enabled(watch)) {
        return TRUE;
    }

    dt_ctx = talloc_get_type(data, struct dbus_connection_toplevel_context);

    conn_w_ctx = talloc_zero(dt_ctx, struct dbus_connection_watch_context);
    conn_w_ctx->top = dt_ctx;
    conn_w_ctx->watch = watch;

    flags = dbus_watch_get_flags(watch);
    conn_w_ctx->fd = dbus_watch_get_unix_fd(watch);

    event_flags = 0;

    if (flags & DBUS_WATCH_READABLE)
        event_flags |= EVENT_FD_READ;

    if (flags & DBUS_WATCH_WRITABLE)
        event_flags |= EVENT_FD_WRITE;

    if (event_flags == 0)
        return FALSE;

    /* Add the file descriptor to the event loop */
    conn_w_ctx->fde = event_add_fd(conn_w_ctx->top->ev, conn_w_ctx, conn_w_ctx->fd,
            event_flags, dbus_connection_read_write_handler, conn_w_ctx);

    /* Save the event to the watch object so it can be removed later */
    dbus_watch_set_data(conn_w_ctx->watch,conn_w_ctx->fde,NULL);

    return TRUE;
}


/*
 * toggle_connection_watch
 * Hook for D-BUS to toggle the enabled/disabled state of
 * an event in the mainloop
 */
void toggle_connection_watch(DBusWatch *watch, void *data) {
    if (dbus_watch_get_enabled(watch))
        add_connection_watch(watch, data);
    else
        remove_watch(watch, data);
}

/*
 * add_connection_timeout
 * Hook for D-BUS to add time-based events to the mainloop
 */
dbus_bool_t add_connection_timeout(DBusTimeout *timeout, void *data) {
    struct dbus_connection_toplevel_context *dt_ctx;
    struct dbus_connection_timeout_context *conn_t_ctx;
    struct timeval tv;

    if (!dbus_timeout_get_enabled(timeout))
        return TRUE;

    dt_ctx = talloc_get_type(data, struct dbus_connection_toplevel_context);

    conn_t_ctx = talloc_zero(dt_ctx,struct dbus_connection_timeout_context);
    conn_t_ctx->top = dt_ctx;
    conn_t_ctx->timeout = timeout;

    tv = _dbus_timeout_get_interval_tv(dbus_timeout_get_interval(timeout));

    struct timeval rightnow;
    gettimeofday(&rightnow, NULL);

    conn_t_ctx->te = event_add_timed(conn_t_ctx->top->ev, conn_t_ctx, tv,
            dbus_connection_timeout_handler, conn_t_ctx);

    /* Save the event to the watch object so it can be removed later */
    dbus_timeout_set_data(conn_t_ctx->timeout,conn_t_ctx->te,NULL);

    return TRUE;
}

/*
 * toggle_connection_timeout
 * Hook for D-BUS to toggle the enabled/disabled state of a mainloop
 * event
 */
void toggle_connection_timeout(DBusTimeout *timeout, void *data) {
    if (dbus_timeout_get_enabled(timeout))
        add_connection_timeout(timeout, data);
    else
        remove_timeout(timeout, data);
}

/*
 * dbus_connection_read_write_handler
 * Callback for D-BUS to handle messages on a file-descriptor
 */

void dbus_connection_read_write_handler(struct event_context *ev, struct fd_event *fde,
        uint16_t flags, void *ptr) {
    struct dbus_connection_watch_context *conn_w_ctx;
    conn_w_ctx = talloc_get_type(ptr,struct dbus_connection_watch_context);

    dbus_connection_ref(conn_w_ctx->top->conn);
    if (flags & EVENT_FD_READ) {
        dbus_watch_handle(conn_w_ctx->watch, DBUS_WATCH_READABLE);
    }
    if (flags & EVENT_FD_WRITE) {
        dbus_watch_handle(conn_w_ctx->watch, DBUS_WATCH_WRITABLE);
    }
    dbus_connection_ref(conn_w_ctx->top->conn);
}
/*
 * dbus_connection_timeout_handler
 * Callback for D-BUS to handle timed events
 */
void dbus_connection_timeout_handler(struct event_context *ev, struct timed_event *te,
        struct timeval t, void *data) {
    struct dbus_connection_timeout_context *conn_t_ctx;
    conn_t_ctx = talloc_get_type(data, struct dbus_connection_timeout_context);
    dbus_timeout_handle(conn_t_ctx->timeout);
}

/* dbus_connection_wakeup_main
 * D-BUS makes a callback to the wakeup_main function when
 * it has data available for dispatching.
 * In order to avoid blocking, this function will create a now()
 * timed event to perform the dispatch during the next iteration
 * through the mainloop
 */
void dbus_connection_wakeup_main(void *data) {
    struct dbus_connection_toplevel_context *dct_ctx;
    struct timeval tv;
    struct timed_event *te;
    dct_ctx = talloc_get_type(data, struct dbus_connection_toplevel_context);
    gettimeofday(&tv, NULL);

    /* D-BUS calls this function when it is time to do a dispatch */
    te = event_add_timed(dct_ctx->ev, dct_ctx->ev, tv, do_dispatch, dct_ctx->conn);
    if (te == NULL) {
        DEBUG(0,("Could not add dispatch event!\n"));
        exit(1);
    }
}
