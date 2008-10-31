#include <sys/time.h>
#include "events.h"
#include "util/util.h"
#include "dbus/dbus.h"
#include "dbus/sssd_dbus.h"
#include "dbus/sssd_dbus_private.h"

/* Types */
struct dbus_ctx_list;

struct dbus_connection_toplevel_context {
    DBusConnection *conn;
    struct event_context *ev;
    int connection_type;
    int disconnect;
    struct sssd_dbus_method_ctx *method_ctx_list;
    sssd_dbus_connection_destructor_fn destructor;
    void *private; /* Private data for this connection */
};

struct dbus_connection_watch_context {
    DBusWatch *watch;
    int fd;
    struct fd_event *fde;
    struct dbus_connection_toplevel_context *top;
};

struct dbus_connection_timeout_context {
    DBusTimeout *timeout;
    struct timed_event *te;
    struct dbus_connection_toplevel_context *top;
};

static int method_list_contains_path(struct sssd_dbus_method_ctx *list, struct sssd_dbus_method_ctx *method);
static void sssd_unregister_object_paths(struct dbus_connection_toplevel_context *dct_ctx);

static void do_dispatch(struct event_context *ev,
                               struct timed_event *te,
                               struct timeval tv, void *data)
{
    struct timed_event *new_event;
    struct dbus_connection_toplevel_context *dct_ctx;
    DBusConnection *conn;
    int ret;

    if (data == NULL) {
        return;
    }

    dct_ctx = talloc_get_type(data, struct dbus_connection_toplevel_context);

    conn = dct_ctx->conn;
    DEBUG(3, ("conn: %lX\n", conn));

    if((dct_ctx->disconnect) || (!dbus_connection_get_is_connected(conn))) {
        DEBUG(0,("Connection is not open for dispatching.\n"));
        /* 
         * Free the connection object.
         * This will invoke the destructor for the connection
         */
        talloc_free(dct_ctx);
        dct_ctx = NULL;
        return;
    }

    /* Dispatch only once each time through the mainloop to avoid
     * starving other features
     */
    ret = dbus_connection_get_dispatch_status(conn);
    if (ret != DBUS_DISPATCH_COMPLETE) {
        DEBUG(2,("Dispatching.\n"));
        dbus_connection_dispatch(conn);
    }

    /* If other dispatches are waiting, queue up the do_dispatch function
     * for the next loop.
     */
    ret = dbus_connection_get_dispatch_status(conn);
    if (ret != DBUS_DISPATCH_COMPLETE) {
        new_event = event_add_timed(ev, ev, tv, do_dispatch, dct_ctx);
        if (new_event == NULL) {
            DEBUG(0,("Could not add dispatch event!\n"));

            /* TODO: Calling exit here is bad */ 
            exit(1);
        }
    }
}

/*
 * dbus_connection_read_write_handler
 * Callback for D-BUS to handle messages on a file-descriptor
 */
static void dbus_connection_read_write_handler(struct event_context *ev,
                                               struct fd_event *fde,
                                               uint16_t flags, void *data)
{
    struct dbus_connection_watch_context *conn_w_ctx;
    conn_w_ctx = talloc_get_type(data, struct dbus_connection_watch_context);

    DEBUG(0,("Connection is open for read/write.\n"));
    dbus_connection_ref(conn_w_ctx->top->conn);
    if (flags & EVENT_FD_READ) {
        dbus_watch_handle(conn_w_ctx->watch, DBUS_WATCH_READABLE);
    }
    if (flags & EVENT_FD_WRITE) {
        dbus_watch_handle(conn_w_ctx->watch, DBUS_WATCH_WRITABLE);
    }
    dbus_connection_unref(conn_w_ctx->top->conn);
}

/*
 * add_connection_watch
 * Set up hooks into the libevents mainloop for
 * D-BUS to add file descriptor-based events
 */
static dbus_bool_t add_connection_watch(DBusWatch *watch, void *data)
{
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

    DEBUG(2,("%lX: %d, %d=%s\n", watch, conn_w_ctx->fd, event_flags, event_flags==EVENT_FD_READ?"READ":"WRITE"));

    /* Add the file descriptor to the event loop */
    conn_w_ctx->fde = event_add_fd(conn_w_ctx->top->ev, conn_w_ctx,
                                   conn_w_ctx->fd, event_flags,
                                   dbus_connection_read_write_handler,
                                   conn_w_ctx);

    /* Save the event to the watch object so it can be removed later */
    dbus_watch_set_data(conn_w_ctx->watch,conn_w_ctx->fde,NULL);

    return TRUE;
}

/*
 * toggle_connection_watch
 * Hook for D-BUS to toggle the enabled/disabled state of
 * an event in the mainloop
 */
static void toggle_connection_watch(DBusWatch *watch, void *data)
{
    if (dbus_watch_get_enabled(watch)) {
        add_connection_watch(watch, data);
    } else {
        remove_watch(watch, data);
    }
}

/*
 * dbus_connection_timeout_handler
 * Callback for D-BUS to handle timed events
 */
static void dbus_connection_timeout_handler(struct event_context *ev,
                                            struct timed_event *te,
                                            struct timeval t, void *data)
{
    struct dbus_connection_timeout_context *conn_t_ctx;
    conn_t_ctx = talloc_get_type(data, struct dbus_connection_timeout_context);

    dbus_timeout_handle(conn_t_ctx->timeout);
}


/*
 * add_connection_timeout
 * Hook for D-BUS to add time-based events to the mainloop
 */
static dbus_bool_t add_connection_timeout(DBusTimeout *timeout, void *data)
{
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
void toggle_connection_timeout(DBusTimeout *timeout, void *data)
{
    if (dbus_timeout_get_enabled(timeout)) {
        add_connection_timeout(timeout, data);
    } else {
        remove_timeout(timeout, data);
    }
}

/* dbus_connection_wakeup_main
 * D-BUS makes a callback to the wakeup_main function when
 * it has data available for dispatching.
 * In order to avoid blocking, this function will create a now()
 * timed event to perform the dispatch during the next iteration
 * through the mainloop
 */
static void dbus_connection_wakeup_main(void *data) {
    struct dbus_connection_toplevel_context *dct_ctx;
    struct timeval tv;
    struct timed_event *te;

    dct_ctx = talloc_get_type(data, struct dbus_connection_toplevel_context);
    gettimeofday(&tv, NULL);

    /* D-BUS calls this function when it is time to do a dispatch */
    te = event_add_timed(dct_ctx->ev, dct_ctx->ev,
                         tv, do_dispatch, dct_ctx);
    if (te == NULL) {
        DEBUG(0,("Could not add dispatch event!\n"));
        exit(1);
    }
}

/*
 * integrate_connection_with_event_loop
 * Set up a D-BUS connection to use the libevents mainloop
 * for handling file descriptor and timed events
 */
int sssd_add_dbus_connection(TALLOC_CTX *ctx,
                             struct event_context *ev,
                             DBusConnection *dbus_conn,
                             struct dbus_connection_toplevel_context **dct_ctx,
                             int connection_type)
{
    dbus_bool_t dbret;
    struct dbus_connection_toplevel_context *dt_ctx;

    DEBUG(0,("Adding connection %lX\n", dbus_conn));
    dt_ctx = talloc_zero(ctx, struct dbus_connection_toplevel_context);
    dt_ctx->ev = ev;
    dt_ctx->conn = dbus_conn;
    dt_ctx->connection_type = connection_type;
    dt_ctx->disconnect = 0;
    /* This will be replaced on the first call to dbus_connection_add_method_ctx() */
    dt_ctx->method_ctx_list = NULL; 
    
    /*
     * Set the default destructor
     * Connections can override this with 
     * sssd_dbus_connection_set_destructor
     */ 
    sssd_dbus_connection_set_destructor(dt_ctx, NULL);

    /* Set up DBusWatch functions */
    dbret = dbus_connection_set_watch_functions(dt_ctx->conn,
                                                add_connection_watch,
                                                remove_watch,
                                                toggle_connection_watch,
                                                dt_ctx, NULL);
    if (!dbret) {
        DEBUG(0,("Error setting up D-BUS connection watch functions\n"));
        return EIO;
    }

    /* Set up DBusTimeout functions */
    dbret = dbus_connection_set_timeout_functions(dt_ctx->conn,
                                                  add_connection_timeout,
                                                  remove_timeout,
                                                  toggle_connection_timeout,
                                                  dt_ctx, NULL);
    if (!dbret) {
        DEBUG(0,("Error setting up D-BUS server timeout functions\n"));
        /* FIXME: free resources ? */
        return EIO;
    }

    /* Set up dispatch handler */
    dbus_connection_set_wakeup_main_function(dt_ctx->conn,
                                             dbus_connection_wakeup_main,
                                             dt_ctx, NULL);
    
    /* Set up any method_contexts passed in */

    /* Attempt to dispatch immediately in case of opportunistic
     * services connecting before the handlers were all up.
     * If there are no messages to be dispatched, this will do
     * nothing.
     */
    dbus_connection_wakeup_main(dt_ctx);

    /* Return the new toplevel object */
    *dct_ctx = dt_ctx;

    return EOK;
}

/*int sssd_new_dbus_connection(struct sssd_dbus_method_ctx *ctx, const char *address,
                             DBusConnection **connection,
                             sssd_dbus_connection_destructor_fn destructor)*/
int sssd_new_dbus_connection(TALLOC_CTX *ctx, struct event_context *ev, const char *address,
                             struct dbus_connection_toplevel_context **dct_ctx, 
                             sssd_dbus_connection_destructor_fn destructor)
{
    DBusConnection *dbus_conn;
    DBusError dbus_error;
    int ret;

    dbus_error_init(&dbus_error);

    /* Open a shared D-BUS connection to the address */
    dbus_conn = dbus_connection_open(address, &dbus_error);
    if (!dbus_conn) {
        DEBUG(0, ("Failed to open connection: name=%s, message=%s\n",
                dbus_error.name, dbus_error.message));
        return EIO;
    }

    ret = sssd_add_dbus_connection(ctx, ev, dbus_conn, dct_ctx, DBUS_CONNECTION_TYPE_SHARED);
    if (ret != EOK) {
        /* FIXME: release resources */
    }

    dbus_connection_set_exit_on_disconnect((*dct_ctx)->conn, FALSE);
    
    /* Set connection destructor */
    sssd_dbus_connection_set_destructor(*dct_ctx, destructor);

    return ret;
}

/*
 * sssd_dbus_connection_set_destructor
 * Configures a callback to clean up this connection when it
 * is finalized.
 * @param dct_ctx The dbus_connection_toplevel_context created
 * when this connection was established
 * @param destructor The destructor function that should be
 * called when the connection is finalized. If passed NULL,
 * this will reset the connection to the default destructor.
 */
void sssd_dbus_connection_set_destructor(struct dbus_connection_toplevel_context *dct_ctx,
        sssd_dbus_connection_destructor_fn destructor) {
    if (!dct_ctx) {
        return;
    }
    
    dct_ctx->destructor = destructor;
    /* TODO: Should we try to handle the talloc_destructor too? */
}

int default_connection_destructor(void *ctx) {
    struct dbus_connection_toplevel_context *dct_ctx;
    dct_ctx = talloc_get_type(ctx, struct dbus_connection_toplevel_context);

    DEBUG(3, ("Invoking default destructor on connection %lX\n", dct_ctx->conn));
    if (dct_ctx->connection_type == DBUS_CONNECTION_TYPE_PRIVATE) {
        /* Private connections must be closed explicitly */
        dbus_connection_close(dct_ctx->conn);
    } else if (dct_ctx->connection_type == DBUS_CONNECTION_TYPE_SHARED) {
        /* Shared connections are destroyed when their last reference is removed */
    }
    else {
        /* Critical Error! */
        DEBUG(0,("Critical Error, connection_type is neither shared nor private!\n"));
        return -1;
    }
    
    /* Remove object path */
    
    
    
    dbus_connection_unref(dct_ctx->conn);
    return 0;
}

/*
 * sssd_get_dbus_connection
 * Utility function to retreive the DBusConnection object
 * from a dbus_connection_toplevel_context
 */
DBusConnection *sssd_get_dbus_connection(struct dbus_connection_toplevel_context *dct_ctx) {
    return dct_ctx->conn;
}

void sssd_dbus_disconnect (struct dbus_connection_toplevel_context *dct_ctx) {
    if (dct_ctx == NULL) {
        return;
    }

    DEBUG(2,("Disconnecting %lX\n", dct_ctx->conn));
    dbus_connection_ref(dct_ctx->conn);
        dct_ctx->disconnect = 1;
        
        /* Invoke the custom destructor, if it exists */
        if(dct_ctx->destructor) {
            dct_ctx->destructor(dct_ctx);
        }
        
        /* Unregister object paths */
        sssd_unregister_object_paths(dct_ctx);

        /* Disable watch functions */
        dbus_connection_set_watch_functions(dct_ctx->conn,
                                            NULL, NULL, NULL,
                                            NULL, NULL);
        /* Disable timeout functions */
        dbus_connection_set_timeout_functions(dct_ctx->conn,
                                              NULL, NULL, NULL,
                                              NULL, NULL);

        /* Disable dispatch status function */
        dbus_connection_set_dispatch_status_function(dct_ctx->conn, NULL, NULL, NULL);
        
        /* Disable wakeup main function */
        dbus_connection_set_wakeup_main_function(dct_ctx->conn, NULL, NULL, NULL);

        /* Finalize the connection */
        default_connection_destructor(dct_ctx);
    dbus_connection_unref(dct_ctx->conn);
    DEBUG(2,("Disconnected %lX\n", dct_ctx->conn));
}

/* messsage_handler
 * Receive messages and process them
 */
static DBusHandlerResult message_handler(DBusConnection *conn,
                                         DBusMessage *message,
                                         void *user_data)
{
    struct sssd_dbus_method_ctx *ctx;
    const char *method;
    const char *path;
    const char *msg_interface;
    DBusMessage *reply = NULL;
    int i, ret;

    ctx = talloc_get_type(user_data, struct sssd_dbus_method_ctx);

    method = dbus_message_get_member(message);
    path = dbus_message_get_path(message);
    msg_interface = dbus_message_get_interface(message);

    if (!method || !path || !msg_interface)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    /* Validate the method interface */
    if (strcmp(msg_interface, ctx->interface) != 0)
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
    
    DEBUG(2, ("Method %s complete. Reply %sneeded.\n", method, reply?"":"not "));

    if (reply) {
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
    }

    return reply ? DBUS_HANDLER_RESULT_HANDLED :
                   DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Adds a new D-BUS path message handler to the connection
 * Note: this must be a unique path.
 */
int dbus_connection_add_method_ctx(struct dbus_connection_toplevel_context *dct_ctx, struct sssd_dbus_method_ctx *method_ctx) {
    DBusObjectPathVTable *connection_vtable;
    dbus_bool_t dbret;
    if (!method_ctx) {
        return EINVAL;
    }
    
    if (method_list_contains_path(dct_ctx->method_ctx_list, method_ctx)) {
        return EINVAL;
    }

    DLIST_ADD(dct_ctx->method_ctx_list, method_ctx);

    /* Set up the vtable for the object path */
    connection_vtable = talloc_zero(dct_ctx, DBusObjectPathVTable);
    if (method_ctx->message_handler) {
        connection_vtable->message_function = method_ctx->message_handler;
    } else {
        connection_vtable->message_function = message_handler;
    }
    
    dbret = dbus_connection_register_object_path(dct_ctx->conn, method_ctx->path, connection_vtable, method_ctx);
    if (!dbret) {
        return ENOMEM; 
    }
    
    return EOK;
}

static int method_list_contains_path(struct sssd_dbus_method_ctx *list, struct sssd_dbus_method_ctx *method) {
    struct sssd_dbus_method_ctx *iter;
    
    if (!list || !method) {
        return 0; /* FALSE */
    }
    
    iter = list;
    while (iter != NULL) {
        if (strcmp(iter->path, method->path) == 0)
            return 1; /* TRUE */
        
        iter = iter->next;
    }
    
    return 0; /* FALSE */
}

static void sssd_unregister_object_paths(struct dbus_connection_toplevel_context *dct_ctx) {
    struct sssd_dbus_method_ctx *iter = dct_ctx->method_ctx_list;
    struct sssd_dbus_method_ctx *purge;
    
    while(iter != NULL) {
        dbus_connection_unregister_object_path(dct_ctx->conn, iter->path);
        DLIST_REMOVE(dct_ctx->method_ctx_list, iter);
        purge = iter;
        iter = iter->next;
        talloc_free(purge);
    }
}

void sssd_connection_set_private_data(struct dbus_connection_toplevel_context *dct_ctx, void *private) {
    dct_ctx->private = private;
}
