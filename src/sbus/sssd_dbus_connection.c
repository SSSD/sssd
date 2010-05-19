/*
    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include "util/util.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

/* Types */
struct dbus_ctx_list;

struct sbus_interface_p {
    struct sbus_interface_p *prev, *next;
    struct sbus_connection *conn;
    struct sbus_interface *intf;
};

static bool path_in_interface_list(struct sbus_interface_p *list,
                                   const char *path);
static void sbus_unreg_object_paths(struct sbus_connection *conn);

static int sbus_auto_reconnect(struct sbus_connection *conn);

static void sbus_dispatch(struct tevent_context *ev,
                          struct tevent_timer *te,
                          struct timeval tv, void *data)
{
    struct tevent_timer *new_event;
    struct sbus_connection *conn;
    DBusConnection *dbus_conn;
    int ret;

    if (data == NULL) return;

    conn = talloc_get_type(data, struct sbus_connection);

    dbus_conn = conn->dbus.conn;
    DEBUG(9, ("dbus conn: %lX\n", dbus_conn));

    if (conn->retries > 0) {
        DEBUG(6, ("SBUS is reconnecting. Deferring.\n"));
        /* Currently trying to reconnect, defer dispatch for 30ms */
        tv = tevent_timeval_current_ofs(0, 30);
        new_event = tevent_add_timer(ev, conn, tv, sbus_dispatch, conn);
        if (new_event == NULL) {
            DEBUG(0,("Could not defer dispatch!\n"));
        }
        return;
    }

    if ((!dbus_connection_get_is_connected(dbus_conn)) &&
        (conn->max_retries != 0)) {
        /* Attempt to reconnect automatically */
        ret = sbus_auto_reconnect(conn);
        if (ret == EOK) {
            DEBUG(1, ("Performing auto-reconnect\n"));
            return;
        }

        DEBUG(0, ("Cannot start auto-reconnection.\n"));
        conn->reconnect_callback(conn,
                                 SBUS_RECONNECT_ERROR,
                                 conn->reconnect_pvt);
        return;
    }

    if ((conn->disconnect) ||
        (!dbus_connection_get_is_connected(dbus_conn))) {
        DEBUG(3,("Connection is not open for dispatching.\n"));
        /*
         * Free the connection object.
         * This will invoke the destructor for the connection
         */
        talloc_free(conn);
        conn = NULL;
        return;
    }

    /* Dispatch only once each time through the mainloop to avoid
     * starving other features
     */
    ret = dbus_connection_get_dispatch_status(dbus_conn);
    if (ret != DBUS_DISPATCH_COMPLETE) {
        DEBUG(9,("Dispatching.\n"));
        dbus_connection_dispatch(dbus_conn);
    }

    /* If other dispatches are waiting, queue up the dispatch function
     * for the next loop.
     */
    ret = dbus_connection_get_dispatch_status(dbus_conn);
    if (ret != DBUS_DISPATCH_COMPLETE) {
        new_event = tevent_add_timer(ev, conn, tv, sbus_dispatch, conn);
        if (new_event == NULL) {
            DEBUG(2,("Could not add dispatch event!\n"));

            /* TODO: Calling exit here is bad */
            exit(1);
        }
    }
}

/* dbus_connection_wakeup_main
 * D-BUS makes a callback to the wakeup_main function when
 * it has data available for dispatching.
 * In order to avoid blocking, this function will create a now()
 * timed event to perform the dispatch during the next iteration
 * through the mainloop
 */
static void sbus_conn_wakeup_main(void *data)
{
    struct sbus_connection *conn;
    struct timeval tv;
    struct tevent_timer *te;

    conn = talloc_get_type(data, struct sbus_connection);

    tv = tevent_timeval_current();

    /* D-BUS calls this function when it is time to do a dispatch */
    te = tevent_add_timer(conn->ev, conn, tv, sbus_dispatch, conn);
    if (te == NULL) {
        DEBUG(2,("Could not add dispatch event!\n"));
        /* TODO: Calling exit here is bad */
        exit(1);
    }
}

static int sbus_conn_set_fns(struct sbus_connection *conn);

/*
 * integrate_connection_with_event_loop
 * Set up a D-BUS connection to use the libevents mainloop
 * for handling file descriptor and timed events
 */
int sbus_init_connection(TALLOC_CTX *ctx,
                         struct tevent_context *ev,
                         DBusConnection *dbus_conn,
                         struct sbus_interface *intf,
                         int connection_type,
                         struct sbus_connection **_conn)
{
    struct sbus_connection *conn;
    int ret;

    DEBUG(5,("Adding connection %lX\n", dbus_conn));
    conn = talloc_zero(ctx, struct sbus_connection);

    conn->ev = ev;
    conn->type = SBUS_CONNECTION;
    conn->dbus.conn = dbus_conn;
    conn->connection_type = connection_type;

    ret = sbus_conn_add_interface(conn, intf);
    if (ret != EOK) {
        talloc_free(conn);
        return ret;
    }

    ret = sbus_conn_set_fns(conn);
    if (ret != EOK) {
        talloc_free(conn);
        return ret;
    }

    *_conn = conn;
    return ret;
}

static int sbus_conn_set_fns(struct sbus_connection *conn)
{
    dbus_bool_t dbret;

    /*
     * Set the default destructor
     * Connections can override this with
     * sbus_conn_set_destructor
     */
    sbus_conn_set_destructor(conn, NULL);

    /* Set up DBusWatch functions */
    dbret = dbus_connection_set_watch_functions(conn->dbus.conn,
                                                sbus_add_watch,
                                                sbus_remove_watch,
                                                sbus_toggle_watch,
                                                conn, NULL);
    if (!dbret) {
        DEBUG(2,("Error setting up D-BUS connection watch functions\n"));
        return EIO;
    }

    /* Set up DBusTimeout functions */
    dbret = dbus_connection_set_timeout_functions(conn->dbus.conn,
                                                  sbus_add_timeout,
                                                  sbus_remove_timeout,
                                                  sbus_toggle_timeout,
                                                  conn, NULL);
    if (!dbret) {
        DEBUG(2,("Error setting up D-BUS server timeout functions\n"));
        /* FIXME: free resources ? */
        return EIO;
    }

    /* Set up dispatch handler */
    dbus_connection_set_wakeup_main_function(conn->dbus.conn,
                                             sbus_conn_wakeup_main,
                                             conn, NULL);

    /* Set up any method_contexts passed in */

    /* Attempt to dispatch immediately in case of opportunistic
     * services connecting before the handlers were all up.
     * If there are no messages to be dispatched, this will do
     * nothing.
     */
    sbus_conn_wakeup_main(conn);

    return EOK;
}

int sbus_new_connection(TALLOC_CTX *ctx, struct tevent_context *ev,
                        const char *address, struct sbus_interface *intf,
                        struct sbus_connection **_conn)
{
    struct sbus_connection *conn;
    DBusConnection *dbus_conn;
    DBusError dbus_error;
    int ret;

    dbus_error_init(&dbus_error);

    /* Open a shared D-BUS connection to the address */
    dbus_conn = dbus_connection_open(address, &dbus_error);
    if (!dbus_conn) {
        DEBUG(1, ("Failed to open connection: name=%s, message=%s\n",
                dbus_error.name, dbus_error.message));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        return EIO;
    }

    ret = sbus_init_connection(ctx, ev, dbus_conn, intf,
                               SBUS_CONN_TYPE_SHARED, &conn);
    if (ret != EOK) {
        /* FIXME: release resources */
    }

    /* Store the address for later reconnection */
    conn->address = talloc_strdup(conn, address);

    dbus_connection_set_exit_on_disconnect(conn->dbus.conn, FALSE);

    *_conn = conn;
    return ret;
}

/*
 * sbus_conn_set_destructor
 * Configures a callback to clean up this connection when it
 * is finalized.
 * @param conn The sbus_connection created
 * when this connection was established
 * @param destructor The destructor function that should be
 * called when the connection is finalized. If passed NULL,
 * this will reset the connection to the default destructor.
 */
void sbus_conn_set_destructor(struct sbus_connection *conn,
                              sbus_conn_destructor_fn destructor)
{
    if (!conn) return;

    conn->destructor = destructor;
    /* TODO: Should we try to handle the talloc_destructor too? */
}

int sbus_default_connection_destructor(void *ctx)
{
    struct sbus_connection *conn;
    conn = talloc_get_type(ctx, struct sbus_connection);

    DEBUG(5, ("Invoking default destructor on connection %lX\n",
              conn->dbus.conn));
    if (conn->connection_type == SBUS_CONN_TYPE_PRIVATE) {
        /* Private connections must be closed explicitly */
        dbus_connection_close(conn->dbus.conn);
    }
    else if (conn->connection_type == SBUS_CONN_TYPE_SHARED) {
        /* Shared connections are destroyed when their last reference is removed */
    }
    else {
        /* Critical Error! */
        DEBUG(1,("Critical Error, connection_type is neither shared nor private!\n"));
        return -1;
    }

    /* Remove object path */
    /* TODO: Remove object paths */

    dbus_connection_unref(conn->dbus.conn);
    return 0;
}

/*
 * sbus_get_connection
 * Utility function to retreive the DBusConnection object
 * from a sbus_connection
 */
DBusConnection *sbus_get_connection(struct sbus_connection *conn)
{
    return conn->dbus.conn;
}

void sbus_disconnect (struct sbus_connection *conn)
{
    if (conn == NULL) {
        return;
    }

    DEBUG(5,("Disconnecting %lX\n", conn->dbus.conn));

    /*******************************
     *  Referencing conn->dbus.conn */
    dbus_connection_ref(conn->dbus.conn);

    conn->disconnect = 1;

    /* Invoke the custom destructor, if it exists */
    if (conn->destructor) {
        conn->destructor(conn);
    }

    /* Unregister object paths */
    sbus_unreg_object_paths(conn);

    /* Disable watch functions */
    dbus_connection_set_watch_functions(conn->dbus.conn,
                                        NULL, NULL, NULL,
                                        NULL, NULL);
    /* Disable timeout functions */
    dbus_connection_set_timeout_functions(conn->dbus.conn,
                                          NULL, NULL, NULL,
                                          NULL, NULL);

    /* Disable dispatch status function */
    dbus_connection_set_dispatch_status_function(conn->dbus.conn,
                                                 NULL, NULL, NULL);

    /* Disable wakeup main function */
    dbus_connection_set_wakeup_main_function(conn->dbus.conn,
                                             NULL, NULL, NULL);

    /* Finalize the connection */
    sbus_default_connection_destructor(conn);

    dbus_connection_unref(conn->dbus.conn);
    /* Unreferenced conn->dbus_conn *
     ******************************/

    DEBUG(5,("Disconnected %lX\n", conn->dbus.conn));
}

static int sbus_reply_internal_error(DBusMessage *message,
                                     struct sbus_connection *conn) {
    DBusMessage *reply = dbus_message_new_error(message, DBUS_ERROR_IO_ERROR,
                                                "Internal Error");
    if (reply) {
        sbus_conn_send_reply(conn, reply);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* messsage_handler
 * Receive messages and process them
 */
DBusHandlerResult sbus_message_handler(DBusConnection *dbus_conn,
                                         DBusMessage *message,
                                         void *user_data)
{
    struct sbus_interface_p *intf_p;
    const char *method;
    const char *path;
    const char *msg_interface;
    DBusMessage *reply = NULL;
    int i, ret;
    int found;

    if (!user_data) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    intf_p = talloc_get_type(user_data, struct sbus_interface_p);

    method = dbus_message_get_member(message);
    DEBUG(9, ("Received SBUS method [%s]\n", method));
    path = dbus_message_get_path(message);
    msg_interface = dbus_message_get_interface(message);

    if (!method || !path || !msg_interface)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    /* Validate the D-BUS path */
    if (strcmp(path, intf_p->intf->path) != 0)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    /* Validate the method interface */
    if (strcmp(msg_interface, intf_p->intf->interface) == 0) {
        found = 0;
        for (i = 0; intf_p->intf->methods[i].method != NULL; i++) {
            if (strcmp(method, intf_p->intf->methods[i].method) == 0) {
                found = 1;
                ret = intf_p->intf->methods[i].fn(message, intf_p->conn);
                if (ret != EOK) {
                    return sbus_reply_internal_error(message, intf_p->conn);
                }
                break;
            }
        }

        if (!found) {
            /* Reply DBUS_ERROR_UNKNOWN_METHOD */
            DEBUG(1, ("No matching method found for %s.\n", method));
            reply = dbus_message_new_error(message, DBUS_ERROR_UNKNOWN_METHOD, NULL);
            sbus_conn_send_reply(intf_p->conn, reply);
            dbus_message_unref(reply);
        }
    }
    else {
        /* Special case: check for Introspection request
         * This is usually only useful for system bus connections
         */
        if (strcmp(msg_interface, DBUS_INTROSPECT_INTERFACE) == 0 &&
            strcmp(method, DBUS_INTROSPECT_METHOD) == 0)
        {
            if (intf_p->intf->introspect_fn) {
                /* If we have been asked for introspection data and we have
                 * an introspection function registered, user that.
                 */
                ret = intf_p->intf->introspect_fn(message, intf_p->conn);
                if (ret != EOK) {
                    return sbus_reply_internal_error(message, intf_p->conn);
                }
            }
        }
        else
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    return DBUS_HANDLER_RESULT_HANDLED;
}

/* Adds a new D-BUS path message handler to the connection
 * Note: this must be a unique path.
 */
int sbus_conn_add_interface(struct sbus_connection *conn,
                             struct sbus_interface *intf)
{
    struct sbus_interface_p *intf_p;
    dbus_bool_t dbret;
    const char *path;

    if (!conn || !intf || !intf->vtable.message_function) {
        return EINVAL;
    }

    path = intf->path;

    if (path_in_interface_list(conn->intf_list, path)) {
        DEBUG(0, ("Cannot add method context with identical path.\n"));
        return EINVAL;
    }

    intf_p = talloc_zero(conn, struct sbus_interface_p);
    if (!intf_p) {
        return ENOMEM;
    }
    intf_p->conn = conn;
    intf_p->intf = intf;

    DLIST_ADD(conn->intf_list, intf_p);

    dbret = dbus_connection_register_object_path(conn->dbus.conn,
                                                 path, &intf->vtable, intf_p);
    if (!dbret) {
        DEBUG(0, ("Could not register object path to the connection.\n"));
        return ENOMEM;
    }

    return EOK;
}

static bool path_in_interface_list(struct sbus_interface_p *list,
                                   const char *path)
{
    struct sbus_interface_p *iter;

    if (!list || !path) {
        return false;
    }

    iter = list;
    while (iter != NULL) {
        if (strcmp(iter->intf->path, path) == 0) {
            return true;
        }
        iter = iter->next;
    }

    return false;
}

static void sbus_unreg_object_paths(struct sbus_connection *conn)
{
    struct sbus_interface_p *iter = conn->intf_list;

    while (iter != NULL) {
        dbus_connection_unregister_object_path(conn->dbus.conn,
                                               iter->intf->path);
        iter = iter->next;
    }
}

void sbus_conn_set_private_data(struct sbus_connection *conn, void *pvt_data)
{
    conn->pvt_data = pvt_data;
}

void *sbus_conn_get_private_data(struct sbus_connection *conn)
{
    return conn->pvt_data;
}

static void sbus_reconnect(struct tevent_context *ev,
                           struct tevent_timer *te,
                           struct timeval tv, void *data)
{
    struct sbus_connection *conn;
    struct sbus_interface_p *iter;
    DBusError dbus_error;
    dbus_bool_t dbret;
    int ret;

    conn = talloc_get_type(data, struct sbus_connection);
    dbus_error_init(&dbus_error);

    DEBUG(3, ("Making reconnection attempt %d to [%s]\n",
              conn->retries, conn->address));
    conn->dbus.conn = dbus_connection_open(conn->address, &dbus_error);
    if (conn->dbus.conn) {
        /* We successfully reconnected. Set up mainloop integration. */
        DEBUG(3, ("Reconnected to [%s]\n", conn->address));
        ret = sbus_conn_set_fns(conn);
        if (ret != EOK) {
            dbus_connection_unref(conn->dbus.conn);
            goto failed;
        }

        /* Re-register object paths */
        iter = conn->intf_list;
        while (iter) {
            dbret = dbus_connection_register_object_path(conn->dbus.conn,
                                                         iter->intf->path,
                                                         &iter->intf->vtable,
                                                         iter);
            if (!dbret) {
                DEBUG(0, ("Could not register object path.\n"));
                dbus_connection_unref(conn->dbus.conn);
                goto failed;
            }
            iter = iter->next;
        }

        /* Reset retries to 0 to resume dispatch processing */
        conn->retries = 0;

        /* Notify the owner of this connection that the
         * reconnection was successful
         */
        conn->reconnect_callback(conn,
                                 SBUS_RECONNECT_SUCCESS,
                                 conn->reconnect_pvt);
        return;
    }

failed:
    /* Reconnection failed, try again in a few seconds */
    DEBUG(1, ("Failed to open connection: name=%s, message=%s\n",
                dbus_error.name, dbus_error.message));
    if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);

    conn->retries++;

    /* Check if we've passed our last chance or if we've lost track of
     * our retry count somehow
     */
    if ((conn->retries > conn->max_retries) || (conn->retries <= 0)) {
        conn->reconnect_callback(conn,
                                 SBUS_RECONNECT_EXCEEDED_RETRIES,
                                 conn->reconnect_pvt);
    }

    if (conn->retries == 2) {
        /* Wait 3 seconds before the second reconnect attempt */
        tv.tv_sec += 3;
    }
    else if (conn->retries == 3) {
        /* Wait 10 seconds before the third reconnect attempt */
        tv.tv_sec += 10;
    }
    else {
        /* Wait 30 seconds before all subsequent reconnect attempts */
        tv.tv_sec += 30;
    }

    te = tevent_add_timer(conn->ev, conn, tv, sbus_reconnect, conn);
    if (!te) {
        conn->reconnect_callback(conn,
                                 SBUS_RECONNECT_ERROR,
                                 conn->reconnect_pvt);
    }
}

/* This function will free and recreate the sbus_connection,
 * calling functions need to be aware of this (and whether
 * they have attached a talloc destructor to the
 * sbus_connection.
 */
static int sbus_auto_reconnect(struct sbus_connection *conn)
{
    struct tevent_timer *te = NULL;
    struct timeval tv;

    conn->retries++;
    if (conn->retries >= conn->max_retries) {
        /* Return EIO (to tell the calling process it
         * needs to create a new connection from scratch
         */
        return EIO;
    }

    gettimeofday(&tv, NULL);
    tv.tv_sec += 1; /* Wait 1 second before the first reconnect attempt */
    te = tevent_add_timer(conn->ev, conn, tv, sbus_reconnect, conn);
    if (!te) {
        return EIO;
    }

    return EOK;
}

/* Max retries */
void sbus_reconnect_init(struct sbus_connection *conn,
                         int max_retries,
                         sbus_conn_reconn_callback_fn callback,
                         void *pvt)
{
    if (max_retries < 0 || callback == NULL) return;

    conn->retries = 0;
    conn->max_retries = max_retries;
    conn->reconnect_callback = callback;
    conn->reconnect_pvt = pvt;
}

bool sbus_conn_disconnecting(struct sbus_connection *conn)
{
    if (conn->disconnect == 1) return true;
    return false;
}

/*
 * Send a message across the SBUS
 * If requested, the DBusPendingCall object will
 * be returned to the caller.
 *
 * This function will return EAGAIN in the event
 * that the connection is not open for
 * communication.
 */
int sbus_conn_send(struct sbus_connection *conn,
                   DBusMessage *msg,
                   int timeout_ms,
                   DBusPendingCallNotifyFunction reply_handler,
                   void *pvt,
                   DBusPendingCall **pending)
{
    DBusPendingCall *pending_reply;
    DBusConnection *dbus_conn;
    dbus_bool_t dbret;

    dbus_conn = sbus_get_connection(conn);

    dbret = dbus_connection_send_with_reply(dbus_conn, msg,
                                            &pending_reply,
                                            timeout_ms);
    if (!dbret) {
        /*
         * Critical Failure
         * Insufficient memory to send message
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        return ENOMEM;
    }

    if (pending_reply) {
        /* Set up the reply handler */
        dbret = dbus_pending_call_set_notify(pending_reply, reply_handler,
                                             pvt, NULL);
        if (!dbret) {
            /*
             * Critical Failure
             * Insufficient memory to create pending call notify
             */
            DEBUG(0, ("D-BUS send failed.\n"));
            dbus_pending_call_cancel(pending_reply);
            dbus_pending_call_unref(pending_reply);
            return ENOMEM;
        }

        if(pending) {
            *pending = pending_reply;
        }
        return EOK;
    }

    /* If pending_reply is NULL, the connection was not
     * open for sending.
     */

    /* TODO: Create a callback into the reconnection logic so this
     * request is invoked when the connection is re-established
     */
    return EAGAIN;
}

void sbus_conn_send_reply(struct sbus_connection *conn, DBusMessage *reply)
{
    dbus_connection_send(conn->dbus.conn, reply, NULL);
}

