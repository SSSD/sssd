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
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"
#include "sbus/sssd_dbus_meta.h"

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
    DEBUG(SSSDBG_TRACE_ALL, "dbus conn: %p\n", dbus_conn);

    if (conn->retries > 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "SBUS is reconnecting. Deferring.\n");
        /* Currently trying to reconnect, defer dispatch for 30ms */
        tv = tevent_timeval_current_ofs(0, 30);
        new_event = tevent_add_timer(ev, conn, tv, sbus_dispatch, conn);
        if (new_event == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,"Could not defer dispatch!\n");
        }
        return;
    }

    if ((!dbus_connection_get_is_connected(dbus_conn)) &&
        (conn->max_retries != 0)) {
        /* Attempt to reconnect automatically */
        ret = sbus_auto_reconnect(conn);
        if (ret == EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Performing auto-reconnect\n");
            return;
        }

        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot start auto-reconnection.\n");
        conn->reconnect_callback(conn,
                                 SBUS_RECONNECT_ERROR,
                                 conn->reconnect_pvt);
        return;
    }

    if ((conn->disconnect) ||
        (!dbus_connection_get_is_connected(dbus_conn))) {
        DEBUG(SSSDBG_MINOR_FAILURE,"Connection is not open for dispatching.\n");
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
        DEBUG(SSSDBG_TRACE_ALL,"Dispatching.\n");
        dbus_connection_dispatch(dbus_conn);
    }

    /* If other dispatches are waiting, queue up the dispatch function
     * for the next loop.
     */
    ret = dbus_connection_get_dispatch_status(dbus_conn);
    if (ret != DBUS_DISPATCH_COMPLETE) {
        new_event = tevent_add_timer(ev, conn, tv, sbus_dispatch, conn);
        if (new_event == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,"Could not add dispatch event!\n");

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
        DEBUG(SSSDBG_OP_FAILURE,"Could not add dispatch event!\n");
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
                         int connection_type,
                         time_t *last_request_time,
                         void *client_destructor_data,
                         struct sbus_connection **_conn)
{
    struct sbus_connection *conn;
    dbus_bool_t dbret;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC,"Adding connection %p\n", dbus_conn);
    conn = talloc_zero(ctx, struct sbus_connection);

    conn->ev = ev;
    conn->type = SBUS_CONNECTION;
    conn->dbus.conn = dbus_conn;
    conn->connection_type = connection_type;
    conn->last_request_time = last_request_time;
    conn->client_destructor_data = client_destructor_data;

    conn->managed_paths = sbus_opath_hash_init(conn, conn);
    if (conn->managed_paths == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create object paths hash table\n");
        talloc_free(conn);
        return EIO;
    }

    conn->nodes_fns = sbus_nodes_hash_init(conn);
    if (conn->nodes_fns == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create node functions hash table\n");
        talloc_free(conn);
        return EIO;
    }

    conn->incoming_signals = sbus_incoming_signal_hash_init(conn);
    if (conn->incoming_signals == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create incoming signals "
              "hash table\n");
        talloc_free(conn);
        return EIO;
    }

    ret = sss_hash_create(conn, 32, &conn->clients);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create clients hash table\n");
        talloc_free(conn);
        return EIO;
    }

    ret = sbus_conn_set_fns(conn);
    if (ret != EOK) {
        talloc_free(conn);
        return ret;
    }

    /* Set up signal handler. */
    dbret = dbus_connection_add_filter(dbus_conn, sbus_signal_handler, conn,
                                       NULL);
    if (dbret == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot register signal handler\n");
        talloc_free(conn);
        return EIO;
    }

    sbus_register_common_signals(conn, conn);

    *_conn = conn;
    return ret;
}

static int sbus_conn_set_fns(struct sbus_connection *conn)
{
    dbus_bool_t dbret;

    /* Set up DBusWatch functions */
    dbret = dbus_connection_set_watch_functions(conn->dbus.conn,
                                                sbus_add_watch,
                                                sbus_remove_watch,
                                                sbus_toggle_watch,
                                                conn, NULL);
    if (!dbret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error setting up D-BUS connection watch functions\n");
        return EIO;
    }

    /* Set up DBusTimeout functions */
    dbret = dbus_connection_set_timeout_functions(conn->dbus.conn,
                                                  sbus_add_timeout,
                                                  sbus_remove_timeout,
                                                  sbus_toggle_timeout,
                                                  conn, NULL);
    if (!dbret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error setting up D-BUS server timeout functions\n");
        /* FIXME: free resources? */
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
                        const char *address, time_t *last_request_time,
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
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to open connection: name=%s, message=%s\n",
                dbus_error.name, dbus_error.message);
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        return EIO;
    }

    ret = sbus_init_connection(ctx, ev, dbus_conn, SBUS_CONN_TYPE_SHARED,
                               last_request_time, NULL, &conn);
    if (ret != EOK) {
        /* FIXME: release resources */
    }

    /* Store the address for later reconnection */
    conn->address = talloc_strdup(conn, address);

    dbus_connection_set_exit_on_disconnect(conn->dbus.conn, FALSE);

    *_conn = conn;
    return ret;
}

static int connection_destructor(void *ctx)
{
    struct sbus_connection *conn;
    conn = talloc_get_type(ctx, struct sbus_connection);

    DEBUG(SSSDBG_TRACE_FUNC, "Invoking default destructor on connection %p\n",
              conn->dbus.conn);
    if (conn->connection_type == SBUS_CONN_TYPE_PRIVATE) {
        /* Private connections must be closed explicitly */
        dbus_connection_close(conn->dbus.conn);
    }
    else if (conn->connection_type == SBUS_CONN_TYPE_SHARED ||
             conn->connection_type == SBUS_CONN_TYPE_SYSBUS) {
        /* Shared and system bus connections are destroyed when their last
           reference is removed */
    }
    else {
        /* Critical Error! */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Critical Error, connection_type is neither shared nor private!\n");
        return -1;
    }

    /* Remove object path */
    /* TODO: Remove object paths */

    dbus_connection_unref(conn->dbus.conn);
    return 0;
}

/*
 * sbus_get_connection
 * Utility function to retrieve the DBusConnection object
 * from a sbus_connection
 */
DBusConnection *sbus_get_connection(struct sbus_connection *conn)
{
    return conn->dbus.conn;
}

void sbus_disconnect(struct sbus_connection *conn)
{
    if (conn == NULL) {
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Disconnecting %p\n", conn->dbus.conn);

    /*******************************
     *  Referencing conn->dbus.conn */
    dbus_connection_ref(conn->dbus.conn);

    conn->disconnect = 1;

    /* Unregister object paths */
    talloc_zfree(conn->managed_paths);

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
    connection_destructor(conn);

    dbus_connection_unref(conn->dbus.conn);
    /* Unreferenced conn->dbus_conn *
     ******************************/

    DEBUG(SSSDBG_TRACE_FUNC ,"Disconnected %p\n", conn->dbus.conn);
}

static void sbus_reconnect(struct tevent_context *ev,
                           struct tevent_timer *te,
                           struct timeval tv, void *data)
{
    struct sbus_connection *conn;
    DBusError dbus_error;
    int ret;

    conn = talloc_get_type(data, struct sbus_connection);
    dbus_error_init(&dbus_error);

    DEBUG(SSSDBG_MINOR_FAILURE, "Making reconnection attempt %d to [%s]\n",
              conn->retries, conn->address);
    conn->dbus.conn = dbus_connection_open(conn->address, &dbus_error);
    if (conn->dbus.conn) {
        /* We successfully reconnected. Set up mainloop integration. */
        DEBUG(SSSDBG_MINOR_FAILURE, "Reconnected to [%s]\n", conn->address);
        ret = sbus_conn_set_fns(conn);
        if (ret != EOK) {
            dbus_connection_unref(conn->dbus.conn);
            goto failed;
        }

        /* Re-register object paths */
        sbus_conn_reregister_paths(conn);

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
    DEBUG(SSSDBG_CRIT_FAILURE,
          "Failed to open connection: name=%s, message=%s\n",
                dbus_error.name, dbus_error.message);
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

int sss_dbus_conn_send(DBusConnection *dbus_conn,
                       DBusMessage *msg,
                       int timeout_ms,
                       DBusPendingCallNotifyFunction reply_handler,
                       void *pvt,
                       DBusPendingCall **pending)
{
    DBusPendingCall *pending_reply;
    dbus_bool_t dbret;

    dbret = dbus_connection_send_with_reply(dbus_conn, msg,
                                            &pending_reply,
                                            timeout_ms);
    if (!dbret) {
        /*
         * Critical Failure
         * Insufficient memory to send message
         */
        DEBUG(SSSDBG_FATAL_FAILURE, "D-BUS send failed.\n");
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
            DEBUG(SSSDBG_FATAL_FAILURE, "D-BUS send failed.\n");
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
    DBusConnection *dbus_conn;

    dbus_conn = sbus_get_connection(conn);
    if (!dbus_conn) {
        DEBUG(SSSDBG_CRIT_FAILURE, "D-BUS not connected\n");
        return ENOTCONN;
    }

    return sss_dbus_conn_send(dbus_conn, msg, timeout_ms,
                              reply_handler, pvt, pending);
}

void sbus_conn_send_reply(struct sbus_connection *conn, DBusMessage *reply)
{
    dbus_connection_send(conn->dbus.conn, reply, NULL);
}

dbus_bool_t is_uid_sssd_user(DBusConnection *connection,
                             unsigned long   uid,
                             void           *data)
{
    uid_t sssd_user = * (uid_t *) data;

    if (uid == 0 || uid == sssd_user) {
        return TRUE;
    }

    return FALSE;
}

void sbus_allow_uid(struct sbus_connection *conn, uid_t *uid)
{
    dbus_connection_set_unix_user_function(sbus_get_connection(conn),
                                           is_uid_sssd_user,
                                           uid, NULL);
}

void *sbus_connection_get_destructor_data(struct sbus_connection *conn)
{
    if (conn == NULL) {
        /* Should never happen! */
        return NULL;
    }

    return conn->client_destructor_data;
}
