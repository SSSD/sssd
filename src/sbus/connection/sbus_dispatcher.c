/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <errno.h>
#include <tevent.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/dlinklist.h"
#include "sbus/sbus_private.h"

static void
sbus_dispatch_schedule(struct sbus_connection *conn, uint32_t usecs);

static void
sbus_dispatch_reconnect(struct sbus_connection *conn)
{
    /* Terminate all outgoing requests associated with this connection. */
    DEBUG(SSSDBG_TRACE_FUNC, "Connection lost. Terminating active requests.\n");
    sbus_requests_terminate_all(conn->requests->outgoing, ERR_TERMINATED);

    switch (conn->type) {
    case SBUS_CONNECTION_CLIENT:
        /* Remote client closed the connection. We can't reestablish
         * connection with a client, it must reconnect to us if it
         * needs to. Therefore we are done here. */
        DEBUG(SSSDBG_TRACE_ALL, "Remote client terminated the connection. "
              "Releasing data...\n");
        sbus_connection_free(conn);
        break;
    case SBUS_CONNECTION_ADDRESS:
    case SBUS_CONNECTION_SYSBUS:
        /* Try to reconnect if it was enabled. */
        if (sbus_reconnect_enabled(conn)) {
            sbus_reconnect(conn);
            return;
        }

        /* We were unable to reconnect. There is nothing we can do. */
        DEBUG(SSSDBG_MINOR_FAILURE, "Connection is not open for "
              "dispatching. Releasing data...\n");
        sbus_connection_free(conn);
        break;
    }
}

static void
sbus_dispatch(struct tevent_context *ev,
              struct tevent_timer *te,
              struct timeval tv,
              void *data)
{
    DBusDispatchStatus status;
    struct sbus_connection *conn;
    bool connected;

    conn = talloc_get_type(data, struct sbus_connection);

    /* Just return if the connection is being terminated. */
    if (conn->disconnecting) {
        return;
    }

    /* Defer dispatch if we reconnecting. */
    if (sbus_reconnect_in_progress(conn)) {
        DEBUG(SSSDBG_TRACE_FUNC, "SBUS is reconnecting. Deferring.\n");
        sbus_dispatch_schedule(conn, 30);
        return;
    }

    /* Try to reconnect if we are not connected. */
    connected = dbus_connection_get_is_connected(conn->connection);
    if (!connected) {
        sbus_dispatch_reconnect(conn);
        return;
    }

    /* Dispatch only once to avoid starving other tevent requests. */
    status = dbus_connection_get_dispatch_status(conn->connection);
    if (status != DBUS_DISPATCH_COMPLETE) {
        DEBUG(SSSDBG_TRACE_ALL, "Dispatching.\n");
        dbus_connection_dispatch(conn->connection);
    }

    /* If other dispatches are waiting, schedule next dispatch. */
    status = dbus_connection_get_dispatch_status(conn->connection);
    if (status != DBUS_DISPATCH_COMPLETE) {
        sbus_dispatch_schedule(conn, 0);
    }
}

static void
sbus_dispatch_schedule(struct sbus_connection *conn, uint32_t usecs)
{
    struct tevent_timer *te;
    struct timeval tv;

    tv = tevent_timeval_current_ofs(0, usecs);
    te = tevent_add_timer(conn->ev, conn, tv, sbus_dispatch, conn);
    if (te == NULL) {
        /* There is not enough memory to create a timer. We can't do
         * anything about it. */
        DEBUG(SSSDBG_OP_FAILURE, "Could not add dispatch event!\n");
    }
}

/**
 * This is called each time when D-Bus has data to dispatch available.
 * We create a timed event to avoid tevent request starving.
 */
static void
sbus_dispatch_wakeup(void *data)
{
    struct sbus_connection *conn;

    conn = talloc_get_type(data, struct sbus_connection);
    sbus_dispatch_schedule(conn, 0);
}

void sbus_dispatcher_setup(struct sbus_connection *conn)
{
    dbus_connection_set_wakeup_main_function(conn->connection,
                                             sbus_dispatch_wakeup,
                                             conn, NULL);
}

void sbus_dispatcher_disable(struct sbus_connection *conn)
{
    dbus_connection_set_wakeup_main_function(conn->connection,
                                             NULL, NULL, NULL);
}

void sbus_dispatch_now(struct sbus_connection *conn)
{
    sbus_dispatch_wakeup(conn);
}
