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
#include "sbus/sbus_private.h"
#include "sbus/connection/sbus_dbus_private.h"

struct sbus_reconnect {
    bool enabled;

    struct {
        unsigned int current;
        unsigned int max;
    } retry;

    sbus_reconnect_cb callback;
    sbus_reconnect_data data;
};

static void
sbus_reconnect_notify(struct sbus_connection *conn,
                      enum sbus_reconnect_status status)
{
    if (conn->reconnect->callback == NULL) {
        return;
    }

    conn->reconnect->callback(conn, status, conn->reconnect->data);
}

static void
sbus_reconnect_success(struct sbus_connection *conn)
{
    conn->reconnect->retry.current = 0;
    DEBUG(SSSDBG_MINOR_FAILURE, "Reconnection successful.\n");
    sbus_reconnect_notify(conn, SBUS_RECONNECT_SUCCESS);
}

static void
sbus_reconnect_attempt(struct tevent_context *ev,
                       struct tevent_timer *te,
                       struct timeval tv,
                       void *data)
{
    struct sbus_connection *sbus_conn;
    DBusConnection *dbus_conn = NULL;
    errno_t ret;

    sbus_conn = talloc_get_type(data, struct sbus_connection);

    /* Do not try to reconnect if the connection is being disconnected. */
    if (sbus_conn->disconnecting) {
        return;
    }

    /* Obtain new connection. */
    switch (sbus_conn->type) {
    case SBUS_CONNECTION_CLIENT:
        /* We can't really reconnect to a client. There is nothing to do. */
        DEBUG(SSSDBG_OP_FAILURE, "We can't reconnect to the client!\n");
        return;
    case SBUS_CONNECTION_ADDRESS:
        DEBUG(SSSDBG_MINOR_FAILURE, "Making reconnection attempt %d to [%s]\n",
              sbus_conn->reconnect->retry.current, sbus_conn->address);
        /* It is necessary to use blocking Hello and RequestName method
         * so those two are the only methods that are sent to the new
         * dbus connection before it is properly initialized.
         */
        dbus_conn = sbus_dbus_connect_address(sbus_conn->address,
                                              sbus_conn->wellknown_name,
                                              true);
        break;
    case SBUS_CONNECTION_SYSBUS:
        DEBUG(SSSDBG_MINOR_FAILURE, "Making reconnection attempt %d "
              "to system bus\n", sbus_conn->reconnect->retry.current);
        dbus_conn = sbus_dbus_connect_bus(DBUS_BUS_SYSTEM,
                                          sbus_conn->wellknown_name);
        break;
    }

    if (dbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to D-Bus\n");
        ret = EIO;
        goto done;
    }

    /* Replace old connection with newly created. */
    ret = sbus_connection_replace(sbus_conn, dbus_conn);
    dbus_connection_unref(dbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to replace D-Bus connection\n");
        goto done;
    }

    ret = EOK;

done:
    /* Issue next attempt or finish. */
    if (ret != EOK) {
        sbus_reconnect(sbus_conn);
        return;
    }

    sbus_reconnect_success(sbus_conn);
}

static struct timeval
sbus_reconnect_delay(struct sbus_reconnect *reconnect)
{
    unsigned int delay;

    /* Calculate how many seconds should we wait
     * before new reconnection attempt. */
    switch (reconnect->retry.current) {
    case 1:
        delay = 1;
        break;
    case 2:
        delay = 3;
        break;
    case 3:
        delay = 10;
        break;
    default:
        delay = 30;
        break;
    }

    return tevent_timeval_current_ofs(delay, 0);
}

void sbus_reconnect(struct sbus_connection *conn)
{
    struct sbus_reconnect *reconnect = conn->reconnect;
    struct tevent_timer *te;
    struct timeval tv;

    /* Do not try to reconnect if the connection is being disconnected. */
    if (conn->disconnecting) {
        return;
    }

    if (dbus_connection_get_is_connected(conn->connection)) {
        DEBUG(SSSDBG_TRACE_FUNC, "Already connected!\n");
        return;
    }

    if (!sbus_reconnect_enabled(conn)) {
        DEBUG(SSSDBG_TRACE_FUNC, "We are not allowed to reconnect!\n");
        return;
    }

    /* Remove tevent integration since the connection is dropped, we have
     * nothing to listen to. */
    sbus_connection_tevent_disable(conn);

    /* Increase retry counter and check if we are still allowed to reconnect. */
    reconnect->retry.current++;

    if (reconnect->retry.current > reconnect->retry.max) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to reconnect: maximum retries exceeded.\n");
        sbus_reconnect_notify(conn, SBUS_RECONNECT_EXCEEDED_RETRIES);
        return;
    }

    tv = sbus_reconnect_delay(reconnect);
    te = tevent_add_timer(conn->ev, conn, tv, sbus_reconnect_attempt, conn);
    if (te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to reconnect: cannot create timed event.\n");
        sbus_reconnect_notify(conn, SBUS_RECONNECT_ERROR);
        return;
    }

    return;
}

struct sbus_reconnect *
sbus_reconnect_init(TALLOC_CTX *mem_ctx)
{
    return talloc_zero(mem_ctx, struct sbus_reconnect);
}

void _sbus_reconnect_enable(struct sbus_connection *conn,
                            unsigned int max_retries,
                            sbus_reconnect_cb callback,
                            sbus_reconnect_data callback_data)
{
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: connection is NULL\n");
        return;
    }

    if (sbus_reconnect_enabled(conn)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: reconnection is already enabled\n");
        return;
    }

    conn->reconnect->enabled = true;
    conn->reconnect->callback = callback;
    conn->reconnect->data = callback_data;
    conn->reconnect->retry.max = max_retries;
    conn->reconnect->retry.current = 0;
}

void sbus_reconnect_disable(struct sbus_connection *conn)
{
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: connection is NULL\n");
        return;
    }

    conn->reconnect->enabled = false;
}

bool sbus_reconnect_in_progress(struct sbus_connection *conn)
{
    return conn->reconnect->retry.current != 0;
}

bool sbus_reconnect_enabled(struct sbus_connection *conn)
{
    return conn->reconnect->enabled;
}
