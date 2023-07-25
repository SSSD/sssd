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
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/connection/sbus_dbus_private.h"
#include "sbus/sbus_errors.h"
#include "sbus/sbus_message.h"
#include "sbus/sbus_sync.h"

struct sbus_sync_connection {
    DBusConnection *connection;
    bool disconnecting;
};

static int
sbus_sync_connection_destructor(struct sbus_sync_connection *sbus_conn)
{
    sbus_conn->disconnecting = true;
    dbus_connection_unref(sbus_conn->connection);

    return 0;
}

static struct sbus_sync_connection *
sbus_sync_connection_init(TALLOC_CTX *mem_ctx,
                          DBusConnection *dbus_conn)
{
    struct sbus_sync_connection *sbus_conn;

    sbus_conn = talloc_zero(mem_ctx, struct sbus_sync_connection);
    if (sbus_conn == NULL) {
        return NULL;
    }

    sbus_conn->connection = dbus_connection_ref(dbus_conn);

    talloc_set_destructor(sbus_conn, sbus_sync_connection_destructor);

    return sbus_conn;
}

struct sbus_sync_connection *
sbus_sync_connect_system(TALLOC_CTX *mem_ctx,
                         const char *dbus_name)
{
    struct sbus_sync_connection *sbus_conn;
    DBusConnection *dbus_conn;

    dbus_conn = sbus_dbus_connect_bus(DBUS_BUS_SYSTEM, dbus_name);
    if (dbus_conn == NULL) {
        return NULL;
    }

    sbus_conn = sbus_sync_connection_init(mem_ctx, dbus_conn);
    dbus_connection_unref(dbus_conn);
    if (sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create connection context!\n");
        return NULL;
    }

    return sbus_conn;
}

struct sbus_sync_connection *
sbus_sync_connect_private(TALLOC_CTX *mem_ctx,
                          const char *address,
                          const char *dbus_name)
{
    struct sbus_sync_connection *sbus_conn;
    DBusConnection *dbus_conn;

    dbus_conn = sbus_dbus_connect_address(address, dbus_name, true);
    if (dbus_conn == NULL) {
        return NULL;
    }

    sbus_conn = sbus_sync_connection_init(mem_ctx, dbus_conn);
    dbus_connection_unref(dbus_conn);
    if (sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create connection context!\n");
        return NULL;
    }

    return sbus_conn;
}

errno_t
sbus_sync_message_send(TALLOC_CTX *mem_ctx,
                       struct sbus_sync_connection *conn,
                       DBusMessage *msg,
                       int timeout_ms,
                       DBusMessage **_reply)
{
    DBusError dbus_error;
    DBusMessage *reply;
    errno_t ret;

    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: message is empty!\n");
        return EINVAL;
    }

    if (conn->disconnecting) {
        DEBUG(SSSDBG_TRACE_FUNC, "Connection is being disconnected\n");
        return ERR_TERMINATED;
    }

    if (_reply == NULL) {
        dbus_connection_send(conn->connection, msg, NULL);
        dbus_connection_flush(conn->connection);
        return EOK;
    }

    dbus_error_init(&dbus_error);
    reply = dbus_connection_send_with_reply_and_block(conn->connection, msg,
                                                      timeout_ms, &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        ret = sbus_error_to_errno(&dbus_error);
        goto done;
    } else if (reply == NULL) {
        ret = ERR_SBUS_NO_REPLY;
        goto done;
    }

    ret = sbus_reply_check(reply);
    if (ret != EOK) {
        goto done;
    }

    if (mem_ctx != NULL) {
        ret = sbus_message_bound(mem_ctx, reply);
        if (ret != EOK) {
            goto done;
        }
    }

    *_reply = reply;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error received [%d]: %s!\n",
              ret, sss_strerror(ret));
    }

    dbus_error_free(&dbus_error);

    return ret;
}

void sbus_sync_emit_signal(struct sbus_sync_connection *conn,
                           DBusMessage *msg)
{
    errno_t ret;

    ret = sbus_sync_message_send(NULL, conn, msg, SBUS_MESSAGE_TIMEOUT, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to emit signal [%d]: %s\n",
              ret, sss_strerror(ret));
    }
}
