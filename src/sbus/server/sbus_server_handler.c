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
#include <string.h>
#include <tevent.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "sbus/sbus_private.h"

static DBusHandlerResult
sbus_server_resend_message(struct sbus_server *server,
                           struct sbus_connection *conn,
                           DBusMessage *message,
                           const char *destination)
{
    struct sbus_connection *destconn;

    destconn = sbus_server_find_connection(server, destination);
    if (destconn == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Trying to send a message to an unknown "
              "destination: %s\n", destination);
        sbus_reply_error(conn, message, DBUS_ERROR_SERVICE_UNKNOWN, destination);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    /* Message is unreferenced by libdbus. */
    dbus_connection_send(destconn->connection, message, NULL);
    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult
sbus_server_route_signal(struct sbus_server *server,
                         struct sbus_connection *conn,
                         DBusMessage *message,
                         const char *destination)
{
    errno_t ret;

    /* If a destination is set (unusual but possible) we simply send the
     * signal to its desired destination. */
    if (destination != NULL) {
        return sbus_server_resend_message(server, conn, message, destination);
    }

    /* Otherwise we need to send it to all connections that listen to it. */
    ret = sbus_server_matchmaker(server, conn, NULL, message);
    if (ret == EOK) {
        return DBUS_HANDLER_RESULT_HANDLED;
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send signal [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
sbus_server_route_message(struct sbus_server *server,
                          struct sbus_connection *conn,
                          DBusMessage *message,
                          const char *destination)
{
    if (strcmp(destination, DBUS_SERVICE_DBUS) == 0) {
        /* This message is addressed to D-Bus service. We must reply to it. */
        return sbus_router_filter(conn, server->router, message);
    }

    return sbus_server_resend_message(server, conn, message, destination);
}

static bool
sbus_server_check_access(struct sbus_connection *conn,
                         DBusMessage *message)
{
    const char *destination;
    const char *interface;
    const char *member;
    int type;

    /* Connection must first obtain its unique name through Hello method. */
    if (conn->unique_name != NULL) {
        return true;
    }

    destination = dbus_message_get_destination(message);
    interface = dbus_message_get_interface(message);
    member = dbus_message_get_member(message);
    type = dbus_message_get_type(message);

    if (type != DBUS_MESSAGE_TYPE_METHOD_CALL) {
        return false;
    }

    if (strcmp(destination, DBUS_SERVICE_DBUS) != 0) {
        return false;
    }

    if (strcmp(interface, DBUS_INTERFACE_DBUS) != 0) {
        return false;
    }

    if (strcmp(member, "Hello") != 0) {
        return false;
    }

    return true;
}

DBusHandlerResult
sbus_server_filter(DBusConnection *dbus_conn,
                   DBusMessage *message,
                   void *handler_data)
{
    struct sbus_server *server;
    struct sbus_connection *conn;
    const char *destination;
    const char *sender;
    dbus_bool_t dbret;
    int type;

    server = talloc_get_type(handler_data, struct sbus_server);

    /* We can't really send signals when the server is being destroyed. */
    if (server == NULL || server->disconnecting) {
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    conn = dbus_connection_get_data(dbus_conn, server->data_slot);
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown connection!\n");
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    if (!sbus_server_check_access(conn, message)) {
        sbus_reply_error(conn, message, DBUS_ERROR_ACCESS_DENIED,
                         "Connection did not call org.freedesktop.DBus.Hello");
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    /* We always require a sender but it may not be assigned yet. We prefer
     * well known name if set. */
    sender = sbus_connection_get_name(conn);
    dbret = dbus_message_set_sender(message, sender);
    if (!dbret) {
        sbus_reply_error(conn, message, DBUS_ERROR_FAILED,
                         "Unable to set sender");
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    /* Set sender may reallocate internal fields so this needs to be read
     * after we call dbus_message_set_sender(). */
    destination = dbus_message_get_destination(message);
    type = dbus_message_get_type(message);

    if (type == DBUS_MESSAGE_TYPE_SIGNAL) {
        return sbus_server_route_signal(server, conn, message, destination);
    }

    /* We do not allow method calls without destination. */
    if (destination == NULL) {
        sbus_reply_error(conn, message, DBUS_ERROR_FAILED,
                         "Non-signal multicast calls are not supported");
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return sbus_server_route_message(server, conn, message, destination);
}
