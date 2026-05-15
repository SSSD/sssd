/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#ifndef _SBUS_SYNC_H_
#define _SBUS_SYNC_H_

#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_typeof.h"
#include "sbus/sbus_declarations.h"
#include "sbus/sbus_interface.h"
#include "sbus/sbus_request.h"
#include "sbus/sbus_errors.h"

struct sbus_sync_connection;

/**
 * Connect to D-Bus system bus, naming this end-point @dbus_name.
 *
 * @param mem_ctx                Memory context.
 * @param dbus_name              Name of this end-point.
 *
 * @return New synchronous sbus connection or NULL on error.
 */
struct sbus_sync_connection *
sbus_sync_connect_system(TALLOC_CTX *mem_ctx,
                         const char *dbus_name);

/**
 * Connect to a private D-Bus bus at @address.
 *
 * @param mem_ctx                Memory context.
 * @param address                Remote end-point address.
 * @param dbus_name              Name of this end-point.
 *
 * @return New synchronous sbus connection or NULL on error.
 */
struct sbus_sync_connection *
sbus_sync_connect_private(TALLOC_CTX *mem_ctx,
                          const char *address,
                          const char *dbus_name);

/**
 * Send a D-Bus message over a synchronous sbus connection.
 *
 * This call will block until a reply is received.
 *
 * @param mem_ctx       Memory context with which the reply will be bound.
 *                      If NULL, the reply is not bound with talloc context.
 * @param conn          Synchronous sbus connection.
 * @param msg           Message to be sent.
 * @param timeout_ms    Timeout is miliseconds.
 * @param _reply        Output reply. If NULL no reply is expected.
 *
 * @return EOK on success, other errno code on error.
 *
 * @see SBUS_MESSAGE_TIMEOUT
 */
errno_t
sbus_sync_message_send(TALLOC_CTX *mem_ctx,
                       struct sbus_sync_connection *conn,
                       DBusMessage *msg,
                       int timeout_ms,
                       DBusMessage **_reply);

/**
 * Emit signal on synchronous sbus connection.
 *
 * @param conn          Synchronous sbus connection.
 * @param msg           Message to be sent.
 */
void sbus_sync_emit_signal(struct sbus_sync_connection *conn,
                           DBusMessage *msg);

#endif /* _SBUS_SYNC_H_ */
