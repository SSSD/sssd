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

#ifndef _SBUS_MESSAGE_H_
#define _SBUS_MESSAGE_H_

#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_errors.h"

/* Use longer default timeout than libdbus default due to expensive
 * selinux operation: see https://bugzilla.redhat.com/show_bug.cgi?id=1654537
 */
#define SBUS_MESSAGE_TIMEOUT 120000

/**
 * Bound message with a talloc context.
 *
 * The message is unreferenced when the talloc context is freed or when
 * the message is unreferenced with dbus_message_unref.
 *
 * @param mem_ctx Memory context to bound the message with. It can not be NULL.
 * @param msg     Message to be bound with memory context.
 *
 * @return EOK on success, other errno code on error.
 */
errno_t
sbus_message_bound(TALLOC_CTX *mem_ctx, DBusMessage *msg);

/**
 * Steal previously bound D-Bus message to a new talloc parent.
 *
 * @param mem_ctx Memory context to bound the message with. It can not be NULL.
 * @param msg     Message to be bound with memory context.
 *
 * @return EOK on success, other errno code on error.
 */
errno_t
sbus_message_bound_steal(TALLOC_CTX *mem_ctx, DBusMessage *msg);

/**
 * Create an empty D-Bus method call.
 *
 * @param bus    Destination bus name.
 * @param path   Object path on which the method should be executed.
 * @param iface  Interface name.
 * @param method Method name.
 *
 * @return D-Bus message.
 */
DBusMessage *
sbus_method_create_empty(TALLOC_CTX *mem_ctx,
                         const char *bus,
                         const char *path,
                         const char *iface,
                         const char *method);

/* @see sbus_method_create */
DBusMessage *
_sbus_method_create(TALLOC_CTX *mem_ctx,
                    const char *bus,
                    const char *path,
                    const char *iface,
                    const char *method,
                    int first_arg_type,
                    ...);

/**
 * Create a new D-Bus method call and append some arguments to it.
 *
 * See dbus_message_append_args to see the argument format.
 *
 * @param bus    Destination bus name.
 * @param path   Object path on which the method should be executed.
 * @param iface  Interface name.
 * @param method Method name.
 * @param ...    Argument tuples.
 *
 * @return D-Bus message.
 */
#define sbus_method_create(mem_ctx, bus, path, iface, method, ...) \
    _sbus_method_create(mem_ctx, bus, path, iface, method,         \
                        ##__VA_ARGS__, DBUS_TYPE_INVALID)

/**
 * Create an empty D-Bus signal call.
 *
 * @param path    Object path on which the method should be executed.
 * @param iface   Interface name.
 * @param signame Signal name.
 *
 * @return D-Bus message.
 */
DBusMessage *
sbus_signal_create_empty(TALLOC_CTX *mem_ctx,
                         const char *path,
                         const char *iface,
                         const char *signame);

/* @see sbus_signal_create */
DBusMessage *
_sbus_signal_create(TALLOC_CTX *mem_ctx,
                    const char *path,
                    const char *iface,
                    const char *signame,
                    int first_arg_type,
                    ...);

/**
 * Create a new D-Bus signal call and append some arguments to it.
 *
 * See dbus_message_append_args to see the argument format.
 *
 * @param path    Object path on which the method should be executed.
 * @param iface   Interface name.
 * @param signame Signal name.
 * @param ...     Argument tuples.
 *
 * @return D-Bus message.
 */
#define sbus_signal_create(mem_ctx, path, iface, signame, ...) \
    _sbus_signal_create(mem_ctx, path, iface, signame,         \
                        ##__VA_ARGS__, DBUS_TYPE_INVALID)

/* @see sbus_reply_parse */
errno_t
_sbus_reply_parse(DBusMessage *msg,
                  int first_arg_type,
                  ...);

/**
 * Check a method call reply and parse it into output arguments if successful.
 *
 * See dbus_message_get_args to see the argument format.
 *
 * @param msg    Method call reply.
 * @param ...    Argument tuples.
 *
 * @return EOK on success, other errno code on failure.
 */
#define sbus_reply_parse(msg, ...) \
    _sbus_reply_parse(msg, ##__VA_ARGS__, DBUS_TYPE_INVALID)

/**
 * Check if the method call was successful or if it replied with an error
 * message. If it is an error message, the return value will be errno code
 * equivalent to the error.
 *
 * @param reply Method call reply.
 *
 * @return EOK on success, other errno code on failure.
 */
errno_t
sbus_reply_check(DBusMessage *reply);

#endif /* _SBUS_MESSAGE_H_ */
