/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#ifndef SSSD_DBUS_UTILS_H_
#define SSSD_DBUS_UTILS_H_

errno_t sbus_talloc_bound_message(TALLOC_CTX *mem_ctx, DBusMessage *msg);
errno_t sbus_error_to_errno(DBusError *error);
errno_t sbus_check_reply(DBusMessage *reply);

/* Creates a DBusMessage from a vararg list. Please note that even though
 * this function and sbus_create_message accept a talloc memory context,
 * it is not valid to free the resulting message with talloc_free() directly.
 * Instead, either free the parent memory context or directly call
 * dbus_message_unref on the message if you pass NULL memory context to
 * these functions
 */
DBusMessage *sbus_create_message_valist(TALLOC_CTX *mem_ctx,
                                        const char *bus,
                                        const char *path,
                                        const char *iface,
                                        const char *method,
                                        int first_arg_type,
                                        va_list va);

DBusMessage *_sbus_create_message(TALLOC_CTX *mem_ctx,
                                  const char *bus,
                                  const char *path,
                                  const char *iface,
                                  const char *method,
                                  int first_arg_type,
                                  ...);

#define sbus_create_message(mem_ctx, bus, path, iface, method, ...) \
    _sbus_create_message(mem_ctx, bus, path, iface, method,         \
                         ##__VA_ARGS__, DBUS_TYPE_INVALID)

errno_t sbus_parse_message_valist(DBusMessage *msg,
                                  bool check_reply,
                                  int first_arg_type,
                                  va_list va);

errno_t _sbus_parse_message(DBusMessage *msg,
                            bool check_reply,
                            int first_arg_type,
                            ...);

#define sbus_parse_message(msg, ...) \
    _sbus_parse_message(msg, false, ##__VA_ARGS__, DBUS_TYPE_INVALID)

#define sbus_parse_reply(msg, ...) \
    _sbus_parse_message(msg, true, ##__VA_ARGS__, DBUS_TYPE_INVALID)

#endif /* SSSD_DBUS_UTILS_H_ */
