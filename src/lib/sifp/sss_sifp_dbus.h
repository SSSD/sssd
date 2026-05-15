/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#ifndef SSS_SIFP_DBUS_H_
#define SSS_SIFP_DBUS_H_

#include <sss_sifp.h>
#include <dbus/dbus.h>

/**
 * @defgroup sss_sifp_dbus Advanced InfoPipe method calls.
 *
 * Functions in this module provide a way to reuse sss_sifp connection
 * to the SSSD's InfoPipe responder.
 *
 * This allows the caller to send more sophisticated messages to the InfoPipe
 * and to use both sss_sifp and D-Bus without the need of maintaining two
 * separate D-Bus connections.
 *
 * However, these functions require the caller to understand the D-Bus
 * bindings from libdbus.
 *
 * @{
 */

/**
 * @brief Create a new method call message for SSSD InfoPipe bus.
 *
 * @param[in] object_path D-Bus object path
 * @param[in] interface   D-Bus interface
 * @param[in] method      D-Bus method
 *
 * @return D-Bus message.
 */
DBusMessage *
sss_sifp_create_message(const char *object_path,
                        const char *interface,
                        const char *method);

/**
 * @brief Send D-Bus message to SSSD InfoPipe bus with 5 seconds timeout.
 *
 * @param[in] ctx    sss_sifp context
 * @param[in] msg    D-Bus message
 * @param[in] _reply D-Bus reply, may be NULL if the caller is not interested
 *
 * @return D-Bus message.
 */
sss_sifp_error
sss_sifp_send_message(sss_sifp_ctx *ctx,
                      DBusMessage *msg,
                      DBusMessage **_reply);

/**
 * @brief Send D-Bus message to SSSD InfoPipe bus.
 *
 * @param[in] ctx     sss_sifp context
 * @param[in] msg     D-Bus message
 * @param[in] timeout Timeout
 * @param[in] _reply D-Bus reply, may be NULL if the caller is not interested
 *
 * @return D-Bus message.
 */
sss_sifp_error
sss_sifp_send_message_ex(sss_sifp_ctx *ctx,
                         DBusMessage *msg,
                         int timeout,
                         DBusMessage **_reply);

/**
 * @brief List objects that satisfies given conditions. This routine will
 * invoke List<method> D-Bus method on given interface and object path. If
 * no interface or object path is given, /org/freedesktop/sssd/infopipe and
 * org.freedesktop.sssd.infopipe is used. Arguments to this method are given
 * as standard variadic D-Bus arguments.
 *
 * @param[in] ctx            sss_sifp context
 * @param[in] object_path    D-Bus object path
 * @param[in] interface      D-Bus interface
 * @param[in] method         D-Bus method to call without the 'List' prefix
 * @param[out] _object_paths List of object paths
 * @param[in] first_arg_type Type of the first D-Bus argument
 * @param[in] ...            D-Bus arguments
 */
sss_sifp_error
sss_sifp_invoke_list_ex(sss_sifp_ctx *ctx,
                        const char *object_path,
                        const char *interface,
                        const char *method,
                        char ***_object_paths,
                        int first_arg_type,
                        ...);

/**
 * @brief List objects that satisfies given conditions. This routine will
 * invoke List<method> D-Bus method on SSSD InfoPipe interface. Arguments
 * to this method are given as standard variadic D-Bus arguments.
 *
 * @param[in] ctx            sss_sifp context
 * @param[in] method         D-Bus method to call without the 'List' prefix
 * @param[out] _object_paths List of object paths
 * @param[in] first_arg_type Type of the first D-Bus argument
 * @param[in] ...            D-Bus arguments
 */
sss_sifp_error
sss_sifp_invoke_list(sss_sifp_ctx *ctx,
                     const char *method,
                     char ***_object_paths,
                     int first_arg_type,
                     ...);

/**
 * @brief Find single object that satisfies given conditions. This routine will
 * invoke Find<method> D-Bus method on given interface and object path. If
 * no interface or object path is given, /org/freedesktop/sssd/infopipe and
 * org.freedesktop.sssd.infopipe is used. Arguments to this method are given
 * as standard variadic D-Bus arguments.
 *
 * @param[in] ctx            sss_sifp context
 * @param[in] object_path    D-Bus object path
 * @param[in] interface      D-Bus interface
 * @param[in] method         D-Bus method to call without the 'Find' prefix
 * @param[out] _object_path  Object path
 * @param[in] first_arg_type Type of the first D-Bus argument
 * @param[in] ...            D-Bus arguments
 */
sss_sifp_error
sss_sifp_invoke_find_ex(sss_sifp_ctx *ctx,
                        const char *object_path,
                        const char *interface,
                        const char *method,
                        char **_object_path,
                        int first_arg_type,
                        ...);

/**
 * @brief Find single object that satisfies given conditions. This routine will
 * invoke Find<method> D-Bus method on SSSD InfoPipe interface. Arguments
 * to this method are given as standard variadic D-Bus arguments.
 *
 * @param[in] ctx            sss_sifp context
 * @param[in] method         D-Bus method to call without the 'Find' prefix
 * @param[out] _object_path  Object path
 * @param[in] first_arg_type Type of the first D-Bus argument
 * @param[in] ...            D-Bus arguments
 */
sss_sifp_error
sss_sifp_invoke_find(sss_sifp_ctx *ctx,
                     const char *method,
                     char **_object_path,
                     int first_arg_type,
                     ...);

/**
 * @}
 */
#endif /* SSS_SIFP_DBUS_H_ */
