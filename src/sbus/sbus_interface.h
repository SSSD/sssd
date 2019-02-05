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

#ifndef _SBUS_INTERFACE_H_
#define _SBUS_INTERFACE_H_

#include "sbus/sbus_request.h"
#include "sbus/sbus_interface_declarations.h"

struct sbus_interface;
struct sbus_listener;
struct sbus_node;

/**
 * Indicate that the interface has no methods.
 */
#define SBUS_NO_METHODS SBUS_INTERFACE_SENTINEL

/**
 * Indicate that the interface has no signals.
 */
#define SBUS_NO_SIGNALS SBUS_INTERFACE_SENTINEL

/**
 * Indicate that the interface has no properties.
 */
#define SBUS_NO_PROPERTIES SBUS_INTERFACE_SENTINEL

/**
 * Add sbus methods into the interface. If the interface does not contain any
 * methods, please use SBUS_NO_METHODS or SBUS_WITHOUT_METHODS.
 *
 * @see SBUS_SYNC, SBUS_ASYNC, SBUS_NO_METHODS, SBUS_WITHOUT_METHODS
 *
 * The following examples demonstrate the intended usage of this macro.
 * Do not use it in any other way.
 *
 * @example Interface with two methods, one with synchronous handler,
 * one with asynchronous handler.
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         SBUS_METHODS(
 *             SBUS_SYNC (METHOD, org_freedekstop_sssd, UpdateMembers,
 *                       update_members_sync, pvt_data),
 *             SBUS_ASYNC(METHOD, org_freedekstop_sssd, UpdateMembersAsync,
 *                        update_members_send, update_members_recv,
 *                        pvt_data)
 *         ),
 *         @signals,
 *         @properties
 *     );
 *
 * @example Interface with no methods.
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         SBUS_METHODS(
 *             SBUS_NO_METHODS
 *         ),
 *         @signals,
 *         @properties
 *     );
 *
 *     or
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         SBUS_WITHOUT_METHODS,
 *         @signals,
 *         @properties
 *     );
 */
#define SBUS_METHODS(...)                                                     \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }

/**
 * Add sbus signals into the interface. If the interface does not contain any
 * signals, please use SBUS_NO_METHODS or SBUS_WITHOUT_METHODS.
 *
 * @see SBUS_EMIT, SBUS_NO_SIGNALS, SBUS_WITHOUT_SIGNALS
 *
 * The following examples demonstrate the intended usage of this macro.
 * Do not use it in any other way.
 *
 * @example Interface that can emit a PropertyChanged signal.
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         @methods,
 *         SBUS_SIGNALS(
 *             SBUS_EMIT(org_freedekstop_sssd, PropertyChanged)
 *         ),
 *         @properties
 *     );
 *
 * @example Interface with no signals.
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         @methods,
 *         SBUS_SIGNALS(
 *             SBUS_NO_SIGNALS
 *         ),
 *         @properties
 *     );
 *
 *     or
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         @methods,
 *         SBUS_WITHOUT_SIGNALS,
 *         @properties
 *     );
 */
#define SBUS_SIGNALS(...)                                                     \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }

/**
 * Add sbus properties into the interface. If the interface does not contain any
 * property, please use SBUS_NO_PROPERTIES or SBUS_WITHOUT_PROPERTIES.
 *
 * @see SBUS_SYNC, SBUS_ASYNC, SBUS_NO_PROPERTIES, SBUS_WITHOUT_PROPERTIES
 *
 * The following examples demonstrate the intended usage of this macro.
 * Do not use it in any other way.
 *
 * @example Interface with one property with asynchronous getter and
 * synchronous setter.
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         @methods,
 *         @signals,
 *         SBUS_PROPERTIES(
 *             SBUS_SYNC (GETTER, org_freedekstop_sssd, domain_name,
 *                        set_domain_name, pvt_data),
 *             SBUS_ASYNC(GETTER, org_freedekstop_sssd, domain_name,
 *                        get_domain_name_send, get_domain_name_recv,
 *                        pvt_data)
 *         )
 *     );
 *
 * @example Interface with no properties.
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         @methods,
 *         @signals,
 *         SBUS_PROPERTIES(
 *             SBUS_NO_PROPERTIES
 *         )
 *     );
 *
 *     or
 *
 *     SBUS_INTERFACE(
 *         iface_variable,
 *         org_freedesktop_sssd,
 *         @methods,
 *         @signals,
 *         SBUS_WITHOUT_PROPERTIES
 *     );
 */
#define SBUS_PROPERTIES(...)                                                  \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }

/**
 * Create list of sbus signal listeners. You can register more than one
 * handler for a single signal.
 *
 * @see SBUS_LISTEN_SYNC, SBUS_LISTEN_ASYNC
 *
 * @example Listen to two signal -- PropertyChanged and DomainEnabled.
 *
 *     struct sbus_listener listeners[] = SBUS_LISTENERS(
 *         SBUS_LISTEN_SYNC (org_freedesktop_sssd, PropertyChanged,
 *                           "/org/freedesktop/sssd/User1",
 *                           on_propert_changed, pvt_data)
 *         SBUS_LISTEN_ASYNC(org_freedesktop_sssd, DomainEnabled,
 *                           "/org/freedesktop/sssd/ad@pb",
 *                           on_domain_enabled_send,
 *                           on_domain_enabled_recv,
 *                           pvt_data)
 *     );
 */
#define SBUS_LISTENERS(...)                                                   \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }

/**
 * Create list of sbus nodes.
 *
 * @see SBUS_NODE_SYNC, SBUS_NODE_ASYNC
 *
 * @example Users node with a factory method that will list all the users.
 *
 *     struct sbus_node nodes[] = SBUS_NODES(
 *         SBUS_NODE_SYNC("/org/freedesktop/sssd/Users",
 *                        list_of_users, pvt_data)
 *     );
 */
#define SBUS_NODES(...)                                                       \
    {                                                                         \
        __VA_ARGS__,                                                          \
        SBUS_INTERFACE_SENTINEL                                               \
    }

/**
 * Indicate that the interface has no methods.
 */
#define SBUS_WITHOUT_METHODS                                                  \
    SBUS_METHODS(SBUS_NO_METHODS)

/**
 * Indicate that the interface has no signals.
 */
#define SBUS_WITHOUT_SIGNALS                                                  \
    SBUS_SIGNALS(SBUS_NO_SIGNALS)

/**
 * Indicate that the interface has no properties.
 */
#define SBUS_WITHOUT_PROPERTIES                                               \
    SBUS_PROPERTIES(SBUS_NO_PROPERTIES)

/**
 * Create and sbus interface.
 *
 * @param varname      Name of the variable that will hold the interface
 *                     description. It is created as:
 *                       struct sbus_interface varname;
 *                     You can refer to it later when creating 'sbus_path'
 *                     structure as &varname.
 * @param iface        Name of the interface with dots replaced
 *                     with underscore. (token, not a string)
 * @param methods      Methods on the interface.
 * @param signals      Signals on the interface.
 * @param properties   Properties on the interface.
 *
 * Please note that the following macro introduced to the scope these variables:
 *   - __varname_m
 *   - __varname_s
 *   - __varname_p
 *
 * These variables are intended for internal purpose only and should not be
 * used outside this macro. They are allocated on stack and will be destroyed
 * with it.
 *
 * Additionally, it creates 'struct sbus_interface varname'. This variable
 * holds the information about the interfaces you created. The structure and
 * all its data are allocated on stack and will be destroyed with it.
 *
 * The only intended usage of this variable is to assign it to an sbus path
 * and then register this path inside the same function where the interface
 * is defined. It should not be used in any other way.
 *
 * The following example demonstrates the intended usage of this macro.
 * Do not use it in any other way.
 *
 * @example
 *     SBUS_INTERFACE(
 *         iface_bus,
 *         org_freedesktop_DBus,
 *         SBUS_METHODS(
 *             SBUS_SYNC(METHOD, org_freedesktop_DBus, Hello, sbus_server_bus_hello, server),
 *             SBUS_SYNC(METHOD, org_freedesktop_DBus, RequestName, sbus_server_bus_request_name, server),
 *         ),
 *         SBUS_SIGNALS(
 *             SBUS_EMITS(org_freedesktop_DBus, NameOwnerChanged),
 *             SBUS_EMITS(org_freedesktop_DBus, NameAcquired),
 *             SBUS_EMITS(org_freedesktop_DBus, NameLost)
 *         ),
 *         SBUS_WITHOUT_PROPERTIES
 *     );
 *
 *     struct sbus_path paths[] = {
 *          {"/org/freedesktop/dbus", &iface_bus},
 *          {NULL, NULL}
 *     };
 *
 *     ret = sbus_router_add_path_map(server->router, paths);
 *     if (ret != EOK) {
 *         DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add paths [%d]: %s\n",
 *               ret, sss_strerror(ret));
 *         return ret;
 *     }
 *
 * @see SBUS_METHODS, SBUS_SIGNALS, SBUS_PROPERTIES to create those arguments.
 */
#define SBUS_INTERFACE(varname, iface, methods, signals, properties)          \
    const struct sbus_method __ ## varname ## _m[] = methods;                 \
    const struct sbus_signal __ ## varname ## _s[] = signals;                 \
    const struct sbus_property __ ## varname ## _p[] = properties;            \
    struct sbus_interface varname = SBUS_IFACE_ ## iface(                     \
        (__ ## varname ## _m),                                                \
        (__ ## varname ## _s),                                                \
        (__ ## varname ## _p)                                                 \
    )

/**
 * Create a new sbus synchronous handler.
 *
 * @param type         Handler type. One of:
 *                     METHOD, GETTER, SETTER.
 * @param iface        Name of the interface with dots replaced
 *                     with underscore. (token, not a string)
 * @param name         Name of the sbus method, property (token, not a string).
 * @param handler      Synchronous handler.
 * @param data         Private data that are passed to the handler.
 *
 * Synchronous handler type is:
 * errno_t handler(TALLOC_CTX *mem_ctx,
 *                 struct sbus_request *sbus_req,
 *                 data_type private_data,
 *                 input parameters,
 *                 output parameters)
 *
 * @example
 *     SBUS_SYNC(SETTER, org_freedesktop_sssd, name, setter_name, pvt_data)
 *
 * @see SBUS_ASYNC
 */
#define SBUS_SYNC(type, iface, method, handler, data)                         \
    SBUS_ ## type ## _SYNC_ ## iface ## _ ## method(handler, data)

/**
 * Create a new sbus asynchronous handler.
 *
 * @param type         Handler type. One of:
 *                     METHOD, GETTER, SETTER.
 * @param iface        Name of the interface with dots replaced
 *                     with underscore. (token, not a string)
 * @param name         Name of the sbus method, property (token, not a string).
 * @param handler_send Handler for _send tevent function.
 * @param handler_recv Handler for _recv tevent function.
 * @param data         Private data that are passed to the handler.
 *
 * Asynchronous handler type is:
 * struct tevent_req * _send(TALLOC_CTX *mem_ctx,
 *                           struct tevent_context *ev,
 *                           struct sbus_request *sbus_req,
 *                           data_type private_data,
 *                           input parameters)
 *
 * errno_t _recv(TALLOC_CTX *mem_ctx,
 *               struct tevent_req *req,
 *               output parameters)
 *
 * @example
 *     SBUS_ASYNC(SETTER, org_freedesktop_sssd, name,
*                 setter_name_send,
 *                setter_name_recv,
 *                pvt_data)
 *
 * @see SBUS_SYNC
 */
#define SBUS_ASYNC(type, iface, property, handler_send, handler_recv, data)   \
    SBUS_ ## type ## _ASYNC_ ## iface ## _ ## property(handler_send, handler_recv, data)

/**
 * Create a new sbus listener with synchronous handler.
 *
 * @param iface        Name of the interface with dots replaced
 *                     with underscore. (token, not a string)
 * @param name         Name of the sbus signal (token, not a string).
 * @param path         Object path to listen at. May be NULL.
 * @param handler      Synchronous handler.
 * @param data         Private data that are passed to the handler.
 *
 * Synchronous handler type for signal listener is:
 * errno_t handler(TALLOC_CTX *mem_ctx,
 *                 struct sbus_request *sbus_req,
 *                 data_type private_data,
 *                 input parameters)
 *
 * @example
 *     SBUS_LISTEN_SYNC(org_freedesktop_sssd, PropertyChanged,
 *                      "/org/freedesktop/sssd/User1",
 *                      signal_handler, pvt_data)
 *
 * @see SBUS_LISTENERS, SBUS_LISTEN_ASYNC
 */
#define SBUS_LISTEN_SYNC(iface, signal, path, handler, data)                  \
    SBUS_SIGNAL_SYNC_ ## iface ## _ ## signal(path, handler, data)

/**
 * Create a new sbus listener with asynchronous handler
 *
 * @param iface        Name of the interface with dots replaced
 *                     with underscore. (token, not a string)
 * @param name         Name of the sbus signal (token, not a string).
 * @param path         Object path to listen at. May be NULL.
 * @param handler_send Handler for _send tevent function.
 * @param handler_recv Handler for _recv tevent function.
 * @param data         Private data that are passed to the handler.
 *
 * Asynchronous handler type for signal listener is:
 * struct tevent_req * _send(TALLOC_CTX *mem_ctx,
 *                           struct tevent_context *ev,
 *                           struct sbus_request *sbus_req,
 *                           data_type private_data,
 *                           input parameters)
 *
 * errno_t _recv(TALLOC_CTX *mem_ctx, struct tevent_req *req)
 *
 * @example
 *     SBUS_LISTEN_ASYNC(org_freedesktop_sssd, PropertyChanged,
 *                       "/org/freedesktop/sssd/User1",
 *                       on_property_changed_send,
 *                       on_property_changed_recv,
 *                       pvt_data)
 *
 * @see SBUS_LISTENERS, SBUS_LISTEN_SYNC
 */
#define SBUS_LISTEN_ASYNC(iface, property, path, handler_send, handler_recv, data)   \
    SBUS_SIGNAL_ASYNC_ ## iface ## _ ## property(path, handler_send, handler_recv, data)

/**
 * Add a signal that can be emitted into the sbus interface.
 *
 * @param iface        Name of the interface with dots replaced
 *                     with underscore. (token, not a string)
 * @param signal       Signal name (token, not a string).
 *
 * @example
 *     SBUS_SIGNAL(org_freedesktop_sssd, PropertyChanged)
 *
 * @see SBUS_SIGNALS, SBUS_NO_SIGNALS
 */
#define SBUS_EMITS(iface, signal)                                             \
    SBUS_SIGNAL_EMITS_ ## iface ## _ ## signal()

/**
 * Create a new sbus node with a synchronous node factory.
 *
 * @param path         Node's object path.
 * @param factory      Synchronous factory function.
 * @param data         Private data that are passed to the factory function.
 *
 * Synchronous handler type for node factory is:
 * errno_t factory(TALLOC_CTX *mem_ctx,
 *                 const char *object_path,
 *                 data_type pvt_data,
 *                 const char ***_nodes)
 *
 * @example
 *     SBUS_NODE_SYNC(/org/freedesktop/sssd/Users",
 *                    list_of_users, pvt_data)
 *
 * @see SBUS_NODES, SBUS_NODE_ASYNC
 */
#define SBUS_NODE_SYNC(path, factory, data)                                   \
    _SBUS_NODE_SYNC(path, factory, data)

/**
 * Create a new sbus node with an asynchronous node factory.
 *
 * @param path         Node's object path.
 * @param factory_send Factory function for _send tevent function.
 * @param factory_recv Factory function for _recv tevent function.
 * @param data         Private data that are passed to the factory function.
 *
 * Asynchronous handler type for signal listener is:
 * struct tevent_req *send(TALLOC_CTX *mem_ctx,
 *                         struct tevent_context *ev,
 *                         const char *object_path,
 *                         data_type pvt_data)
 *
 * errno_t recv(TALLOC_CTX *mem_ctx,
 *              struct tevent_req *req,
 *              const char ***_nodes)
 *
 * @example
 *     SBUS_NODE_ASYNC("/org/freedesktop/sssd/Users",
 *                     list_users_send,
 *                     list_users_recv,
 *                     pvt_data)
 *
 * @see SBUS_NODES, SBUS_NODE_SYNC
 */
#define SBUS_NODE_ASYNC(path, factory_send, factory_recv, data)               \
    _SBUS_NODE_ASYNC(path, handler_send, factory_recv, data)

#endif /* _SBUS_INTERFACE_H_ */
