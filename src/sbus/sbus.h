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

#ifndef _SBUS_H_
#define _SBUS_H_

#include <dhash.h>
#include <talloc.h>
#include <tevent.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_typeof.h"
#include "sbus/sbus_declarations.h"
#include "sbus/sbus_interface.h"
#include "sbus/sbus_request.h"
#include "sbus/sbus_errors.h"

struct sbus_listener;
struct sbus_connection;
struct sbus_server;
struct sbus_node;

/**
 * Connect to D-Bus system bus, naming this end-point @dbus_name.
 *
 * If @last_activity_time pointer is given, it is updated with current time
 * each time an important event (such as method or property call) on the bus
 * occurs. It is not updated when an signal arrives.
 *
 * @param mem_ctx                Memory context.
 * @param ev                     Tevent context.
 * @param dbus_name              Name of this end-point.
 * @param last_activity_time     Pointer to a time that is updated each time
 *                               an event occurs.
 *
 * @return New sbus connection or NULL on error.
 */
struct sbus_connection *
sbus_connect_system(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    const char *dbus_name,
                    time_t *last_activity_time);

/**
 * Connect to a private D-Bus bus at @address.
 *
 * If @last_activity_time pointer is given, it is updated with current time
 * each time an important event (such as method or property call) on the bus
 * occurs. It is not updated when an signal arrives.
 *
 * @param mem_ctx                Memory context.
 * @param ev                     Tevent context.
 * @param address                Remote end-point address.
 * @param dbus_name              Name of this end-point.
 * @param last_activity_time     Pointer to a time that is updated each time
 *                               an event occurs.
 *
 * @return New sbus connection or NULL on error.
 *
 * @see sbus_server_create
 */
struct sbus_connection *
sbus_connect_private(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     const char *address,
                     const char *dbus_name,
                     time_t *last_activity_time);

/**
 * Create a new sbus server at socket address @address.
 *
 * @param mem_ctx                Memory context.
 * @param ev                     Tevent context.
 * @param address                Socket address.
 * @param use_symlink            If a symlink to @address should be created.
 * @param on_conn_cb             On new connection callback function.
 * @param on_conn_data           Private data passed to the callback.
 *
 * @return New sbus server or NULL on error.
 */
struct sbus_server *
sbus_server_create(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   const char *address,
                   bool use_symlink,
                   uint32_t max_connections,
                   sbus_server_on_connection_cb on_conn_cb,
                   sbus_server_on_connection_data on_conn_data);

/**
 * Create a new sbus server at socket address @address and connect to it.
 *
 * @param mem_ctx                Memory context.
 * @param ev                     Tevent context.
 * @param dbus_name              Name of the connection.
 * @param last_activity_time     Pointer to a time that is updated each time
 *                               an event occurs on connection.
 * @param address                Socket address.
 * @param use_symlink            If a symlink to @address should be created.
 * @param on_conn_cb             On new connection callback function.
 * @param on_conn_data           Private data passed to the callback.
 *
 * @return Tevent request or NULL on error.
 */
struct tevent_req *
sbus_server_create_and_connect_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    const char *dbus_name,
                                    time_t *last_activity_time,
                                    const char *address,
                                    bool use_symlink,
                                    uint32_t max_connections,
                                    sbus_server_on_connection_cb on_conn_cb,
                                    sbus_server_on_connection_data on_conn_data);

/**
 * Receive reply from @sbus_server_create_and_connect_send.
 *
 * @param mem_ctx                Memory context.
 * @param req                    Tevent request.
 * @param _server                Created sbus server.
 * @param _conn                  Established sbus connection.
 *
 * @return EOK on success, other errno code on failure.
 *
 * @see sbus_server_create_and_connect_send
 */
errno_t
sbus_server_create_and_connect_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct sbus_server **_server,
                                    struct sbus_connection **_conn);

/**
 * Find active sbus connection by its name.
 *
 * @param server An sbus server.
 * @param name   Connection unique or well-known name.
 *
 * @return The sbus connection associated with name or NULL if not found.
 */
struct sbus_connection *
sbus_server_find_connection(struct sbus_server *server, const char *name);

/**
 * Set server callback that is run everytime a new connection is established
 * with the server.
 *
 * Callback is of type:
 * errno_t callback(struct sbus_connection *conn,
 *                  data_type *data)
 *
 * where @conn is the newly established sbus connection. If other error code
 * than EOK is returned by the callback, the connection is killed.
 *
 * @param server        An sbus server.
 * @param callback      Callback function.
 * @param data          Private data passed to the callback.
 */
#define sbus_server_set_on_connection(server, callback, data) do {            \
    SBUS_CHECK_FUNCTION(callback, errno_t,                                    \
                        struct sbus_connection *,                             \
                        SBUS_TYPEOF(data));                                   \
    _sbus_server_set_on_connection((server), #callback,                       \
        (sbus_server_on_connection_cb)callback,                               \
        (sbus_server_on_connection_data)data);                                \
} while(0)

/**
 * Set custom destructor on an sbus connection.
 *
 * This destructor is called when a connection is being freed after it
 * is finalized. It is not allowed to use further manipulate with this
 * connection within the destructor.
 *
 * Destructor is of type:
 * void my_destructor(data_type *data)
 *
 * @param conn          An sbus connection.
 * @param destructor    Destructor function.
 * @param data          Private data passed to the destructor.
 */
#define sbus_connection_set_destructor(conn, destructor, data) do {           \
    SBUS_CHECK_FUNCTION(destructor, void, SBUS_TYPEOF(data));                 \
    _sbus_connection_set_destructor((conn), #destructor,                      \
        (sbus_connection_destructor_fn)destructor,                            \
        (sbus_connection_destructor_data)data);                               \
} while(0)

/**
 * Set custom access check function on an sbus connection.
 *
 * This function is called on each incoming sbus request to check whether
 * the caller has enough permissions to run such request.
 *
 * Access check function is of type:
 * errno_t my_access_check(struct sbus_request *sbus_request, data_type *data)
 *
 * The function shall return EOK if access is granted, EPERM if access is
 * denied and other errno code on error.
 *
 * @param conn          An sbus connection.
 * @param check_fn      Access check function.
 * @param data          Private data passed to the access check function.
 */
#define sbus_connection_set_access_check(conn, check_fn, data) do {           \
    SBUS_CHECK_FUNCTION(check_fn, errno_t,                                    \
                        struct sbus_request *,                                \
                        SBUS_TYPEOF(data));                                   \
    _sbus_connection_set_access_check((conn), #check_fn,                      \
        (sbus_connection_access_check_fn)check_fn,                            \
        (sbus_connection_access_check_data)data);                             \
} while(0)

/**
 * Set connection private data.
 *
 * @param conn          An sbus connection.
 * @param data          Private data.
 */
void sbus_connection_set_data(struct sbus_connection *conn,
                              void *data);

/**
 * Retrieve connection private data.
 *
 * @param conn          An sbus connection.
 * @param type          Private data type.
 */
#define sbus_connection_get_data(conn, type) \
    talloc_get_type(_sbus_connection_get_data(conn), type)

/**
 * Reconnection status that is pass to a reconnection callback.
 */
enum sbus_reconnect_status {
    /**
     * Reconnection was successful.
     */
    SBUS_RECONNECT_SUCCESS,

    /**
     * Reconnection failed because maximum number of retires was exceeded.
     */
    SBUS_RECONNECT_EXCEEDED_RETRIES,

    /**
     * Reconnection failed due to unspecified error.
     */
    SBUS_RECONNECT_ERROR
};

/**
 * Enable automatic reconnection when an sbus connection is dropped.
 *
 * You can also set a callback that is called upon successful or
 * unsuccessful reconnection.
 *
 * Callback is of type:
 * void callback(struct sbus_connection *conn,
 *               enum sbus_reconnect_status status,
 *               data_type *data)
 *
 * @param conn          An sbus connection.
 * @param max_retries   Maximum number of reconnection retries.
 * @param callback      Callback function.
 * @param data          Private data passed to the callback.
 */
#define sbus_reconnect_enable(conn, max_retries, callback, data) do {         \
    SBUS_CHECK_FUNCTION(callback, void,                                       \
                        struct sbus_connection *,                             \
                        enum sbus_reconnect_status,                           \
                        SBUS_TYPEOF(data));                                   \
    _sbus_reconnect_enable((conn), max_retries,                               \
        (sbus_reconnect_cb)callback, (sbus_reconnect_data)data);              \
} while(0)

/**
 * Associate an object path with an sbus interface. The object @path may also
 * contain an asterisk at the end to indicate that the interface should be
 * applied for the path subtree.
 */
struct sbus_path {
    const char *path;
    struct sbus_interface *iface;
};

/**
 * Add new object or subtree path to the connection router.
 *
 * The specified interface will be associated with this path. You can add
 * single path multiple times if you want this path to have more interfaces
 * associated.
 *
 * @param conn      An sbus connection.
 * @param path      Object or subtree path.
 * @param iface     An sbus interface.
 *
 * @return EOK or other error code on failure.
 */
errno_t
sbus_connection_add_path(struct sbus_connection *conn,
                         const char *path,
                         struct sbus_interface *iface);

/**
 * Associate multiple object paths with interfaces at once.
 *
 * The paths and  interfaces are associated through @map which is
 * NULL terminated array of @sbus_router_path.
 *
 * @param conn      An sbus connection.
 * @param map       <path, interface> pairs to add into router.
 *
 * @return EOK or other error code on failure.
 */
errno_t
sbus_connection_add_path_map(struct sbus_connection *conn,
                             struct sbus_path *map);

/**
 * Add new signal listener to the router.
 *
 * Create a new listener with @SBUS_LISTEN_SYNC or @SBUS_LISTEN_ASYNC.
 *
 * @param conn      An sbus connection.
 * @param listener  An sbus signal listerner.
 *
 * @return EOK or other error code on failure.
 *
 * @see SBUS_LISTENERS, SBUS_LISTEN_SYNC, SBUS_LISTEN_ASYNC
 */
errno_t
sbus_router_listen(struct sbus_connection *conn,
                   struct sbus_listener *listener);

/**
 * Add multiple signal listeners to the router at once.
 *
 * @param conn      An sbus connection.
 * @param listener  An sbus signal listener array.
 *
 * @return EOK or other error code on failure.
 *
 * @see SBUS_LISTENERS, SBUS_LISTEN_SYNC, SBUS_LISTEN_ASYNC
 */
errno_t
sbus_router_listen_map(struct sbus_connection *conn,
                       struct sbus_listener *map);

/**
 * Register new node with the router.
 *
 * Each node is associated with a node factory which is a function that
 * returns list of node object names for given object path.
 *
 * Create a new node with @SBUS_NODE_SYNC or @SBUS_NODE_ASYNC.
 *
 * @param conn      An sbus connection.
 * @param node      An sbus node description.
 *
 * @return EOK or other error code on failure
 *
 * @see SBUS_NODES, SBUS_NODE_SYNC, SBUS_NODE_ASYNC
 */
errno_t
sbus_router_add_node(struct sbus_connection *conn,
                     struct sbus_node *node);

/**
 * Register multiple nodes with the router at once. Each node is associated
 * with a node factory which is a function that returns list of node object
 * names or given object path.
 *
 * @param conn      An sbus connection.
 * @param node      An sbus node description array.
 *
 * @return EOK or other error code on failure.
 *
 * @see SBUS_NODES, SBUS_NODE_SYNC, SBUS_NODE_ASYNC
 */
errno_t
sbus_router_add_node_map(struct sbus_connection *conn,
                         struct sbus_node *map);

/* Get connection name, well known name is preferred. */
const char * sbus_connection_get_name(struct sbus_connection *conn);

#endif /* _SBUS_H_ */
