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

#ifndef _SBUS_PRIVATE_H_
#define _SBUS_PRIVATE_H_

#include <time.h>
#include <dhash.h>
#include <talloc.h>
#include <tevent.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus.h"
#include "sbus/sbus_message.h"
#include "sbus/sbus_sync_private.h"
#include "sbus/sbus_interface_declarations.h"

/**
 * First, declare all structures, since they are often cross referenced.
 */

struct sbus_connection_destructor;
struct sbus_connection_access;
struct sbus_connection;
struct sbus_reconnect;
struct sbus_server;
struct sbus_router;
struct sbus_watch;
struct sbus_sender;
struct sbus_listener;
struct sbus_interface;
struct sbus_active_requests;
struct sbus_server_on_connection;

enum sbus_connection_type {
    /**
     * Client connection is owned by sbus and not by D-Bus, therefore it
     * needs to be explicitly closed before removing the last reference.
     *
     * This is used for connections created by sbus server.
     */
    SBUS_CONNECTION_CLIENT,

    /**
     * Address and system bus connections are owned by libdbus thus we can not
     * close these connections explicitly. These connections may be recycled
     * when we connect to the same address more than once.
     */
    SBUS_CONNECTION_ADDRESS,
    SBUS_CONNECTION_SYSBUS
};

struct sbus_connection {
    struct tevent_context *ev;
    DBusConnection *connection;
    enum sbus_connection_type type;
    const char *address;

    /* D-Bus connection well-known name as request by the application. */
    const char *wellknown_name;

    /* D-Bus connection unique name as assigned by bus. */
    const char *unique_name;

    /**
     * True if the connection is being disconnected or freed. No further
     * manipulation with the connection is allowed.
     */
    bool disconnecting;

    /* Make all the structures pointers so we can have them encapsulated. */
    struct sbus_connection_access *access;
    struct sbus_connection_destructor *destructor;
    struct sbus_active_requests *requests;
    struct sbus_reconnect *reconnect;
    struct sbus_router *router;
    struct sbus_watch *watch;

    /**
     * Connection private data.
     */
    void *data;

    /**
     * Table of <dbus-sender, sbus-sender> pair. Contains resolved uids
     * of remote D-Bus clients.
     */
    hash_table_t *senders;

    /* Pointer to a caller's last activity variable. The time is updated
     * each time the bus is active (when a method arrives). */
    time_t *last_activity;
};

struct sbus_server {
    struct tevent_context *ev;
    DBusServer *server;
    const char *symlink;
    struct sbus_watch *watch_ctx;
    struct sbus_router *router;
    dbus_int32_t data_slot;
    time_t *last_activity;
    hash_table_t *names;
    hash_table_t *match_rules;
    uint32_t max_connections;

    struct sbus_server_on_connection *on_connection;
    bool disconnecting;

    /* Last generated unique name information. */
    struct {
        uint32_t major;
        uint32_t minor;
    } name;
};

/* Setup server interface implementing org.freedesktop.DBus. */
errno_t
sbus_server_setup_interface(struct sbus_server *server);

/* Add signal match. */
errno_t
sbus_server_add_match(struct sbus_server *server,
                      struct sbus_connection *conn,
                      const char *rule);

/* Remove signal match. */
errno_t
sbus_server_remove_match(struct sbus_server *server,
                         struct sbus_connection *conn,
                         const char *rule);

/* Send message to all connections whose rule matches the message. */
errno_t
sbus_server_matchmaker(struct sbus_server *server,
                       struct sbus_connection *conn,
                       const char *avoid_name,
                       DBusMessage *message);

/* Send NameAcquired signal to given connection. */
void
sbus_server_name_acquired(struct sbus_server *server,
                          struct sbus_connection *conn,
                          const char *name);

/* Send NameLost signal to given connection. */
void
sbus_server_name_lost(struct sbus_server *server,
                      struct sbus_connection *conn,
                      const char *name);

/* Initialize new sbus connection. */
struct sbus_connection *
sbus_connection_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     DBusConnection *dbus_conn,
                     const char *address,
                     const char *dbus_name,
                     enum sbus_connection_type type,
                     time_t *last_activity_time);

/* Replace current D-Bus connection context with a new one. */
errno_t sbus_connection_replace(struct sbus_connection *sbus_conn,
                                DBusConnection *dbus_conn);

/* Integrate an sbus connection with tevent loop. */
errno_t sbus_connection_tevent_enable(struct sbus_connection *conn);
void sbus_connection_tevent_disable(struct sbus_connection *conn);

/* Mark that this connection is currently active (new method call arrived). */
void sbus_connection_mark_active(struct sbus_connection *conn);

/* Set connection well known name. */
errno_t sbus_connection_set_name(struct sbus_connection *conn,
                                 const char *name);

/* Free connection next time the event loop is processed. We do it
 * asynchronously to avoid a potential use after free from tevent
 * callbacks that may be already scheduled. */
void sbus_connection_free(struct sbus_connection *conn);

/* Try to reconnect to D-Bus if connection was dropped. It will notify
 * the user with a result through a reconnection callback. */
void sbus_reconnect(struct sbus_connection *conn);

/* Initialize reconnection structure. */
struct sbus_reconnect *sbus_reconnect_init(TALLOC_CTX *mem_ctx);

/* Disable any further reconnection attempts. */
void sbus_reconnect_disable(struct sbus_connection *conn);

/* Return true if we are already trying to reconnect. */
bool sbus_reconnect_in_progress(struct sbus_connection *conn);

/* Return true if we are allowed to reconnect. */
bool sbus_reconnect_enabled(struct sbus_connection *conn);

/* Call Hello and RequestName methods. */
struct tevent_req *
sbus_connect_init_send(TALLOC_CTX *mem_ctx,
                      struct sbus_connection *conn,
                      const char *name);

errno_t sbus_connect_init_recv(struct tevent_req *req);

/* Setup D-Bus event watchers to integrate D-Bus with event loop. */
errno_t sbus_watch_server(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          DBusServer *server,
                          struct sbus_watch **_watch);

errno_t sbus_watch_connection(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              DBusConnection *conn,
                              struct sbus_watch **_watch);

/* Perform an access check on the given request using registered
 * access check function of connection.*/
errno_t sbus_check_access(struct sbus_connection *conn,
                          struct sbus_request *sbus_req);

/* Setup D-Bus tevent dispatcher. */
void sbus_dispatcher_setup(struct sbus_connection *conn);
void sbus_dispatcher_disable(struct sbus_connection *conn);
void sbus_dispatch_now(struct sbus_connection *conn);

/* Send a new D-Bus message. */
struct tevent_req *
sbus_message_send(TALLOC_CTX *mem_ctx,
                  struct sbus_connection *conn,
                  DBusMessage *msg,
                  int timeout_ms);

errno_t
sbus_message_recv(TALLOC_CTX *mem_ctx,
                  struct tevent_req *req,
                  DBusMessage **_reply);

/* Send reply to a D-Bus message. The @reply is unreferenced when sent. */
void sbus_reply(struct sbus_connection *conn,
                DBusMessage *reply);

/* Replz to a D-Bus message with error. */
void sbus_reply_error(struct sbus_connection *conn,
                      DBusMessage *reply_to,
                      const char *error_name,
                      const char *error_message);

/* Emit a new signal. */
void sbus_emit_signal(struct sbus_connection *conn,
                      DBusMessage *msg);

struct sbus_interface_list {
    struct sbus_interface *interface;

    struct sbus_interface_list *next;
    struct sbus_interface_list *prev;
};

struct sbus_listener_list {
    struct sbus_listener *listener;

    struct sbus_listener_list *next;
    struct sbus_listener_list *prev;
};

struct sbus_router {
    struct sbus_connection *conn;

    /**
     * Table of <object-path, interface> pair. Contains description of
     * sbus interfaces that are implemented and supported on given path.
     */
    hash_table_t *paths;

    /**
     * Table of <object-path, node> pair. A node contains factory function
     * given for selected object paths. This function is used to create
     * list of object paths nodes that are available under requested path
     * during introspection.
     */
    hash_table_t *nodes;

    /**
     * Table of <interface.signal, listener> pair. Contains description of
     * sbus signal listeners.
     */
    hash_table_t *listeners;
};

/* Initialize router structure. */
struct sbus_router *
sbus_router_init(TALLOC_CTX *mem_ctx,
                 struct sbus_connection *conn);

/* Re-register paths and listeners on dropped connection. */
errno_t
sbus_router_reset(struct sbus_connection *conn);

/* Initialize object paths hash table. */
hash_table_t *
sbus_router_paths_init(TALLOC_CTX *mem_ctx);

/* Register an interface with an object path. */
errno_t
sbus_router_paths_add(hash_table_t *table,
                      const char *path,
                      struct sbus_interface *iface);

/* Lookup interface for given object path. */
struct sbus_interface *
sbus_router_paths_lookup(hash_table_t *table,
                         const char *path,
                         const char *iface_name);

/* Return list of all interfaces registered with given object path. */
errno_t
sbus_router_paths_supported(TALLOC_CTX *mem_ctx,
                            hash_table_t *table,
                            const char *path,
                            struct sbus_interface_list **_list);

/* Return all registered paths converted to node names. */
const char **
sbus_router_paths_nodes(TALLOC_CTX *mem_ctx,
                        hash_table_t *table);

/* Check if given object path is registered. */
bool
sbus_router_paths_exist(hash_table_t *table,
                        const char *object_path);

/* Initialize signal listeners hash table. */
hash_table_t *
sbus_router_listeners_init(TALLOC_CTX *mem_ctx,
                           struct sbus_connection *conn);

/* Add new signal listener. */
errno_t
sbus_router_listeners_add(hash_table_t *table,
                          const char *interface,
                          const char *signal_name,
                          struct sbus_listener *listener,
                          bool *_signal_known);

/* Find all listeners for given signal. */
struct sbus_listener_list *
sbus_router_listeners_lookup(hash_table_t *table,
                             const char *interface,
                             const char *signal_name);

/* Initialize nodes hash table. */
hash_table_t *
sbus_router_nodes_init(TALLOC_CTX *mem_ctx);

/* Add new node factory. */
errno_t
sbus_router_nodes_add(hash_table_t *table,
                      struct sbus_node *node);

/* Lookup node factory for given object path. */
struct sbus_node *
sbus_router_nodes_lookup(hash_table_t *table,
                         const char *path);

/* Register new interface on path with the router. */
errno_t
sbus_router_add_path(struct sbus_router *router,
                     const char *path,
                     struct sbus_interface *iface);

/* Register new interface on path with the router from map. */
errno_t
sbus_router_add_path_map(struct sbus_router *router,
                         struct sbus_path *map);

/* Return D-Bus match rule for given signal. */
char *
sbus_router_signal_rule(TALLOC_CTX *mem_ctx,
                        const char *interface,
                        const char *signal_name);

/* Parse interface.signal into interface and signal parts. */
errno_t
sbus_router_signal_parse(TALLOC_CTX *mem_ctx,
                         const char *qualified_signal,
                         char **_interface,
                         char **_signal_name);

/* Process incoming messages. */
DBusHandlerResult
sbus_router_filter(struct sbus_connection *conn,
                   struct sbus_router *router,
                   DBusMessage *message);

/* Handler for incoming D-Bus messages that are recieve by connection. */
DBusHandlerResult
sbus_connection_filter(DBusConnection *dbus_conn,
                       DBusMessage *message,
                       void *handler_data);

/* Server filter function. Routes messages between connections. */
DBusHandlerResult
sbus_server_filter(DBusConnection *dbus_conn,
                   DBusMessage *message,
                   void *handler_data);

/* Spy that ensures that the request list item is invalidated when the
 * request or connection is freed. */
struct sbus_request_spy;

struct sbus_request_list {
    struct tevent_req *req;
    struct sbus_connection *conn;

    bool is_invalid;
    bool is_dbus;

    struct {
        struct sbus_request_spy *req;
        struct sbus_request_spy *conn;
    } spy;

    struct sbus_request_list *prev;
    struct sbus_request_list *next;
};

struct sbus_active_requests {
    hash_table_t *incoming;
    hash_table_t *outgoing;
};

/* Initialize active requests structure. */
struct sbus_active_requests *
sbus_active_requests_init(TALLOC_CTX *mem_ctx);

/* Initialize request table. */
hash_table_t *
sbus_requests_init(TALLOC_CTX *mem_ctx);

/* Add new active request into the table. */
errno_t
sbus_requests_add(hash_table_t *table,
                  const char *key,
                  struct sbus_connection *conn,
                  struct tevent_req *req,
                  bool is_dbus,
                  bool *_key_exists);

/* Lookup active requests list. */
struct sbus_request_list *
sbus_requests_lookup(hash_table_t *table,
                     const char *key);

/* Delete active requests list. */
void
sbus_requests_delete(struct sbus_request_list *list);

/* Finish a request. */
void
sbus_requests_finish(struct sbus_request_list *item,
                     errno_t error);

/* Terminate all requests. */
void
sbus_requests_terminate_all(hash_table_t *table,
                            errno_t error);

/* Create new sbus request. */
struct sbus_request *
sbus_request_create(TALLOC_CTX *mem_ctx,
                    struct sbus_connection *conn,
                    enum sbus_request_type type,
                    const char *destination,
                    const char *interface,
                    const char *member,
                    const char *path);

/* Run an incoming request handler. */
struct tevent_req *
sbus_incoming_request_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_connection *conn,
                           struct sbus_request *request,
                           const struct sbus_invoker *invoker,
                           const struct sbus_handler *handler,
                           const char *sender_name,
                           DBusMessageIter *read_iter,
                           DBusMessage *msg);

errno_t
sbus_incoming_request_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           DBusMessage **_reply);

/* Issue a new outgoing request. */
struct tevent_req *
sbus_outgoing_request_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_connection *conn,
                           const char *key,
                           DBusMessage *msg);

errno_t
sbus_outgoing_request_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           DBusMessage **_reply);

/* Initialize senders hash table. */
hash_table_t *
sbus_senders_init(TALLOC_CTX *mem_ctx);

/* Remove sender from the table. */
void
sbus_senders_delete(hash_table_t *table,
                    const char *name);

/* Create new sbus sender. */
struct sbus_sender *
sbus_sender_create(TALLOC_CTX *mem_ctx,
                   const char *name,
                   int64_t uid);

/* Copy sbus sender structure. */
struct sbus_sender *
sbus_sender_copy(TALLOC_CTX *mem_ctx,
                 const struct sbus_sender *input);

/* Resolve sender of the incoming message. */
struct tevent_req *
sbus_sender_resolve_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_connection *conn,
                         enum sbus_request_type type,
                         const char *destination,
                         const char *object_path,
                         const char *interface,
                         const char *member,
                         const char *name);

errno_t
sbus_sender_resolve_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct sbus_sender **_sender);

/* Generic receiver of sbus invoker. */
errno_t
sbus_invoker_recv(struct tevent_req *req);

/* Build key of given request. */
errno_t
sbus_request_key(TALLOC_CTX *mem_ctx,
                 sbus_invoker_keygen keygen,
                 struct sbus_request *sbus_req,
                 void *input,
                 const char **_key);

/**
 * Create copy of provided interface. It expects that the interface was
 * not created manually but through sbus API, therefore many of its fields
 * must point to a static memory and same pointers are used for copy.
 */
struct sbus_interface *
sbus_interface_copy(TALLOC_CTX *mem_ctx,
                    const struct sbus_interface *input);

/* Find given method in interface. */
const struct sbus_method *
sbus_interface_find_method(struct sbus_interface *iface,
                           const char *method_name);

/* Find given property in interface. */
const struct sbus_property *
sbus_interface_find_property(struct sbus_interface *iface,
                             enum sbus_property_access access,
                             const char *property_name);

/**
 * Create copy of provided signal listener. It expects that the listener was
 * not created manually but through sbus API, therefore many of its fields
 * must point to a static memory and same pointers are used for copy.
 */
struct sbus_listener *
sbus_listener_copy(TALLOC_CTX *mem_ctx,
                   const struct sbus_listener *input);

/**
 * Create copy of provided node. It expects that the listener was
 * not created manually but through sbus API, therefore many of its fields
 * must point to a static memory and same pointers are used for copy.
 */
struct sbus_node *
sbus_node_copy(TALLOC_CTX *mem_ctx,
               struct sbus_node *input);

/* Find given annotation. */
const char *
sbus_annotation_find(const struct sbus_annotation *annotations,
                     const char *name);

/* Find given annotation and return its value as boolean. */
bool
sbus_annotation_find_as_bool(const struct sbus_annotation *annotations,
                             const char *name);

/* Print a warning if specific annotations exist. */
void
sbus_annotation_warn(const struct sbus_interface *iface,
                     const struct sbus_method *method);

/* Register D-Bus introspection interface. */
errno_t
sbus_register_introspection(struct sbus_router *router);

/* Register D-Bus properties interface. */
errno_t
sbus_register_properties(struct sbus_router *router);

/* Register listeners for org.freedesktop.DBus signals. */
errno_t
sbus_register_standard_signals(struct sbus_connection *conn);

/* Send a D-Bus method call. Used in generated callers. */
struct tevent_req *
sbus_call_method_send(TALLOC_CTX *mem_ctx,
                      struct sbus_connection *conn,
                      DBusMessage *raw_message,
                      sbus_invoker_keygen keygen,
                      sbus_invoker_writer_fn writer,
                      const char *bus,
                      const char *path,
                      const char *iface,
                      const char *method,
                      void *input);

errno_t
sbus_call_method_recv(TALLOC_CTX *mem_ctx,
                      struct tevent_req *req,
                      DBusMessage **_reply);

/* Send a D-Bus signal call. Used in generated callers. */
void
sbus_call_signal_send(struct sbus_connection *conn,
                      DBusMessage *raw_message,
                      sbus_invoker_writer_fn writer,
                      const char *path,
                      const char *iface,
                      const char *signal_name,
                      void *input);

#endif /* _SBUS_PRIVATE_H_ */
