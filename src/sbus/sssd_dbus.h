/*
   SSSD

   SSSD - D-BUS interface

   Copyright (C) Stephen Gallagher         2008

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

#ifndef _SSSD_DBUS_H_
#define _SSSD_DBUS_H_

struct sbus_connection;
struct sbus_interface;
struct sbus_request;

#include <dbus/dbus.h>
#include <sys/types.h>
#include "util/util.h"
#include "sbus/sssd_dbus_errors.h"
#include "sbus/sssd_dbus_utils.h"

/* Older platforms (such as RHEL-6) might not have these error constants
 * defined */
#ifndef DBUS_ERROR_UNKNOWN_INTERFACE
/** Interface you invoked a method on isn't known by the object. */
#define DBUS_ERROR_UNKNOWN_INTERFACE \
    "org.freedesktop.DBus.Error.UnknownInterface"
#endif /* DBUS_ERROR_UNKNOWN_INTERFACE */

#ifndef DBUS_ERROR_UNKNOWN_PROPERTY
/** Property you tried to access isn't known by the object. */
#define DBUS_ERROR_UNKNOWN_PROPERTY \
    "org.freedesktop.DBus.Error.UnknownProperty"
#endif /* DBUS_ERROR_UNKNOWN_PROPERTY */

#ifndef DBUS_ERROR_PROPERTY_READ_ONLY
/** Property you tried to set is read-only. */
#define DBUS_ERROR_PROPERTY_READ_ONLY \
    "org.freedesktop.DBus.Error.PropertyReadOnly"
#endif /* DBUS_ERROR_PROPERTY_READ_ONLY */

#ifndef DBUS_ERROR_INIT
#define DBUS_ERROR_INIT { NULL, NULL, TRUE, 0, 0, 0, 0, NULL }
#endif /* DBUS_ERROR_INIT */

/**
 * Note: internal functions do not rely on the value of this constant to
 * simplify implementation. If this constant change, some functions in
 * sssd_dbus_interface.c needs to be amended.
 */
#define SBUS_SUBTREE_SUFFIX "/*"

/**
 * It is not possible to send NULL over D-Bus. We can only test if it
 * is empty or not.
 */
#define SBUS_IS_STRING_EMPTY(str) ((str) == NULL || (str)[0] == '\0')
#define SBUS_SET_STRING(str) (SBUS_IS_STRING_EMPTY(str) ? NULL : (str))


typedef int (*sbus_msg_handler_fn)(struct sbus_request *dbus_req,
                                   void *handler_data);

typedef void (*sbus_conn_reconn_callback_fn)(struct sbus_connection *, int, void *);

/*
 * sbus_server_conn_init_fn
 * Set up function for connection-specific activities
 * This function should define the sbus_conn_destructor_fn
 * for this connection at a minimum
 */
typedef int (*sbus_server_conn_init_fn)(struct sbus_connection *, void *);

typedef const char ** (* sbus_nodes_fn)(TALLOC_CTX *mem_ctx,
                                        const char *path,
                                        void *data);

enum {
    SBUS_CONN_TYPE_PRIVATE = 1,
    SBUS_CONN_TYPE_SHARED,
    SBUS_CONN_TYPE_SYSBUS
};

enum {
    SBUS_RECONNECT_SUCCESS = 1,
    SBUS_RECONNECT_EXCEEDED_RETRIES,
    SBUS_RECONNECT_ERROR
};

/*
 * This represents vtable of interface handlers for methods and
 * properties and so on. The actual vtable structs derive from this struct
 * (i.e.: have this struct as their first member).
 *
 * The offsets for matching vtable function pointers are in sbus_method_meta
 * These are used to dynamically dispatch the method invocations.
 */
struct sbus_vtable {
    const struct sbus_interface_meta *meta;
    int flags; /* unused for now */

    /* derived structs place function pointers here. */
};

/* Special interface and method for D-BUS introspection */
#define DBUS_INTROSPECT_INTERFACE "org.freedesktop.DBus.Introspectable"
#define DBUS_INTROSPECT_METHOD "Introspect"

/* Special interface and method for D-BUS properties */
#define DBUS_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"

struct sbus_interface {
    const char *path;
    struct sbus_vtable *vtable;
    void *handler_data;
};

/* Server Functions */
int sbus_new_server(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    const char *address,
                    uid_t uid, gid_t gid,
                    bool use_symlink,
                    struct sbus_connection **server,
                    sbus_server_conn_init_fn init_fn,
                    void *init_pvt_data,
                    void *client_destructor_data);

/* Connection Functions */

/* sbus_new_connection
 * Use this function when connecting a new process to
 * the standard SSSD interface.
 * This will connect to the address specified and then
 * call sbus_add_connection to integrate with the main
 * loop.
 */
int sbus_new_connection(TALLOC_CTX *ctx,
                        struct tevent_context *ev,
                        const char *address,
                        time_t *last_request_time,
                        struct sbus_connection **conn);

/* sbus_add_connection
 * Integrates a D-BUS connection with the TEvent main
 * loop. Use this function when you already have a
 * DBusConnection object (for example from dbus_bus_get)
 * Connection type can be either:
 * SBUS_CONN_TYPE_PRIVATE: Used only from within a D-BUS
 *     server such as the Monitor in the
 *     new_connection_callback
 * SBUS_CONN_TYPE_SHARED: Used for all D-BUS client
 *     connections, including those retrieved from
 *     dbus_bus_get
 */
int sbus_init_connection(TALLOC_CTX *ctx,
                         struct tevent_context *ev,
                         DBusConnection *dbus_conn,
                         int connection_type,
                         time_t *last_request_time,
                         void *destructor_data,
                         struct sbus_connection **_conn);

DBusConnection *sbus_get_connection(struct sbus_connection *conn);

void sbus_disconnect(struct sbus_connection *conn);

/*
 * Register a new interface to be available at given object path.
 *
 * The interface will be exported at @object_path. The method handlers are
 * represented by @iface_vtable. @pvt contains additional caller specific data
 * which is made available to handlers.
 */
int sbus_conn_register_iface(struct sbus_connection *conn,
                             struct sbus_vtable *iface_vtable,
                             const char *object_path,
                             void *handler_data);

struct sbus_iface_map {
    const char *path;
    struct sbus_vtable *vtable;
};

errno_t sbus_conn_register_iface_map(struct sbus_connection *conn,
                                     struct sbus_iface_map *map,
                                     void *pvt);

void
sbus_conn_register_nodes(struct sbus_connection *conn,
                         const char *path,
                         sbus_nodes_fn nodes_fn,
                         void *data);

errno_t
sbus_conn_reregister_paths(struct sbus_connection *conn);

char *
sbus_opath_escape_part(TALLOC_CTX *mem_ctx,
                       const char *object_path_part);

char *
sbus_opath_unescape_part(TALLOC_CTX *mem_ctx,
                         const char *object_path_part);

char *
_sbus_opath_compose(TALLOC_CTX *mem_ctx,
                    const char *base,
                    const char *part, ...);

#define sbus_opath_compose(mem_ctx, base, ...) \
    _sbus_opath_compose(mem_ctx, base, ##__VA_ARGS__, NULL)

errno_t
sbus_opath_decompose(TALLOC_CTX *mem_ctx,
                     const char *object_path,
                     const char *prefix,
                     char ***_components,
                     size_t *_len);

errno_t
sbus_opath_decompose_exact(TALLOC_CTX *mem_ctx,
                           const char *object_path,
                           const char *prefix,
                           size_t expected,
                           char ***_components);

const char *
sbus_opath_strip_prefix(const char *object_path,
                        const char *prefix);

char *
sbus_opath_get_object_name(TALLOC_CTX *mem_ctx,
                           const char *object_path,
                           const char *base_path);

/* max_retries < 0: retry forever
 * max_retries = 0: never retry (why are you calling this function?)
 * max_retries > 0: obvious
 */
void sbus_reconnect_init(struct sbus_connection *conn,
                         int max_retries,
                         sbus_conn_reconn_callback_fn callback,
                         void *pvt);

/*
 * Send a message across the SBUS
 * If requested, the DBusPendingCall object will
 * be returned to the caller.
 *
 * This function will return EAGAIN in the event
 * that the connection is not open for
 * communication.
 */
int sbus_conn_send(struct sbus_connection *conn,
                   DBusMessage *msg,
                   int timeout_ms,
                   DBusPendingCallNotifyFunction reply_handler,
                   void *pvt,
                   DBusPendingCall **pending);

void sbus_conn_send_reply(struct sbus_connection *conn,
                          DBusMessage *reply);

/* Set up D-BUS access control. If there is an SSSD user, we must allow
 * him to connect. root is always allowed */
void sbus_allow_uid(struct sbus_connection *conn, uid_t *uid);

/*
 * This structure is passed to all dbus method and property
 * handlers. It is a talloc context which will be valid until
 * the request is completed with either the sbus_request_complete()
 * or sbus_request_fail() functions.
 */
struct sbus_request {
    int64_t client;
    struct sbus_connection *conn;
    DBusMessage *message;
    struct sbus_interface *intf;
    const struct sbus_method_meta *method;
    const char *path;
};

/*
 * Complete a DBus request, and free the @dbus_req context. The @dbus_req
 * and associated talloc context are no longer valid after this function
 * returns.
 *
 * If @reply is non-NULL then the reply is sent to the caller. Not sending
 * a reply when the caller is expecting one is fairly rude behavior.
 *
 * The return value is useful for logging, but not much else. In particular
 * even if this function return !EOK, @dbus_req is still unusable after this
 * function returns.
 */
int sbus_request_finish(struct sbus_request *dbus_req,
                        DBusMessage *reply);

/*
 * Return a reply for a DBus method call request. The variable
 * arguments are (unfortunately) formatted exactly the same as those of the
 * dbus_message_append_args() function. Documented here:
 *
 * http://dbus.freedesktop.org/doc/api/html/group__DBusMessage.html
 *
 * Important: don't pass int or bool or such types as
 * values to this function. That's not portable. Use actual dbus types.
 * You must also pass pointers as the values:
 *
 *    dbus_bool_t val1 = TRUE;
 *    dbus_int32_t val2 = 5;
 *    ret = sbus_request_finish(dbus_req,
 *                              DBUS_TYPE_BOOLEAN, &val1,
 *                              DBUS_TYPE_INT32, &val2,
 *                              DBUS_TYPE_INVALID);
 *
 * To pass arrays to this function, use the following syntax. Never
 * pass actual C arrays with [] syntax to this function. The C standard is
 * rather vague with C arrays and varargs, and it just plain doesn't work.
 *
 *    const char *array[] = { "one", "two", "three" };
 *    int count = 3; // yes, a plain int
 *    const char **ptr = array;
 *    ret = sbus_request_finish(dbus_req,
 *                              DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &ptr, 3,
 *                              DBUS_TYPE_INVALID);
 *
 * The @dbus_req and associated talloc context are no longer valid after this
 * function returns, even if this function returns an error code.
 */
int sbus_request_return_and_finish(struct sbus_request *dbus_req,
                                   int first_arg_type,
                                   ...);

/*

 * Return an error for a DBus method call request. The @error is a normal
 * DBusError.
 *
 * The @dbus_req and associated talloc context are no longer valid after this
 * function returns, even if this function returns an error code.
 */
int sbus_request_fail_and_finish(struct sbus_request *dbus_req,
                                 const DBusError *error);

void sbus_request_reply_error(struct sbus_request *sbus_req,
                              const char *error_name,
                              const char *fmt,
                              ...) SSS_ATTRIBUTE_PRINTF(3, 4);

/*
 * Construct a new DBusError instance which can be consumed by functions such
 * as @sbus_request_fail_and_finish().
 *
 * The @error is a string constant representing a DBus error as documented at
 * http://dbus.freedesktop.org/doc/api/html/group__DBusProtocol.html.
 * The parameter @err_msg is a human-readable error representation (or
 * NULL for none). The returned DBusError is a talloc context and the err_msg
 * is duplicated using the returned DBusError instance as a talloc parent.
 */
DBusError *sbus_error_new(TALLOC_CTX *mem_ctx,
                          const char *dbus_error_name,
                          const char *fmt,
                          ...) SSS_ATTRIBUTE_PRINTF(3, 4);

/*
 * Parse a DBus method call request.
 *
 * If parsing the method call message does not succeed, then an error is
 * sent to the DBus caller and the request is finished. If this function
 * returns false then @request is no longer valid.
 *
 * This also means if this method returns false within a handler, you should
 * return EOK from the handler. The message has been handled, appropriate
 * logs have been written, and everything should just move on.
 *
 * If the method call does not match the expected arguments, then a
 * org.freedesktop.DBus.Error.InvalidArgs is returned to the caller as
 * expected.
 *
 * The variable arguments are (unfortunately) formatted exactly the same
 * as those of the dbus_message_get_args() function. Documented here:
 *
 * http://dbus.freedesktop.org/doc/api/html/group__DBusMessage.html
 *
 * Exception: You don't need to free string arrays returned by this
 * function. They are automatically talloc parented to the request memory
 * context and can be used until the request has been finished.
 *
 * Important: don't pass int or bool or such types as values to this
 * function. That's not portable. Use actual dbus types. You must also pass
 * pointers as the values:
 *
 *    dbus_bool_t val1;
 *    dbus_int32_t val2;
 *    ret = sbus_request_parse_or_finish(request,
 *                                       DBUS_TYPE_BOOLEAN, &val1,
 *                                       DBUS_TYPE_INT32, &val2,
 *                                       DBUS_TYPE_INVALID);
 *
 * To pass arrays to this function, use the following syntax. Never
 * pass actual C arrays with [] syntax to this function. The C standard is
 * rather vague with C arrays and varargs, and it just plain doesn't work.
 *
 *    int count; // yes, a plain int
 *    const char **array;
 *    ret = sbus_request_parse_or_finish(request,
 *                                       DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &array, &count,
 *                                       DBUS_TYPE_INVALID);
 */
bool sbus_request_parse_or_finish(struct sbus_request *request,
                                  int first_arg_type,
                                  ...);

struct sbus_incoming_signal {
    struct sbus_connection *conn;
    DBusMessage *message;
    int64_t client;
    const char *interface;
    const char *signal;
    const char *path;
};

typedef void
(*sbus_incoming_signal_fn)(struct sbus_incoming_signal *sbus_signal,
                           void *handler_data);

errno_t
sbus_signal_listen(struct sbus_connection *conn,
                   const char *iface,
                   const char *signal,
                   sbus_incoming_signal_fn handler_fn,
                   void *handler_data);

/* This function returns the destructor data passed when in starting
 * a new dbus server/connection. Its use, for now, must be restricted
 * to {dbus,socket}-activated services in order to proper shut them
 * down, unregistering them in the monitor. */
void *sbus_connection_get_destructor_data(struct sbus_connection *conn);

#endif /* _SSSD_DBUS_H_*/
