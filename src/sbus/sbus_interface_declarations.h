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

#ifndef _SBUS_INTERFACE_DECLARATIONS_H_
#define _SBUS_INTERFACE_DECLARATIONS_H_

#include <talloc.h>
#include <tevent.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_typeof.h"
#include "sbus/sbus_request.h"

/*****************************************************************************
 *
 * This file contains declarations of symbols that must be generally available
 * to the user but that must not be used on their own so they should not be
 * present in sbus.h or other header files.
 *
 * Do not include this file directly.
 *
 *****************************************************************************/

/**
 * Terminator for the arrays in struct sbus_interface.
 */
#define SBUS_INTERFACE_SENTINEL {0}

enum sbus_handler_type {
    /**
     * Synchronous handler.
     *
     * Control is immediately returned from this type of handler.
     */
    SBUS_HANDLER_SYNC,

    /**
     * Asynchronous handler.
     *
     * Control is given to tevent.
     */
    SBUS_HANDLER_ASYNC
};

enum sbus_property_access {
    /**
     * The property is readable.
     */
    SBUS_PROPERTY_READABLE = 1,

    /**
     * The property is writable.
     */
    SBUS_PROPERTY_WRITABLE = 2,
};

struct sbus_handler;
struct sbus_invoker;

typedef void * sbus_handler_send_fn;
typedef void * sbus_handler_recv_fn;
typedef void * sbus_handler_sync_fn;
typedef void * sbus_handler_data;
typedef void * sbus_invoker_keygen;

typedef struct tevent_req *
(*sbus_invoker_issue)(TALLOC_CTX *,
                      struct tevent_context *,
                      struct sbus_request *,
                      sbus_invoker_keygen,
                      const struct sbus_handler *,
                      DBusMessageIter *read_iterator,
                      DBusMessageIter *write_iterator,
                      const char **_key);

struct sbus_invoker {
    sbus_invoker_issue issue;
    sbus_invoker_keygen keygen;
};

struct sbus_annotation {
    const char *name;
    const char *value;
};

struct sbus_handler {
    enum sbus_handler_type type;

    /* Asynchronous handler functions. */
    sbus_handler_send_fn async_send;
    sbus_handler_recv_fn async_recv;

    /* Synchronous handler functions. */
    sbus_handler_sync_fn sync;

    /* Handler private data that are passed to it. */
    sbus_handler_data data;
};

/**
 * An sbus argument of a method or signal.
 */
struct sbus_argument {
    /**
     * D-Bus type of the argument.
     */
    const char *type;

    /**
     * Argument name.
     */
    const char *name;
};

struct sbus_method_arguments {
    const struct sbus_argument *input;
    const struct sbus_argument *output;
};

/**
 * An sbus method.
 */
struct sbus_method {
    /**
     * Method name.
     */
    const char *name;

    /**
     * Method handler.
     */
    const struct sbus_handler handler;

    /**
     * Internal function that will issue the handler.
     */
    const struct sbus_invoker invoker;

    /**
     * Input and output arguments, used to generate introspection.
     */
    const struct sbus_method_arguments *arguments;

    /**
     * Method annotations.
     */
    const struct sbus_annotation *annotations;
};

/**
 * An sbus signal.
 */
struct sbus_signal {
    /**
     * Signal name (without the interface part).
     */
    const char *name;

    /**
     * Signal annotations.
     */
    const struct sbus_annotation *annotations;

    /**
     * Input arguments, used to generate introspection.
     */
    const struct sbus_argument *arguments;
};

/**
 * An sbus property.
 */
struct sbus_property {
    /**
     * Property name.
     */
    const char *name;

    /**
     * D-Bus type of the property, used in introspection.
     */
    const char *type;

    /**
     * Property access type.
     */
    const enum sbus_property_access access;

    /**
     * Property annotations.
     */
    const struct sbus_annotation *annotations;

    /**
     * Property handler. If the property is readable, a setter. If it is
     * writable, a getter.
     */
    const struct sbus_handler handler;

    /**
     * Internal function that will issue the handler.
     */
    const struct sbus_invoker invoker;
};

/**
 * Object describing D-Bus interface for sbus implementation.
 */
struct sbus_interface {
    /**
     * Interface name.
     */
    const char *name;

    /**
     * Interface annotations.
     */
    const struct sbus_annotation *annotations;

    /**
     * Methods implemented on this interface.
     */
    const struct sbus_method *methods;

    /**
     * Signals that can be emitted on this interface.
     */
    const struct sbus_signal *signals;

    /**
     * Properties implemented on this interface.
     */
    const struct sbus_property *properties;
};

/**
 * Object describing D-Bus signal listener.
 */
struct sbus_listener {
    /**
     * Interface name.
     */
    const char *interface;

    /**
     * Signal name on the interface to listen for.
     */
    const char *signal_name;

    /**
     * Object path to listen at, may be NULL to listen on all paths.
     */
    const char *object_path;

    /**
     * Signal handler.
     */
    const struct sbus_handler handler;

    /**
     * Internal function that will issue the handler.
     */
    const struct sbus_invoker invoker;
};

/**
 * Provide a D-Bus node factory for given object path.
 */
struct sbus_node {
    /**
     * D-Bus object path.
     */
    const char *path;

    /**
     * Node factory is an sbus handler of following type:
     */
    struct sbus_handler factory;
};

/**
 * Return an sbus interface object.
 */
struct sbus_interface
sbus_interface(const char *name,
               const struct sbus_annotation *annotations,
               const struct sbus_method *methods,
               const struct sbus_signal *signals,
               const struct sbus_property *properties);


/**
 * Return an sbus interface method object with a synchronous handler.
 */
struct sbus_method
sbus_method_sync(const char *name,
                 const struct sbus_method_arguments *arguments,
                 const struct sbus_annotation *annotations,
                 sbus_invoker_issue invoker_issue,
                 sbus_invoker_keygen invoker_keygen,
                 sbus_handler_sync_fn handler,
                 sbus_handler_data data);

/**
 * Return an sbus interface method object with an asynchronous handler.
 */
struct sbus_method
sbus_method_async(const char *name,
                  const struct sbus_method_arguments *arguments,
                  const struct sbus_annotation *annotations,
                  sbus_invoker_issue invoker_issue,
                  sbus_invoker_keygen invoker_keygen,
                  sbus_handler_send_fn handler_send,
                  sbus_handler_recv_fn handler_recv,
                  sbus_handler_data data);

/**
 * Return an sbus interface signal object.
 */
struct sbus_signal
sbus_signal(const char *name,
            const struct sbus_argument *arguments,
            const struct sbus_annotation *annotations);

/**
 * Return an sbus interface property object with a synchronous handler.
 */
struct sbus_property
sbus_property_sync(const char *name,
                   const char *type,
                   enum sbus_property_access access,
                   const struct sbus_annotation *annotations,
                   sbus_invoker_issue invoker_issue,
                   sbus_handler_sync_fn handler,
                   sbus_handler_data data);

/**
 * Return an sbus interface property object with an asynchronous handler.
 */
struct sbus_property
sbus_property_async(const char *name,
                    const char *type,
                    enum sbus_property_access access,
                    const struct sbus_annotation *annotations,
                    sbus_invoker_issue invoker_issue,
                    sbus_handler_send_fn handler_send,
                    sbus_handler_recv_fn handler_recv,
                    sbus_handler_data data);

/**
 * Return an sbus signal listener object with n synchronous handler.
 */
struct sbus_listener
sbus_listener_sync(const char *interface,
                   const char *signal_name,
                   const char *object_path,
                   sbus_invoker_issue invoker_issue,
                   sbus_invoker_keygen invoker_keygen,
                   sbus_handler_sync_fn handler,
                   sbus_handler_data data);

/**
 * Return an sbus signal listener object with an asynchronous handler.
 */
struct sbus_listener
sbus_listener_async(const char *interface,
                    const char *signal_name,
                    const char *object_path,
                    sbus_invoker_issue invoker_issue,
                    sbus_invoker_keygen invoker_keygen,
                    sbus_handler_send_fn handler_send,
                    sbus_handler_recv_fn handler_recv,
                    sbus_handler_data data);

/**
 * Associate an object path with a synchronous node factory function.
 */
struct sbus_node
sbus_node_sync(const char *path,
               sbus_handler_sync_fn factory,
               sbus_handler_data data);

/**
 * Associate an object path with an asynchronous node factory function.
 */
struct sbus_node
sbus_node_async(const char *path,
                sbus_handler_send_fn factory_send,
                sbus_handler_recv_fn factory_recv,
                sbus_handler_data data);

/**
 * Check type of request synchronous handler. The expected type is:
 * errno_t handler(struct sbus_request *request_data, data_type data
 *                [, method input arg, ...] [, method output arg, ...])
 *
 * For example:
 * errno_t handler(struct sbus_request *, struct ctx * data,
 *                 const char *input, int *_output)
 */
#define SBUS_CHECK_SYNC(handler, data, ...)                                   \
    SBUS_CHECK_FUNCTION((handler),                                            \
                        /* return type */                                     \
                        errno_t,                                              \
                        /* input parameters types */                          \
                        TALLOC_CTX *,                                         \
                        struct sbus_request *,                                \
                        SBUS_TYPEOF(data),                                    \
                        /* method specific parameters types */                \
                        ## __VA_ARGS__)

/**
 * Check type of request asynchronous send handler. The expected type is:
 * struct tevent_req * handler(TALLOC_CTX *mem_ctx,
 *                             struct tevent_context *ev,
 *                             struct sbus_request *request_data,
 *                             data_type data
 *                            [, method input arg, ...])
 *
 * For example:
 * struct tevent_req * handler_send(TALLOC_CTX *mem_ctx,
 *                                  struct tevent_context *ev,
 *                                  struct sbus_request *sbus_req,
 *                                  struct ctx *data,
 *                                  const char *input)
 */
#define SBUS_CHECK_SEND(handler, data, ...)                                   \
    SBUS_CHECK_FUNCTION((handler),                                            \
                        /* return type */                                     \
                        struct tevent_req *,                                  \
                        /* input parameters types */                          \
                        TALLOC_CTX *,                                         \
                        struct tevent_context *,                              \
                        struct sbus_request *,                                \
                        SBUS_TYPEOF(data),                                    \
                        /* method specific input parameters types */          \
                        ## __VA_ARGS__)                                       \

/**
 * Check type of asynchronous recv handler. The expected type is:
 * errno_t handler(TALLOC_CTX *mem_ctx, struct tevent_req *req
 *                 [, method output arg, ...])
 *
 * For example:
 * errno_t handler_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req,
 *                      int *_output)
 */
#define SBUS_CHECK_RECV(handler, ...)                                         \
    SBUS_CHECK_FUNCTION((handler),                                            \
                        /* return type */                                     \
                        errno_t,                                              \
                        /* input parameters types */                          \
                        TALLOC_CTX *,                                         \
                        struct tevent_req *,                                  \
                        /* method specific output parameters types */         \
                        ## __VA_ARGS__)


#define _SBUS_NODE_SYNC(path, factory, data) ({                               \
    SBUS_CHECK_FUNCTION((factory),                                            \
                        /* return type */ errno_t,                            \
                        TALLOC_CTX *, const char *, SBUS_TYPEOF(data),        \
                        const char ***);                                      \
    sbus_node_sync((path), (factory), (data));                                \
})

#define _SBUS_NODE_ASYNC(path, factory_send, factory_recv, data)  ({          \
    SBUS_CHECK_FUNCTION((factory_send),                                       \
                        /* return type */ struct tevent_req *,                \
                        TALLOC_CTX *, struct tevent_context *ev,              \
                        const char *, SBUS_TYPEOF(data));                     \
    SBUS_CHECK_FUNCTION((factory_recv),                                       \
                        /* return type */ errno_t,                            \
                        TALLOC_CTX *, struct tevent_req *,                    \
                        const char ***);                                      \
    sbus_node_async((path), (factory_send), (factory_recv), (data));          \
})

#endif /* _SBUS_INTERFACE_DECLARATIONS_H_ */
