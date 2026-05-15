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

#include <string.h>
#include <stdio.h>

#include "util/util.h"
#include "util/dlinklist.h"
#include "sbus/sbus_request.h"
#include "sbus/sbus_private.h"
#include "sbus/sbus_interface.h"
#include "sbus/interface_dbus/sbus_dbus_server.h"

#define FMT_DOCTYPE \
    "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" \
    " \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"

#define FMT_NODE                "<node name=\"%s\">\n"
#define FMT_IFACE               "  <interface name=\"%s\">\n"
#define FMT_ANNOTATION          "    %s<annotation name=\"%s\" value=\"%s\" />\n"
#define FMT_METHOD_EMPTY        "    <method name=\"%s\" />\n"
#define FMT_METHOD_OPEN         "    <method name=\"%s\">\n"
#define FMT_METHOD_ARG          "      <arg type=\"%s\" name=\"%s\" direction=\"%s\" />\n"
#define FMT_METHOD_CLOSE        "    </method>\n"
#define FMT_SIGNAL_EMPTY        "    <signal name=\"%s\" />\n"
#define FMT_SIGNAL_OPEN         "    <signal name=\"%s\">\n"
#define FMT_SIGNAL_ARG          "      <arg type=\"%s\" name=\"%s\" />\n"
#define FMT_SIGNAL_CLOSE        "    </signal>\n"
#define FMT_PROPERTY_EMPTY      "    <property name=\"%s\" type=\"%s\" access=\"%s\" />\n"
#define FMT_PROPERTY_OPEN       "    <property name=\"%s\" type=\"%s\" access=\"%s\">\n"
#define FMT_PROPERTY_CLOSE      "    </property>\n"
#define FMT_IFACE_CLOSE         "  </interface>\n"
#define FMT_CHILD_NODE          "  <node name=\"%s\" />\n"
#define FMT_NODE_CLOSE          "</node>\n"

#define WRITE_OR_FAIL(file, ret, label, fmt, ...) do { \
    ret = fprintf(file, fmt, ##__VA_ARGS__); \
    if (ret < 0) { \
        ret = EIO; \
        goto label; \
    } \
} while (0)

#define EMPTY(field) ((field) == NULL || (field)[0].name == NULL)

enum sbus_arg_type {
    SBUS_ARG_IN,
    SBUS_ARG_OUT,
    SBUS_ARG_SIGNAL
};

static errno_t
sbus_introspect_annotations(FILE *file,
                            bool inside,
                            const struct sbus_annotation *annotations)
{
    errno_t ret;
    const char *indent = inside ? "  " : "";
    int i;

    if (annotations == NULL) {
        return EOK;
    }

    for (i = 0; annotations[i].name != NULL; i++) {
        WRITE_OR_FAIL(file, ret, done, FMT_ANNOTATION, indent,
                      annotations[i].name, annotations[i].value);
    }

    ret = EOK;

done:
    return ret;
}

static errno_t
sbus_introspect_args(FILE *file,
                     enum sbus_arg_type type,
                     const struct sbus_argument *args)
{
    errno_t ret;
    int i;

    if (args == NULL) {
        return EOK;
    }

    for (i = 0; args[i].name != NULL; i++) {
        switch (type) {
        case SBUS_ARG_SIGNAL:
            WRITE_OR_FAIL(file, ret, done, FMT_SIGNAL_ARG,
                          args[i].type, args[i].name);
            break;
        case SBUS_ARG_IN:
            WRITE_OR_FAIL(file, ret, done, FMT_METHOD_ARG,
                          args[i].type, args[i].name, "in");
            break;
        case SBUS_ARG_OUT:
            WRITE_OR_FAIL(file, ret, done, FMT_METHOD_ARG,
                          args[i].type, args[i].name, "out");
            break;
        }
    }

    ret = EOK;

done:
    return ret;
}

static errno_t
sbus_introspect_methods(FILE *file,
                        const struct sbus_method *methods)
{
    errno_t ret;
    int i;

    if (methods == NULL) {
        return EOK;
    }

    for (i = 0; methods[i].name != NULL; i++) {
        if (EMPTY(methods[i].annotations)
                && EMPTY(methods[i].arguments->input)
                && EMPTY(methods[i].arguments->output)) {
            WRITE_OR_FAIL(file, ret, done, FMT_METHOD_EMPTY, methods[i].name);
            continue;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_METHOD_OPEN, methods[i].name);

        ret = sbus_introspect_annotations(file, true, methods[i].annotations);
        if (ret != EOK) {
            goto done;
        }

        ret = sbus_introspect_args(file, SBUS_ARG_IN,
                                   methods[i].arguments->input);
        if (ret != EOK) {
            goto done;
        }

        ret = sbus_introspect_args(file, SBUS_ARG_OUT,
                                   methods[i].arguments->output);
        if (ret != EOK) {
            goto done;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_METHOD_CLOSE);
    }

    ret = EOK;

done:
    return ret;
}

static errno_t
sbus_introspect_signals(FILE *file,
                        const struct sbus_signal *signals)
{
    errno_t ret;
    int i;

    if (signals == NULL) {
        return EOK;
    }

    for (i = 0; signals[i].name != NULL; i++) {
        if (EMPTY(signals[i].annotations) && EMPTY(signals[i].arguments)) {
            WRITE_OR_FAIL(file, ret, done, FMT_SIGNAL_EMPTY, signals[i].name);
            continue;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_SIGNAL_OPEN, signals[i].name);

        ret = sbus_introspect_annotations(file, true, signals[i].annotations);
        if (ret != EOK) {
            goto done;
        }

        ret = sbus_introspect_args(file, SBUS_ARG_SIGNAL, signals[i].arguments);
        if (ret != EOK) {
            goto done;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_SIGNAL_CLOSE);
    }

    ret = EOK;

done:
    return ret;
}

struct sbus_introspect_property {
    const char *name;
    const char *type;
    const struct sbus_annotation *annotations;
    enum sbus_property_access access;
};

static void
sbus_introspect_property_set(struct sbus_introspect_property *properties,
                             const struct sbus_property *property)
{
    int i;

    for (i = 0; properties[i].name != NULL; i++) {
        if (strcmp(properties[i].name, property->name) == 0) {
            break;
        }
    }

    /* Name, type and annotation is the same for both getter and setter.
     * We just need to update access mode. */
    properties[i].name = property->name;
    properties[i].type = property->type;
    properties[i].annotations = property->annotations;
    properties[i].access |= property->access;
}

static const char *
sbus_introspect_property_mode(struct sbus_introspect_property *property)
{
    switch (property->access) {
    case SBUS_PROPERTY_READABLE:
        return "read";
    case SBUS_PROPERTY_WRITABLE:
        return "write";
    default:
        return "readwrite";
    }
}

static errno_t
sbus_introspect_properties(FILE *file,
                           const struct sbus_property *properties)
{
    struct sbus_introspect_property *props;
    const char *mode;
    errno_t ret;
    int len;
    int i;

    if (properties == NULL) {
        return EOK;
    }

    for (len = 0; properties[len].name != NULL ; len++);

    props = talloc_zero_array(NULL, struct sbus_introspect_property, len + 1);
    if (props == NULL) {
        return ENOMEM;
    }

    for (i = 0; properties[i].name != NULL; i++) {
        sbus_introspect_property_set(props, &properties[i]);
    }

    for (i = 0; props[i].name != NULL; i++) {
        mode = sbus_introspect_property_mode(&props[i]);

        if (EMPTY(props[i].annotations)) {
            WRITE_OR_FAIL(file, ret, done, FMT_PROPERTY_EMPTY,
                          props[i].name, props[i].type, mode);
            continue;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_PROPERTY_OPEN,
                      props[i].name, props[i].type, mode);

        ret = sbus_introspect_annotations(file, true, props[i].annotations);
        if (ret != EOK) {
            goto done;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_PROPERTY_CLOSE);
    }

    ret = EOK;

done:
    talloc_free(props);
    return ret;
}

static int
sbus_introspect_iface(FILE *file, struct sbus_interface *iface)
{
    errno_t ret;

    WRITE_OR_FAIL(file, ret, done, FMT_IFACE, iface->name);

    ret = sbus_introspect_annotations(file, false, iface->annotations);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_introspect_methods(file, iface->methods);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_introspect_signals(file, iface->signals);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_introspect_properties(file, iface->properties);
    if (ret != EOK) {
        goto done;
    }

    WRITE_OR_FAIL(file, ret, done, FMT_IFACE_CLOSE);

    ret = EOK;

done:
    return ret;
}

static int
sbus_introspect_nodes(FILE *file, const char **nodes)
{
    errno_t ret;
    int i;

    if (nodes == NULL) {
        return EOK;
    }

    for (i = 0; nodes[i] != NULL; i++) {
        WRITE_OR_FAIL(file, ret, done, FMT_CHILD_NODE, nodes[i]);
    }

    ret = EOK;

done:
    return ret;
}

static char *
sbus_introspect(TALLOC_CTX *mem_ctx,
                const char *node,
                const char **nodes,
                struct sbus_interface_list *list)
{
    struct sbus_interface_list *item;
    char *introspection = NULL;
    FILE *memstream;
    char *buffer;
    size_t size;
    errno_t ret;

    memstream = open_memstream(&buffer, &size);
    if (memstream == NULL) {
        goto done;
    }

    WRITE_OR_FAIL(memstream, ret, done, FMT_DOCTYPE);
    WRITE_OR_FAIL(memstream, ret, done, FMT_NODE, node);

    DLIST_FOR_EACH(item, list) {
        ret = sbus_introspect_iface(memstream, item->interface);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = sbus_introspect_nodes(memstream, nodes);
    if (ret != EOK) {
        goto done;
    }

    WRITE_OR_FAIL(memstream, ret, done, FMT_NODE_CLOSE);

    fflush(memstream);
    introspection = talloc_memdup(mem_ctx, buffer, size + 1);

done:
    if (memstream != NULL) {
        fclose(memstream);
        free(buffer);
    }

    return introspection;
}

typedef errno_t
(*sbus_node_factory_sync)(TALLOC_CTX *, const char *, void *, const char ***);

typedef struct tevent_req *
(*sbus_node_factory_send)(TALLOC_CTX *, struct tevent_context *,
                          const char *, void *);

typedef errno_t
(*sbus_node_factory_recv)(TALLOC_CTX *, struct tevent_req *, const char ***);

struct sbus_acquire_nodes_state {
    const char **nodes;
    struct sbus_handler *handler;
};

static void sbus_acquire_nodes_done(struct tevent_req *subreq);

static struct tevent_req *
sbus_acquire_nodes_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sbus_router *router,
                        const char *path)
{
    struct sbus_acquire_nodes_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    struct sbus_node *node;
    sbus_node_factory_sync handler_sync;
    sbus_node_factory_send handler_send;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_acquire_nodes_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    node = sbus_router_nodes_lookup(router->nodes, path);
    if (node == NULL) {
        /* If there is no node factory registered and it is a root path,
         * we return all known paths to the router. */
        if (strcmp(path, "/") == 0) {
            state->nodes = sbus_router_paths_nodes(state, router->paths);
        } else {
            state->nodes = NULL;
        }
        ret = EOK;
        goto done;
    }

    state->handler = &node->factory;

    switch (node->factory.type) {
    case SBUS_HANDLER_SYNC:
        handler_sync = node->factory.sync;
        if (handler_sync == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: sync handler is not specified!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        ret = handler_sync(state, path, node->factory.data, &state->nodes);
        goto done;
    case SBUS_HANDLER_ASYNC:
        handler_send = node->factory.async_send;
        if (handler_send == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: async handler is not specified!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        subreq = handler_send(state, ev, path, node->factory.data);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, sbus_acquire_nodes_done, req);
        break;
    }

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sbus_acquire_nodes_done(struct tevent_req *subreq)
{
    struct sbus_acquire_nodes_state *state;
    sbus_node_factory_recv handler_recv;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_acquire_nodes_state);

    handler_recv = state->handler->async_recv;
    if (handler_recv == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: async handler is not specified!\n");
        tevent_req_error(req, ERR_INTERNAL);
        return;
    }

    ret = handler_recv(state, subreq, &state->nodes);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static errno_t
sbus_acquire_nodes_recv(struct tevent_req *req,
                        const char ***_nodes)
{
    struct sbus_acquire_nodes_state *state;
    state = tevent_req_data(req, struct sbus_acquire_nodes_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    /* We keep the nodes allocated on this request state, so we do not have
     * to expect that state->nodes is a talloc context. This way, it may
     * be static array. */

    *_nodes = state->nodes;

    return EOK;
}

struct sbus_introspection_state {
    struct sbus_interface_list *list;
    const char *introspection;
    const char *path;
};

static void sbus_introspection_done(struct tevent_req *subreq);

static struct tevent_req *
sbus_introspection_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sbus_request *sbus_req,
                        struct sbus_router *router)
{
    struct sbus_introspection_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_introspection_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->path = sbus_req->path;
    state->introspection = NULL;

    ret = sbus_router_paths_supported(state, router->paths,
                                      sbus_req->path, &state->list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire interface list "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    subreq = sbus_acquire_nodes_send(mem_ctx, ev, router, sbus_req->path);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_introspection_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sbus_introspection_done(struct tevent_req *subreq)
{
    struct sbus_introspection_state *state;
    struct tevent_req *req;
    const char **nodes;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_introspection_state);

    /* We keep the nodes allocated on subrequest state, so we do not have
     * to expect that it is a talloc context and allow it also as a static
     * array. Therefore we must free subreq later. */

    ret = sbus_acquire_nodes_recv(subreq, &nodes);
    if (ret != EOK) {
        goto done;
    }

    state->introspection = sbus_introspect(state, state->path,
                                           nodes, state->list);
    if (state->introspection == NULL) {
        ret = ENOMEM;
        goto done;
    }

done:
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static errno_t
sbus_introspection_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        const char **_introspection)
{
    struct sbus_introspection_state *state;
    state = tevent_req_data(req, struct sbus_introspection_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_introspection = talloc_steal(mem_ctx, state->introspection);

    return EOK;
}

errno_t
sbus_register_introspection(struct sbus_router *router)
{

    SBUS_INTERFACE(iface,
        org_freedesktop_DBus_Introspectable,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, org_freedesktop_DBus_Introspectable, Introspect,
                      sbus_introspection_send, sbus_introspection_recv,
                      router)
        ),
        SBUS_WITHOUT_SIGNALS,
        SBUS_WITHOUT_PROPERTIES
    );

    struct sbus_path paths[] = {
        {"/", &iface},
        {"/*", &iface},
        {NULL, NULL}
    };

    return sbus_router_add_path_map(router, paths);
}
