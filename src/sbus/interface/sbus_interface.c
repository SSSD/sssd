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

#include <talloc.h>
#include <string.h>

#include "sbus/sbus_annotations.h"
#include "sbus/sbus_interface_declarations.h"

static struct sbus_handler
sbus_sync_handler(sbus_handler_sync_fn handler,
                  sbus_handler_data data)
{
    struct sbus_handler object = {
        .type = SBUS_HANDLER_SYNC,
        .sync = handler,
        .data = data
    };

    return object;
}

static struct sbus_handler
sbus_async_handler(sbus_handler_send_fn handler_send,
                   sbus_handler_recv_fn handler_recv,
                   sbus_handler_data data)
{
    struct sbus_handler object = {
        .type = SBUS_HANDLER_ASYNC,
        .async_send = handler_send,
        .async_recv = handler_recv,
        .data = data
    };

    return object;
}

struct sbus_method
sbus_method_sync(const char *name,
                 const struct sbus_method_arguments *arguments,
                 const struct sbus_annotation *annotations,
                 sbus_invoker_issue invoker_issue,
                 sbus_invoker_keygen invoker_keygen,
                 sbus_handler_sync_fn handler,
                 sbus_handler_data data)
{
    struct sbus_method object = {
        .name = name,
        .annotations = annotations,
        .invoker = {.issue = invoker_issue, .keygen = invoker_keygen},
        .handler = sbus_sync_handler(handler, data),
        .arguments = arguments
    };

    return object;
}

struct sbus_method
sbus_method_async(const char *name,
                  const struct sbus_method_arguments *arguments,
                  const struct sbus_annotation *annotations,
                  sbus_invoker_issue invoker_issue,
                  sbus_invoker_keygen invoker_keygen,
                  sbus_handler_send_fn handler_send,
                  sbus_handler_recv_fn handler_recv,
                  sbus_handler_data data)
{
    struct sbus_method object = {
        .name = name,
        .annotations = annotations,
        .invoker = {.issue = invoker_issue, .keygen = invoker_keygen},
        .handler = sbus_async_handler(handler_send, handler_recv, data),
        .arguments = arguments
    };

    return object;
}

static struct sbus_method *
sbus_method_copy(TALLOC_CTX *mem_ctx,
                 const struct sbus_method *input)
{
    struct sbus_method *copy;
    size_t count;

    for (count = 0; input[count].name != NULL; count++);

    copy = talloc_zero_array(mem_ctx, struct sbus_method, count + 1);
    if (copy == NULL) {
        return NULL;
    }

    /* All data is either pointer to a static data or it is not a pointer.
     * We can just copy it. */
    memcpy(copy, input, sizeof(struct sbus_method) * (count + 1));

    return copy;
}

struct sbus_signal
sbus_signal(const char *name,
            const struct sbus_argument *arguments,
            const struct sbus_annotation *annotations)
{
    struct sbus_signal object = {
        .name = name,
        .arguments = arguments,
        .annotations = annotations
    };

    return object;
}

static struct sbus_signal *
sbus_signal_copy(TALLOC_CTX *mem_ctx,
                 const struct sbus_signal *input)
{
    struct sbus_signal *copy;
    size_t count;

    for (count = 0; input[count].name != NULL; count++);

    copy = talloc_zero_array(mem_ctx, struct sbus_signal, count + 1);
    if (copy == NULL) {
        return NULL;
    }

    /* All data is either pointer to a static data or it is not a pointer.
     * We can just copy it. */
    memcpy(copy, input, sizeof(struct sbus_signal) * (count + 1));

    return copy;
}

struct sbus_property
sbus_property_sync(const char *name,
                   const char *type,
                   enum sbus_property_access access,
                   const struct sbus_annotation *annotations,
                   sbus_invoker_issue invoker_issue,
                   sbus_handler_sync_fn handler,
                   sbus_handler_data data)
{
    struct sbus_property object = {
        .name = name,
        .type = type,
        .access = access,
        .annotations = annotations,
        .invoker = {.issue = invoker_issue, .keygen = NULL},
        .handler = sbus_sync_handler(handler, data)
    };

    return object;
}

struct sbus_property
sbus_property_async(const char *name,
                    const char *type,
                    enum sbus_property_access access,
                    const struct sbus_annotation *annotations,
                    sbus_invoker_issue invoker_issue,
                    sbus_handler_send_fn handler_send,
                    sbus_handler_recv_fn handler_recv,
                    sbus_handler_data data)
{
    struct sbus_property object = {
        .name = name,
        .type = type,
        .access = access,
        .annotations = annotations,
        .invoker = {.issue = invoker_issue, .keygen = NULL},
        .handler = sbus_async_handler(handler_send, handler_recv, data)
    };

    return object;
}

static struct sbus_property *
sbus_property_copy(TALLOC_CTX *mem_ctx,
                   const struct sbus_property *input)
{
    struct sbus_property *copy;
    size_t count;

    for (count = 0; input[count].name != NULL; count++);

    copy = talloc_zero_array(mem_ctx, struct sbus_property, count + 1);
    if (copy == NULL) {
        return NULL;
    }

    /* All data is either pointer to a static data or it is not a pointer.
     * We can just copy it. */
    memcpy(copy, input, sizeof(struct sbus_property) * (count + 1));

    return copy;
}

struct sbus_interface
sbus_interface(const char *name,
               const struct sbus_annotation *annotations,
               const struct sbus_method *methods,
               const struct sbus_signal *signals,
               const struct sbus_property *properties)
{
    struct sbus_interface object = {
        .name = name,
        .annotations = annotations,
        .methods = methods,
        .signals = signals,
        .properties = properties
    };

    return object;
}

struct sbus_interface *
sbus_interface_copy(TALLOC_CTX *mem_ctx,
                    const struct sbus_interface *input)
{
    struct sbus_interface *copy;

    copy = talloc_zero(mem_ctx, struct sbus_interface);
    if (copy == NULL) {
        return NULL;
    }

    /* Name and annotations are pointer to static data, no need to copy them. */
    copy->name = input->name;
    copy->annotations = input->annotations;

    copy->methods = sbus_method_copy(copy, input->methods);
    copy->signals = sbus_signal_copy(copy, input->signals);
    copy->properties = sbus_property_copy(copy, input->properties);

    if (copy->methods == NULL || copy->signals == NULL
            || copy->properties == NULL) {
        talloc_free(copy);
        return NULL;
    }

    return copy;
}

const struct sbus_method *
sbus_interface_find_method(struct sbus_interface *iface,
                           const char *method_name)
{
    unsigned int i;

    for (i = 0; iface->methods[i].name != NULL; i++) {
        if (strcmp(iface->methods[i].name, method_name) == 0) {
            return &iface->methods[i];
        }
    }

    return NULL;
}

const struct sbus_property *
sbus_interface_find_property(struct sbus_interface *iface,
                             enum sbus_property_access access,
                             const char *property_name)
{
    unsigned int i;

    for (i = 0; iface->properties[i].name != NULL; i++) {
        if (iface->properties[i].access != access) {
            continue;
        }

        if (strcmp(iface->properties[i].name, property_name) == 0) {
            return &iface->properties[i];
        }
    }

    return NULL;
}

struct sbus_listener
sbus_listener_sync(const char *interface,
                   const char *signal_name,
                   const char *object_path,
                   sbus_invoker_issue invoker_issue,
                   sbus_invoker_keygen invoker_keygen,
                   sbus_handler_sync_fn handler,
                   sbus_handler_data data)
{
    struct sbus_listener object = {
        .interface = interface,
        .signal_name = signal_name,
        .object_path = object_path,
        .invoker = {.issue = invoker_issue, .keygen = invoker_keygen},
        .handler = sbus_sync_handler(handler, data)
    };

    return object;
}

struct sbus_listener
sbus_listener_async(const char *interface,
                    const char *signal_name,
                    const char *object_path,
                    sbus_invoker_issue invoker_issue,
                    sbus_invoker_keygen invoker_keygen,
                    sbus_handler_send_fn handler_send,
                    sbus_handler_recv_fn handler_recv,
                    sbus_handler_data data)
{
    struct sbus_listener object = {
        .interface = interface,
        .signal_name = signal_name,
        .object_path = object_path,
        .invoker = {.issue = invoker_issue, .keygen = invoker_keygen},
        .handler = sbus_async_handler(handler_send, handler_recv, data)
    };

    return object;
}

struct sbus_listener *
sbus_listener_copy(TALLOC_CTX *mem_ctx,
                   const struct sbus_listener *input)
{
    /* All data is either pointer to a static data or it is not a pointer.
     * We can just copy it. */
    return talloc_memdup(mem_ctx, input, sizeof(struct sbus_listener));
}

struct sbus_node
sbus_node_sync(const char *path,
               sbus_handler_sync_fn factory,
               sbus_handler_data data)
{
    struct sbus_node object = {
        .path = path,
        .factory = sbus_sync_handler(factory, data)
    };

    return object;
}

struct sbus_node
sbus_node_async(const char *path,
                sbus_handler_send_fn factory_send,
                sbus_handler_recv_fn factory_recv,
                sbus_handler_data data)
{
    struct sbus_node object = {
        .path = path,
        .factory = sbus_async_handler(factory_send, factory_recv, data)
    };

    return object;
}

struct sbus_node *
sbus_node_copy(TALLOC_CTX *mem_ctx,
               struct sbus_node *input)
{
    struct sbus_node *copy;

    copy = talloc_zero(mem_ctx, struct sbus_node);
    if (copy == NULL) {
        return NULL;
    }

    copy->path = talloc_strdup(copy, input->path);
    if (copy->path == NULL) {
        talloc_free(copy);
        return NULL;
    }

    copy->factory = input->factory;

    return copy;
}

const char *
sbus_annotation_find(const struct sbus_annotation *annotations,
                     const char *name)
{
    int i;

    if (annotations == NULL) {
        return NULL;
    }

    for (i = 0; annotations[i].name != NULL; i++) {
        if (strcmp(annotations[i].name, name) == 0) {
            return annotations[i].value;
        }
    }

    return NULL;
}

bool
sbus_annotation_find_as_bool(const struct sbus_annotation *annotations,
                             const char *name)
{
    const char *value;

    value = sbus_annotation_find(annotations, name);

    if (value != NULL && strcasecmp(value, "true") == 0) {
        return true;
    }

    return false;
}

static void
sbus_warn_deprecated(const struct sbus_annotation *annotations,
                     const char *iface_name,
                     const char *method_name)
{
    const char *by;
    const char *member;
    const char *dot;

    if (annotations == NULL) {
        return;
    }

    if (sbus_annotation_find_as_bool(annotations, SBUS_ANNOTATION_DEPRECATED)) {
        member = method_name == NULL ? "" : method_name;
        dot = method_name == NULL ? "" : ".";

        by = sbus_annotation_find(annotations, SBUS_ANNOTATION_DEPRECATED_BY);
        if (by != NULL) {
            DEBUG(SSSDBG_IMPORTANT_INFO, "%s%s%s is deprecated by %s\n",
                  iface_name, dot, member, by);
        } else {
            DEBUG(SSSDBG_IMPORTANT_INFO, "%s%s%s is deprecated\n",
                  iface_name, dot, member);
        }
    }
}

void
sbus_annotation_warn(const struct sbus_interface *iface,
                     const struct sbus_method *method)
{
    sbus_warn_deprecated(iface->annotations, iface->name, NULL);
    sbus_warn_deprecated(method->annotations, iface->name, method->name);
}
