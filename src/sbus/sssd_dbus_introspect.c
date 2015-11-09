/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

    SBUS: Interface introspection

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

#include "config.h"

#include <stdio.h>

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_private.h"

#define FMT_DOCTYPE \
    "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" \
    " \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"

#define FMT_NODE         "<node name=\"%s\">\n"
#define FMT_IFACE        "  <interface name=\"%s\">\n"
#define FMT_METHOD       "    <method name=\"%s\">\n"
#define FMT_METHOD_NOARG "    <method name=\"%s\" />\n"
#define FMT_METHOD_ARG   "      <arg type=\"%s\" name=\"%s\" direction=\"%s\" />\n"
#define FMT_METHOD_CLOSE "    </method>\n"
#define FMT_SIGNAL       "    <signal name=\"%s\">\n"
#define FMT_SIGNAL_NOARG "    <signal name=\"%s\" />\n"
#define FMT_SIGNAL_ARG   "      <arg type=\"%s\" name=\"%s\" />\n"
#define FMT_SIGNAL_CLOSE "    </signal>\n"
#define FMT_PROPERTY     "    <property name=\"%s\" type=\"%s\" access=\"%s\" />\n"
#define FMT_IFACE_CLOSE  "  </interface>\n"
#define FMT_CHILD_NODE   "  <node name=\"%s\" />\n"
#define FMT_NODE_CLOSE   "</node>\n"

#define WRITE_OR_FAIL(file, ret, label, fmt, ...) do { \
    ret = fprintf(file, fmt, ##__VA_ARGS__); \
    if (ret < 0) { \
        ret = EIO; \
        goto label; \
    } \
} while (0)

#define METHOD_HAS_ARGS(m) ((m)->in_args != NULL || (m)->out_args != NULL)
#define SIGNAL_HAS_ARGS(s) ((s)->args != NULL)

enum sbus_arg_type {
    SBUS_ARG_IN,
    SBUS_ARG_OUT,
    SBUS_ARG_SIGNAL
};

static int
iface_Introspect_finish(struct sbus_request *req, const char *arg_data)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_STRING, &arg_data,
                                         DBUS_TYPE_INVALID);
}

struct iface_introspectable {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*Introspect)(struct sbus_request *req, void *data);
};

static int sbus_introspect(struct sbus_request *sbus_req, void *pvt);

struct sbus_vtable *
sbus_introspect_vtable(void)
{
    static const struct sbus_arg_meta iface_out[] = {
        {"data", "s"},
        {NULL, NULL}
    };

    static const struct sbus_method_meta iface_methods[] = {
        {"Introspect", NULL, iface_out,
         offsetof(struct iface_introspectable, Introspect), NULL},
        {NULL, }
    };

    static const struct sbus_interface_meta iface_meta = {
        "org.freedesktop.DBus.Introspectable", /* name */
        iface_methods,
        NULL, /* no signals */
        NULL, /* no properties */
        NULL, /* no GetAll invoker */
    };

    static struct iface_introspectable iface = {
        { &iface_meta, 0 },
        .Introspect = sbus_introspect
    };

    return &iface.vtable;
}

static int
sbus_introspect_generate_args(FILE *file,
                              const struct sbus_arg_meta *args,
                              enum sbus_arg_type type)
{
    const struct sbus_arg_meta *arg;
    int ret;
    int i;

    if (args == NULL) {
        return EOK;
    }

    for (i = 0; args[i].name != NULL; i++) {
        arg = &args[i];

        switch (type) {
        case SBUS_ARG_SIGNAL:
            WRITE_OR_FAIL(file, ret, done, FMT_SIGNAL_ARG,
                          arg->type, arg->name);
            break;
        case SBUS_ARG_IN:
            WRITE_OR_FAIL(file, ret, done, FMT_METHOD_ARG,
                          arg->type, arg->name, "in");
            break;
        case SBUS_ARG_OUT:
            WRITE_OR_FAIL(file, ret, done, FMT_METHOD_ARG,
                          arg->type, arg->name, "out");
            break;
        }
    }

    ret = EOK;

done:
    return ret;
}

#define sbus_introspect_generate_in_args(file, args) \
    sbus_introspect_generate_args(file, args, SBUS_ARG_IN)

#define sbus_introspect_generate_out_args(file, args) \
    sbus_introspect_generate_args(file, args, SBUS_ARG_OUT)

#define sbus_introspect_generate_signal_args(file, args) \
    sbus_introspect_generate_args(file, args, SBUS_ARG_SIGNAL)

static int
sbus_introspect_generate_methods(FILE *file,
                                 const struct sbus_method_meta *methods)
{
    const struct sbus_method_meta *method;
    int ret;
    int i;

    if (methods == NULL) {
        return EOK;
    }

    for (i = 0; methods[i].name != NULL; i++) {
        method = &methods[i];

        if (!METHOD_HAS_ARGS(method)) {
            WRITE_OR_FAIL(file, ret, done, FMT_METHOD_NOARG, method->name);
            continue;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_METHOD, method->name);

        ret = sbus_introspect_generate_in_args(file, method->in_args);
        if (ret != EOK) {
            goto done;
        }

        ret = sbus_introspect_generate_out_args(file, method->out_args);
        if (ret != EOK) {
            goto done;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_METHOD_CLOSE);
    }

    ret = EOK;

done:
    return ret;
}

static int
sbus_introspect_generate_signals(FILE *file,
                                 const struct sbus_signal_meta *signals)
{
    const struct sbus_signal_meta *a_signal;
    int ret;
    int i;

    if (signals == NULL) {
        return EOK;
    }

    for (i = 0; signals[i].name != NULL; i++) {
        a_signal = &signals[i];

        if (!SIGNAL_HAS_ARGS(a_signal)) {
            WRITE_OR_FAIL(file, ret, done, FMT_SIGNAL_NOARG, a_signal->name);
            continue;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_SIGNAL, a_signal->name);

        ret = sbus_introspect_generate_signal_args(file, a_signal->args);
        if (ret != EOK) {
            goto done;
        }

        WRITE_OR_FAIL(file, ret, done, FMT_SIGNAL_CLOSE);
    }

    ret = EOK;

done:
    return ret;
}

static int
sbus_introspect_generate_properties(FILE *file,
                                    const struct sbus_property_meta *props)
{
    const struct sbus_property_meta *prop;
    const char *access_mode;
    int ret;
    int i;

    if (props == NULL) {
        return EOK;
    }

    for (i = 0; props[i].name != NULL; i++) {
        prop = &props[i];

        access_mode = prop->flags & SBUS_PROPERTY_WRITABLE
                      ? "readwrite" : "read";
        WRITE_OR_FAIL(file, ret, done, FMT_PROPERTY,
                   prop->name, prop->type, access_mode);
    }

    ret = EOK;

done:
    return ret;
}

static int
sbus_introspect_generate_iface(FILE *file, struct sbus_interface *iface)
{
    const struct sbus_interface_meta *meta;
    int ret;

    meta = iface->vtable->meta;

    WRITE_OR_FAIL(file, ret, done, FMT_IFACE, meta->name);

    ret = sbus_introspect_generate_methods(file, meta->methods);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_introspect_generate_signals(file, meta->signals);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_introspect_generate_properties(file, meta->properties);
    if (ret != EOK) {
        goto done;
    }

    WRITE_OR_FAIL(file, ret, done, FMT_IFACE_CLOSE);

    ret = EOK;

done:
    return ret;
}

static int
sbus_introspect_generate_nodes(FILE *file, const char **nodes)
{
    int ret;
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
sbus_introspect_generate(TALLOC_CTX *mem_ctx,
                         const char *node,
                         const char **nodes,
                         struct sbus_interface_list *list)
{
    struct sbus_interface_list *item;
    char *introspect = NULL;
    FILE *memstream;
    char *buffer;
    size_t size;
    int ret;

    memstream = open_memstream(&buffer, &size);
    if (memstream == NULL) {
        goto done;
    }

    WRITE_OR_FAIL(memstream, ret, done, FMT_DOCTYPE);
    WRITE_OR_FAIL(memstream, ret, done, FMT_NODE, node);

    DLIST_FOR_EACH(item, list) {
        ret = sbus_introspect_generate_iface(memstream, item->interface);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = sbus_introspect_generate_nodes(memstream, nodes);
    if (ret != EOK) {
        goto done;
    }

    WRITE_OR_FAIL(memstream, ret, done, FMT_NODE_CLOSE);

    fflush(memstream);
    introspect = talloc_memdup(mem_ctx, buffer, size + 1);

    DEBUG(SSSDBG_TRACE_ALL, "Introspection: \n%s\n", introspect);

done:
    if (memstream != NULL) {
        fclose(memstream);
        free(buffer);
    }

    return introspect;
}

static int
sbus_introspect(struct sbus_request *sbus_req, void *pvt)
{
    DBusError *error;
    struct sbus_interface_list *list;
    struct sbus_connection *conn;
    const char **nodes;
    char *introspect;
    errno_t ret;

    conn = talloc_get_type(pvt, struct sbus_connection);

    ret = sbus_opath_hash_lookup_supported(sbus_req, conn->managed_paths,
                                           sbus_req->path, &list);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED,
                               "%s", sss_strerror(ret));
        return sbus_request_fail_and_finish(sbus_req, error);
    }

    nodes = sbus_nodes_hash_lookup(sbus_req, conn->nodes_fns, sbus_req->path);

    introspect = sbus_introspect_generate(sbus_req, sbus_req->path,
                                          nodes, list);
    if (introspect == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED,
                               "%s", sss_strerror(ret));
        return sbus_request_fail_and_finish(sbus_req, error);
    }

    return iface_Introspect_finish(sbus_req, introspect);
}
