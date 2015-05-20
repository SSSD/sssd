/*
    Authors:
        Stef Walter <stefw@redhat.com>
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

#include "config.h"

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_private.h"
#include "sbus/sssd_dbus_invokers.h"

#define CHECK_SIGNATURE_OR_FAIL(req, error, label, exp) do { \
    const char *__sig; \
    __sig = dbus_message_get_signature(req->message); \
    if (strcmp(__sig, exp) != 0) { \
        error = sbus_error_new(req, DBUS_ERROR_INVALID_ARGS, \
               "Invalid arguments: expected \"%s\", got \"%s\"", exp, __sig); \
        goto label; \
    } \
} while (0)

struct iface_properties {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn Get;
    sbus_msg_handler_fn Set;
    sbus_msg_handler_fn GetAll;
};

static int sbus_properties_get(struct sbus_request *sbus_req, void *pvt);
static int sbus_properties_set(struct sbus_request *sbus_req, void *pvt);
static int sbus_properties_get_all(struct sbus_request *sbus_req, void *pvt);

struct sbus_vtable *
sbus_properties_vtable(void)
{
    /* Properties.Get */
    static const struct sbus_arg_meta get_args_in[] = {
        { "interface_name", "s" },
        { "property_name", "s" },
        { NULL, }
    };

    static const struct sbus_arg_meta get_args_out[] = {
        { "value", "v" },
        { NULL, }
    };

    /* Properties.Set */
    static const struct sbus_arg_meta set_args_in[] = {
        { "interface_name", "s" },
        { "property_name", "s" },
        { "value", "v" },
        { NULL, }
    };

    /* Properties.GetAll */
    static const struct sbus_arg_meta getall_args_in[] = {
        { "interface_name", "s" },
        { NULL, }
    };

    static const struct sbus_arg_meta getall_args_out[] = {
        { "props", "a{sv}" },
        { NULL, }
    };

    static const struct sbus_method_meta iface_methods[] = {
        {
            "Get", /* name */
            get_args_in,
            get_args_out,
            offsetof(struct iface_properties, Get),
            NULL, /* no invoker */
        },
        {
            "Set", /* name */
            set_args_in,
            NULL, /* no out_args */
            offsetof(struct iface_properties, Set),
            NULL, /* no invoker */
        },
        {
            "GetAll", /* name */
            getall_args_in,
            getall_args_out,
            offsetof(struct iface_properties, GetAll),
            NULL, /* no invoker */
        },
        { NULL, }
    };

    static const struct sbus_interface_meta iface_meta = {
        "org.freedesktop.DBus.Properties", /* name */
        iface_methods,
        NULL, /* no signals */
        NULL, /* no properties */
        NULL, /* no GetAll invoker */
    };

    static struct iface_properties iface = {
        { &iface_meta, 0 },
        .Get = sbus_properties_get,
        .Set = sbus_properties_set,
        .GetAll = sbus_properties_get_all,
    };

    return &iface.vtable;
}

static struct sbus_request *
sbus_properties_subreq(struct sbus_request *sbus_req,
                       struct sbus_interface *iface)
{
    struct sbus_request *sbus_subreq;

    /* Create new sbus_request to so it contain given interface. The
     * old sbus_request talloc context will be attached to this new one
     * so it is freed together. */
    sbus_subreq = sbus_new_request(sbus_req->conn, iface, sbus_req->message);
    if (sbus_subreq == NULL) {
        return NULL;
    }

    talloc_steal(sbus_subreq, sbus_req);

    return sbus_subreq;
}

static int sbus_properties_get(struct sbus_request *sbus_req, void *pvt)
{
    DBusError *error;
    struct sbus_request *sbus_subreq;
    struct sbus_connection *conn;
    struct sbus_interface *iface;
    const struct sbus_property_meta *prop;
    sbus_msg_handler_fn handler_fn;
    const char *interface_name;
    const char *property_name;
    bool bret;

    conn = talloc_get_type(pvt, struct sbus_connection);

    CHECK_SIGNATURE_OR_FAIL(sbus_req, error, fail, "ss");

    bret = sbus_request_parse_or_finish(sbus_req,
                                        DBUS_TYPE_STRING, &interface_name,
                                        DBUS_TYPE_STRING, &property_name,
                                        DBUS_TYPE_INVALID);
    if (!bret) {
        /* request was handled */
        return EOK;
    }

    /* find interface */
    iface = sbus_opath_hash_lookup_iface(conn->managed_paths, sbus_req->path,
                                         interface_name);
    if (iface == NULL) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_UNKNOWN_INTERFACE,
                               "Unknown interface");
        goto fail;
    }

    /* find property handler */
    prop = sbus_meta_find_property(iface->vtable->meta, property_name);
    if (prop == NULL) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_UNKNOWN_PROPERTY,
                               "Unknown property");
        goto fail;
    }

    if (!(prop->flags & SBUS_PROPERTY_READABLE)) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_ACCESS_DENIED,
                               "Property is not readable");
        goto fail;
    }

    handler_fn = VTABLE_FUNC(iface->vtable, prop->vtable_offset_get);
    if (handler_fn == NULL) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_NOT_SUPPORTED,
                               "Getter is not implemented");
        goto fail;
    }

    sbus_subreq = sbus_properties_subreq(sbus_req, iface);
    if (sbus_subreq == NULL) {
        error = NULL;
        goto fail;
    }

    sbus_invoke_get(sbus_subreq, prop->type,
                    prop->invoker_get, handler_fn);
    return EOK;

fail:
    return sbus_request_fail_and_finish(sbus_req, error);
}

/*
 * We don't implement any handlers for setters yet. This code is for future
 * use and it is likely it will need some changes.
 */
static int sbus_properties_set(struct sbus_request *sbus_req, void *pvt)
{
    DBusError *error;
    DBusMessageIter iter;
    DBusMessageIter iter_variant;
    struct sbus_request *sbus_subreq;
    struct sbus_connection *conn;
    struct sbus_interface *iface;
    const struct sbus_property_meta *prop;
    const char *interface_name;
    const char *property_name;
    const char *variant_sig;
    sbus_msg_handler_fn handler_fn;

    conn = talloc_get_type(pvt, struct sbus_connection);

    CHECK_SIGNATURE_OR_FAIL(sbus_req, error, fail, "ssv");

    /* get interface and property */
    dbus_message_iter_init(sbus_req->message, &iter);
    dbus_message_iter_get_basic(&iter, &interface_name);
    dbus_message_iter_next(&iter);
    dbus_message_iter_get_basic(&iter, &property_name);
    dbus_message_iter_next(&iter);

    /* find interface */
    iface = sbus_opath_hash_lookup_iface(conn->managed_paths, sbus_req->path,
                                         interface_name);
    if (iface == NULL) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_UNKNOWN_INTERFACE,
                               "Unknown interface");
        goto fail;
    }

    /* find property handler */
    prop = sbus_meta_find_property(iface->vtable->meta, property_name);
    if (prop == NULL) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_UNKNOWN_PROPERTY,
                               "Unknown property");
        goto fail;
    }

    if (!(prop->flags & SBUS_PROPERTY_WRITABLE)) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_ACCESS_DENIED,
                               "Property is not writable");
        goto fail;
    }

    handler_fn = VTABLE_FUNC(iface->vtable, prop->vtable_offset_set);
    if (handler_fn == NULL) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_NOT_SUPPORTED,
                               "Setter is not implemented");
        goto fail;
    }

    /* check variant type */
    dbus_message_iter_recurse(&iter, &iter_variant);
    variant_sig = dbus_message_iter_get_signature(&iter_variant);
    if (strcmp(prop->type, variant_sig) != 0) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_INVALID_ARGS,
                               "Invalid data type for property");
        goto fail;
    }

    sbus_subreq = sbus_properties_subreq(sbus_req, iface);
    if (sbus_subreq == NULL) {
        error = NULL;
        goto fail;
    }

    sbus_request_invoke_or_finish(sbus_subreq, handler_fn,
                                  iface->handler_data, prop->invoker_set);

    return EOK;

fail:
    return sbus_request_fail_and_finish(sbus_req, error);
}

static int sbus_properties_get_all(struct sbus_request *sbus_req, void *pvt)
{
    DBusError *error;
    struct sbus_request *sbus_subreq;
    struct sbus_connection *conn;
    struct sbus_interface *iface;
    const char *interface_name;
    bool bret;

    conn = talloc_get_type(pvt, struct sbus_connection);

    CHECK_SIGNATURE_OR_FAIL(sbus_req, error, fail, "s");

    bret = sbus_request_parse_or_finish(sbus_req,
                                        DBUS_TYPE_STRING, &interface_name,
                                        DBUS_TYPE_INVALID);
    if (!bret) {
        /* request was handled */
        return EOK;
    }

    /* find interface */
    iface = sbus_opath_hash_lookup_iface(conn->managed_paths, sbus_req->path,
                                         interface_name);
    if (iface == NULL) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_UNKNOWN_INTERFACE,
                               "Unknown interface");
        goto fail;
    }

    sbus_subreq = sbus_properties_subreq(sbus_req, iface);
    if (sbus_subreq == NULL) {
        error = NULL;
        goto fail;
    }

    if (iface->vtable->meta->invoker_get_all == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No get all invoker set,"
              "using the default one\n");

        sbus_invoke_get_all(sbus_req);
    } else {
        iface->vtable->meta->invoker_get_all(sbus_subreq);
    }

    return EOK;

fail:
    return sbus_request_fail_and_finish(sbus_req, error);
}
