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

#include <dbus/dbus.h>
#include <stdlib.h>
#include <string.h>

#include "lib/sifp/sss_sifp.h"
#include "lib/sifp/sss_sifp_dbus.h"
#include "lib/sifp/sss_sifp_private.h"

#define DBUS_IFACE_PROP "org.freedesktop.DBus.Properties"

static void * default_alloc(size_t size, void *pvt)
{
    return malloc(size);
}

static void default_free(void *ptr, void *pvt)
{
    free(ptr);
}

static DBusMessage * sss_sifp_create_prop_msg(const char *object_path,
                                              const char *method)
{
    return sss_sifp_create_message(object_path, DBUS_IFACE_PROP, method);
}

sss_sifp_error
sss_sifp_init(sss_sifp_ctx **_ctx)
{
    return sss_sifp_init_ex(NULL, default_alloc, default_free, _ctx);
}

sss_sifp_error
sss_sifp_init_ex(void *alloc_pvt,
                 sss_sifp_alloc_func *alloc_func,
                 sss_sifp_free_func *free_func,
                 sss_sifp_ctx **_ctx)
{
    sss_sifp_ctx *ctx = NULL;
    DBusConnection *conn = NULL;
    DBusError dbus_error;
    sss_sifp_error ret;

    if (_ctx == NULL || alloc_func == NULL || free_func == NULL) {
        return SSS_SIFP_INVALID_ARGUMENT;
    }

    dbus_error_init(&dbus_error);

    ctx = alloc_func(sizeof(sss_sifp_ctx), alloc_pvt);
    if (ctx == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    ctx->conn = NULL;
    ctx->alloc_fn = alloc_func;
    ctx->free_fn = free_func;
    ctx->alloc_pvt = alloc_pvt;
    ctx->io_error = alloc_func(sizeof(DBusError), alloc_pvt);
    if (ctx->io_error == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    *_ctx = ctx;

    dbus_error_init(ctx->io_error);

    conn = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        sss_sifp_set_io_error(ctx, &dbus_error);
        ret = SSS_SIFP_IO_ERROR;
        goto done;
    }

    ctx->conn = conn;

    ret = SSS_SIFP_OK;

done:
    if (ret != SSS_SIFP_OK) {
        sss_sifp_free(&ctx);
    }

    dbus_error_free(&dbus_error);
    return ret;
}

const char *
sss_sifp_get_last_io_error_name(sss_sifp_ctx *ctx)
{
    if (ctx == NULL) {
        return "Invalid sss_sifp context";
    }

    if (!dbus_error_is_set(ctx->io_error)) {
        return NULL;
    }

    return ctx->io_error->name;
}

const char *
sss_sifp_get_last_io_error_message(sss_sifp_ctx *ctx)
{
    if (ctx == NULL) {
        return "Invalid sss_sifp context";
    }

    if (!dbus_error_is_set(ctx->io_error)) {
        return NULL;
    }

    return ctx->io_error->message;
}

const char *
sss_sifp_strerr(sss_sifp_error error)
{
    switch (error) {
    case SSS_SIFP_OK:
        return "Success";
    case SSS_SIFP_OUT_OF_MEMORY:
        return "Out of memory";
    case SSS_SIFP_INVALID_ARGUMENT:
        return "Invalid argument";
    case SSS_SIFP_IO_ERROR:
        return "Communication error";
    case SSS_SIFP_INTERNAL_ERROR:
        return "Internal error";
    case SSS_SIFP_NOT_SUPPORTED:
        return "Not supported";
    case SSS_SIFP_ATTR_MISSING:
        return "Attribute does not exist";
    case SSS_SIFP_ATTR_NULL:
        return "Attribute does not have any value set";
    case SSS_SIFP_INCORRECT_TYPE:
        return "Incorrect type";
    case SSS_SIFP_ERROR_SENTINEL:
        return "Invalid error code";
    }

    return "Invalid error code";
}

sss_sifp_error
sss_sifp_fetch_attr(sss_sifp_ctx *ctx,
                    const char *object_path,
                    const char *interface,
                    const char *name,
                    sss_sifp_attr ***_attrs)
{
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    dbus_bool_t bret;
    sss_sifp_error ret;

    if (ctx == NULL || object_path == NULL || interface == NULL
            || name == NULL || _attrs == NULL) {
        return SSS_SIFP_INVALID_ARGUMENT;
    }

    /* Message format:
     * In: string:interface
     * In: string:attribute
     * Out: variant(misc:value)
     */

    msg = sss_sifp_create_prop_msg(object_path, "Get");
    if (msg == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    bret = dbus_message_append_args(msg, DBUS_TYPE_STRING, &interface,
                                         DBUS_TYPE_STRING, &name,
                                         DBUS_TYPE_INVALID);
    if (!bret) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    ret = sss_sifp_send_message(ctx, msg, &reply);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    ret = sss_sifp_parse_attr(ctx, name, reply, _attrs);

done:
    if (msg != NULL) {
        dbus_message_unref(msg);
    }

    if (reply != NULL) {
        dbus_message_unref(reply);
    }

    return ret;
}

sss_sifp_error
sss_sifp_fetch_all_attrs(sss_sifp_ctx *ctx,
                         const char *object_path,
                         const char *interface,
                         sss_sifp_attr ***_attrs)
{
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    dbus_bool_t bret;
    sss_sifp_error ret;

    if (ctx == NULL || object_path == NULL || interface == NULL
            || _attrs == NULL) {
        return SSS_SIFP_INVALID_ARGUMENT;
    }

    msg = sss_sifp_create_prop_msg(object_path, "GetAll");
    if (msg == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    bret = dbus_message_append_args(msg, DBUS_TYPE_STRING, &interface,
                                         DBUS_TYPE_INVALID);
    if (!bret) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    ret = sss_sifp_send_message(ctx, msg, &reply);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    ret = sss_sifp_parse_attr_list(ctx, reply, _attrs);

done:
    if (msg != NULL) {
        dbus_message_unref(msg);
    }

    if (reply != NULL) {
        dbus_message_unref(reply);
    }

    return ret;
}

sss_sifp_error
sss_sifp_fetch_object(sss_sifp_ctx *ctx,
                      const char *object_path,
                      const char *interface,
                      sss_sifp_object **_object)
{
    sss_sifp_object *object = NULL;
    sss_sifp_attr **attrs = NULL;
    const char *name = NULL;
    sss_sifp_error ret;

    if (ctx == NULL || object_path == NULL || interface == NULL
            || _object == NULL) {
        return SSS_SIFP_INVALID_ARGUMENT;
    }

    ret = sss_sifp_fetch_all_attrs(ctx, object_path, interface, &attrs);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    ret = sss_sifp_find_attr_as_string(attrs, "name", &name);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    object = _alloc_zero(ctx, sss_sifp_object, 1);
    if (object == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    object->attrs = attrs;

    object->name = sss_sifp_strdup(ctx, name);
    if (object->name == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    object->object_path = sss_sifp_strdup(ctx, object_path);
    if (object->object_path == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    object->interface = sss_sifp_strdup(ctx, interface);
    if (object->interface == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    *_object = object;

    ret = SSS_SIFP_OK;

done:
    if (ret != SSS_SIFP_OK) {
        sss_sifp_free_object(ctx, &object);
    }

    return ret;
}

void
sss_sifp_free(sss_sifp_ctx **_ctx)
{
    sss_sifp_ctx *ctx = NULL;

    if (_ctx == NULL || *_ctx == NULL) {
        return;
    }

    ctx = *_ctx;

    if (ctx->conn != NULL) {
        dbus_connection_unref(ctx->conn);
    }

    if (ctx->io_error != NULL) {
        dbus_error_free(ctx->io_error);
        _free(ctx, ctx->io_error);
    }

    _free(ctx, ctx);
    *_ctx = NULL;

    return;
}

void
sss_sifp_free_attrs(sss_sifp_ctx *ctx,
                    sss_sifp_attr ***_attrs)
{
    sss_sifp_attr **attrs = NULL;
    unsigned int i, j;

    if (_attrs == NULL || *_attrs == NULL) {
        return;
    }

    attrs = *_attrs;

    for (i = 0; attrs[i] != NULL; i++) {
        switch (attrs[i]->type) {
        case SSS_SIFP_ATTR_TYPE_BOOL:
            _free(ctx, attrs[i]->data.boolean);
            break;
        case SSS_SIFP_ATTR_TYPE_INT16:
            _free(ctx, attrs[i]->data.int16);
            break;
        case SSS_SIFP_ATTR_TYPE_UINT16:
            _free(ctx, attrs[i]->data.uint16);
            break;
        case SSS_SIFP_ATTR_TYPE_INT32:
            _free(ctx, attrs[i]->data.int32);
            break;
        case SSS_SIFP_ATTR_TYPE_UINT32:
            _free(ctx, attrs[i]->data.uint32);
            break;
        case SSS_SIFP_ATTR_TYPE_INT64:
            _free(ctx, attrs[i]->data.int64);
            break;
        case SSS_SIFP_ATTR_TYPE_UINT64:
            _free(ctx, attrs[i]->data.uint64);
            break;
        case SSS_SIFP_ATTR_TYPE_STRING:
            for (j = 0; j < attrs[i]->num_values; j++) {
                _free(ctx, attrs[i]->data.str[j]);
            }
            _free(ctx, attrs[i]->data.str);
            break;
        case SSS_SIFP_ATTR_TYPE_STRING_DICT:
            if (attrs[i]->data.str_dict != NULL) {
                hash_destroy(attrs[i]->data.str_dict);
            }
            attrs[i]->data.str_dict = NULL;
            break;
        }
        _free(ctx, attrs[i]->name);
        _free(ctx, attrs[i]);
    }

    _free(ctx, attrs);

    *_attrs = NULL;
}

void
sss_sifp_free_object(sss_sifp_ctx *ctx,
                     sss_sifp_object **_object)
{
    sss_sifp_object *object = NULL;

    if (_object == NULL || *_object == NULL) {
        return;
    }

    object = *_object;

    sss_sifp_free_attrs(ctx, &object->attrs);
    _free(ctx, object->object_path);
    _free(ctx, object->interface);
    _free(ctx, object->name);
    _free(ctx, object);

    *_object = NULL;
}

void
sss_sifp_free_string(sss_sifp_ctx *ctx,
                     char **_str)
{
    if (_str == NULL || *_str == NULL) {
        return;
    }

    _free(ctx, *_str);

    *_str = NULL;
}

void
sss_sifp_free_string_array(sss_sifp_ctx *ctx,
                           char ***_str_array)
{
    char **str_array = NULL;
    int i;

    if (_str_array == NULL || *_str_array == NULL) {
        return;
    }

    str_array = *_str_array;

    for (i = 0; str_array[i] != NULL; i++) {
        _free(ctx, str_array[i]);
    }

    _free(ctx, str_array);

    *_str_array = NULL;
}
