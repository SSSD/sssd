/*
    Authors:
        Stef Walter <stefw@redhat.com>

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

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_private.h"

static char *
type_to_string(char type, char *str)
{
    int l;

    l = snprintf(str, 2, "%c", type);
    if (l != 1) {
        return NULL;
    }

    return str;
}

int sbus_add_variant_to_dict(DBusMessageIter *iter_dict,
                             const char *key,
                             int type,
                             const void *value)
{
    DBusMessageIter iter_dict_entry;
    DBusMessageIter iter_dict_val;
    dbus_bool_t dbret;
    char strtype[2];

    type_to_string(type, strtype);

    dbret = dbus_message_iter_open_container(iter_dict,
                                             DBUS_TYPE_DICT_ENTRY, NULL,
                                             &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    /* Start by appending the key */
    dbret = dbus_message_iter_append_basic(&iter_dict_entry,
                                           DBUS_TYPE_STRING, &key);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_open_container(&iter_dict_entry,
                                             DBUS_TYPE_VARIANT,
                                             strtype,
                                             &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    /* Now add the value */
    dbret = dbus_message_iter_append_basic(&iter_dict_val, type, value);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(&iter_dict_entry,
                                              &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(iter_dict,
                                              &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}

int sbus_add_array_as_variant_to_dict(DBusMessageIter *iter_dict,
                                      const char *key,
                                      int type,
                                      uint8_t *values,
                                      const int len,
                                      const unsigned int item_size)
{
    DBusMessageIter iter_dict_entry;
    DBusMessageIter iter_variant;
    DBusMessageIter iter_array;
    dbus_bool_t dbret;
    char variant_type[] = {DBUS_TYPE_ARRAY, type, '\0'};
    char array_type[] = {type, '\0'};
    void *addr = NULL;
    int i;

    dbret = dbus_message_iter_open_container(iter_dict,
                                             DBUS_TYPE_DICT_ENTRY, NULL,
                                             &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    /* Start by appending the key */
    dbret = dbus_message_iter_append_basic(&iter_dict_entry,
                                           DBUS_TYPE_STRING, &key);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_open_container(&iter_dict_entry,
                                             DBUS_TYPE_VARIANT,
                                             variant_type,
                                             &iter_variant);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_open_container(&iter_variant,
                                             DBUS_TYPE_ARRAY,
                                             array_type,
                                             &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    /* Now add the value */
    for (i = 0; i < len; i++) {
        addr = values + i * item_size;
        dbret = dbus_message_iter_append_basic(&iter_array, type, addr);
        if (!dbret) {
            return ENOMEM;
        }
    }

    dbret = dbus_message_iter_close_container(&iter_variant,
                                              &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(&iter_dict_entry,
                                              &iter_variant);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(iter_dict,
                                              &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}

static int
dispatch_properties_set(struct sbus_connection *conn,
                        struct sbus_interface *intf,
                        DBusMessage *message)
{
    const char *signature;
    const struct sbus_interface_meta *meta;
    const struct sbus_property_meta *property;
    const char *interface_name;
    const char *property_name;
    const char *type;
    struct sbus_request *req;
    sbus_msg_handler_fn handler_fn;
    DBusMessageIter iter;
    DBusMessageIter variant;

    req = sbus_new_request(conn, intf, message);
    if (!req)
        return ENOMEM;

    meta = intf->vtable->meta;

    signature = dbus_message_get_signature(message);
    if (strcmp (signature, "ssv") != 0) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_INVALID_ARGS,
                                   "Invalid argument types passed " \
                                   "to Set method"));
    }

    dbus_message_iter_init (message, &iter);
    dbus_message_iter_get_basic (&iter, &interface_name);
    dbus_message_iter_next (&iter);
    dbus_message_iter_get_basic (&iter, &property_name);
    dbus_message_iter_next (&iter);

    if (strcmp (interface_name, meta->name) != 0) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_UNKNOWN_INTERFACE,
                                   "No such interface"));
    }

    property = sbus_meta_find_property (intf->vtable->meta, property_name);
    if (property == NULL) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_UNKNOWN_PROPERTY,
                                   "No such property"));
    }

    if (!(property->flags & SBUS_PROPERTY_WRITABLE)) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_PROPERTY_READ_ONLY,
                                   "Property is not writable"));
    }

    dbus_message_iter_recurse(&iter, &variant);
    type = dbus_message_iter_get_signature (&variant);
    if (strcmp (property->type, type) != 0) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_INVALID_ARGS,
                                   "Invalid data type for property"));
    }

    handler_fn = VTABLE_FUNC(intf->vtable, property->vtable_offset_set);
    if (!handler_fn) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_NOT_SUPPORTED,
                                   "Not implemented"));
    }

    sbus_request_invoke_or_finish(req, handler_fn,
                                  intf->instance_data,
                                  property->invoker_set);
    return EOK;
}

static int
dispatch_properties_get(struct sbus_connection *conn,
                        struct sbus_interface *intf,
                        DBusMessage *message)
{
    struct sbus_request *req;
    const char *signature;
    const struct sbus_interface_meta *meta;
    DBusMessageIter iter;
    sbus_msg_handler_fn handler_fn;
    const struct sbus_property_meta *property;
    const char *interface_name;
    const char *property_name;

    req = sbus_new_request(conn, intf, message);
    if (req == NULL) {
        return ENOMEM;
    }

    meta = intf->vtable->meta;

    signature = dbus_message_get_signature(message);
    /* Interface name, property name */
    if (strcmp(signature, "ss") != 0) {
        return sbus_request_fail_and_finish(req,
                 sbus_error_new(req,
                                DBUS_ERROR_INVALID_ARGS,
                                "Invalid argument types passed to Get method"));
    }

    dbus_message_iter_init(message, &iter);
    dbus_message_iter_get_basic(&iter, &interface_name);
    dbus_message_iter_next(&iter);
    dbus_message_iter_get_basic(&iter, &property_name);

    if (strcmp(interface_name, meta->name) != 0) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_UNKNOWN_INTERFACE,
                                   "No such interface"));
    }

    property = sbus_meta_find_property(intf->vtable->meta, property_name);
    if (property == NULL) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_UNKNOWN_PROPERTY,
                                   "No such property"));
    }

    if (!(property->flags & SBUS_PROPERTY_READABLE)) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_ACCESS_DENIED,
                                   "Property is not readable"));
    }

    handler_fn = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
    if (!handler_fn) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_NOT_SUPPORTED,
                                   "Not implemented"));
    }

    sbus_request_invoke_or_finish(req, handler_fn,
                                  intf->instance_data,
                                  property->invoker_get);
    return EOK;
}

static int
dispatch_properties_get_all(struct sbus_connection *conn,
                            struct sbus_interface *intf,
                            DBusMessage *message)
{
    struct sbus_request *req;
    const char *signature;
    const struct sbus_interface_meta *meta;
    const char *interface_name;
    DBusMessageIter iter;

    req = sbus_new_request(conn, intf, message);
    if (req == NULL) {
        return ENOMEM;
    }

    meta = intf->vtable->meta;

    signature = dbus_message_get_signature(message);
    /* Interface name */
    if (strcmp(signature, "s") != 0) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_INVALID_ARGS,
                                   "Invalid argument types passed " \
                                   "to GetAll method"));
    }

    dbus_message_iter_init(message, &iter);
    dbus_message_iter_get_basic(&iter, &interface_name);

    if (strcmp(interface_name, meta->name) != 0) {
        return sbus_request_fail_and_finish(req,
                    sbus_error_new(req,
                                   DBUS_ERROR_UNKNOWN_INTERFACE,
                                   "No such interface"));
    }

    sbus_request_invoke_or_finish(req, NULL, NULL, meta->invoker_get_all);
    return EOK;
}

int sbus_properties_dispatch(struct sbus_request *dbus_req)
{
    const char *member;

    member = dbus_message_get_member(dbus_req->message);

    /* Set is handled a lot like a method invocation */
    if (strcmp(member, "Set") == 0) {
        return dispatch_properties_set(dbus_req->conn,
                                       dbus_req->intf,
                                       dbus_req->message);
    } else if (strcmp (member, "Get") == 0) {
        return dispatch_properties_get(dbus_req->conn,
                                       dbus_req->intf,
                                       dbus_req->message);
    } else if (strcmp (member, "GetAll") == 0) {
        return dispatch_properties_get_all(dbus_req->conn,
                                            dbus_req->intf,
                                            dbus_req->message);
    }

    return ERR_SBUS_NOSUP;
}
