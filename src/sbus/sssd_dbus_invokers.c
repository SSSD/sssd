/*
    Authors:
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

#include <dbus/dbus.h>
#include <errno.h>

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_private.h"
#include "sbus/sssd_dbus_invokers.h"

static int
sbus_invoke_get_basic(struct sbus_request *sbus_req,
                      void *function_ptr,
                      void *value_ptr,
                      int dbus_type,
                      DBusMessageIter *iter)
{
    void (*handler_fn)(struct sbus_request *, void *, void *);
    dbus_bool_t value_bool;
    dbus_bool_t dbret;

    handler_fn = function_ptr;
    handler_fn(sbus_req, sbus_req->intf->handler_data, value_ptr);

    if (dbus_type == DBUS_TYPE_BOOLEAN) {
        /* Special case to convert bool into dbus_bool_t. */
        value_bool = *((bool *) value_ptr);
        value_ptr = &value_bool;
    }

    dbret = dbus_message_iter_append_basic(iter, dbus_type, value_ptr);
    return dbret ? EOK : EIO;
}

static int
sbus_invoke_get_string(struct sbus_request *sbus_req,
                       void *function_ptr,
                       const char *default_value,
                       int dbus_type,
                       DBusMessageIter *iter)
{
    void (*handler_fn)(struct sbus_request *, void *, const char **);
    const char *value = NULL;
    dbus_bool_t dbret;

    handler_fn = function_ptr;
    handler_fn(sbus_req, sbus_req->intf->handler_data, &value);

    value = value == NULL ? default_value : value;

    dbret = dbus_message_iter_append_basic(iter, dbus_type, &value);
    return dbret ? EOK : EIO;
}

static int
sbus_invoke_get_array(struct sbus_request *sbus_req,
                      void *function_ptr,
                      unsigned int item_size,
                      int dbus_type,
                      DBusMessageIter *iter)
{
    void (*handler_fn)(struct sbus_request *, void *, void *, int *);
    const char array_type[2] = {dbus_type, '\0'};
    DBusMessageIter array;
    dbus_bool_t dbret;
    uint8_t *values;
    void *addr;
    int num_values;
    int i;

    handler_fn = function_ptr;
    handler_fn(sbus_req, sbus_req->intf->handler_data, &values, &num_values);

    dbret = dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
                                             array_type, &array);
    if (!dbret) {
        return EIO;
    }

    for (i = 0; i < num_values; i++) {
        addr = values + i * item_size;

        dbret = dbus_message_iter_append_basic(&array, dbus_type, addr);
        if (!dbret) {
            return ENOMEM;
        }
    }

    dbret = dbus_message_iter_close_container(iter, &array);
    if (!dbret) {
        return EIO;
    }

    return EOK;
}

int sbus_invoke_get_y(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    uint8_t value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_BYTE, iter);
}

int sbus_invoke_get_b(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    bool value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_BOOLEAN, iter);
}

int sbus_invoke_get_n(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    int16_t value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_INT16, iter);
}

int sbus_invoke_get_q(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    uint16_t value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_UINT16, iter);
}

int sbus_invoke_get_i(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    int32_t value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_INT32, iter);
}

int sbus_invoke_get_u(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    uint32_t value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_UINT32, iter);
}

int sbus_invoke_get_x(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    int64_t value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_INT64, iter);
}

int sbus_invoke_get_t(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    uint64_t value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_UINT64, iter);
}

int sbus_invoke_get_d(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    double value;

    return sbus_invoke_get_basic(sbus_req, function_ptr, &value,
                                 DBUS_TYPE_DOUBLE, iter);
}

int sbus_invoke_get_s(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    return sbus_invoke_get_string(sbus_req, function_ptr, "",
                                  DBUS_TYPE_STRING, iter);
}

int sbus_invoke_get_o(DBusMessageIter *iter,
                      struct sbus_request *sbus_req,
                      void *function_ptr)
{
    return sbus_invoke_get_string(sbus_req, function_ptr, "/",
                                  DBUS_TYPE_OBJECT_PATH, iter);
}

int sbus_invoke_get_ay(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(uint8_t),
                                 DBUS_TYPE_BYTE, iter);
}

int sbus_invoke_get_an(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(int16_t),
                                 DBUS_TYPE_INT16, iter);
}

int sbus_invoke_get_aq(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(uint16_t),
                                 DBUS_TYPE_UINT16, iter);
}

int sbus_invoke_get_ai(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(int32_t),
                                 DBUS_TYPE_INT32, iter);
}

int sbus_invoke_get_au(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(uint32_t),
                                 DBUS_TYPE_UINT32, iter);
}

int sbus_invoke_get_ax(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(int64_t),
                                 DBUS_TYPE_INT64, iter);
}

int sbus_invoke_get_at(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(uint64_t),
                                 DBUS_TYPE_UINT64, iter);
}

int sbus_invoke_get_ad(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(double),
                                 DBUS_TYPE_DOUBLE, iter);
}

int sbus_invoke_get_as(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(const char *),
                                 DBUS_TYPE_STRING, iter);
}

int sbus_invoke_get_ao(DBusMessageIter *iter,
                       struct sbus_request *sbus_req,
                       void *function_ptr)
{
    return sbus_invoke_get_array(sbus_req, function_ptr, sizeof(const char *),
                                 DBUS_TYPE_OBJECT_PATH, iter);
}

int sbus_invoke_get_aDOsasDE(DBusMessageIter *iter,
                             struct sbus_request *sbus_req,
                             void *function_ptr)
{
    void (*handler_fn)(struct sbus_request *, void *, hash_table_t **);
    DBusMessageIter it_array;
    DBusMessageIter it_dict;
    DBusMessageIter it_values;
    hash_table_t *table;
    struct hash_iter_context_t *table_iter = NULL;
    hash_entry_t *entry;
    const char **values;
    dbus_bool_t dbret;
    errno_t ret;
    int i;

    handler_fn = function_ptr;
    handler_fn(sbus_req, sbus_req->intf->handler_data, &table);

    dbret = dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
                    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                    DBUS_TYPE_STRING_AS_STRING
                    DBUS_TYPE_ARRAY_AS_STRING
                    DBUS_TYPE_STRING_AS_STRING
                    DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &it_array);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    /* iterate over keys */

    if (table == NULL) {
        dbret = dbus_message_iter_close_container(iter, &it_array);
        if (!dbret) {
            ret = EIO;
            goto done;
        }

        ret = EOK;
        goto done;
    }

    table_iter = new_hash_iter_context(table);
    while ((entry = table_iter->next(table_iter)) != NULL) {
        if (entry->key.type != HASH_KEY_STRING || entry->key.str == NULL
                || entry->value.type != HASH_VALUE_PTR
                || entry->value.ptr == NULL) {
            continue;
        }

        dbret = dbus_message_iter_open_container(&it_array,
                                                 DBUS_TYPE_DICT_ENTRY, NULL,
                                                 &it_dict);
        if (!dbret) {
            ret = EIO;
            goto done;
        }

        /* append key as dict entry key */

        dbret = dbus_message_iter_append_basic(&it_dict,
                                               DBUS_TYPE_STRING,
                                               &entry->key.str);
        if (!dbret) {
            ret = EIO;
            goto done;
        }

        /* iterate over values */

        dbret = dbus_message_iter_open_container(&it_dict,
                                                 DBUS_TYPE_ARRAY,
                                                 DBUS_TYPE_STRING_AS_STRING,
                                                 &it_values);
        if (!dbret) {
            ret = EIO;
            goto done;
        }

        values = entry->value.ptr;
        for (i = 0; values[i] != NULL; i++) {
            /* append value into array */
            dbret = dbus_message_iter_append_basic(&it_values,
                                                   DBUS_TYPE_STRING,
                                                   &values[i]);
            if (!dbret) {
                ret = EIO;
                goto done;
            }
        }

        dbret = dbus_message_iter_close_container(&it_dict, &it_values);
        if (!dbret) {
            ret = EIO;
            goto done;
        }

        dbret = dbus_message_iter_close_container(&it_array, &it_dict);
        if (!dbret) {
            ret = EIO;
            goto done;
        }
    }

    dbret = dbus_message_iter_close_container(iter, &it_array);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(table_iter);
    return ret;
}

void sbus_invoke_get(struct sbus_request *sbus_req,
                     const char *type,
                     sbus_get_invoker_fn invoker_fn,
                     sbus_msg_handler_fn handler_fn)
{
    DBusMessage *reply = NULL;
    DBusMessageIter iter;
    DBusMessageIter variant;
    dbus_bool_t dbret;
    errno_t ret;

    reply = dbus_message_new_method_return(sbus_req->message);
    if (reply == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    dbus_message_iter_init_append(reply, &iter);

    dbret = dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
                                             type, &variant);
    if (!dbret) {
        ret = ENOMEM;
        goto fail;
    }

    ret = invoker_fn(&variant, sbus_req, handler_fn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Invoker error [%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    dbret = dbus_message_iter_close_container(&iter, &variant);
    if (!dbret) {
        ret = EIO;
        goto fail;
    }

    sbus_request_finish(sbus_req, reply);
    return;

fail:
    DEBUG(SSSDBG_CRIT_FAILURE,
          "Unable to reply [%d]: %s\n", ret, sss_strerror(ret));

    if (reply != NULL) {
        dbus_message_unref(reply);
    }
    sbus_request_finish(sbus_req, NULL);

    return;
}

void sbus_invoke_get_all(struct sbus_request *sbus_req)
{
    const struct sbus_property_meta *props;
    sbus_msg_handler_fn *handler_fn;
    DBusMessage *reply = NULL;
    DBusMessageIter iter;
    DBusMessageIter array;
    DBusMessageIter dict;
    DBusMessageIter variant;
    dbus_bool_t dbret;
    errno_t ret;
    int i;

    reply = dbus_message_new_method_return(sbus_req->message);
    if (reply == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    dbus_message_iter_init_append(reply, &iter);

    dbret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING
                                     DBUS_TYPE_VARIANT_AS_STRING
                                     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                     &array);
    if (!dbret) {
        ret = ENOMEM;
        goto fail;
    }

    props = sbus_req->intf->vtable->meta->properties;

    if (props != NULL) {
        for (i = 0; props[i].name != NULL; i++) {
            dbret = dbus_message_iter_open_container(&array,
                                                     DBUS_TYPE_DICT_ENTRY, NULL,
                                                     &dict);
            if (!dbret) {
                ret = ENOMEM;
                goto fail;
            }

            /* key */
            dbret = dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING,
                                                   &props[i].name);
            if (!dbret) {
                ret = ENOMEM;
                goto fail;
            }

            /* value */
            dbret = dbus_message_iter_open_container(&dict, DBUS_TYPE_VARIANT,
                                                     props[i].type, &variant);
            if (!dbret) {
                ret = ENOMEM;
                goto fail;
            }

            handler_fn = VTABLE_FUNC(sbus_req->intf->vtable,
                                     props[i].vtable_offset_get);
            if (handler_fn == NULL) {
                ret = ERR_INTERNAL;
                goto fail;
            }

            ret = props[i].invoker_get(&variant, sbus_req, handler_fn);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Invoker error [%d]: %s\n", ret, sss_strerror(ret));
                goto fail;
            }

            dbret = dbus_message_iter_close_container(&dict, &variant);
            if (!dbret) {
                ret = EIO;
                goto fail;
            }

            dbret = dbus_message_iter_close_container(&array, &dict);
            if (!dbret) {
                ret = EIO;
                goto fail;
            }
        }
    }

    dbret = dbus_message_iter_close_container(&iter, &array);
    if (!dbret) {
        ret = EIO;
        goto fail;
    }

    sbus_request_finish(sbus_req, reply);
    return;

fail:
    DEBUG(SSSDBG_CRIT_FAILURE,
          "Unable to reply [%d]: %s\n", ret, sss_strerror(ret));

    dbus_message_unref(reply);
    sbus_request_finish(sbus_req, NULL);

    return;
}
