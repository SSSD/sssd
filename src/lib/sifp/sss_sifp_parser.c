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
#include <string.h>
#include <dhash.h>

#include "lib/sifp/sss_sifp.h"
#include "lib/sifp/sss_sifp_private.h"

#define check_dbus_arg(iter, type, ret, done) do { \
    if (dbus_message_iter_get_arg_type((iter)) != (type)) { \
        ret = SSS_SIFP_INTERNAL_ERROR; \
        goto done; \
    } \
} while (0)

#define parse_basic(ctx, iter, ret, attr_type, dbus_type, \
                    data_type, field, done) \
do { \
    dbus_type val; \
    dbus_message_iter_get_basic(iter, &val); \
    attr->type = attr_type; \
    attr->data.field = _alloc_zero(ctx, data_type, 1); \
    \
    if (attr->data.field == NULL) { \
        ret = SSS_SIFP_OUT_OF_MEMORY; \
        goto done; \
    } \
    \
    attr->data.field[0] = val; \
    attr->num_values = 1; \
    \
    ret = SSS_SIFP_OK; \
} while (0)

#define parse_array(ctx, iter, ret, attr_type, dbus_type, \
                    data_type, field, done) \
do { \
    dbus_type val; \
    unsigned int i; \
    \
    attr->type = attr_type; \
    if (attr->num_values == 0) { \
        attr->data.field = NULL; \
        ret = SSS_SIFP_OK; \
        goto done; \
    } \
    \
    attr->data.field = _alloc_zero(ctx, data_type, attr->num_values); \
    if (attr->data.field == NULL) { \
        ret = SSS_SIFP_OUT_OF_MEMORY; \
        goto done; \
    } \
    \
    for (i = 0; i < attr->num_values; i++) { \
        dbus_message_iter_get_basic(iter, &val); \
        attr->data.field[i] = val; \
        \
        if (!dbus_message_iter_next(iter) && i + 1 < attr->num_values) { \
            ret = SSS_SIFP_INTERNAL_ERROR; \
            goto done; \
        } \
    } \
    \
    ret = SSS_SIFP_OK; \
} while (0)

static unsigned int
sss_sifp_get_array_length(DBusMessageIter *iter)
{
    DBusMessageIter array_iter;
    unsigned int size;

    dbus_message_iter_recurse(iter, &array_iter);

    if (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_INVALID) {
        return 0;
    }

    size = 0;
    do {
        size++;
    } while (dbus_message_iter_next(&array_iter));

    return size;
}

static void hash_delete_cb(hash_entry_t *item,
                           hash_destroy_enum type,
                           void *pvt)
{
    sss_sifp_ctx *ctx = (sss_sifp_ctx*)pvt;
    char **values = (char**)(item->value.ptr);
    int i;

    if (values == NULL) {
        return;
    }

    for (i = 0; values[i] != NULL; i++) {
        _free(ctx, values[i]);
        values[i] = NULL;
    }

    _free(ctx, values);
    item->value.ptr = NULL;
}

static sss_sifp_error
sss_sifp_parse_dict(sss_sifp_ctx *ctx,
                    DBusMessageIter *iter,
                    hash_table_t *table)
{
    DBusMessageIter dict_iter;
    DBusMessageIter array_iter;
    sss_sifp_error ret;
    hash_key_t table_key = {0};
    hash_value_t table_value;
    const char *key = NULL;
    const char *value = NULL;
    char **values = NULL;
    unsigned int i;
    unsigned int num_values;
    int hret;

    dbus_message_iter_recurse(iter, &dict_iter);

    /* get the key */
    check_dbus_arg(&dict_iter, DBUS_TYPE_STRING, ret, done);
    dbus_message_iter_get_basic(&dict_iter, &key);

    table_key.type = HASH_KEY_STRING;
    table_key.str = sss_sifp_strdup(ctx, key);
    if (table_key.str == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    if (!dbus_message_iter_next(&dict_iter)) {
        ret = SSS_SIFP_INTERNAL_ERROR;
        goto done;
    }

    /* now read the value */
    switch (dbus_message_iter_get_arg_type(&dict_iter)) {
    case DBUS_TYPE_STRING:
        dbus_message_iter_get_basic(&dict_iter, &value);
        values = _alloc_zero(ctx, char *, 2);
        if (values == NULL) {
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }

        values[0] = sss_sifp_strdup(ctx, value);
        if (values[0] == NULL) {
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }

        values[1] = NULL;

        ret = SSS_SIFP_OK;
        break;
    case DBUS_TYPE_ARRAY:
        num_values = sss_sifp_get_array_length(&dict_iter);
        if (num_values == 0) {
            values = NULL;
            ret = SSS_SIFP_OK;
            goto done;
        }

        if (dbus_message_iter_get_element_type(&dict_iter)
                != DBUS_TYPE_STRING) {
            ret = SSS_SIFP_NOT_SUPPORTED;
            goto done;
        }

        dbus_message_iter_recurse(&dict_iter, &array_iter);

        values = _alloc_zero(ctx, char*, num_values + 1);
        if (values == NULL) {
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }

        for (i = 0; i < num_values; i++) {
            dbus_message_iter_get_basic(&array_iter, &value);
            values[i] = sss_sifp_strdup(ctx, value);
            if (values[i] == NULL) {
                ret = SSS_SIFP_OUT_OF_MEMORY;
                goto done;
            }

            dbus_message_iter_next(&array_iter);
        }

        ret = SSS_SIFP_OK;
        break;
    default:
        ret = SSS_SIFP_NOT_SUPPORTED;
        break;
    }

    table_value.type = HASH_VALUE_PTR;
    table_value.ptr = values;

    hret = hash_enter(table, &table_key, &table_value);
    if (hret == HASH_ERROR_NO_MEMORY) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
    } else if (hret != HASH_SUCCESS) {
        ret = SSS_SIFP_INTERNAL_ERROR;
    }

done:
    if (table_key.str != NULL) {
        _free(ctx, table_key.str);
    }

    if (ret != SSS_SIFP_OK) {
        if (values != NULL) {
            for (i = 0; values[i] != NULL; i++) {
                _free(ctx, values[i]);
            }
            _free(ctx, values);
        }
    }

    return ret;
}

static sss_sifp_error
sss_sifp_parse_basic(sss_sifp_ctx *ctx,
                     DBusMessageIter *iter,
                     sss_sifp_attr *attr)
{
    sss_sifp_error ret;

    switch (dbus_message_iter_get_arg_type(iter)) {
    case DBUS_TYPE_BOOLEAN:
        parse_basic(ctx, iter, ret, SSS_SIFP_ATTR_TYPE_BOOL,
                    dbus_bool_t, bool, boolean, done);
        break;
    case DBUS_TYPE_INT16:
        parse_basic(ctx, iter, ret, SSS_SIFP_ATTR_TYPE_INT16,
                    int16_t, int16_t, int16, done);
        break;
    case DBUS_TYPE_UINT16:
        parse_basic(ctx, iter, ret, SSS_SIFP_ATTR_TYPE_UINT16,
                    uint16_t, uint16_t, uint16, done);
        break;
    case DBUS_TYPE_INT32:
        parse_basic(ctx, iter, ret, SSS_SIFP_ATTR_TYPE_INT32,
                    int32_t, int32_t, int32, done);
        break;
    case DBUS_TYPE_UINT32:
        parse_basic(ctx, iter, ret, SSS_SIFP_ATTR_TYPE_UINT32,
                    uint32_t, uint32_t, uint32, done);
        break;
    case DBUS_TYPE_INT64:
        parse_basic(ctx, iter, ret, SSS_SIFP_ATTR_TYPE_INT64,
                    int64_t, int64_t, int64, done);
        break;
    case DBUS_TYPE_UINT64:
        parse_basic(ctx, iter, ret, SSS_SIFP_ATTR_TYPE_UINT64,
                    uint64_t, uint64_t, uint64, done);
        break;
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
    {
        const char *val = NULL;

        dbus_message_iter_get_basic(iter, &val);

        attr->type = SSS_SIFP_ATTR_TYPE_STRING;
        attr->data.str = _alloc_zero(ctx, char*, 1);
        if (attr->data.str == NULL) { \
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }

        attr->data.str[0] = sss_sifp_strdup(ctx, val);
        if (attr->data.str[0] == NULL) {
            _free(ctx, attr->data.str);
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }

        attr->num_values = 1;

        ret = SSS_SIFP_OK;
        break;
    }
    default:
        ret = SSS_SIFP_INVALID_ARGUMENT;
        break;
    }

done:
    return ret;
}

static sss_sifp_error
sss_sifp_parse_array(sss_sifp_ctx *ctx,
                     DBusMessageIter *iter,
                     sss_sifp_attr *attr)
{
    DBusMessageIter array_iter;
    sss_sifp_error ret;
    int hret;

    attr->num_values = sss_sifp_get_array_length(iter);
    dbus_message_iter_recurse(iter, &array_iter);

    switch (dbus_message_iter_get_element_type(iter)) {
    case DBUS_TYPE_BOOLEAN:
        parse_array(ctx, &array_iter, ret, SSS_SIFP_ATTR_TYPE_BOOL,
                    dbus_bool_t, bool, boolean, done);
        break;
    case DBUS_TYPE_INT16:
        parse_array(ctx, &array_iter, ret, SSS_SIFP_ATTR_TYPE_INT16,
                    int16_t, int16_t, int16, done);
        break;
    case DBUS_TYPE_UINT16:
        parse_array(ctx, &array_iter, ret, SSS_SIFP_ATTR_TYPE_UINT16,
                    uint16_t, uint16_t, uint16, done);
        break;
    case DBUS_TYPE_INT32:
        parse_array(ctx, &array_iter, ret, SSS_SIFP_ATTR_TYPE_INT32,
                    int32_t, int32_t, int32, done);
        break;
    case DBUS_TYPE_UINT32:
        parse_array(ctx, &array_iter, ret, SSS_SIFP_ATTR_TYPE_UINT32,
                    uint32_t, uint32_t, uint32, done);
        break;
    case DBUS_TYPE_INT64:
        parse_array(ctx, &array_iter, ret, SSS_SIFP_ATTR_TYPE_INT64,
                    int64_t, int64_t, int64, done);
        break;
    case DBUS_TYPE_UINT64:
        parse_array(ctx, &array_iter, ret, SSS_SIFP_ATTR_TYPE_UINT64,
                    uint64_t, uint64_t, uint64, done);
        break;
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH: ;
        const char *val;
        unsigned int i;

        attr->type = SSS_SIFP_ATTR_TYPE_STRING;
        if (attr->num_values == 0) {
            attr->data.str = NULL;
            ret = SSS_SIFP_OK;
            goto done;
        }

        attr->data.str = _alloc_zero(ctx, char *, attr->num_values);
        if (attr->data.str == NULL) {
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }

        for (i = 0; i < attr->num_values; i++) {
            dbus_message_iter_get_basic(&array_iter, &val);
            attr->data.str[i] = sss_sifp_strdup(ctx, val);
            if (attr->data.str[i] == NULL) {
                ret = SSS_SIFP_OUT_OF_MEMORY;
                goto done;
            }

            if (!dbus_message_iter_next(&array_iter)
                    && i + 1 < attr->num_values) {
                ret = SSS_SIFP_INTERNAL_ERROR;
                goto done;
            }
        }

        ret = SSS_SIFP_OK;
        break;
    case DBUS_TYPE_DICT_ENTRY:
        attr->type = SSS_SIFP_ATTR_TYPE_STRING_DICT;
        if (attr->num_values == 0) {
            attr->data.str_dict = NULL;
            ret = SSS_SIFP_OK;
            goto done;
        }

        hret = hash_create_ex(0, &(attr->data.str_dict), 0, 0, 0, 0,
                              ctx->alloc_fn, ctx->free_fn, ctx->alloc_pvt,
                              hash_delete_cb, ctx);
        if (hret != HASH_SUCCESS) {
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }

        for (i = 0; i < attr->num_values; i++) {
            ret = sss_sifp_parse_dict(ctx, &array_iter, attr->data.str_dict);
            if (ret != SSS_SIFP_OK) {
                _free(ctx, attr->data.str_dict);
                goto done;
            }

            if (!dbus_message_iter_next(&array_iter)
                    && i + 1 < attr->num_values) {
                ret = SSS_SIFP_INTERNAL_ERROR;
                goto done;
            }
        }

        ret = SSS_SIFP_OK;
        break;
    default:
        ret = SSS_SIFP_INVALID_ARGUMENT;
        break;
    }

done:
    if (ret != SSS_SIFP_OK) {
        if (attr->type == SSS_SIFP_ATTR_TYPE_STRING && attr->data.str != NULL) {
            for (unsigned int i = 0;
                 (i < attr->num_values) && (attr->data.str[i] != NULL);
                 i++) {
                _free(ctx, attr->data.str[i]);
            }
            _free(ctx, attr->data.str);
        } else if (attr->type == SSS_SIFP_ATTR_TYPE_STRING_DICT
                    && attr->data.str_dict != NULL) {
            hash_destroy(attr->data.str_dict);
            attr->data.str_dict = NULL;
        }
    }

    return ret;
}

static sss_sifp_error
sss_sifp_parse_variant(sss_sifp_ctx *ctx,
                       DBusMessageIter *iter,
                       sss_sifp_attr *attr)
{
    DBusMessageIter variant_iter;
    sss_sifp_error ret;
    int type;

    check_dbus_arg(iter, DBUS_TYPE_VARIANT, ret, done);

    dbus_message_iter_recurse(iter, &variant_iter);

    type = dbus_message_iter_get_arg_type(&variant_iter);
    if (dbus_type_is_basic(type)) {
        ret = sss_sifp_parse_basic(ctx, &variant_iter, attr);
    } else {
        /* container types */
        switch (type) {
        /* case DBUS_TYPE_DICT_ENTRY may only be contained within an array
         * in variant */
        case DBUS_TYPE_ARRAY:
            ret = sss_sifp_parse_array(ctx, &variant_iter, attr);
            break;
        default:
            ret = SSS_SIFP_NOT_SUPPORTED;
            break;
        }
    }

done:
    return ret;
}

/**
 * DBusMessage format:
 * variant:value
 *
 * Iterator has to point to the variant but not inside the variant.
 */
static sss_sifp_error
sss_sifp_parse_single_attr(sss_sifp_ctx *ctx,
                           const char *name,
                           DBusMessageIter *iter,
                           sss_sifp_attr **_attr)
{
    sss_sifp_attr *attr = NULL;
    sss_sifp_error ret;

    attr = _alloc_zero(ctx, sss_sifp_attr, 1);
    if (attr == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    attr->name = sss_sifp_strdup(ctx, name);
    if (attr->name == NULL) {
        _free(ctx, attr);
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    ret = sss_sifp_parse_variant(ctx, iter, attr);
    if (ret != SSS_SIFP_OK) {
        _free(ctx, attr->name);
        _free(ctx, attr);
    }

    *_attr = attr;

done:
    return ret;
}

/**
 * DBusMessage format:
 * variant:value
 */
sss_sifp_error
sss_sifp_parse_attr(sss_sifp_ctx *ctx,
                    const char *name,
                    DBusMessage *msg,
                    sss_sifp_attr ***_attrs)
{
    sss_sifp_attr **attrs = NULL;
    DBusMessageIter iter;
    sss_sifp_error ret;

    dbus_message_iter_init(msg, &iter);

    attrs = _alloc_zero(ctx, sss_sifp_attr *, 2);
    if (attrs == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    ret = sss_sifp_parse_single_attr(ctx, name, &iter, &attrs[0]);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    *_attrs = attrs;

    ret = SSS_SIFP_OK;

done:
    if (ret != SSS_SIFP_OK) {
        sss_sifp_free_attrs(ctx, &attrs);
    }

    return ret;
}

/**
 * DBusMessage format:
 * array of dict_entry(string:attr_name, variant:value)
 */
sss_sifp_error
sss_sifp_parse_attr_list(sss_sifp_ctx *ctx,
                         DBusMessage *msg,
                         sss_sifp_attr ***_attrs)
{
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter dict_iter;
    sss_sifp_attr **attrs = NULL;
    const char *name = NULL;
    unsigned int num_values;
    sss_sifp_error ret;
    unsigned int i;

    dbus_message_iter_init(msg, &iter);

    check_dbus_arg(&iter, DBUS_TYPE_ARRAY, ret, done);

    if (dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY) {
        ret = SSS_SIFP_INTERNAL_ERROR;
        goto done;
    }

    num_values = sss_sifp_get_array_length(&iter);
    attrs = _alloc_zero(ctx, sss_sifp_attr *, num_values + 1);
    if (attrs == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    dbus_message_iter_recurse(&iter, &array_iter);

    for (i = 0; i < num_values; i++) {
        dbus_message_iter_recurse(&array_iter, &dict_iter);

        /* get the key */
        check_dbus_arg(&dict_iter, DBUS_TYPE_STRING, ret, done);
        dbus_message_iter_get_basic(&dict_iter, &name);

        if (!dbus_message_iter_next(&dict_iter)) {
            ret = SSS_SIFP_INTERNAL_ERROR;
            goto done;
        }

        /* now read the value */
        check_dbus_arg(&dict_iter, DBUS_TYPE_VARIANT, ret, done);

        ret = sss_sifp_parse_single_attr(ctx, name, &dict_iter, &attrs[i]);
        if (ret != SSS_SIFP_OK) {
            goto done;
        }

        dbus_message_iter_next(&array_iter);
    }

    *_attrs = attrs;
    ret = SSS_SIFP_OK;

done:
    if (ret != SSS_SIFP_OK) {
        sss_sifp_free_attrs(ctx, &attrs);
    }

    return ret;
}

sss_sifp_error
sss_sifp_parse_object_path(sss_sifp_ctx *ctx,
                           DBusMessage *msg,
                           char **_object_path)
{
    char *object_path = NULL;
    const char *dbus_path = NULL;
    DBusError dbus_error;
    dbus_bool_t bret;
    sss_sifp_error ret;

    dbus_error_init(&dbus_error);

    bret = dbus_message_get_args(msg, &dbus_error,
                                 DBUS_TYPE_OBJECT_PATH, &dbus_path,
                                 DBUS_TYPE_INVALID);
    if (!bret) {
        sss_sifp_set_io_error(ctx, &dbus_error);
        ret = SSS_SIFP_IO_ERROR;
        goto done;
    }

    object_path = sss_sifp_strdup(ctx, dbus_path);
    if (object_path == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    *_object_path = object_path;
    ret = SSS_SIFP_OK;

done:
    dbus_error_free(&dbus_error);

    return ret;
}

sss_sifp_error
sss_sifp_parse_object_path_list(sss_sifp_ctx *ctx,
                                DBusMessage *msg,
                                char ***_object_paths)
{
    char **object_paths = NULL;
    char **dbus_paths = NULL;
    int num_paths;
    DBusError dbus_error;
    dbus_bool_t bret;
    sss_sifp_error ret;
    int i;

    dbus_error_init(&dbus_error);

    bret = dbus_message_get_args(msg, &dbus_error,
                                 DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
                                 &dbus_paths, &num_paths,
                                 DBUS_TYPE_INVALID);
    if (!bret) {
        sss_sifp_set_io_error(ctx, &dbus_error);
        ret = SSS_SIFP_IO_ERROR;
        goto done;
    }

    object_paths = _alloc_zero(ctx, char *, num_paths + 1);
    if (object_paths == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    for (i = 0; i < num_paths; i++) {
        object_paths[i] = sss_sifp_strdup(ctx, dbus_paths[i]);
        if (object_paths[i] == NULL) {
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }
    }

    *_object_paths = object_paths;
    ret = SSS_SIFP_OK;

done:
    dbus_error_free(&dbus_error);
    dbus_free_string_array(dbus_paths);

    if (ret != SSS_SIFP_OK && object_paths != NULL) {
        sss_sifp_free_string_array(ctx, &object_paths);
    }

    return ret;
}
