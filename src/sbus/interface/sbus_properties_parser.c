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
#include <talloc.h>

#include "sbus/sbus_private.h"
#include "sbus/interface/sbus_iterator_readers.h"
#include "sbus/interface/sbus_iterator_writers.h"

static errno_t
sbus_parse_get_value(TALLOC_CTX *mem_ctx,
                     sbus_value_reader_fn reader,
                     sbus_value_reader_talloc_fn reader_talloc,
                     DBusMessageIter *iter,
                     void *_value_ptr)
{
    DBusMessageIter variant;

    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_VARIANT) {
        return ERR_SBUS_INVALID_TYPE;
    }

    dbus_message_iter_recurse(iter, &variant);

    if (reader != NULL) {
        return reader(&variant, _value_ptr);
    }

    return reader_talloc(mem_ctx, &variant, _value_ptr);
}

errno_t
sbus_parse_get_message(TALLOC_CTX *mem_ctx,
                       sbus_value_reader_fn reader,
                       sbus_value_reader_talloc_fn reader_talloc,
                       DBusMessage *msg,
                       void *_value_ptr)
{
    DBusMessageIter iterator;

    dbus_message_iter_init(msg, &iterator);

    return sbus_parse_get_value(mem_ctx, reader, reader_talloc,
                                &iterator, _value_ptr);
}

static errno_t
sbus_parse_getall_name(struct sbus_parse_getall_table *table,
                       DBusMessageIter *dict_iter,
                       struct sbus_parse_getall_table **_property)
{
    const char *name;
    int type;
    int i;

    type = dbus_message_iter_get_arg_type(dict_iter);
    if (type != DBUS_TYPE_STRING) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected type [%d]\n", type);
        return ERR_SBUS_INVALID_TYPE;
    }

    dbus_message_iter_get_basic(dict_iter, &name);

    for (i = 0; table[i].name != NULL; i++) {
        if (strcmp(table[i].name, name) == 0) {
            *_property = &table[i];
            return EOK;
        }
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "Unknown property [%s], skipping...\n", name);
    *_property = NULL;

    return EOK;
}

static errno_t
sbus_parse_getall_dict_entry(TALLOC_CTX *mem_ctx,
                             struct sbus_parse_getall_table *table,
                             DBusMessageIter *dict_iter)
{
    struct sbus_parse_getall_table *property;
    dbus_bool_t dbret;
    errno_t ret;

    ret = sbus_parse_getall_name(table, dict_iter, &property);
    if (ret != EOK) {
        return ret;
    }

    dbret = dbus_message_iter_next(dict_iter);
    if (!dbret) {
        return ERR_SBUS_INVALID_TYPE;
    }

    if (property == NULL) {
        return EOK;
    }

    ret = sbus_parse_get_value(mem_ctx, property->reader,
                               property->reader_talloc, dict_iter,
                               property->destination);
    if (ret != EOK) {
        return ret;
    }

    *(property->is_set) = true;

    return EOK;
}

static errno_t
sbus_parse_getall_array(TALLOC_CTX *mem_ctx,
                        struct sbus_parse_getall_table *table,
                        DBusMessageIter *array_iter)
{
    DBusMessageIter dict_iter;
    errno_t ret;
    int type;

    do {
        type = dbus_message_iter_get_arg_type(array_iter);

        switch (type) {
        case DBUS_TYPE_INVALID:
            /* We have reached the end of the array. */
            return EOK;
        case DBUS_TYPE_DICT_ENTRY:
            dbus_message_iter_recurse(array_iter, &dict_iter);
            ret = sbus_parse_getall_dict_entry(mem_ctx, table, &dict_iter);
            if (ret != EOK) {
                return ret;
            }
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected type [%d]\n", type);
            return  ERR_SBUS_INVALID_TYPE;
        }
    } while (dbus_message_iter_next(array_iter));

    return EOK;
}

errno_t
sbus_parse_getall_message(TALLOC_CTX *mem_ctx,
                          struct sbus_parse_getall_table *table,
                          DBusMessage *msg)
{
    DBusMessageIter array_iter;
    DBusMessageIter iter;
    errno_t ret;
    int type;

    dbus_message_iter_init(msg, &iter);

    type = dbus_message_iter_get_arg_type(&iter);

    switch (type) {
    case DBUS_TYPE_INVALID:
        /* Empty message. */
        return EOK;
    case DBUS_TYPE_ARRAY:
        dbus_message_iter_recurse(&iter, &array_iter);
        ret = sbus_parse_getall_array(mem_ctx, table, &array_iter);
        if (ret != EOK) {
            return ret;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected type [%d]\n", type);
        return ERR_SBUS_INVALID_TYPE;
    }

    if (dbus_message_iter_has_next(&iter)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid GetAll reply\n");
        return ERR_SBUS_INVALID_TYPE;
    }

    return EOK;
}
