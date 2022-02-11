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

#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "responder/ifp/ifp_iface/ifp_iface_types.h"
#include "sbus/interface/sbus_iterator_readers.h"
#include "sbus/interface/sbus_iterator_writers.h"

/**
 * D-Bus signature: a{sas}
 */
errno_t sbus_iterator_read_ifp_extra(TALLOC_CTX *mem_ctx,
                                     DBusMessageIter *iterator,
                                     hash_table_t **_table)
{
    DBusMessageIter iter_array;
    DBusMessageIter iter_dict;
    hash_table_t *table;
    hash_key_t hkey;
    hash_value_t hvalue;
    char **values;
    char *key;
    int arg_type;
    errno_t ret;
    int count;
    int hret;
    int i;

    ret = sss_hash_create(mem_ctx, 0, &table);
    if (ret != EOK) {
        return ret;
    }

    arg_type = dbus_message_iter_get_arg_type(iterator);
    if (arg_type != DBUS_TYPE_ARRAY) {
        ret = ERR_SBUS_INVALID_TYPE;
        goto done;
    }

    count = dbus_message_iter_get_element_count(iterator);
    dbus_message_iter_recurse(iterator, &iter_array);

    for (i = 0; i < count; i++) {
        arg_type = dbus_message_iter_get_arg_type(&iter_array);
        if (arg_type != DBUS_TYPE_DICT_ENTRY) {
            ret = ERR_SBUS_INVALID_TYPE;
            goto done;
        }

        dbus_message_iter_recurse(&iter_array, &iter_dict);

        ret = sbus_iterator_read_S(table, &iter_dict, &key);
        if (ret != EOK) {
            goto done;
        }

        ret = sbus_iterator_read_aS(table, &iter_dict, &values);
        if (ret != EOK) {
            goto done;
        }

        hkey.type = HASH_KEY_STRING;
        hkey.str = key;

        hvalue.type = HASH_VALUE_PTR;
        hvalue.ptr = values;

        hret = hash_enter(table, &hkey, &hvalue);
        if (hret != HASH_SUCCESS) {
            ret = EIO;
            goto done;
        }

        /* dhash will duplicate the key internally */
        talloc_free(key);

        dbus_message_iter_next(&iter_array);
    }

    *_table = table;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(table);
    }

    return ret;
}

/**
 * D-Bus signature: a{sas}
 */
errno_t sbus_iterator_write_ifp_extra(DBusMessageIter *iterator,
                                      hash_table_t *table)
{
    DBusMessageIter it_array;
    DBusMessageIter it_dict;
    struct hash_iter_context_t *table_iter = NULL;
    bool in_array = false;
    bool in_dict = false;
    hash_entry_t *entry;
    const char **values;
    dbus_bool_t dbret;
    errno_t ret;

    dbret = dbus_message_iter_open_container(iterator, DBUS_TYPE_ARRAY,
                    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                    DBUS_TYPE_STRING_AS_STRING
                    DBUS_TYPE_ARRAY_AS_STRING
                    DBUS_TYPE_STRING_AS_STRING
                    DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &it_array);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    in_array = true;

    if (table == NULL) {
        dbret = dbus_message_iter_close_container(iterator, &it_array);
        if (!dbret) {
            ret = EIO;
            goto done;
        }

        in_array = false;
        ret = EOK;
        goto done;
    }

    table_iter = new_hash_iter_context(table);
    if (table_iter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "new_hash_iter_context failed.\n");
        ret = EINVAL;
        goto done;
    }

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

        in_dict = true;

        ret = sbus_iterator_write_s(&it_dict, entry->key.str);
        if (ret != EOK) {
            goto done;
        }

        values = entry->value.ptr;
        ret = sbus_iterator_write_as(&it_dict, values);
        if (ret != EOK) {
            goto done;
        }

        dbret = dbus_message_iter_close_container(&it_array, &it_dict);
        if (!dbret) {
            ret = EIO;
            goto done;
        }

        in_dict = false;
    }

    dbret = dbus_message_iter_close_container(iterator, &it_array);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    in_array = false;
    ret = EOK;

done:
    if (ret != EOK) {
        if (in_dict) {
            dbus_message_iter_abandon_container(&it_array, &it_dict);
        }

        if (in_array) {
            dbus_message_iter_abandon_container(iterator, &it_array);
        }
    }

    if (table_iter != NULL) {
        talloc_free(table_iter);
    }

    return ret;
}
