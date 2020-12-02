/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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
#include <dhash.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"

static bool sss_ptr_hash_check_type(void *ptr, const char *type)
{
    void *type_ptr;

    type_ptr = talloc_check_name(ptr, type);
    if (type_ptr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Invalid data type detected. Expected [%s], got [%s].\n",
              type, talloc_get_name(ptr));
        return false;
    }

    return true;
}

static int sss_ptr_hash_table_destructor(hash_table_t *table)
{
    sss_ptr_hash_delete_all(table, false);
    return 0;
}

struct sss_ptr_hash_delete_data {
    hash_delete_callback *callback;
    void *pvt;
};

struct sss_ptr_hash_value {
    hash_table_t *table;
    const char *key;
    void *payload;
    bool delete_in_progress;
};

static int
sss_ptr_hash_value_destructor(struct sss_ptr_hash_value *value)
{
    hash_key_t table_key;

    /* Do not call hash_delete() if we got here from hash delete callback when
     * the callback calls talloc_free(payload) which frees the value. This
     * should not happen since talloc will avoid circular free but let's be
     * over protective here. */
    if (value->delete_in_progress) {
        return 0;
    }

    value->delete_in_progress = true;
    if (value->table && value->key) {
        table_key.type = HASH_KEY_STRING;
        table_key.str = discard_const_p(char, value->key);
        if (hash_delete(value->table, &table_key) != HASH_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "failed to delete entry with key '%s'\n", value->key);
            value->delete_in_progress = false;
        }
    }

    return 0;
}

static struct sss_ptr_hash_value *
sss_ptr_hash_value_create(hash_table_t *table,
                          const char *key,
                          void *talloc_ptr)
{
    struct sss_ptr_hash_value *value;

    value = talloc_zero(talloc_ptr, struct sss_ptr_hash_value);
    if (value == NULL) {
        return NULL;
    }

    value->key = talloc_strdup(value, key);
    if (value->key == NULL) {
        talloc_free(value);
        return NULL;
    }

    value->table = table;
    value->payload = talloc_ptr;
    talloc_set_destructor(value, sss_ptr_hash_value_destructor);

    return value;
}

static void
sss_ptr_hash_delete_cb(hash_entry_t *item,
                       hash_destroy_enum deltype,
                       void *pvt)
{
    struct sss_ptr_hash_delete_data *data;
    struct sss_ptr_hash_value *value;
    struct hash_entry_t callback_entry;

    if (pvt == NULL) {
        return;
    }

    value = talloc_get_type(item->value.ptr, struct sss_ptr_hash_value);
    if (value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid value!\n");
        return;
    }

    /* Switch to the input value and call custom callback. */
    data = talloc_get_type(pvt, struct sss_ptr_hash_delete_data);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid data!\n");
        return;
    }

    callback_entry.key = item->key;
    callback_entry.value.type = HASH_VALUE_PTR;
    callback_entry.value.ptr = value->payload;

    /* Delete the value in case this callback has been called directly
     * from dhash (overwriting existing entry) instead of hash_delete()
     * in value's destructor. */
    if (!value->delete_in_progress) {
        talloc_set_destructor(value, NULL);
        talloc_free(value);
    }

    /* Even if execution is already in the context of
     * talloc_free(payload) -> talloc_free(value) -> ...
     * there still might be legitimate reasons to execute callback.
     */
    data->callback(&callback_entry, deltype, data->pvt);
}

hash_table_t *sss_ptr_hash_create(TALLOC_CTX *mem_ctx,
                                  hash_delete_callback *del_cb,
                                  void *del_cb_pvt)
{
    struct sss_ptr_hash_delete_data *data = NULL;
    hash_table_t *table;
    errno_t ret;

    if (del_cb != NULL) {
        data = talloc_zero(NULL, struct sss_ptr_hash_delete_data);
        if (data == NULL) {
            return NULL;
        }

        data->callback = del_cb;
        data->pvt = del_cb_pvt;
    }

    ret = sss_hash_create_ex(mem_ctx, 0, &table, 0, 0, 0, 0,
                             sss_ptr_hash_delete_cb, data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
              ret, sss_strerror(ret));
        talloc_free(data);
        return NULL;
    }

    if (data != NULL) {
        talloc_steal(table, data);
    }

    talloc_set_destructor(table, sss_ptr_hash_table_destructor);

    return table;
}

errno_t _sss_ptr_hash_add(hash_table_t *table,
                          const char *key,
                          void *talloc_ptr,
                          const char *type,
                          bool override)
{
    struct sss_ptr_hash_value *value;
    hash_value_t table_value;
    hash_key_t table_key;
    int hret;

    if (table == NULL || key == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid input!\n");
        return EINVAL;
    }

    if (!sss_ptr_hash_check_type(talloc_ptr, type)) {
        return ERR_INVALID_DATA_TYPE;
    }

    table_key.type = HASH_KEY_STRING;
    table_key.str = discard_const_p(char, key);

    if (override == false && hash_has_key(table, &table_key)) {
        return EEXIST;
    }

    value = sss_ptr_hash_value_create(table, key, talloc_ptr);
    if (value == NULL) {
        return ENOMEM;
    }

    table_value.type = HASH_VALUE_PTR;
    table_value.ptr = value;

    hret = hash_enter(table, &table_key, &table_value);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add key %s!\n", key);
        talloc_free(value);
        return EIO;
    }

    return EOK;
}

static struct sss_ptr_hash_value *
sss_ptr_hash_lookup_internal(hash_table_t *table,
                             const char *key)
{
    hash_value_t table_value;
    hash_key_t table_key;
    int hret;

    table_key.type = HASH_KEY_STRING;
    table_key.str = discard_const_p(char, key);

    hret = hash_lookup(table, &table_key, &table_value);
    if (hret == HASH_ERROR_KEY_NOT_FOUND) {
        return NULL;
    } else if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to search hash table [%d]\n", hret);
        return NULL;
    }

    /* Check value type. */
    if (table_value.type != HASH_VALUE_PTR) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid value type found: %d\n",
              table_value.type);
        return NULL;
    }

    if (!sss_ptr_hash_check_type(table_value.ptr, "struct sss_ptr_hash_value")) {
        return NULL;
    }

    return table_value.ptr;
}

void *_sss_ptr_hash_lookup(hash_table_t *table,
                           const char *key,
                           const char *type)
{
    struct sss_ptr_hash_value *value;

    value = sss_ptr_hash_lookup_internal(table, key);
    if (value == NULL || value->payload == NULL) {
        return NULL;
    }

    if (!sss_ptr_hash_check_type(value->payload, type)) {
        return NULL;
    }

    return value->payload;
}

void *_sss_ptr_get_value(hash_value_t *table_value,
                         const char *type)
{
    struct sss_ptr_hash_value *value;

    /* Check value type. */
    if (table_value->type != HASH_VALUE_PTR) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid value type found: %d\n",
              table_value->type);
        return NULL;
    }

    if (!sss_ptr_hash_check_type(table_value->ptr, "struct sss_ptr_hash_value")) {
        return NULL;
    }

    value = table_value->ptr;

    if (!sss_ptr_hash_check_type(value->payload, type)) {
        return NULL;
    }

    return value->payload;
}

void sss_ptr_hash_delete(hash_table_t *table,
                         const char *key,
                         bool free_value)
{
    struct sss_ptr_hash_value *value;
    void *payload = NULL;

    if (table == NULL || key == NULL) {
        return;
    }

    value = sss_ptr_hash_lookup_internal(table, key);
    if (value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to remove key '%s' from table\n", key);
        return;
    }

    if (free_value) {
        payload = value->payload;
    }

    talloc_free(value); /* this will call hash_delete() in value d-tor */

    talloc_free(payload); /* it is safe to call talloc_free(NULL) */

    return;
}

void sss_ptr_hash_delete_all(hash_table_t *table,
                             bool free_values)
{
    hash_value_t *content;
    struct sss_ptr_hash_value *value;
    void *payload = NULL;
    unsigned long count;
    unsigned long i;
    int hret;

    if (table == NULL) {
        return;
    }

    hret = hash_values(table, &count, &content);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get values [%d]\n", hret);
        return;
    }

    for (i = 0; i < count; ++i) {
        if ((content[i].type == HASH_VALUE_PTR)  &&
            sss_ptr_hash_check_type(content[i].ptr,
                                    "struct sss_ptr_hash_value")) {
            value = content[i].ptr;
            if (free_values) {
                payload = value->payload;
            }
            talloc_free(value);
            if (free_values) {
                talloc_free(payload); /* it's safe to call talloc_free(NULL) */
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected type of table content, skipping");
        }
    }

    talloc_free(content);

    return;
}

bool sss_ptr_hash_has_key(hash_table_t *table,
                          const char *key)
{
    hash_key_t table_key;

    table_key.type = HASH_KEY_STRING;
    table_key.str = discard_const_p(char, key);

    return hash_has_key(table, &table_key);
}
