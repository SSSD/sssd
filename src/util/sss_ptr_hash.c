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

struct sss_ptr_hash_delete_data {
    hash_delete_callback *callback;
    void *pvt;
};

struct sss_ptr_hash_value {
    struct sss_ptr_hash_spy *spy;
    void *ptr;
};

struct sss_ptr_hash_spy {
    struct sss_ptr_hash_value *value;
    hash_table_t *table;
    const char *key;
};

static int
sss_ptr_hash_spy_destructor(struct sss_ptr_hash_spy *spy)
{
    spy->value->spy = NULL;

    /* This results in removing entry from hash table and freeing the value. */
    sss_ptr_hash_delete(spy->table, spy->key, false);

    return 0;
}

static struct sss_ptr_hash_spy *
sss_ptr_hash_spy_create(TALLOC_CTX *mem_ctx,
                        hash_table_t *table,
                        const char *key,
                        struct sss_ptr_hash_value *value)
{
    struct sss_ptr_hash_spy *spy;

    spy = talloc_zero(mem_ctx, struct sss_ptr_hash_spy);
    if (spy == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    spy->key = talloc_strdup(spy, key);
    if (spy->key == NULL) {
        talloc_free(spy);
        return NULL;
    }

    spy->table = table;
    spy->value = value;
    talloc_set_destructor(spy, sss_ptr_hash_spy_destructor);

    return spy;
}

static int
sss_ptr_hash_value_destructor(struct sss_ptr_hash_value *value)
{
    if (value->spy != NULL) {
        /* Disable spy destructor and free it. */
        talloc_set_destructor(value->spy, NULL);
        talloc_zfree(value->spy);
    }

    return 0;
}

static struct sss_ptr_hash_value *
sss_ptr_hash_value_create(hash_table_t *table,
                          const char *key,
                          void *talloc_ptr)
{
    struct sss_ptr_hash_value *value;

    value = talloc_zero(table, struct sss_ptr_hash_value);
    if (value == NULL) {
        return NULL;
    }

    value->spy = sss_ptr_hash_spy_create(talloc_ptr, table, key, value);
    if (value->spy == NULL) {
        talloc_free(value);
        return NULL;
    }

    value->ptr = talloc_ptr;
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

    value = talloc_get_type(item->value.ptr, struct sss_ptr_hash_value);
    if (value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid value!\n");
        return;
    }

    callback_entry.key = item->key;
    callback_entry.value.type = HASH_VALUE_PTR;
    callback_entry.value.ptr = value->ptr;

    /* Free value, this also will disable spy */
    talloc_free(value);

    if (pvt != NULL) {
        /* Switch to the input value and call custom callback. */
        data = talloc_get_type(pvt, struct sss_ptr_hash_delete_data);
        if (data == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid data!\n");
            return;
        }

        data->callback(&callback_entry, deltype, data->pvt);
    }
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

    ret = sss_hash_create_ex(mem_ctx, 10, &table, 0, 0, 0, 0,
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

    value = sss_ptr_hash_value_create(table, key, talloc_ptr);
    if (value == NULL) {
        return ENOMEM;
    }

    table_key.type = HASH_KEY_STRING;
    table_key.str = discard_const_p(char, key);

    table_value.type = HASH_VALUE_PTR;
    table_value.ptr = value;

    if (override == false && hash_has_key(table, &table_key)) {
        return EEXIST;
    }

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

    /* This may happen if we are in delete callback
     * and we try to search the hash table. */
    if (table_value.ptr == NULL) {
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
    if (value == NULL || value->ptr == NULL) {
        return NULL;
    }

    if (!sss_ptr_hash_check_type(value->ptr, type)) {
        return NULL;
    }

    return value->ptr;
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

    if (!sss_ptr_hash_check_type(value->ptr, type)) {
        return NULL;
    }

    return value->ptr;
}

void sss_ptr_hash_delete(hash_table_t *table,
                         const char *key,
                         bool free_value)
{
    struct sss_ptr_hash_value *value;
    hash_key_t table_key;
    int hret;
    void *ptr;

    if (table == NULL || key == NULL) {
        return;
    }

    value = sss_ptr_hash_lookup_internal(table, key);
    if (value == NULL) {
        /* Value not found. */
        return;
    }

    ptr = value->ptr;

    table_key.type = HASH_KEY_STRING;
    table_key.str = discard_const_p(char, key);

    /* Delete table entry. This will free value and spy in delete callback. */
    hret = hash_delete(table, &table_key);
    if (hret != HASH_SUCCESS && hret != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to remove key from table [%d]\n",
              hret);
    }

    /* Also free the original value if requested. */
    if (free_value) {
        talloc_free(ptr);
    }

    return;
}

void sss_ptr_hash_delete_all(hash_table_t *table,
                             bool free_values)
{
    struct sss_ptr_hash_value *value;
    hash_value_t *values;
    unsigned long count;
    unsigned long i;
    int hret;
    void *ptr;

    if (table == NULL) {
        return;
    }

    hret = hash_values(table, &count, &values);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get values [%d]\n", hret);
        return;
    }

    for (i = 0; i < count; i++) {
        value = values[i].ptr;
        ptr = value->ptr;

        /* This will remove the entry from hash table and free value. */
        talloc_free(value->spy);

        if (free_values) {
            /* Also free the original value. */
            talloc_free(ptr);
        }
    }

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
