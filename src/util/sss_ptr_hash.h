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

#ifndef _SSS_PTR_HASH_H_
#define _SSS_PTR_HASH_H_

#include <talloc.h>
#include <dhash.h>

#include "util/util.h"

/**
 * Create a new hash table with string key and talloc pointer value with
 * possible custom delete callback @del_cb.
 * Table will have destructor setup to wipe content.
 * Never call hash_destroy(table) and hash_delete() explicitly but rather
 * use talloc_free(table) and sss_ptr_hash_delete().
 *
 * A notes about @del_cb:
 *  - this callback must never modify hash table (i.e. add/del entries);
 *  - this callback is triggered when value is either explicitly removed
 *    from the table or simply freed (latter leads to removal of an entry
 *    from the table);
 *  - this callback is also triggered for every entry when table is freed
 *    entirely. In this case (deltype == HASH_TABLE_DESTROY) any table
 *    lookups / iteration are forbidden as table might be already invalidated.
 */
hash_table_t *sss_ptr_hash_create(TALLOC_CTX *mem_ctx,
                                  hash_delete_callback *del_cb,
                                  void *del_cb_pvt);

/**
 * Add a new value @talloc_ptr of type @type into the table.
 *
 * If the @key already exist in the table and @override is true,
 * the value is overridden. Otherwise EEXIST error is returned.
 *
 * If talloc_ptr is freed the key and value are automatically
 * removed from the hash table (del_cb that was set up during
 * table creation is executed as a first step of this removal).
 *
 * @return EOK If the <@key, @talloc_ptr> pair was inserted.
 * @return EEXIST If @key already exists and @override is false.
 * @return Other errno code in case of an error.
 */
errno_t _sss_ptr_hash_add(hash_table_t *table,
                          const char *key,
                          void *talloc_ptr,
                          const char *type,
                          bool override);

/**
 * Add a new value @talloc_ptr of type @type into the table.
 *
 * If talloc_ptr is freed the key and value are automatically
 * removed from the hash table.
 *
 * @return EOK If the <@key, @talloc_ptr> pair was inserted.
 * @return EEXIST If @key already exists.
 * @return Other errno code in case of an error.
 */
#define sss_ptr_hash_add(table, key, talloc_ptr, type) \
    _sss_ptr_hash_add(table, key, talloc_ptr, #type, false)

/**
 * Add a new value @talloc_ptr of type @type into the table.
 *
 * If the @key already exists in the table, its value is
 * overridden. If talloc_ptr is freed the key and value
 * are automatically removed from the hash table.
 *
 * @return EOK If the <@key, @talloc_ptr> pair was inserted.
 * @return Other errno code in case of an error.
 */
#define sss_ptr_hash_add_or_override(table, key, talloc_ptr, type) \
    _sss_ptr_hash_add(table, key, talloc_ptr, #type, true)

void *_sss_ptr_hash_lookup(hash_table_t *table,
                           const char *key,
                           const char *type);

/**
 * Lookup @key in the table and return its value as typed to @type.
 * The type of the value must match with @type, otherwise NULL is returned.
 *
 * @return talloc_ptr If the value is found as type matches.
 * @return NULL If the value is not found or if the type is invalid.
 */
#define sss_ptr_hash_lookup(table, key, type) \
    (type *)_sss_ptr_hash_lookup(table, key, #type)

void *_sss_ptr_get_value(hash_value_t *table_value,
                         const char *type);

/**
 * Obtain inserted talloc pointer from table value typed to @type.
 * The type of the value must match with @type, otherwise NULL is returned.
 *
 * @return talloc_ptr If the value is found as type matches.
 * @return NULL If the value is not found or if the type is invalid.
 */
#define sss_ptr_get_value(table_value, type) \
    (type *)_sss_ptr_get_value(table_value, #type)

/**
 * Delete @key from table. If @free_value is true then also the value
 * associated with @key is freed, otherwise it is left intact.
 */
void sss_ptr_hash_delete(hash_table_t *table,
                         const char *key,
                         bool free_value);

/**
 * Delete all keys from the table. If @free_value sis true then also
 * the values associated with those keys are reed, otherwise
 * they are left intact.
 */
void sss_ptr_hash_delete_all(hash_table_t *table,
                             bool free_values);

/**
 * @return true If @key is present in the table.
 * @return false Otherwise.
 */
bool sss_ptr_hash_has_key(hash_table_t *table,
                          const char *key);

#endif /* _SSS_PTR_HASH_H_ */
