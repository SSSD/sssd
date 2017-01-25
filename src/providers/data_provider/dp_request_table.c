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
#include <tevent.h>
#include <dhash.h>

#include "sbus/sssd_dbus.h"
#include "providers/data_provider/dp_private.h"
#include "util/dlinklist.h"
#include "util/util.h"

static int
dp_sbus_req_item_destructor(struct dp_sbus_req_item *item)
{
    DLIST_REMOVE(item->parent->list, item);

    return 0;
}

static int
dp_table_value_destructor(struct dp_table_value *value)
{
    struct dp_sbus_req_item *next_item;
    struct dp_sbus_req_item *item;

    DEBUG(SSSDBG_TRACE_FUNC, "Removing [%s] from reply table\n", value->key);

    dp_req_table_del(value->table, value->key);

    for (item = value->list; item != NULL; item = next_item) {
        next_item = item->next;
        talloc_free(item);
    }

    return 0;
}

static struct dp_sbus_req_item *
dp_sbus_req_item_new(struct dp_table_value *value,
                     struct sbus_request *sbus_req)
{
    struct dp_sbus_req_item *item;

    /* Attach to sbus_request so we ensure that this sbus_req is removed
     * from the list when it is unexpectedly freed, for example when
     * client connection is dropped. */
    item = talloc_zero(sbus_req, struct dp_sbus_req_item);
    if (item == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return NULL;
    }

    item->parent = value;
    item->sbus_req = sbus_req;

    talloc_set_destructor(item, dp_sbus_req_item_destructor);

    return item;
}

char *dp_req_table_key(TALLOC_CTX *mem_ctx,
                       enum dp_targets target,
                       enum dp_methods method,
                       uint32_t dp_flags,
                       const char *custom_part)
{
    const char *str = custom_part == NULL ? "(null)" : custom_part;

    return talloc_asprintf(mem_ctx, "%u:%u:%#.4x:%s",
                           target, method, dp_flags, str);
}

errno_t dp_req_table_init(TALLOC_CTX *mem_ctx, hash_table_t **_table)
{
    return sss_hash_create(mem_ctx, 100, _table);
}

struct dp_table_value *dp_req_table_lookup(hash_table_t *table,
                                           const char *key)
{
    hash_key_t hkey;
    hash_value_t hvalue;
    int hret;

    hkey.type = HASH_KEY_STRING;
    hkey.str = discard_const_p(char, key);

    hret = hash_lookup(table, &hkey, &hvalue);
    if (hret == HASH_ERROR_KEY_NOT_FOUND) {
        return NULL;
    } else if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to search hash table [%d]\n", hret);
        return NULL;
    }

    return hvalue.ptr;
}

static errno_t dp_req_table_new_item(hash_table_t *table,
                                     const char *key,
                                     struct tevent_req *req,
                                     struct sbus_request *sbus_req)
{
    hash_key_t hkey;
    hash_value_t hvalue;
    struct dp_table_value *table_value;
    errno_t ret;
    int hret;

    /* Attach it to request. */
    table_value = talloc_zero(req, struct dp_table_value);
    if (table_value == NULL) {
        return ENOMEM;
    }

    table_value->table = table;
    table_value->key = talloc_strdup(table_value, key);
    if (table_value->key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    table_value->req = req;
    table_value->list = dp_sbus_req_item_new(table_value, sbus_req);
    if (table_value->list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor(table_value, dp_table_value_destructor);

    hkey.type = HASH_KEY_STRING;
    hkey.str = discard_const_p(char, key);

    hvalue.type = HASH_VALUE_PTR;
    hvalue.ptr = table_value;

    hret = hash_enter(table, &hkey, &hvalue);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to enter value into hash table "
              "[%d]\n", hret);
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(table_value);
    }

    return ret;
}

static errno_t dp_req_table_mod_item(hash_table_t *table,
                                     struct dp_table_value *table_value,
                                     struct sbus_request *sbus_req)
{
    struct dp_sbus_req_item *item;

    item = dp_sbus_req_item_new(table_value, sbus_req);
    if (item == NULL) {
        return ENOMEM;
    }

    DLIST_ADD(table_value->list, item);

    return EOK;
}

errno_t dp_req_table_add(hash_table_t *table,
                         const char *key,
                         struct tevent_req *req,
                         struct sbus_request *sbus_req)
{
    struct dp_table_value *table_value;

    if (sbus_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "SBUS request cannot be NULL\n");
        return EINVAL;
    }

    table_value = dp_req_table_lookup(table, key);
    if (table_value == NULL) {
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Tevent request cannot be NULL\n");
            return EINVAL;
        }

        return dp_req_table_new_item(table, key, req, sbus_req);
    }

    return dp_req_table_mod_item(table, table_value, sbus_req);
}

void dp_req_table_del(hash_table_t *table,
                      const char *key)
{
    hash_key_t hkey;
    int hret;

    if (table == NULL || key == NULL) {
        return;
    }

    hkey.type = HASH_KEY_STRING;
    hkey.str = discard_const_p(char, key);

    hret = hash_delete(table, &hkey);
    if (hret != HASH_SUCCESS && hret != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to remove key from table [%d]\n",
              hret);
    }

    return;
}

void dp_req_table_del_and_free(hash_table_t *table,
                               const char *key)
{
    struct dp_table_value *value;

    value = dp_req_table_lookup(table, key);
    if (value == NULL) {
        /* We're done here. */
        return;
    }

    dp_req_table_del(table, key);
    talloc_free(value);

    return;
}

bool dp_req_table_has_key(hash_table_t *table,
                          const char *key)
{
    hash_key_t hkey;

    hkey.type = HASH_KEY_STRING;
    hkey.str = discard_const_p(char, key);

    return hash_has_key(table, &hkey);
}
