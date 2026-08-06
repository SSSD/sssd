/*
   Transactional membership graph maintenance for the SSSD sysdb.

   Direct group "member" edges are source data. Reverse memberships,
   memberUid, and inherited ghost users are materialized once when the outer
   LDB transaction is prepared. This prevents one recursive database walk for
   every removed edge during a large group replacement.
*/

#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <dhash.h>

#include "ldb_module.h"
#include "util/util.h"
#include "ldb_modules/memberof_transaction.h"

#define TX_DB_MEMBER "member"
#define TX_DB_GHOST "ghost"
#define TX_DB_GHOST_DIRECT "ghostDirect"
#define TX_DB_MEMBEROF "memberof"
#define TX_DB_MEMBERUID "memberuid"
#define TX_DB_NAME "name"
#define TX_DB_OC "objectCategory"
#define TX_DB_USER_CLASS "user"
#define TX_DB_GROUP_CLASS "group"
#define TX_DB_CACHE_EXPIRE "dataExpireTimestamp"

#define TX_REBUILD_DN "@MEMBEROF-REBUILD"
#define TX_MIGRATION_DN "@MEMBEROF-TRANSACTIONAL"
#define TX_MIGRATION_ATTR "@GHOST-DIRECT-VERSION"
#define TX_MIGRATION_VERSION "1"

/* Expiration and other cache metadata do not participate in the graph. */
static const char *tx_graph_attrs[] = {
    TX_DB_OC, TX_DB_NAME, TX_DB_MEMBER,
    TX_DB_MEMBEROF, TX_DB_MEMBERUID,
    TX_DB_GHOST, TX_DB_GHOST_DIRECT, NULL
};

struct tx_set_entry {
    const char *key;
    const char *output;
};

struct tx_set {
    TALLOC_CTX *owner;
    TALLOC_CTX *storage;
    hash_table_t *table;
    struct tx_set_entry **ordered;
    size_t count;
    size_t capacity;
};

struct tx_legacy_ghost {
    struct tx_set direct;
    bool ambiguous;
};

struct tx_ghost_op {
    struct tx_ghost_op *next;
    struct ldb_dn *dn;
    unsigned int flags;
    struct ldb_val *values;
    unsigned int num_values;
};

struct tx_rename {
    struct tx_rename *next;
    struct tx_rename *prev;
    struct ldb_dn *old_dn;
    struct ldb_dn *new_dn;
    const char *old_key;
    const char *new_key;
};

struct tx_journal {
    bool dirty;
    bool migration_checked;
    bool migration_marker_exists;
    bool migration_complete;
    bool migration_written;

    hash_table_t *legacy_ghosts;
    struct tx_ghost_op *ghost_ops;
    struct tx_ghost_op *last_ghost_op;
    struct tx_rename *renames;
    struct tx_rename *last_rename;
    struct tx_set deleted_dns;
    struct ldb_result *snapshot;
    hash_table_t *snapshot_map;
};

struct tx_private {
    bool enabled;
    bool flushing;
    bool migration_persisted;
    struct tx_journal *journal;
};

struct tx_snapshot_group {
    struct ldb_message *msg;
    const char *key;
    struct tx_set public_ghosts;
    struct tx_set direct_ghosts;
};

static int tx_graph_flush(struct ldb_module *module,
                          struct tx_journal *journal);

static void *tx_hash_alloc(size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void tx_hash_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

static int tx_hash_create(TALLOC_CTX *mem_ctx, unsigned long size,
                          hash_table_t **_table)
{
    int hret;

    hret = hash_create_ex(size, _table, 0, 0, 0, 0,
                          tx_hash_alloc, tx_hash_free,
                          mem_ctx, NULL, NULL);
    return hret == HASH_SUCCESS ? LDB_SUCCESS : LDB_ERR_OPERATIONS_ERROR;
}

static int tx_hash_put_ptr(hash_table_t *table, const char *key_string,
                           void *ptr)
{
    hash_value_t value;
    hash_key_t key;
    int hret;

    key.type = HASH_KEY_STRING;
    key.str = discard_const(key_string);
    value.type = HASH_VALUE_PTR;
    value.ptr = ptr;

    hret = hash_enter(table, &key, &value);
    return hret == HASH_SUCCESS ? LDB_SUCCESS : LDB_ERR_OPERATIONS_ERROR;
}

static void *tx_hash_get_ptr(hash_table_t *table, const char *key_string)
{
    hash_value_t value;
    hash_key_t key;
    int hret;

    if (table == NULL || key_string == NULL) {
        return NULL;
    }

    key.type = HASH_KEY_STRING;
    key.str = discard_const(key_string);
    hret = hash_lookup(table, &key, &value);
    if (hret != HASH_SUCCESS || value.type != HASH_VALUE_PTR) {
        return NULL;
    }

    return value.ptr;
}

static int tx_hash_delete_key(hash_table_t *table, const char *key_string)
{
    hash_key_t key;
    int hret;

    if (table == NULL || key_string == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    key.type = HASH_KEY_STRING;
    key.str = discard_const(key_string);
    hret = hash_delete(table, &key);
    return hret == HASH_SUCCESS ? LDB_SUCCESS
                                : LDB_ERR_OPERATIONS_ERROR;
}

static void tx_set_init(struct tx_set *set, TALLOC_CTX *owner)
{
    set->owner = owner;
}

static int tx_set_ensure(struct tx_set *set, unsigned long size)
{
    int ret;

    if (set->table != NULL) {
        return LDB_SUCCESS;
    }

    set->storage = talloc_new(set->owner);
    if (set->storage == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = tx_hash_create(set->storage, size, &set->table);
    if (ret != LDB_SUCCESS) {
        talloc_zfree(set->storage);
    }

    return ret;
}

static void tx_set_clear(struct tx_set *set)
{
    talloc_zfree(set->storage);
    set->table = NULL;
    set->ordered = NULL;
    set->count = 0;
    set->capacity = 0;
}

static unsigned long tx_set_count(const struct tx_set *set)
{
    return set->count;
}

static bool tx_set_has(const struct tx_set *set, const char *key_string)
{
    hash_key_t key;

    if (set->table == NULL || key_string == NULL) {
        return false;
    }

    key.type = HASH_KEY_STRING;
    key.str = discard_const(key_string);
    return hash_has_key(set->table, &key);
}

static int tx_set_add(struct tx_set *set, const char *key_string,
                      const char *output)
{
    struct tx_set_entry **ordered;
    struct tx_set_entry *entry;
    hash_value_t value;
    hash_key_t key;
    size_t capacity;
    int ret;

    if (key_string == NULL || output == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = tx_set_ensure(set, 0);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    key.type = HASH_KEY_STRING;
    key.str = discard_const(key_string);
    if (hash_has_key(set->table, &key)) {
        return LDB_SUCCESS;
    }

    if (set->count == set->capacity) {
        capacity = set->capacity == 0 ? 8 : set->capacity * 2;
        if (capacity < set->capacity) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        ordered = talloc_realloc(set->storage, set->ordered,
                                 struct tx_set_entry *, capacity);
        if (ordered == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        set->ordered = ordered;
        set->capacity = capacity;
    }

    entry = talloc_zero(set->storage, struct tx_set_entry);
    if (entry == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    entry->key = talloc_strdup(entry, key_string);
    entry->output = talloc_strdup(entry, output);
    if (entry->key == NULL || entry->output == NULL) {
        talloc_free(entry);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    key.str = discard_const(entry->key);
    value.type = HASH_VALUE_PTR;
    value.ptr = entry;
    ret = hash_enter(set->table, &key, &value);
    if (ret != HASH_SUCCESS) {
        talloc_free(entry);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    set->ordered[set->count++] = entry;
    return LDB_SUCCESS;
}

static int tx_set_remove(struct tx_set *set, const char *key_string)
{
    struct tx_set_entry *entry;
    hash_value_t value;
    hash_key_t key;
    size_t i;
    int hret;

    if (set->table == NULL || key_string == NULL) {
        return LDB_SUCCESS;
    }

    key.type = HASH_KEY_STRING;
    key.str = discard_const(key_string);
    if (!hash_has_key(set->table, &key)) {
        return LDB_SUCCESS;
    }

    hret = hash_lookup(set->table, &key, &value);
    if (hret != HASH_SUCCESS || value.type != HASH_VALUE_PTR) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    entry = value.ptr;
    for (i = 0; i < set->count; i++) {
        if (set->ordered[i] == entry) {
            break;
        }
    }
    if (i == set->count) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    hret = hash_delete(set->table, &key);
    if (hret != HASH_SUCCESS) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    set->count--;
    if (i != set->count) {
        memmove(&set->ordered[i], &set->ordered[i + 1],
                (set->count - i) * sizeof(set->ordered[0]));
    }
    talloc_free(entry);
    return LDB_SUCCESS;
}

static int tx_set_union(struct tx_set *dest, const struct tx_set *source)
{
    size_t i;
    int ret;

    for (i = 0; i < source->count; i++) {
        ret = tx_set_add(dest, source->ordered[i]->key,
                         source->ordered[i]->output);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return LDB_SUCCESS;
}

static int tx_set_copy(struct tx_set *dest, const struct tx_set *source)
{
    tx_set_clear(dest);
    return tx_set_union(dest, source);
}

static const char *tx_dn_key(struct ldb_dn *dn)
{
    if (dn == NULL || !ldb_dn_validate(dn)) {
        return NULL;
    }

    return ldb_dn_get_casefold(dn);
}

static bool tx_message_is_class(const struct ldb_message *message,
                                const char *object_class)
{
    struct ldb_message_element *el;
    unsigned int i;

    el = ldb_msg_find_element(message, TX_DB_OC);
    if (el == NULL) {
        return false;
    }

    for (i = 0; i < el->num_values; i++) {
        if (strcasecmp((const char *)el->values[i].data,
                       object_class) == 0) {
            return true;
        }
    }

    return false;
}

static bool tx_message_is_identity(const struct ldb_message *message)
{
    return tx_message_is_class(message, TX_DB_USER_CLASS)
        || tx_message_is_class(message, TX_DB_GROUP_CLASS);
}

static int tx_snapshot_ensure(struct ldb_module *module,
                              struct tx_journal *journal)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    const char *key;
    unsigned int i;
    int ret;

    if (journal->snapshot != NULL) {
        return LDB_SUCCESS;
    }

    ret = ldb_search(ldb, journal, &journal->snapshot,
                     NULL, LDB_SCOPE_SUBTREE, tx_graph_attrs, NULL);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    ret = tx_hash_create(journal, journal->snapshot->count,
                         &journal->snapshot_map);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    for (i = 0; i < journal->snapshot->count; i++) {
        key = tx_dn_key(journal->snapshot->msgs[i]->dn);
        if (key == NULL) {
            return LDB_ERR_INVALID_DN_SYNTAX;
        }
        ret = tx_hash_put_ptr(journal->snapshot_map, key,
                              journal->snapshot->msgs[i]);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return LDB_SUCCESS;
}

static struct ldb_message *tx_snapshot_lookup(struct tx_journal *journal,
                                              struct ldb_dn *dn)
{
    return tx_hash_get_ptr(journal->snapshot_map, tx_dn_key(dn));
}

static bool tx_value_equal(const struct ldb_val *left,
                           const struct ldb_val *right)
{
    return left->length == right->length
        && memcmp(left->data, right->data, left->length) == 0;
}

static bool tx_values_have(const struct ldb_val *values, size_t count,
                           const struct ldb_val *value)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (tx_value_equal(&values[i], value)) {
            return true;
        }
    }
    return false;
}

static int tx_snapshot_set_values(struct ldb_message *message,
                                  const char *name,
                                  const struct ldb_val *values,
                                  size_t count)
{
    struct ldb_message_element *element;
    struct ldb_val *copies = NULL;
    struct ldb_dn *dn = message->dn;
    TALLOC_CTX *tmp_ctx;
    size_t i;
    int ret;

    tmp_ctx = talloc_new(message);
    if (tmp_ctx == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (count != 0) {
        copies = talloc_zero_array(tmp_ctx, struct ldb_val, count);
        if (copies == NULL) {
            talloc_free(tmp_ctx);
            return LDB_ERR_OPERATIONS_ERROR;
        }
        for (i = 0; i < count; i++) {
            copies[i].data = talloc_zero_size(copies,
                                              values[i].length + 1);
            if (copies[i].data == NULL) {
                talloc_free(tmp_ctx);
                return LDB_ERR_OPERATIONS_ERROR;
            }
            memcpy(copies[i].data, values[i].data, values[i].length);
            copies[i].length = values[i].length;
        }
    }

    ldb_msg_remove_attr(message, name);
    message->dn = dn;
    if (count == 0) {
        talloc_free(tmp_ctx);
        return LDB_SUCCESS;
    }

    ret = ldb_msg_add_empty(message, name, 0, &element);
    if (ret != LDB_SUCCESS) {
        talloc_free(tmp_ctx);
        return ret;
    }
    element->values = talloc_steal(message, copies);
    element->num_values = count;
    talloc_free(tmp_ctx);
    return LDB_SUCCESS;
}

static int tx_snapshot_apply_element(struct ldb_message *message,
                                     const struct ldb_message_element *change)
{
    struct ldb_message_element *current;
    struct ldb_val *values;
    TALLOC_CTX *tmp_ctx;
    size_t current_count;
    size_t count = 0;
    size_t i;
    unsigned int j;
    int ret;

    current = ldb_msg_find_element(message, change->name);
    current_count = current == NULL ? 0 : current->num_values;
    switch (change->flags & LDB_FLAG_MOD_MASK) {
    case 0:
    case LDB_FLAG_MOD_REPLACE:
        return tx_snapshot_set_values(message, change->name,
                                      change->values,
                                      change->num_values);

    case LDB_FLAG_MOD_ADD:
        tmp_ctx = talloc_new(message);
        if (tmp_ctx == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        values = talloc_array(tmp_ctx, struct ldb_val,
                              current_count + change->num_values);
        if (values == NULL
                && current_count + change->num_values != 0) {
            talloc_free(tmp_ctx);
            return LDB_ERR_OPERATIONS_ERROR;
        }
        for (i = 0; i < current_count; i++) {
            values[count++] = current->values[i];
        }
        for (j = 0; j < change->num_values; j++) {
            if (!tx_values_have(values, count, &change->values[j])) {
                values[count++] = change->values[j];
            }
        }
        ret = tx_snapshot_set_values(message, change->name, values, count);
        talloc_free(tmp_ctx);
        return ret;

    case LDB_FLAG_MOD_DELETE:
        if (current == NULL || change->num_values == 0) {
            return tx_snapshot_set_values(message, change->name, NULL, 0);
        }
        tmp_ctx = talloc_new(message);
        if (tmp_ctx == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        values = talloc_array(tmp_ctx, struct ldb_val, current_count);
        if (values == NULL && current_count != 0) {
            talloc_free(tmp_ctx);
            return LDB_ERR_OPERATIONS_ERROR;
        }
        for (i = 0; i < current_count; i++) {
            if (!tx_values_have(change->values, change->num_values,
                                &current->values[i])) {
                values[count++] = current->values[i];
            }
        }
        ret = tx_snapshot_set_values(message, change->name, values, count);
        talloc_free(tmp_ctx);
        return ret;

    default:
        return LDB_ERR_OPERATIONS_ERROR;
    }
}

static bool tx_snapshot_tracks_attr(const char *name)
{
    return strcasecmp(name, TX_DB_OC) == 0
        || strcasecmp(name, TX_DB_NAME) == 0
        || strcasecmp(name, TX_DB_MEMBER) == 0
        || strcasecmp(name, TX_DB_GHOST) == 0;
}

static int tx_snapshot_modify(struct tx_journal *journal,
                              const struct ldb_message *change)
{
    struct ldb_message *message;
    unsigned int i;
    int ret;

    message = tx_snapshot_lookup(journal, change->dn);
    if (message == NULL) {
        return LDB_SUCCESS;
    }
    for (i = 0; i < change->num_elements; i++) {
        if (!tx_snapshot_tracks_attr(change->elements[i].name)) {
            continue;
        }
        ret = tx_snapshot_apply_element(message, &change->elements[i]);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }
    return LDB_SUCCESS;
}

static int tx_snapshot_add(struct tx_journal *journal,
                           const struct ldb_message *source)
{
    struct ldb_message **messages;
    struct ldb_message *message;
    const char *key;
    int ret;

    if (tx_snapshot_lookup(journal, source->dn) != NULL) {
        return LDB_ERR_ENTRY_ALREADY_EXISTS;
    }
    message = ldb_msg_copy(journal->snapshot, source);
    if (message == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    messages = talloc_realloc(journal->snapshot,
                              journal->snapshot->msgs,
                              struct ldb_message *,
                              journal->snapshot->count + 1);
    if (messages == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    journal->snapshot->msgs = messages;
    key = tx_dn_key(message->dn);
    if (key == NULL) {
        return LDB_ERR_INVALID_DN_SYNTAX;
    }
    ret = tx_hash_put_ptr(journal->snapshot_map, key, message);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    journal->snapshot->msgs[journal->snapshot->count++] = message;
    return LDB_SUCCESS;
}

static int tx_snapshot_remove(struct tx_journal *journal, struct ldb_dn *dn)
{
    struct ldb_message *message;
    const char *key;
    unsigned int i;
    int ret;

    message = tx_snapshot_lookup(journal, dn);
    if (message == NULL) {
        return LDB_ERR_NO_SUCH_OBJECT;
    }
    key = tx_dn_key(dn);
    ret = tx_hash_delete_key(journal->snapshot_map, key);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    for (i = 0; i < journal->snapshot->count; i++) {
        if (journal->snapshot->msgs[i] == message) {
            break;
        }
    }
    if (i == journal->snapshot->count) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    journal->snapshot->count--;
    if (i != journal->snapshot->count) {
        memmove(&journal->snapshot->msgs[i],
                &journal->snapshot->msgs[i + 1],
                (journal->snapshot->count - i)
                    * sizeof(journal->snapshot->msgs[0]));
    }
    talloc_free(message);
    return LDB_SUCCESS;
}

static int tx_snapshot_rename(struct tx_journal *journal,
                              struct ldb_dn *old_dn,
                              struct ldb_dn *new_dn)
{
    struct ldb_message *message;
    struct ldb_dn *copy;
    const char *old_key;
    const char *new_key;
    int ret;

    message = tx_snapshot_lookup(journal, old_dn);
    if (message == NULL) {
        return LDB_ERR_NO_SUCH_OBJECT;
    }
    copy = ldb_dn_copy(message, new_dn);
    if (copy == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    old_key = tx_dn_key(old_dn);
    ret = tx_hash_delete_key(journal->snapshot_map, old_key);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    message->dn = copy;
    new_key = tx_dn_key(message->dn);
    if (new_key == NULL) {
        return LDB_ERR_INVALID_DN_SYNTAX;
    }
    return tx_hash_put_ptr(journal->snapshot_map, new_key, message);
}

static int tx_snapshot_public_ghosts(struct tx_snapshot_group *group)
{
    struct ldb_message_element *el;
    unsigned int i;
    int ret;

    tx_set_init(&group->public_ghosts, group);
    tx_set_init(&group->direct_ghosts, group);

    el = ldb_msg_find_element(group->msg, TX_DB_GHOST);
    if (el == NULL) {
        return LDB_SUCCESS;
    }

    for (i = 0; i < el->num_values; i++) {
        ret = tx_set_add(&group->public_ghosts,
                         (const char *)el->values[i].data,
                         (const char *)el->values[i].data);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return tx_set_copy(&group->direct_ghosts, &group->public_ghosts);
}

static int tx_check_migration_marker(struct ldb_module *module,
                                     TALLOC_CTX *mem_ctx,
                                     bool *_exists,
                                     bool *_complete)
{
    static const char *attrs[] = { TX_MIGRATION_ATTR, NULL };
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct ldb_result *result = NULL;
    struct ldb_dn *dn;
    const char *version;
    int ret;

    *_exists = false;
    *_complete = false;
    dn = ldb_dn_new(mem_ctx, ldb, TX_MIGRATION_DN);
    if (dn == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = ldb_search(ldb, mem_ctx, &result, dn, LDB_SCOPE_BASE,
                     attrs, NULL);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    if (result->count == 0) {
        return LDB_SUCCESS;
    }
    if (result->count != 1) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    *_exists = true;
    version = ldb_msg_find_attr_as_string(result->msgs[0],
                                           TX_MIGRATION_ATTR, NULL);
    *_complete = version != NULL
              && strcmp(version, TX_MIGRATION_VERSION) == 0;
    return LDB_SUCCESS;
}

static int tx_capture_legacy_ghosts(struct ldb_module *module,
                                    struct tx_journal *journal)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct tx_snapshot_group **groups = NULL;
    struct tx_snapshot_group *group;
    struct tx_snapshot_group *child;
    struct ldb_message_element *members;
    struct ldb_result *result = journal->snapshot;
    struct tx_legacy_ghost *record;
    TALLOC_CTX *tmp_ctx;
    hash_table_t *group_map = NULL;
    struct ldb_dn *member_dn;
    const char *key;
    size_t num_groups = 0;
    size_t group_index = 0;
    size_t k;
    unsigned int i;
    unsigned int j;
    int ret;

    if (journal->migration_checked) {
        return LDB_SUCCESS;
    }
    journal->migration_checked = true;

    tmp_ctx = talloc_new(journal);
    if (tmp_ctx == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = tx_check_migration_marker(module, tmp_ctx,
                                    &journal->migration_marker_exists,
                                    &journal->migration_complete);
    if (ret != LDB_SUCCESS || journal->migration_complete) {
        talloc_free(tmp_ctx);
        return ret;
    }

    if (result == NULL) {
        talloc_free(tmp_ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    for (i = 0; i < result->count; i++) {
        if (tx_message_is_class(result->msgs[i], TX_DB_GROUP_CLASS)) {
            num_groups++;
        }
    }

    ret = tx_hash_create(journal, num_groups, &journal->legacy_ghosts);
    if (ret != LDB_SUCCESS) {
        talloc_free(tmp_ctx);
        return ret;
    }
    ret = tx_hash_create(tmp_ctx, num_groups, &group_map);
    if (ret != LDB_SUCCESS) {
        talloc_free(tmp_ctx);
        return ret;
    }

    groups = talloc_zero_array(tmp_ctx, struct tx_snapshot_group *,
                               num_groups);
    if (groups == NULL && num_groups != 0) {
        talloc_free(tmp_ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    for (i = 0; i < result->count; i++) {
        if (!tx_message_is_class(result->msgs[i], TX_DB_GROUP_CLASS)) {
            continue;
        }
        group = talloc_zero(tmp_ctx, struct tx_snapshot_group);
        if (group == NULL) {
            ret = LDB_ERR_OPERATIONS_ERROR;
            goto done;
        }
        groups[group_index++] = group;
        group->msg = result->msgs[i];
        group->key = tx_dn_key(group->msg->dn);
        if (group->key == NULL) {
            ret = LDB_ERR_INVALID_DN_SYNTAX;
            goto done;
        }

        ret = tx_snapshot_public_ghosts(group);
        if (ret != LDB_SUCCESS) {
            goto done;
        }
        ret = tx_hash_put_ptr(group_map, group->key, group);
        if (ret != LDB_SUCCESS) {
            goto done;
        }
    }

    for (i = 0; i < num_groups; i++) {
        group = groups[i];
        members = ldb_msg_find_element(group->msg, TX_DB_MEMBER);
        if (members == NULL) {
            continue;
        }

        for (j = 0; j < members->num_values; j++) {
            member_dn = ldb_dn_from_ldb_val(tmp_ctx, ldb,
                                            &members->values[j]);
            key = tx_dn_key(member_dn);
            child = tx_hash_get_ptr(group_map, key);
            if (child == NULL || child->public_ghosts.table == NULL) {
                continue;
            }

            for (k = 0; k < child->public_ghosts.count; k++) {
                key = child->public_ghosts.ordered[k]->key;
                if (tx_set_has(&group->direct_ghosts, key)) {
                    record = tx_hash_get_ptr(journal->legacy_ghosts,
                                             group->key);
                    if (record == NULL) {
                        record = talloc_zero(journal,
                                             struct tx_legacy_ghost);
                        if (record == NULL) {
                            ret = LDB_ERR_OPERATIONS_ERROR;
                            goto done;
                        }
                        tx_set_init(&record->direct, record);
                        record->ambiguous = true;
                        ret = tx_hash_put_ptr(journal->legacy_ghosts,
                                              group->key, record);
                        if (ret != LDB_SUCCESS) {
                            goto done;
                        }
                    } else {
                        record->ambiguous = true;
                    }
                }

                ret = tx_set_remove(&group->direct_ghosts, key);
                if (ret != LDB_SUCCESS) {
                    goto done;
                }
            }
        }
    }

    for (i = 0; i < num_groups; i++) {
        group = groups[i];
        record = tx_hash_get_ptr(journal->legacy_ghosts, group->key);
        if (record == NULL) {
            record = talloc_zero(journal, struct tx_legacy_ghost);
            if (record == NULL) {
                ret = LDB_ERR_OPERATIONS_ERROR;
                goto done;
            }
            tx_set_init(&record->direct, record);
            ret = tx_hash_put_ptr(journal->legacy_ghosts,
                                  group->key, record);
            if (ret != LDB_SUCCESS) {
                goto done;
            }
        }

        ret = tx_set_copy(&record->direct, &group->direct_ghosts);
        if (ret != LDB_SUCCESS) {
            goto done;
        }
    }

    ret = LDB_SUCCESS;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static struct tx_private *tx_get_private(struct ldb_module *module)
{
    return talloc_get_type(ldb_module_get_private(module),
                           struct tx_private);
}

bool memberof_tx_enabled(struct ldb_module *module)
{
    struct tx_private *private_data = tx_get_private(module);

    return private_data != NULL && private_data->enabled;
}

int memberof_tx_init(struct ldb_module *module)
{
    struct tx_private *private_data;

    private_data = talloc_zero(module, struct tx_private);
    if (private_data == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    private_data->enabled = getenv("SSSD_MEMBEROF_LEGACY") == NULL;
    ldb_module_set_private(module, private_data);
    return LDB_SUCCESS;
}

static int tx_require_journal(struct ldb_module *module,
                              struct tx_private **_private,
                              struct tx_journal **_journal)
{
    struct tx_private *private_data = tx_get_private(module);

    if (private_data == NULL || private_data->journal == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    *_private = private_data;
    *_journal = private_data->journal;
    return LDB_SUCCESS;
}

static int tx_mark_dirty(struct ldb_module *module,
                         struct tx_journal *journal)
{
    struct tx_private *private_data;
    int ret;

    ret = tx_snapshot_ensure(module, journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    if (!journal->dirty) {
        ret = tx_capture_legacy_ghosts(module, journal);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        if (journal->migration_complete) {
            private_data = tx_get_private(module);
            if (private_data != NULL) {
                private_data->migration_persisted = true;
            }
        }
    }

    journal->dirty = true;
    return LDB_SUCCESS;
}

static bool tx_has_attr(const struct ldb_message *message, const char *name)
{
    return ldb_msg_find_element(message, name) != NULL;
}

static bool tx_modify_affects_graph(const struct ldb_message *message)
{
    return tx_has_attr(message, TX_DB_MEMBER)
        || tx_has_attr(message, TX_DB_GHOST)
        || tx_has_attr(message, TX_DB_NAME)
        || tx_has_attr(message, TX_DB_OC);
}

static bool tx_element_has_value(const struct ldb_message_element *element,
                                 const struct ldb_val *value)
{
    unsigned int i;

    if (element == NULL) {
        return false;
    }
    for (i = 0; i < element->num_values; i++) {
        if (element->values[i].length == value->length
                && memcmp(element->values[i].data, value->data,
                          value->length) == 0) {
            return true;
        }
    }

    return false;
}

static bool tx_element_changes(const struct ldb_message_element *current,
                               const struct ldb_message_element *change)
{
    unsigned int i;

    switch (change->flags & LDB_FLAG_MOD_MASK) {
    case 0:
    case LDB_FLAG_MOD_REPLACE:
        if (current == NULL) {
            return change->num_values != 0;
        }
        return ldb_msg_element_compare(
            discard_const_p(struct ldb_message_element, current),
            discard_const_p(struct ldb_message_element, change)) != 0;

    case LDB_FLAG_MOD_ADD:
        for (i = 0; i < change->num_values; i++) {
            if (!tx_element_has_value(current, &change->values[i])) {
                return true;
            }
        }
        return false;

    case LDB_FLAG_MOD_DELETE:
        if (current == NULL) {
            return false;
        }
        if (change->num_values == 0) {
            return current->num_values != 0;
        }
        for (i = 0; i < change->num_values; i++) {
            if (tx_element_has_value(current, &change->values[i])) {
                return true;
            }
        }
        return false;

    default:
        return true;
    }
}

static bool tx_modify_changes_graph(const struct ldb_message *current,
                                    const struct ldb_message *change)
{
    const struct ldb_message_element *old_element;
    const struct ldb_message_element *new_element;
    unsigned int i;

    for (i = 0; i < change->num_elements; i++) {
        new_element = &change->elements[i];
        if (strcasecmp(new_element->name, TX_DB_MEMBER) == 0
                || strcasecmp(new_element->name, TX_DB_NAME) == 0
                || strcasecmp(new_element->name, TX_DB_OC) == 0) {
            old_element = ldb_msg_find_element(current, new_element->name);
        } else if (strcasecmp(new_element->name, TX_DB_GHOST) == 0) {
            old_element = ldb_msg_find_element(current,
                                               TX_DB_GHOST_DIRECT);
        } else {
            continue;
        }

        if (tx_element_changes(old_element, new_element)) {
            return true;
        }
    }

    return false;
}

static int tx_load_migration_state(struct ldb_module *module,
                                   struct tx_private *private_data,
                                   struct tx_journal *journal)
{
    int ret;

    ret = tx_capture_legacy_ghosts(module, journal);
    if (ret == LDB_SUCCESS && journal->migration_complete) {
        private_data->migration_persisted = true;
    }
    return ret;
}

static int tx_check_readonly(struct ldb_module *module,
                             const struct ldb_message *message)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);

    if (tx_has_attr(message, TX_DB_MEMBEROF)
            || tx_has_attr(message, TX_DB_MEMBERUID)
            || tx_has_attr(message, TX_DB_GHOST_DIRECT)) {
        ldb_debug(ldb, LDB_DEBUG_ERROR,
                  "Transactional memberOf derived attributes are readonly");
        return LDB_ERR_UNWILLING_TO_PERFORM;
    }

    return LDB_SUCCESS;
}

static int tx_validate_members(struct ldb_module *module,
                               const struct ldb_message *message)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct ldb_message_element *members;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    unsigned int i;

    members = ldb_msg_find_element(message, TX_DB_MEMBER);
    if (members == NULL || members->num_values == 0) {
        return LDB_SUCCESS;
    }

    tmp_ctx = talloc_new(module);
    if (tmp_ctx == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    for (i = 0; i < members->num_values; i++) {
        dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &members->values[i]);
        if (dn == NULL || !ldb_dn_validate(dn)) {
            ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid member DN: [%s]",
                      (const char *)members->values[i].data);
            talloc_free(tmp_ctx);
            return LDB_ERR_INVALID_DN_SYNTAX;
        }
    }

    talloc_free(tmp_ctx);
    return LDB_SUCCESS;
}

static int tx_record_ghosts(struct tx_journal *journal,
                            struct ldb_dn *dn,
                            const struct ldb_message *message,
                            bool is_add)
{
    struct ldb_message_element *el;
    struct tx_ghost_op *op;
    unsigned int i;

    el = ldb_msg_find_element(message, TX_DB_GHOST);
    if (el == NULL) {
        return LDB_SUCCESS;
    }

    op = talloc_zero(journal, struct tx_ghost_op);
    if (op == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    op->dn = ldb_dn_copy(op, dn);
    if (op->dn == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    op->flags = is_add ? LDB_FLAG_MOD_REPLACE
                       : (el->flags & LDB_FLAG_MOD_MASK);
    op->num_values = el->num_values;
    if (el->num_values != 0) {
        op->values = talloc_zero_array(op, struct ldb_val, el->num_values);
        if (op->values == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }

        for (i = 0; i < el->num_values; i++) {
            op->values[i].data = (uint8_t *)talloc_strndup(
                op->values, (const char *)el->values[i].data,
                el->values[i].length);
            if (op->values[i].data == NULL) {
                return LDB_ERR_OPERATIONS_ERROR;
            }
            op->values[i].length = el->values[i].length;
        }
    }

    if (journal->last_ghost_op == NULL) {
        journal->ghost_ops = op;
    } else {
        journal->last_ghost_op->next = op;
    }
    journal->last_ghost_op = op;
    return LDB_SUCCESS;
}

static int tx_record_request_ghosts(struct tx_journal *journal,
                                    struct ldb_request *req,
                                    bool is_add)
{
    const struct ldb_message *source;

    source = is_add ? req->op.add.message : req->op.mod.message;
    return tx_record_ghosts(journal, source->dn, source, is_add);
}

static int tx_record_rename(struct tx_journal *journal,
                            struct ldb_dn *old_dn,
                            struct ldb_dn *new_dn)
{
    struct tx_rename *rename;

    rename = talloc_zero(journal, struct tx_rename);
    if (rename == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    rename->old_dn = ldb_dn_copy(rename, old_dn);
    rename->new_dn = ldb_dn_copy(rename, new_dn);
    if (rename->old_dn == NULL || rename->new_dn == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    rename->old_key = tx_dn_key(rename->old_dn);
    rename->new_key = tx_dn_key(rename->new_dn);
    if (rename->old_key == NULL || rename->new_key == NULL) {
        return LDB_ERR_INVALID_DN_SYNTAX;
    }

    if (journal->last_rename == NULL) {
        journal->renames = rename;
    } else {
        journal->last_rename->next = rename;
        rename->prev = journal->last_rename;
    }
    journal->last_rename = rename;
    return LDB_SUCCESS;
}

static int tx_complete_noop(struct ldb_request *req)
{
    return ldb_module_done(req, NULL, NULL, LDB_SUCCESS);
}

int memberof_tx_add(struct ldb_module *module, struct ldb_request *req)
{
    struct tx_private *private_data;
    struct tx_journal *journal;
    const char *dn_string;
    const char *key;
    bool identity;
    int ret;

    ret = tx_require_journal(module, &private_data, &journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    if (private_data->flushing || getenv("SSSD_UPGRADE_DB") != NULL) {
        return ldb_next_request(module, req);
    }

    if (ldb_dn_is_special(req->op.add.message->dn)) {
        dn_string = ldb_dn_get_linearized(req->op.add.message->dn);
        if (dn_string != NULL && strcmp(dn_string, TX_REBUILD_DN) == 0) {
            ret = tx_mark_dirty(module, journal);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            return tx_complete_noop(req);
        }
        return ldb_next_request(module, req);
    }
    ret = tx_snapshot_ensure(module, journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    ret = tx_check_readonly(module, req->op.add.message);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    ret = tx_validate_members(module, req->op.add.message);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    identity = tx_message_is_identity(req->op.add.message);
    if (identity) {
        ret = tx_mark_dirty(module, journal);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        ret = tx_record_request_ghosts(journal, req, true);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    key = tx_dn_key(req->op.add.message->dn);
    if (key == NULL) {
        return LDB_ERR_INVALID_DN_SYNTAX;
    }
    ret = tx_set_remove(&journal->deleted_dns, key);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    ret = tx_snapshot_add(journal, req->op.add.message);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(module, req);
}

int memberof_tx_modify(struct ldb_module *module, struct ldb_request *req)
{
    struct tx_private *private_data;
    struct tx_journal *journal;
    struct ldb_message *identity;
    bool changes_graph;
    bool is_identity;
    bool relevant;
    bool was_identity;
    int ret;

    ret = tx_require_journal(module, &private_data, &journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    if (private_data->flushing || getenv("SSSD_UPGRADE_DB") != NULL) {
        return ldb_next_request(module, req);
    }
    if (ldb_dn_is_special(req->op.mod.message->dn)) {
        return ldb_next_request(module, req);
    }

    ret = tx_check_readonly(module, req->op.mod.message);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    ret = tx_validate_members(module, req->op.mod.message);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    relevant = tx_modify_affects_graph(req->op.mod.message);
    if (!relevant) {
        /* Initgroups can commit thousands of metadata-only cache updates. */
        return ldb_next_request(module, req);
    }

    ret = tx_snapshot_ensure(module, journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    identity = tx_snapshot_lookup(journal, req->op.mod.message->dn);
    if (identity == NULL) {
        return ldb_next_request(module, req);
    }
    was_identity = tx_message_is_identity(identity);

    ret = tx_load_migration_state(module, private_data, journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    changes_graph = true;
    if (journal->migration_complete) {
        changes_graph = tx_modify_changes_graph(identity,
                                                 req->op.mod.message);
    }

    ret = tx_snapshot_modify(journal, req->op.mod.message);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    is_identity = tx_message_is_identity(identity);
    if (!was_identity && !is_identity) {
        return ldb_next_request(module, req);
    }

    ret = tx_record_request_ghosts(journal, req, false);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    relevant = !journal->migration_complete || changes_graph;
    if (relevant) {
        ret = tx_mark_dirty(module, journal);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return ldb_next_request(module, req);
}

int memberof_tx_delete(struct ldb_module *module, struct ldb_request *req)
{
    struct tx_private *private_data;
    struct tx_journal *journal;
    struct ldb_message *identity;
    const char *key;
    bool is_identity;
    int ret;

    ret = tx_require_journal(module, &private_data, &journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    if (private_data->flushing || getenv("SSSD_UPGRADE_DB") != NULL) {
        return ldb_next_request(module, req);
    }
    if (ldb_dn_is_special(req->op.del.dn)) {
        return ldb_next_request(module, req);
    }
    ret = tx_snapshot_ensure(module, journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    identity = tx_snapshot_lookup(journal, req->op.del.dn);
    if (identity == NULL) {
        return ldb_next_request(module, req);
    }

    is_identity = tx_message_is_identity(identity);
    if (is_identity) {
        ret = tx_mark_dirty(module, journal);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        key = tx_dn_key(req->op.del.dn);
        if (key == NULL) {
            return LDB_ERR_INVALID_DN_SYNTAX;
        }
        ret = tx_set_add(&journal->deleted_dns, key, key);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }
    ret = tx_snapshot_remove(journal, req->op.del.dn);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(module, req);
}

int memberof_tx_rename(struct ldb_module *module, struct ldb_request *req)
{
    struct tx_private *private_data;
    struct tx_journal *journal;
    struct ldb_message *identity;
    const char *new_key;
    bool is_identity;
    int ret;

    ret = tx_require_journal(module, &private_data, &journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    if (private_data->flushing || getenv("SSSD_UPGRADE_DB") != NULL) {
        return ldb_next_request(module, req);
    }
    if (ldb_dn_is_special(req->op.rename.olddn)
            || ldb_dn_is_special(req->op.rename.newdn)) {
        return ldb_next_request(module, req);
    }
    ret = tx_snapshot_ensure(module, journal);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    identity = tx_snapshot_lookup(journal, req->op.rename.olddn);
    if (identity == NULL) {
        return ldb_next_request(module, req);
    }

    is_identity = tx_message_is_identity(identity);
    if (is_identity) {
        ret = tx_mark_dirty(module, journal);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        ret = tx_record_rename(journal, req->op.rename.olddn,
                               req->op.rename.newdn);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }
    new_key = tx_dn_key(req->op.rename.newdn);
    if (new_key == NULL) {
        return LDB_ERR_INVALID_DN_SYNTAX;
    }
    ret = tx_set_remove(&journal->deleted_dns, new_key);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    ret = tx_snapshot_rename(journal, req->op.rename.olddn,
                             req->op.rename.newdn);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(module, req);
}

int memberof_tx_start(struct ldb_module *module)
{
    struct tx_private *private_data = tx_get_private(module);
    struct tx_journal *journal;
    int ret;

    if (private_data == NULL || !private_data->enabled) {
        return ldb_next_start_trans(module);
    }
    if (private_data->journal != NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    journal = talloc_zero(private_data, struct tx_journal);
    if (journal == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    tx_set_init(&journal->deleted_dns, journal);
    journal->migration_complete = private_data->migration_persisted;
    journal->migration_checked = private_data->migration_persisted;

    /* Write hooks snapshot after start succeeds but before forwarding a write. */
    ret = ldb_next_start_trans(module);
    if (ret != LDB_SUCCESS) {
        talloc_free(journal);
        return ret;
    }

    private_data->journal = journal;
    return LDB_SUCCESS;
}

int memberof_tx_prepare_commit(struct ldb_module *module)
{
    struct tx_private *private_data = tx_get_private(module);
    struct tx_journal *journal;
    int ret;

    if (private_data == NULL || !private_data->enabled) {
        return ldb_next_prepare_commit(module);
    }
    journal = private_data->journal;
    if (journal == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (journal->dirty) {
        private_data->flushing = true;
        ret = tx_graph_flush(module, journal);
        private_data->flushing = false;
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return ldb_next_prepare_commit(module);
}

int memberof_tx_end(struct ldb_module *module)
{
    struct tx_private *private_data = tx_get_private(module);
    struct tx_journal *journal;
    int ret;

    if (private_data == NULL || !private_data->enabled) {
        return ldb_next_end_trans(module);
    }
    journal = private_data->journal;
    if (journal == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = ldb_next_end_trans(module);
    if (ret == LDB_SUCCESS && journal->migration_written) {
        private_data->migration_persisted = true;
    }
    private_data->journal = NULL;
    talloc_free(journal);
    return ret;
}

int memberof_tx_cancel(struct ldb_module *module)
{
    struct tx_private *private_data = tx_get_private(module);
    struct tx_journal *journal;
    int ret;

    if (private_data == NULL || !private_data->enabled) {
        return ldb_next_del_trans(module);
    }
    journal = private_data->journal;

    ret = ldb_next_del_trans(module);
    private_data->journal = NULL;
    talloc_free(journal);
    return ret;
}

struct tx_node;

struct tx_component {
    struct tx_node **members;
    size_t num_members;
    size_t members_capacity;
    struct tx_component **children;
    size_t num_children;
    size_t children_capacity;
    size_t indegree;
    struct tx_component *last_edge_parent;
    struct tx_set ancestors;
};

struct tx_node {
    struct ldb_message *msg;
    const char *key;
    const char *linearized_dn;
    const char *name;
    bool is_group;
    bool visited;
    bool member_changed;
    bool ghost_ambiguous;

    struct tx_node **children;
    size_t num_children;
    size_t children_capacity;
    struct tx_node **parents;
    size_t num_parents;
    size_t parents_capacity;
    struct tx_component *component;

    struct tx_set normalized_members;
    struct tx_set memberof;
    struct tx_set memberuid;
    struct tx_set direct_ghosts;
    struct tx_set ghosts;
};

struct tx_graph {
    struct ldb_context *ldb;
    struct tx_journal *journal;
    struct ldb_result *result;
    hash_table_t *node_map;

    struct tx_node **nodes;
    size_t num_nodes;
    struct tx_node **groups;
    size_t num_groups;
    struct tx_node **users;
    size_t num_users;

    struct tx_component **components;
    size_t num_components;
    size_t components_capacity;
    size_t changed_entries;
    size_t changed_attributes;
};

struct tx_dfs_frame {
    struct tx_node *node;
    size_t next_child;
};

static int tx_append_node(TALLOC_CTX *mem_ctx,
                          struct tx_node ***array,
                          size_t *count,
                          size_t *capacity,
                          struct tx_node *node)
{
    struct tx_node **new_array;
    size_t new_capacity;

    if (*count == *capacity) {
        new_capacity = *capacity == 0 ? 8 : *capacity * 2;
        if (new_capacity < *capacity) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        new_array = talloc_realloc(mem_ctx, *array,
                                   struct tx_node *, new_capacity);
        if (new_array == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        *array = new_array;
        *capacity = new_capacity;
    }

    (*array)[*count] = node;
    (*count)++;
    return LDB_SUCCESS;
}

static int tx_append_component(TALLOC_CTX *mem_ctx,
                               struct tx_component ***array,
                               size_t *count,
                               size_t *capacity,
                               struct tx_component *component)
{
    struct tx_component **new_array;
    size_t new_capacity;

    if (*count == *capacity) {
        new_capacity = *capacity == 0 ? 8 : *capacity * 2;
        if (new_capacity < *capacity) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        new_array = talloc_realloc(mem_ctx, *array,
                                   struct tx_component *, new_capacity);
        if (new_array == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        *array = new_array;
        *capacity = new_capacity;
    }

    (*array)[*count] = component;
    (*count)++;
    return LDB_SUCCESS;
}

static struct ldb_dn *tx_resolve_rename(struct tx_journal *journal,
                                        struct ldb_dn *input,
                                        bool *changed)
{
    struct tx_rename *rename;
    struct ldb_dn *current = input;
    const char *key;

    *changed = false;
    for (rename = journal->renames;
         rename != NULL;
         rename = rename->next) {
        key = tx_dn_key(current);
        if (key == NULL) {
            return NULL;
        }
        if (strcmp(key, rename->old_key) == 0) {
            current = rename->new_dn;
            *changed = true;
        }
    }

    return current;
}

static struct tx_legacy_ghost *
tx_find_legacy_ghost(struct tx_journal *journal, const char *current_key)
{
    struct tx_legacy_ghost *record;
    struct tx_rename *rename;
    const char *key = current_key;

    record = tx_hash_get_ptr(journal->legacy_ghosts, key);
    if (record != NULL) {
        return record;
    }

    for (rename = journal->last_rename;
         rename != NULL;
         rename = rename->prev) {
        if (strcmp(key, rename->new_key) == 0) {
            key = rename->old_key;
        }
        record = tx_hash_get_ptr(journal->legacy_ghosts, key);
        if (record != NULL) {
            return record;
        }
    }

    return NULL;
}

static int tx_graph_add_nodes(struct tx_graph *graph)
{
    struct tx_node *node;
    struct ldb_message *msg;
    unsigned int i;
    int ret;

    ret = tx_hash_create(graph, graph->result->count, &graph->node_map);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    graph->nodes = talloc_zero_array(graph, struct tx_node *,
                                     graph->result->count);
    graph->groups = talloc_zero_array(graph, struct tx_node *,
                                      graph->result->count);
    graph->users = talloc_zero_array(graph, struct tx_node *,
                                     graph->result->count);
    if ((graph->nodes == NULL || graph->groups == NULL
            || graph->users == NULL) && graph->result->count != 0) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    for (i = 0; i < graph->result->count; i++) {
        msg = graph->result->msgs[i];
        if (!tx_message_is_identity(msg)) {
            continue;
        }
        node = talloc_zero(graph, struct tx_node);
        if (node == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        node->msg = msg;
        node->key = tx_dn_key(msg->dn);
        node->linearized_dn = ldb_dn_get_linearized(msg->dn);
        node->name = ldb_msg_find_attr_as_string(msg, TX_DB_NAME, NULL);
        node->is_group = tx_message_is_class(msg, TX_DB_GROUP_CLASS);
        if (node->key == NULL || node->linearized_dn == NULL) {
            return LDB_ERR_INVALID_DN_SYNTAX;
        }

        tx_set_init(&node->normalized_members, node);
        tx_set_init(&node->memberof, node);
        tx_set_init(&node->memberuid, node);
        tx_set_init(&node->direct_ghosts, node);
        tx_set_init(&node->ghosts, node);

        graph->nodes[graph->num_nodes++] = node;
        if (node->is_group) {
            graph->groups[graph->num_groups++] = node;
        } else {
            graph->users[graph->num_users++] = node;
        }

        ret = tx_hash_put_ptr(graph->node_map, node->key, node);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return LDB_SUCCESS;
}

static int tx_graph_add_edges(struct tx_graph *graph)
{
    struct ldb_message_element *members;
    struct tx_node *parent;
    struct tx_node *child;
    struct ldb_dn *raw_dn;
    struct ldb_dn *resolved_dn;
    const char *raw_value;
    const char *resolved_key;
    const char *output;
    bool renamed;
    size_t i;
    unsigned int j;
    int ret;

    for (i = 0; i < graph->num_groups; i++) {
        parent = graph->groups[i];
        members = ldb_msg_find_element(parent->msg, TX_DB_MEMBER);
        if (members == NULL) {
            continue;
        }

        for (j = 0; j < members->num_values; j++) {
            raw_value = (const char *)members->values[j].data;
            raw_dn = ldb_dn_from_ldb_val(parent, graph->ldb,
                                         &members->values[j]);
            if (raw_dn == NULL || !ldb_dn_validate(raw_dn)) {
                ldb_debug(graph->ldb, LDB_DEBUG_ERROR,
                          "Ignoring invalid cached member DN [%s]",
                          raw_value);
                continue;
            }

            resolved_dn = tx_resolve_rename(graph->journal, raw_dn,
                                             &renamed);
            resolved_key = tx_dn_key(resolved_dn);
            if (resolved_dn == NULL || resolved_key == NULL) {
                return LDB_ERR_INVALID_DN_SYNTAX;
            }

            if (tx_set_has(&graph->journal->deleted_dns, resolved_key)) {
                parent->member_changed = true;
                continue;
            }

            child = tx_hash_get_ptr(graph->node_map, resolved_key);
            if (child == parent) {
                parent->member_changed = true;
                continue;
            }

            output = renamed ? ldb_dn_get_linearized(resolved_dn) : raw_value;
            if (output == NULL) {
                return LDB_ERR_INVALID_DN_SYNTAX;
            }
            if (tx_set_has(&parent->normalized_members, resolved_key)) {
                parent->member_changed = true;
                continue;
            }
            ret = tx_set_add(&parent->normalized_members,
                             resolved_key, output);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            if (renamed) {
                parent->member_changed = true;
            }

            if (child == NULL) {
                continue;
            }
            ret = tx_append_node(parent, &parent->children,
                                 &parent->num_children,
                                 &parent->children_capacity, child);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            ret = tx_append_node(child, &child->parents,
                                 &child->num_parents,
                                 &child->parents_capacity, parent);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }
    }

    return LDB_SUCCESS;
}

static int tx_graph_components(struct tx_graph *graph)
{
    struct tx_dfs_frame *frames;
    struct tx_component **queue;
    struct tx_component *component;
    struct tx_component *parent_component;
    struct tx_component *child_component;
    struct tx_node **order;
    struct tx_node **stack;
    struct tx_node *node;
    struct tx_node *child;
    struct tx_node *parent;
    size_t order_count = 0;
    size_t frame_count;
    size_t stack_count;
    size_t queue_head = 0;
    size_t queue_tail = 0;
    size_t i;
    size_t j;
    int ret;

    if (graph->num_groups == 0) {
        return LDB_SUCCESS;
    }

    order = talloc_zero_array(graph, struct tx_node *, graph->num_groups);
    stack = talloc_zero_array(graph, struct tx_node *, graph->num_groups);
    frames = talloc_zero_array(graph, struct tx_dfs_frame,
                               graph->num_groups);
    queue = talloc_zero_array(graph, struct tx_component *,
                              graph->num_groups);
    if (order == NULL || stack == NULL || frames == NULL
            || queue == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    /* Iterative first Kosaraju pass: group DFS finishing order. */
    for (i = 0; i < graph->num_groups; i++) {
        node = graph->groups[i];
        if (node->visited) {
            continue;
        }

        frame_count = 1;
        frames[0].node = node;
        frames[0].next_child = 0;
        node->visited = true;

        while (frame_count != 0) {
            struct tx_dfs_frame *frame = &frames[frame_count - 1];
            child = NULL;
            while (frame->next_child < frame->node->num_children) {
                child = frame->node->children[frame->next_child++];
                if (child->is_group && !child->visited) {
                    break;
                }
                child = NULL;
            }

            if (child != NULL) {
                child->visited = true;
                frames[frame_count].node = child;
                frames[frame_count].next_child = 0;
                frame_count++;
                continue;
            }

            order[order_count++] = frame->node;
            frame_count--;
        }
    }

    /* Reverse pass assigns strongly connected components. */
    for (i = order_count; i > 0; i--) {
        node = order[i - 1];
        if (node->component != NULL) {
            continue;
        }

        component = talloc_zero(graph, struct tx_component);
        if (component == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        ret = tx_append_component(graph, &graph->components,
                                  &graph->num_components,
                                  &graph->components_capacity, component);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        tx_set_init(&component->ancestors, component);
        stack_count = 1;
        stack[0] = node;
        node->component = component;

        while (stack_count != 0) {
            child = stack[--stack_count];
            ret = tx_append_node(component, &component->members,
                                 &component->num_members,
                                 &component->members_capacity, child);
            if (ret != LDB_SUCCESS) {
                return ret;
            }

            for (j = 0; j < child->num_parents; j++) {
                parent = child->parents[j];
                if (!parent->is_group || parent->component != NULL) {
                    continue;
                }
                parent->component = component;
                stack[stack_count++] = parent;
            }
        }
    }

    /* Build the condensed DAG. */
    for (i = 0; i < graph->num_components; i++) {
        component = graph->components[i];
        for (j = 0; j < component->num_members; j++) {
            node = component->members[j];
            for (size_t k = 0; k < node->num_children; k++) {
                child = node->children[k];
                if (!child->is_group
                        || child->component == component) {
                    continue;
                }
                if (child->component->last_edge_parent == component) {
                    continue;
                }
                child->component->last_edge_parent = component;
                ret = tx_append_component(component,
                                           &component->children,
                                           &component->num_children,
                                           &component->children_capacity,
                                           child->component);
                if (ret != LDB_SUCCESS) {
                    return ret;
                }
                child->component->indegree++;
            }
        }
    }

    for (i = 0; i < graph->num_components; i++) {
        if (graph->components[i]->indegree == 0) {
            queue[queue_tail++] = graph->components[i];
        }
    }

    while (queue_head < queue_tail) {
        parent_component = queue[queue_head++];

        /* Keep the legacy root-to-leaf order for derived memberships. */
        for (j = 0; j < parent_component->num_members; j++) {
            node = parent_component->members[j];
            ret = tx_set_add(&parent_component->ancestors,
                             node->key, node->linearized_dn);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        for (i = 0; i < parent_component->num_children; i++) {
            child_component = parent_component->children[i];
            ret = tx_set_union(&child_component->ancestors,
                               &parent_component->ancestors);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            if (--child_component->indegree == 0) {
                queue[queue_tail++] = child_component;
            }
        }
    }

    if (queue_tail != graph->num_components) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    return LDB_SUCCESS;
}

static int tx_load_direct_ghosts(struct tx_graph *graph,
                                 struct tx_node *group)
{
    struct tx_legacy_ghost *legacy;
    struct ldb_message_element *el;
    unsigned int i;
    int ret;

    if (!graph->journal->migration_complete) {
        legacy = tx_find_legacy_ghost(graph->journal, group->key);
        if (legacy == NULL) {
            return LDB_SUCCESS;
        }
        group->ghost_ambiguous = legacy->ambiguous;
        return tx_set_copy(&group->direct_ghosts, &legacy->direct);
    }

    el = ldb_msg_find_element(group->msg, TX_DB_GHOST_DIRECT);
    if (el == NULL) {
        return LDB_SUCCESS;
    }
    for (i = 0; i < el->num_values; i++) {
        ret = tx_set_add(&group->direct_ghosts,
                         (const char *)el->values[i].data,
                         (const char *)el->values[i].data);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return LDB_SUCCESS;
}

static int tx_apply_ghost_value(struct tx_set *set,
                                const struct ldb_val *value,
                                bool add)
{
    char *string;
    int ret;

    string = talloc_strndup(set->owner, (const char *)value->data,
                            value->length);
    if (string == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (add) {
        ret = tx_set_add(set, string, string);
    } else {
        ret = tx_set_remove(set, string);
    }
    talloc_free(string);
    return ret;
}

static int tx_apply_ghost_ops(struct tx_graph *graph)
{
    struct tx_ghost_op *op;
    struct tx_node *group;
    struct ldb_dn *resolved_dn;
    const char *key;
    bool renamed;
    unsigned int i;
    int ret;

    for (op = graph->journal->ghost_ops; op != NULL; op = op->next) {
        resolved_dn = tx_resolve_rename(graph->journal, op->dn, &renamed);
        (void)renamed;
        key = tx_dn_key(resolved_dn);
        group = tx_hash_get_ptr(graph->node_map, key);
        if (group == NULL || !group->is_group) {
            continue;
        }

        switch (op->flags) {
        case LDB_FLAG_MOD_ADD:
            for (i = 0; i < op->num_values; i++) {
                ret = tx_apply_ghost_value(&group->direct_ghosts,
                                           &op->values[i], true);
                if (ret != LDB_SUCCESS) {
                    return ret;
                }
            }
            break;

        case LDB_FLAG_MOD_DELETE:
            if (op->num_values == 0) {
                tx_set_clear(&group->direct_ghosts);
                break;
            }
            for (i = 0; i < op->num_values; i++) {
                ret = tx_apply_ghost_value(&group->direct_ghosts,
                                           &op->values[i], false);
                if (ret != LDB_SUCCESS) {
                    return ret;
                }
            }
            break;

        case LDB_FLAG_MOD_REPLACE:
        case 0:
            tx_set_clear(&group->direct_ghosts);
            for (i = 0; i < op->num_values; i++) {
                ret = tx_apply_ghost_value(&group->direct_ghosts,
                                           &op->values[i], true);
                if (ret != LDB_SUCCESS) {
                    return ret;
                }
            }
            break;

        default:
            return LDB_ERR_PROTOCOL_ERROR;
        }
    }

    return LDB_SUCCESS;
}

static int tx_graph_derive(struct tx_graph *graph)
{
    struct tx_node *node;
    struct tx_node *parent;
    struct tx_node *group;
    struct tx_set_entry *entry;
    const char *output;
    size_t i;
    size_t j;
    size_t k;
    size_t p;
    int ret;

    ret = tx_graph_components(graph);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    for (i = 0; i < graph->num_groups; i++) {
        node = graph->groups[i];
        ret = tx_set_copy(&node->memberof, &node->component->ancestors);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        ret = tx_set_remove(&node->memberof, node->key);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        ret = tx_load_direct_ghosts(graph, node);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    for (i = 0; i < graph->num_users; i++) {
        node = graph->users[i];
        for (j = 0; j < node->num_parents; j++) {
            parent = node->parents[j];
            ret = tx_set_union(&node->memberof,
                               &parent->component->ancestors);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }
    }

    ret = tx_apply_ghost_ops(graph);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    /* A user's ancestor groups are exactly the groups needing memberUid. */
    for (i = 0; i < graph->num_users; i++) {
        node = graph->users[i];
        if (node->name == NULL || node->memberof.table == NULL) {
            continue;
        }
        for (k = 0; k < node->memberof.count; k++) {
            entry = node->memberof.ordered[k];
            group = tx_hash_get_ptr(graph->node_map, entry->key);
            if (group == NULL || !group->is_group) {
                return LDB_ERR_OPERATIONS_ERROR;
            }
            ret = tx_set_add(&group->memberuid, node->name, node->name);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }
    }

    /* Direct ghosts are inherited by the group itself and every ancestor. */
    for (i = 0; i < graph->num_groups; i++) {
        node = graph->groups[i];
        if (node->direct_ghosts.table == NULL) {
            continue;
        }
        for (k = 0; k < node->direct_ghosts.count; k++) {
            entry = node->direct_ghosts.ordered[k];
            output = entry->output;
            ret = tx_set_add(&node->ghosts, entry->key, output);
            if (ret != LDB_SUCCESS) {
                return ret;
            }

            if (node->memberof.table == NULL) {
                continue;
            }
            for (p = 0; p < node->memberof.count; p++) {
                group = tx_hash_get_ptr(graph->node_map,
                                        node->memberof.ordered[p]->key);
                if (group == NULL || !group->is_group) {
                    return LDB_ERR_OPERATIONS_ERROR;
                }
                ret = tx_set_add(&group->ghosts, entry->key, output);
                if (ret != LDB_SUCCESS) {
                    return ret;
                }
            }
        }
    }

    return LDB_SUCCESS;
}

static int tx_element_set(TALLOC_CTX *mem_ctx,
                          struct ldb_context *ldb,
                          const struct ldb_message_element *element,
                          bool dn_values,
                          struct tx_set *set)
{
    struct ldb_dn *dn;
    const char *key;
    const char *value;
    unsigned int i;
    int ret;

    tx_set_init(set, mem_ctx);
    if (element == NULL) {
        return LDB_SUCCESS;
    }

    for (i = 0; i < element->num_values; i++) {
        value = (const char *)element->values[i].data;
        if (dn_values) {
            dn = ldb_dn_from_ldb_val(mem_ctx, ldb, &element->values[i]);
            key = tx_dn_key(dn);
            if (key == NULL) {
                return LDB_ERR_INVALID_DN_SYNTAX;
            }
        } else {
            key = value;
        }

        ret = tx_set_add(set, key, value);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return LDB_SUCCESS;
}

static bool tx_sets_equal(const struct tx_set *left,
                          const struct tx_set *right)
{
    size_t i;

    if (tx_set_count(left) != tx_set_count(right)) {
        return false;
    }
    if (left->table == NULL) {
        return true;
    }

    for (i = 0; i < left->count; i++) {
        if (!tx_set_has(right, left->ordered[i]->key)) {
            return false;
        }
    }

    return true;
}

static int tx_add_difference_mod(struct ldb_message *modification,
                                 const char *attribute,
                                 int flags,
                                 const struct tx_set *candidates,
                                 const struct tx_set *excluded)
{
    struct ldb_message_element *element;
    const char *output;
    size_t count = 0;
    size_t i;
    size_t j = 0;
    int ret;

    for (i = 0; i < candidates->count; i++) {
        if (!tx_set_has(excluded, candidates->ordered[i]->key)) {
            count++;
        }
    }
    if (count == 0) {
        return LDB_SUCCESS;
    }
    if (count > UINT_MAX) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = ldb_msg_add_empty(modification, attribute, flags, &element);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    element->values = talloc_zero_array(modification, struct ldb_val, count);
    if (element->values == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    for (i = 0; i < candidates->count; i++) {
        if (tx_set_has(excluded, candidates->ordered[i]->key)) {
            continue;
        }
        output = candidates->ordered[i]->output;
        element->values[j].data = (uint8_t *)talloc_strdup(
            element->values, output);
        if (element->values[j].data == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        element->values[j].length = strlen(output);
        j++;
    }
    element->num_values = count;
    return LDB_SUCCESS;
}

static int tx_add_set_mod(struct tx_graph *graph,
                          struct ldb_message *modification,
                          struct tx_node *node,
                          const char *attribute,
                          const struct tx_set *new_values,
                          bool dn_values)
{
    struct ldb_message_element *old_element;
    struct tx_set old_values = { 0 };
    TALLOC_CTX *tmp_ctx;
    int ret;

    old_element = ldb_msg_find_element(node->msg, attribute);
    tmp_ctx = talloc_new(modification);
    if (tmp_ctx == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    ret = tx_element_set(tmp_ctx, graph->ldb, old_element,
                         dn_values, &old_values);
    if (ret != LDB_SUCCESS) {
        talloc_free(tmp_ctx);
        return ret;
    }

    if (tx_sets_equal(&old_values, new_values)) {
        talloc_free(tmp_ctx);
        return LDB_SUCCESS;
    }

    if (tx_set_count(new_values) == 0) {
        ret = ldb_msg_add_empty(modification, attribute,
                                LDB_FLAG_MOD_DELETE, NULL);
        if (ret == LDB_SUCCESS) {
            graph->changed_attributes++;
        }
        talloc_free(tmp_ctx);
        return ret;
    }

    ret = tx_add_difference_mod(modification, attribute,
                                LDB_FLAG_MOD_DELETE,
                                &old_values, new_values);
    if (ret != LDB_SUCCESS) {
        talloc_free(tmp_ctx);
        return ret;
    }
    ret = tx_add_difference_mod(modification, attribute,
                                LDB_FLAG_MOD_ADD,
                                new_values, &old_values);
    if (ret != LDB_SUCCESS) {
        talloc_free(tmp_ctx);
        return ret;
    }

    graph->changed_attributes++;
    talloc_free(tmp_ctx);
    return LDB_SUCCESS;
}

static int tx_add_expire_mod(struct tx_graph *graph,
                             struct ldb_message *modification,
                             struct tx_node *node)
{
    int ret;

    if (!node->ghost_ambiguous) {
        return LDB_SUCCESS;
    }

    /* The migration marker makes this unconditional replacement one-time. */
    ret = ldb_msg_add_empty(modification, TX_DB_CACHE_EXPIRE,
                            LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    ret = ldb_msg_add_string(modification, TX_DB_CACHE_EXPIRE, "1");
    if (ret == LDB_SUCCESS) {
        graph->changed_attributes++;
    }
    return ret;
}

static int tx_graph_write_nodes(struct tx_graph *graph)
{
    struct ldb_message *modification;
    struct tx_node *node;
    size_t i;
    int ret;

    for (i = 0; i < graph->num_nodes; i++) {
        node = graph->nodes[i];
        modification = ldb_msg_new(graph);
        if (modification == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        modification->dn = node->msg->dn;

        if (node->is_group && node->member_changed) {
            ret = tx_add_set_mod(graph, modification, node,
                                 TX_DB_MEMBER,
                                 &node->normalized_members, true);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        ret = tx_add_set_mod(graph, modification, node,
                             TX_DB_MEMBEROF, &node->memberof, true);
        if (ret != LDB_SUCCESS) {
            return ret;
        }

        if (node->is_group) {
            ret = tx_add_set_mod(graph, modification, node,
                                 TX_DB_MEMBERUID, &node->memberuid, false);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            ret = tx_add_set_mod(graph, modification, node,
                                 TX_DB_GHOST, &node->ghosts, false);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            ret = tx_add_set_mod(graph, modification, node,
                                 TX_DB_GHOST_DIRECT,
                                 &node->direct_ghosts, false);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            ret = tx_add_expire_mod(graph, modification, node);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        if (modification->num_elements == 0) {
            talloc_free(modification);
            continue;
        }

        ret = ldb_modify(graph->ldb, modification);
        if (ret != LDB_SUCCESS) {
            ldb_debug(graph->ldb, LDB_DEBUG_ERROR,
                      "Transactional memberOf update failed for [%s]: %s",
                      node->linearized_dn, ldb_errstring(graph->ldb));
            return ret;
        }
        graph->changed_entries++;
        talloc_free(modification);
    }

    return LDB_SUCCESS;
}

static int tx_write_migration_marker(struct tx_graph *graph)
{
    struct ldb_message *message;
    int ret;

    if (graph->journal->migration_complete) {
        return LDB_SUCCESS;
    }

    message = ldb_msg_new(graph);
    if (message == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    message->dn = ldb_dn_new(message, graph->ldb, TX_MIGRATION_DN);
    if (message->dn == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (graph->journal->migration_marker_exists) {
        ret = ldb_msg_add_empty(message, TX_MIGRATION_ATTR,
                                LDB_FLAG_MOD_REPLACE, NULL);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }
    ret = ldb_msg_add_string(message, TX_MIGRATION_ATTR,
                             TX_MIGRATION_VERSION);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    if (graph->journal->migration_marker_exists) {
        ret = ldb_modify(graph->ldb, message);
    } else {
        ret = ldb_add(graph->ldb, message);
    }
    if (ret == LDB_SUCCESS) {
        graph->journal->migration_written = true;
    }
    return ret;
}

static int tx_graph_flush(struct ldb_module *module,
                          struct tx_journal *journal)
{
    struct tx_graph *graph;
    size_t edge_count = 0;
    size_t i;
    int ret;

    graph = talloc_zero(journal, struct tx_graph);
    if (graph == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    graph->ldb = ldb_module_get_ctx(module);
    graph->journal = journal;
    graph->result = journal->snapshot;
    if (graph->result == NULL) {
        ret = LDB_ERR_OPERATIONS_ERROR;
        goto done;
    }

    ret = tx_graph_add_nodes(graph);
    if (ret != LDB_SUCCESS) {
        goto done;
    }
    ret = tx_graph_add_edges(graph);
    if (ret != LDB_SUCCESS) {
        goto done;
    }
    ret = tx_graph_derive(graph);
    if (ret != LDB_SUCCESS) {
        goto done;
    }
    ret = tx_graph_write_nodes(graph);
    if (ret != LDB_SUCCESS) {
        goto done;
    }
    ret = tx_write_migration_marker(graph);
    if (ret != LDB_SUCCESS) {
        goto done;
    }
    for (i = 0; i < graph->num_groups; i++) {
        edge_count += graph->groups[i]->num_children;
    }
    ldb_debug(graph->ldb, LDB_DEBUG_TRACE,
              "Transactional memberOf flush: %zu nodes, %zu direct edges, "
              "%zu entries and %zu attributes changed",
              graph->num_nodes, edge_count,
              graph->changed_entries, graph->changed_attributes);
done:
    talloc_free(graph);
    return ret;
}
