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

#include <dhash.h>
#include <string.h>
#include <talloc.h>

#include "util/util.h"
#include "util/dlinklist.h"
#include "sbus/sbus_opath.h"
#include "sbus/sbus_private.h"
#include "util/sss_ptr_hash.h"

static struct sbus_interface *
sbus_interface_list_lookup(struct sbus_interface_list *list,
                           const char *name)
{
    struct sbus_interface_list *item;

    DLIST_FOR_EACH(item, list) {
        if (strcmp(item->interface->name, name) == 0) {
            return item->interface;
        }
    }

    return NULL;
}

static errno_t
sbus_interface_list_copy(TALLOC_CTX *mem_ctx,
                         struct sbus_interface_list *list,
                         struct sbus_interface_list **_copy)
{
    TALLOC_CTX *list_ctx;
    struct sbus_interface_list *list_copy;
    struct sbus_interface_list *item_copy;
    struct sbus_interface_list *item;
    struct sbus_interface *iface;
    errno_t ret;

    if (list == NULL) {
        *_copy = NULL;
        return EOK;
    }

    /* Create a memory context that will be used as a parent for copies. */
    list_ctx = talloc_new(mem_ctx);
    if (list_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    /* Start with an empty list. */
    list_copy = NULL;
    DLIST_FOR_EACH(item, list) {
        iface = sbus_interface_list_lookup(list_copy, item->interface->name);
        if (iface != NULL) {
            /* This interface already exist in the list. */
            continue;
        }

        /* Create a copy of this item and insert it into the list. */
        item_copy = talloc_zero(list_ctx, struct sbus_interface_list);
        if (item_copy == NULL) {
            ret = ENOMEM;
            goto done;
        }

        item_copy->interface = item->interface;
        DLIST_ADD(list_copy, item_copy);
    }

    *_copy = list_copy;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(list_ctx);
    }

    return ret;
}

hash_table_t *
sbus_router_paths_init(TALLOC_CTX *mem_ctx)
{
    return sss_ptr_hash_create(mem_ctx, NULL, NULL);
}

errno_t
sbus_router_paths_add(hash_table_t *table,
                      const char *path,
                      struct sbus_interface *iface)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_interface_list *list;
    struct sbus_interface_list *item;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    item = talloc_zero(tmp_ctx, struct sbus_interface_list);
    if (item == NULL) {
        ret = ENOMEM;
        goto done;
    }

    item->interface = sbus_interface_copy(item, iface);
    if (item->interface == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* First, check if the path already exist and just append the interface
     * to the list if it does (but only if the interface does not exist). */
    list = sss_ptr_hash_lookup(table, path, struct sbus_interface_list);
    if (list != NULL) {
        if (sbus_interface_list_lookup(list, iface->name) != NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Trying to register the same interface"
                  " twice: iface=%s, opath=%s\n", iface->name, path);
            ret = EEXIST;
            goto done;
        }

        DLIST_ADD_END(list, item, struct sbus_interface_list *);
        ret = EOK;
        goto done;
    }

    /* Otherwise create new hash entry and new list. */
    list = item;

    ret = sss_ptr_hash_add(table, path, list, struct sbus_interface_list);

done:
    if (ret == EOK) {
        talloc_steal(table, item);
    }

    talloc_free(tmp_ctx);

    return ret;
}

/**
 * First @object_path is looked up in @table, if it is not found it steps up
 * in the path hierarchy and try to lookup the parent node. This continues
 * until the root is reached.
 */
struct sbus_interface *
sbus_router_paths_lookup(hash_table_t *table,
                         const char *path,
                         const char *iface_name)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_interface_list *list;
    struct sbus_interface *iface;
    const char *lookup_path;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    iface = NULL;
    lookup_path = path;
    while (lookup_path != NULL) {
        list = sss_ptr_hash_lookup(table, lookup_path,
                                   struct sbus_interface_list);
        if (list != NULL) {
            iface = sbus_interface_list_lookup(list, iface_name);
            if (iface != NULL) {
                goto done;
            }
        }

        /* We will not free lookup path since it is freed with tmp_ctx
         * and the object paths are supposed to be small. */
        lookup_path = sbus_opath_subtree_parent(tmp_ctx, lookup_path);
    }

done:
    talloc_free(tmp_ctx);
    return iface;
}

/**
 * Acquire list of all interfaces that are supported on given object path.
 */
errno_t
sbus_router_paths_supported(TALLOC_CTX *mem_ctx,
                            hash_table_t *table,
                            const char *path,
                            struct sbus_interface_list **_list)
{
    TALLOC_CTX *tmp_ctx;
    TALLOC_CTX *list_ctx;
    struct sbus_interface_list *list;
    struct sbus_interface_list *list_copy;
    struct sbus_interface_list *list_output;
    const char *lookup_path;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    list_ctx = talloc_new(tmp_ctx);
    if (list_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Start with an empty list. */
    list_output = NULL;
    lookup_path = path;
    while (lookup_path != NULL) {
        list = sss_ptr_hash_lookup(table, lookup_path,
                                   struct sbus_interface_list);
        if (list != NULL) {
            ret = sbus_interface_list_copy(list_ctx, list, &list_copy);
            if (ret != EOK) {
                goto done;
            }

            DLIST_CONCATENATE(list_output, list_copy,
                              struct sbus_interface_list *);
        }

        /* We will not free lookup path since it is freed with tmp_ctx
         * and the object paths are supposed to be small. */
        lookup_path = sbus_opath_subtree_parent(tmp_ctx, lookup_path);
    }

    talloc_steal(mem_ctx, list_ctx);
    *_list = list_output;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

const char **
sbus_router_paths_nodes(TALLOC_CTX *mem_ctx,
                        hash_table_t *table)
{
    const char **paths = NULL;
    hash_key_t *keys;
    unsigned long count;
    unsigned long i, j;
    char *basepath;
    errno_t ret;
    int hret;

    hret = hash_keys(table, &count, &keys);
    if (hret != HASH_SUCCESS) {
        return NULL;
    }

    paths = talloc_zero_array(mem_ctx, const char *, count + 2);
    if (paths == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0, j = 0; i < count; i++) {
        /* Do not include subtree paths. The must have node factory. */
        basepath = keys[i].str;
        if (sbus_opath_is_subtree(basepath)) {
            basepath = sbus_opath_subtree_base(paths, basepath);
            if (basepath == NULL) {
                ret = ENOMEM;
                goto done;
            }

            if (sbus_router_paths_exist(table, basepath)) {
                talloc_free(basepath);
                continue;
            }
        }

        if (strcmp(basepath, "/") == 0) {
            continue;
        }

        /* All paths starts with / that is not part of the node name. */
        paths[j] = basepath + 1;
        j++;
    }

    ret = EOK;

done:
    talloc_free(keys);

    if (ret != EOK) {
        talloc_zfree(paths);
    }

    return paths;
}

bool
sbus_router_paths_exist(hash_table_t *table,
                        const char *object_path)
{
    return sss_ptr_hash_has_key(table, object_path);
}

static struct sbus_listener *
sbus_listener_list_lookup(struct sbus_listener_list *list,
                          struct sbus_listener *a)
{
    struct sbus_listener_list *item;
    struct sbus_listener *b;

    /* We know that interface and signal name already match. We need to check
     * handlers and object paths. */
    DLIST_FOR_EACH(item, list) {
        b = item->listener;

        if (memcmp(&a->handler, &b->handler, sizeof(struct sbus_handler)) != 0) {
            continue;
        }

        if (a->object_path == NULL && b->object_path == NULL) {
            return b;
        }

        if (a->object_path == NULL && b->object_path != NULL) {
            continue;
        }

        if (a->object_path != NULL && b->object_path == NULL) {
            continue;
        }

        if (strcmp(a->object_path, b->object_path) != 0) {
            continue;
        }

        return b;
    }

    return NULL;
}

static void
sbus_router_listeners_delete_cb(hash_entry_t *item,
                                hash_destroy_enum deltype,
                                void *pvt)
{
    struct sbus_connection *conn;
    char *signal_name;
    char *interface;
    char *rule;
    errno_t ret;

    conn = talloc_get_type(pvt, struct sbus_connection);
    if (conn->connection == NULL) {
        return;
    }

    if (conn->disconnecting) {
        return;
    }

    /* If we still have the D-Bus connection available, we try to unregister
     * the previously registered listener when its removed from table. */

    ret = sbus_router_signal_parse(NULL, item->key.str,
                                   &interface, &signal_name);
    if (ret != EOK) {
        /* There is nothing we can do. */
        return;
    }

    rule = sbus_router_signal_rule(NULL, interface, signal_name);
    talloc_free(interface);
    talloc_free(signal_name);
    if (rule == NULL) {
        /* There is nothing we can do. */
        return;
    }

    dbus_bus_remove_match(conn->connection, rule, NULL);

    talloc_free(rule);
}

hash_table_t *
sbus_router_listeners_init(TALLOC_CTX *mem_ctx,
                           struct sbus_connection *conn)
{
    return sss_ptr_hash_create(mem_ctx, sbus_router_listeners_delete_cb, conn);
}

errno_t
sbus_router_listeners_add(hash_table_t *table,
                          const char *interface,
                          const char *signal_name,
                          struct sbus_listener *listener,
                          bool *_signal_known)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_listener_list *list;
    struct sbus_listener_list *item;
    bool signal_known = false;
    const char *key;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    key = talloc_asprintf(tmp_ctx, "%s.%s", interface, signal_name);
    if (key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    item = talloc_zero(tmp_ctx, struct sbus_listener_list);
    if (item == NULL) {
        ret = ENOMEM;
        goto done;
    }

    item->listener = sbus_listener_copy(item, listener);
    if (item->listener == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* First, check if the listener already exist and just append it to the
     * list if it does (but only if this listener doesn't already exist. */
    list = sss_ptr_hash_lookup(table, key, struct sbus_listener_list);
    if (list != NULL) {
        signal_known = true;

        if (sbus_listener_list_lookup(list, listener) != NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Trying to register the same listener"
                  " twice: iface=%s, signal=%s, path=%s\n",
                  interface, signal_name, (listener->object_path == NULL ?
                                           "<null>": listener->object_path));
            ret = EEXIST;
            goto done;
        }

        DLIST_ADD_END(list, item, struct sbus_listener_list *);
        ret = EOK;
        goto done;
    }

    /* Otherwise create new hash entry and new list. */
    signal_known = false;
    list = item;

    ret = sss_ptr_hash_add(table, key, list, struct sbus_listener_list);

done:
    if (ret == EOK) {
        talloc_steal(table, item);
        *_signal_known = signal_known;
    }

    talloc_free(tmp_ctx);

    return ret;
}

struct sbus_listener_list *
sbus_router_listeners_lookup(hash_table_t *table,
                             const char *interface,
                             const char *signal_name)
{
    struct sbus_listener_list *list;
    char *key;

    key = talloc_asprintf(NULL, "%s.%s", interface, signal_name);
    if (key == NULL) {
        return NULL;
    }

    list = sss_ptr_hash_lookup(table, key, struct sbus_listener_list);
    talloc_free(key);

    return list;
}

hash_table_t *
sbus_router_nodes_init(TALLOC_CTX *mem_ctx)
{
    return sss_ptr_hash_create(mem_ctx, NULL, NULL);
}

errno_t
sbus_router_nodes_add(hash_table_t *table,
                      struct sbus_node *node)
{
    struct sbus_node *copy;
    errno_t ret;

    copy = sbus_node_copy(table, node);
    if (copy == NULL) {
        return ENOMEM;
    }

    ret = sss_ptr_hash_add(table, copy->path, copy, struct sbus_node);
    if (ret != EOK) {
        talloc_free(copy);
        return ret;
    }

    return EOK;
}

struct sbus_node *
sbus_router_nodes_lookup(hash_table_t *table,
                         const char *path)
{
    return sss_ptr_hash_lookup(table, path, struct sbus_node);
}
