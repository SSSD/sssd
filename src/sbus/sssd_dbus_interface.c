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

#include <talloc.h>
#include <dbus/dbus.h>
#include <dhash.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_private.h"

static struct sbus_interface *
sbus_iface_list_lookup(struct sbus_interface_list *list,
                       const char *iface)
{
    struct sbus_interface_list *item;

    DLIST_FOR_EACH(item, list) {
        if (strcmp(item->interface->vtable->meta->name, iface) == 0) {
            return item->interface;
        }
    }

    return NULL;
}

static errno_t
sbus_iface_list_copy(TALLOC_CTX *mem_ctx,
                     struct sbus_interface_list *list,
                     struct sbus_interface_list **_copy)
{
    TALLOC_CTX *list_ctx;
    struct sbus_interface_list *new_list = NULL;
    struct sbus_interface_list *new_item;
    struct sbus_interface_list *item;
    errno_t ret;

    if (list == NULL) {
        *_copy = NULL;
        return EOK;
    }

    list_ctx = talloc_new(mem_ctx);
    if (list_ctx == NULL) {
        return ENOMEM;
    }

    DLIST_FOR_EACH(item, list) {
        if (sbus_iface_list_lookup(new_list,
               item->interface->vtable->meta->name) != NULL) {
            /* already in list */
            continue;
        }

        new_item = talloc_zero(list_ctx, struct sbus_interface_list);
        if (new_item == NULL) {
            ret = ENOMEM;
            goto done;
        }

        new_item->interface = item->interface;
        DLIST_ADD(new_list, new_item);
    }

    *_copy = new_list;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(list_ctx);
    }

    return ret;
}

/**
 * Object paths that represent all objects under the path:
 * /org/object/path/~* (without tilda)
 */
static bool sbus_opath_is_subtree(const char *path)
{
    size_t len;

    len = strlen(path);

    if (len < 2) {
        return false;
    }

    return path[len - 2] == '/' && path[len - 1] == '*';
}

/**
 * If the path represents a subtree object path, this function will
 * remove /~* from the end.
 */
static char *sbus_opath_get_base_path(TALLOC_CTX *mem_ctx,
                                      const char *object_path)
{
    char *tree_path;
    size_t len;

    tree_path = talloc_strdup(mem_ctx, object_path);
    if (tree_path == NULL) {
        return NULL;
    }

    if (!sbus_opath_is_subtree(tree_path)) {
        return tree_path;
    }

    /* replace / only if it is not a root path (only slash) */
    len = strlen(tree_path);
    tree_path[len - 1] = '\0';
    tree_path[len - 2] = (len - 2 != 0) ? '\0' : '/';

    return tree_path;
}

static char *sbus_opath_parent_subtree(TALLOC_CTX *mem_ctx,
                                       const char *path)
{
    char *subtree;
    char *slash;

    /* first remove /~* from the end, stop when we have reached the root i.e.
     * subtree == "/" */
    subtree = sbus_opath_get_base_path(mem_ctx, path);
    if (subtree == NULL || subtree[1] == '\0') {
        return NULL;
    }

    /* Find the first separator and replace the part with asterisk. */
    slash = strrchr(subtree, '/');
    if (slash == NULL) {
        /* we cannot continue up */
        talloc_free(subtree);
        return NULL;
    }

    if (*(slash + 1) == '\0') {
        /* this object path is invalid since it cannot end with slash */
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid object path '%s'?\n", path);
        talloc_free(subtree);
        return NULL;
    }

    /* because object path cannot end with / there is enough space for
     * asterisk and terminating zero */
    *(slash + 1) = '*';
    *(slash + 2) = '\0';

    return subtree;
}

/**
 * The following path related functions are based on similar code in
 * storaged, just tailored to use talloc instead of glib
 */
char *
sbus_opath_escape_part(TALLOC_CTX *mem_ctx,
                       const char *object_path_part)
{
    size_t n;
    char *safe_path = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    /* The path must be valid */
    if (object_path_part == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    safe_path = talloc_strdup(tmp_ctx, "");
    if (safe_path == NULL) {
        goto done;
    }

    /* Special case for an empty string */
    if (strcmp(object_path_part, "") == 0) {
        /* the for loop would just fall through */
        safe_path = talloc_asprintf_append_buffer(safe_path, "_");
        if (safe_path == NULL) {
            goto done;
        }
    }

    for (n = 0; object_path_part[n]; n++) {
        int c = object_path_part[n];
        /* D-Bus spec says:
         * *
         * * Each element must only contain the ASCII characters
         * "[A-Z][a-z][0-9]_"
         * */
        if ((c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')) {
            safe_path = talloc_asprintf_append_buffer(safe_path, "%c", c);
            if (safe_path == NULL) {
                goto done;
            }
        } else {
            safe_path = talloc_asprintf_append_buffer(safe_path, "_%02x", c);
            if (safe_path == NULL) {
                goto done;
            }
        }
    }

    safe_path = talloc_steal(mem_ctx, safe_path);

done:
    talloc_free(tmp_ctx);
    return safe_path;
}

static inline int unhexchar(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

char *
sbus_opath_unescape_part(TALLOC_CTX *mem_ctx,
                         const char *object_path_part)
{
    char *safe_path;
    const char *p;
    int a, b, c;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    safe_path = talloc_strdup(tmp_ctx, "");
    if (safe_path == NULL) {
        goto done;
    }

    /* Special case for the empty string */
    if (strcmp(object_path_part, "_") == 0) {
        safe_path = talloc_steal(mem_ctx, safe_path);
        goto done;
    }

    for (p = object_path_part; *p; p++) {
        if (*p == '_') {
            /* There must be at least two more chars after underscore */
            if (p[1] == '\0' || p[2] == '\0') {
                safe_path = NULL;
                goto done;
            }

            if ((a = unhexchar(p[1])) < 0
                    || (b = unhexchar(p[2])) < 0) {
                /* Invalid escape code, let's take it literal then */
                c = '_';
            } else {
                c = ((a << 4) | b);
                p += 2;
            }
        } else  {
            c = *p;
        }

        safe_path = talloc_asprintf_append_buffer(safe_path, "%c", c);
        if (safe_path == NULL) {
            goto done;
        }
    }

    safe_path = talloc_steal(mem_ctx, safe_path);

done:
    talloc_free(tmp_ctx);
    return safe_path;
}

char *
_sbus_opath_compose(TALLOC_CTX *mem_ctx,
                    const char *base,
                    const char *part, ...)
{
    char *safe_part;
    char *path = NULL;
    va_list va;

    if (base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Wrong object path base!\n");
        return NULL;
    }

    path = talloc_strdup(mem_ctx, base);
    if (path == NULL) return NULL;

    va_start(va, part);
    while (part != NULL) {
        safe_part = sbus_opath_escape_part(mem_ctx, part);
        if (safe_part == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add [%s] to objpath\n", part);
            goto fail;
        }

        path = talloc_asprintf_append(path, "/%s", safe_part);
        talloc_free(safe_part);
        if (path == NULL) {
            goto fail;
        }

        part = va_arg(va, const char *);
    }
    va_end(va);

    return path;

fail:
    va_end(va);
    talloc_free(path);
    return NULL;
}

errno_t
sbus_opath_decompose(TALLOC_CTX *mem_ctx,
                     const char *object_path,
                     const char *prefix,
                     char ***_components,
                     size_t *_len)
{
    TALLOC_CTX *tmp_ctx;
    const char *path;
    char **decomposed;
    char **unescaped;
    errno_t ret;
    int len;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Strip prefix from the path. */
    if (prefix != NULL) {
        path = sbus_opath_strip_prefix(object_path, prefix);
        if (path == NULL) {
            ret = ERR_SBUS_INVALID_PATH;
            goto done;
        }
    } else {
        path = object_path;
    }

    /* Split the string using / as delimiter. */
    split_on_separator(tmp_ctx, path, '/', true, true, &decomposed, &len);

    /* Unescape parts. */
    unescaped = talloc_zero_array(tmp_ctx, char *, len + 1);
    if (unescaped == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < len; i++) {
        unescaped[i] = sbus_opath_unescape_part(unescaped, decomposed[i]);
        if (unescaped[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (_components != NULL) {
        *_components = talloc_steal(mem_ctx, unescaped);
    }

    if (_len != NULL) {
        *_len = len;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sbus_opath_decompose_exact(TALLOC_CTX *mem_ctx,
                           const char *object_path,
                           const char *prefix,
                           size_t expected,
                           char ***_components)
{
    char **components;
    size_t len;
    errno_t ret;

    ret = sbus_opath_decompose(mem_ctx, object_path, prefix,
                               &components, &len);
    if (ret != EOK) {
        return ret;
    }

    if (len != expected) {
        talloc_free(components);
        return ERR_SBUS_INVALID_PATH;
    }

    if (_components != NULL) {
        *_components = components;
    }

    return EOK;
}

const char *
sbus_opath_strip_prefix(const char *object_path,
                        const char *prefix)
{
    if (strncmp(object_path, prefix, strlen(prefix)) == 0) {
        return object_path + strlen(prefix);
    }

    return NULL;
}

char *
sbus_opath_get_object_name(TALLOC_CTX *mem_ctx,
                           const char *object_path,
                           const char *base_path)
{
    const char *name;

    name = sbus_opath_strip_prefix(object_path, base_path);
    if (name == NULL || name[0] == '\0') {
        return NULL;
    }

    /* if base_path did not end with / */
    if (name[0] == '/') {
        name = name + 1;
    }

    return sbus_opath_unescape_part(mem_ctx, name);
}

static void
sbus_opath_hash_delete_cb(hash_entry_t *item,
                          hash_destroy_enum deltype,
                          void *pvt)
{
    struct sbus_connection *conn;
    char *path;

    conn = talloc_get_type(pvt, struct sbus_connection);
    path = sbus_opath_get_base_path(NULL, item->key.str);

    /* There seem to be code paths where the data is added to the hash
     * before the connection is properly initialized, to avoid core dump
     * during shut down we only call dbus_connection_unregister_object_path()
     * if there is a connection. */
    if (conn->dbus.conn != NULL) {
        dbus_connection_unregister_object_path(conn->dbus.conn, path);
    }
}

hash_table_t *
sbus_opath_hash_init(TALLOC_CTX *mem_ctx,
                     struct sbus_connection *conn)
{
    return sss_ptr_hash_create(mem_ctx, sbus_opath_hash_delete_cb, conn);
}

static errno_t
sbus_opath_hash_add_iface(hash_table_t *table,
                          const char *object_path,
                          struct sbus_interface *iface,
                          bool *_path_known)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sbus_interface_list *list = NULL;
    struct sbus_interface_list *item = NULL;
    const char *iface_name = iface->vtable->meta->name;
    bool path_known;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Registering interface %s with path %s\n",
          iface_name, object_path);

    /* create new list item */

    item = talloc_zero(tmp_ctx, struct sbus_interface_list);
    if (item == NULL) {
        return ENOMEM;
    }

    item->interface = iface;

    /* first lookup existing list in hash table */

    list = sss_ptr_hash_lookup(table, object_path, struct sbus_interface_list);
    if (list != NULL) {
        /* This object path has already some interface registered. We will
         * check for existence of the interface currently being added and
         * add it if missing. */

        path_known = true;

        if (sbus_iface_list_lookup(list, iface_name) != NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Trying to register the same interface"
                  " twice: iface=%s, opath=%s\n", iface_name, object_path);
            ret = EEXIST;
            goto done;
        }

        DLIST_ADD_END(list, item, struct sbus_interface_list *);
        ret = EOK;
        goto done;
    }

    /* otherwise create new hash entry and new list */

    path_known = false;
    list = item;

    ret = sss_ptr_hash_add(table, object_path, list,
                           struct sbus_interface_list);

done:
    if (ret == EOK) {
        talloc_steal(item, iface);
        talloc_steal(table, item);
        *_path_known = path_known;
    }

    talloc_free(tmp_ctx);
    return ret;
}

static bool
sbus_opath_hash_has_path(hash_table_t *table,
                         const char *object_path)
{
    return sss_ptr_hash_has_key(table, object_path);
}

/**
 * First @object_path is looked up in @table, if it is not found it steps up
 * in the path hierarchy and try to lookup the parent node. This continues
 * until the root is reached.
 */
struct sbus_interface *
sbus_opath_hash_lookup_iface(hash_table_t *table,
                             const char *object_path,
                             const char *iface_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sbus_interface_list *list = NULL;
    struct sbus_interface *iface = NULL;
    char *lookup_path = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    lookup_path = talloc_strdup(tmp_ctx, object_path);
    if (lookup_path == NULL) {
        goto done;
    }

    while (lookup_path != NULL) {
        list = sss_ptr_hash_lookup(table, lookup_path,
                                   struct sbus_interface_list);
        if (list != NULL) {
            iface = sbus_iface_list_lookup(list, iface_name);
            if (iface != NULL) {
                goto done;
            }
        }

        /* we will not free lookup path since it is freed with tmp_ctx
         * and the object paths are supposed to be small */
        lookup_path = sbus_opath_parent_subtree(tmp_ctx, lookup_path);
    }

done:
    talloc_free(tmp_ctx);
    return iface;
}

/**
 * Acquire list of all interfaces that are supported on given object path.
 */
errno_t
sbus_opath_hash_lookup_supported(TALLOC_CTX *mem_ctx,
                                 hash_table_t *table,
                                 const char *object_path,
                                 struct sbus_interface_list **_list)
{
    TALLOC_CTX *tmp_ctx = NULL;
    TALLOC_CTX *list_ctx = NULL;
    struct sbus_interface_list *copy;
    struct sbus_interface_list *output_list;
    struct sbus_interface_list *table_list;
    char *lookup_path = NULL;
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

    lookup_path = talloc_strdup(tmp_ctx, object_path);
    if (lookup_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Initialize output_list. */
    output_list = NULL;

    while (lookup_path != NULL) {
        table_list = sss_ptr_hash_lookup(table, lookup_path,
                                         struct sbus_interface_list);
        if (table_list != NULL) {
            ret = sbus_iface_list_copy(list_ctx, table_list, &copy);
            if (ret != EOK) {
                goto done;
            }

            DLIST_CONCATENATE(output_list, copy, struct sbus_interface_list *);
        }

        /* we will not free lookup path since it is freed with tmp_ctx
         * and the object paths are supposed to be small */
        lookup_path = sbus_opath_parent_subtree(tmp_ctx, lookup_path);
    }

    talloc_steal(mem_ctx, list_ctx);
    *_list = output_list;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

hash_table_t *
sbus_nodes_hash_init(TALLOC_CTX *mem_ctx)
{
    return sss_ptr_hash_create(mem_ctx, NULL, NULL);
}

struct sbus_nodes_data {
    sbus_nodes_fn nodes_fn;
    void *handler_data;
};

static errno_t
sbus_nodes_hash_add(hash_table_t *table,
                    const char *object_path,
                    sbus_nodes_fn nodes_fn,
                    void *handler_data)
{
    struct sbus_nodes_data *data;
    errno_t ret;

    data = talloc_zero(table, struct sbus_nodes_data);
    if (data == NULL) {
        return ENOMEM;
    }

    data->handler_data = handler_data;
    data->nodes_fn = nodes_fn;

    ret = sss_ptr_hash_add(table, object_path, data, struct sbus_nodes_data);
    if (ret != EOK) {
        talloc_free(data);
        return ret;
    }

    return EOK;
}

const char **
sbus_nodes_hash_lookup(TALLOC_CTX *mem_ctx,
                       hash_table_t *table,
                       const char *object_path)
{
    struct sbus_nodes_data *data;

    data = sss_ptr_hash_lookup(table, object_path, struct sbus_nodes_data);
    if (data == NULL) {
        return NULL;
    }

    return data->nodes_fn(mem_ctx, object_path, data->handler_data);
}

static struct sbus_interface *
sbus_new_interface(TALLOC_CTX *mem_ctx,
                   const char *object_path,
                   struct sbus_vtable *iface_vtable,
                   void *handler_data)
{
    struct sbus_interface *intf;

    intf = talloc_zero(mem_ctx, struct sbus_interface);
    if (intf == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot allocate a new sbus_interface.\n");
        return NULL;
    }

    intf->path = talloc_strdup(intf, object_path);
    if (intf->path == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot duplicate object path.\n");
        talloc_free(intf);
        return NULL;
    }

    intf->vtable = iface_vtable;
    intf->handler_data = handler_data;
    return intf;
}

static DBusHandlerResult
sbus_message_handler(DBusConnection *dbus_conn,
                     DBusMessage *message,
                     void *user_data);

static errno_t
sbus_conn_register_path(struct sbus_connection *conn,
                        const char *path)
{
    static DBusObjectPathVTable vtable = {NULL, sbus_message_handler,
                                          NULL, NULL, NULL, NULL};
    DBusError error;
    char *reg_path = NULL;
    dbus_bool_t dbret;

    DEBUG(SSSDBG_TRACE_FUNC, "Registering object path %s with D-Bus "
          "connection\n", path);

    if (sbus_opath_is_subtree(path)) {
        reg_path = sbus_opath_get_base_path(conn, path);
        if (reg_path == NULL) {
            return ENOMEM;
        }

        /* D-Bus does not allow to have both object path and fallback
         * registered. Since we handle the real message handlers ourselves
         * we will register fallback only in this case. */
        if (sbus_opath_hash_has_path(conn->managed_paths, reg_path)) {
            dbus_connection_unregister_object_path(conn->dbus.conn, reg_path);
        }

        dbret = dbus_connection_register_fallback(conn->dbus.conn, reg_path,
                                                  &vtable, conn);
        talloc_free(reg_path);
    } else {
        dbus_error_init(&error);

        dbret = dbus_connection_try_register_object_path(conn->dbus.conn, path,
                                                         &vtable, conn, &error);

        if (dbus_error_is_set(&error) &&
                strcmp(error.name, DBUS_ERROR_OBJECT_PATH_IN_USE) == 0) {
            /* A fallback is probably already registered. Just return. */
            dbus_error_free(&error);
            return EOK;
        }
    }

    if (!dbret) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register object path "
              "%s with D-Bus connection.\n", path);
        return ENOMEM;
    }

    return EOK;
}

errno_t
sbus_conn_register_iface(struct sbus_connection *conn,
                         struct sbus_vtable *iface_vtable,
                         const char *object_path,
                         void *handler_data)
{
    struct sbus_interface *iface = NULL;
    bool path_known;
    errno_t ret;

    if (conn == NULL || iface_vtable == NULL || object_path == NULL) {
        return EINVAL;
    }

    iface = sbus_new_interface(conn, object_path, iface_vtable, handler_data);
    if (iface == NULL) {
        return ENOMEM;
    }

    ret = sbus_opath_hash_add_iface(conn->managed_paths, object_path, iface,
                                    &path_known);
    if (ret != EOK) {
        talloc_free(iface);
        return ret;
    }

    if (path_known) {
        /* this object path is already registered */
        return EOK;
    }

    /* if ret != EOK we will still leave iface in the table, since
     * we probably don't have enough memory to remove it correctly anyway */

    ret = sbus_conn_register_path(conn, object_path);
    if (ret != EOK) {
        return ret;
    }

    /* register standard interfaces with this object path as well */
    ret = sbus_conn_register_iface(conn, sbus_properties_vtable(),
                                   object_path, conn);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_conn_register_iface(conn, sbus_introspect_vtable(),
                                   object_path, conn);
    if (ret != EOK) {
        return ret;
    }

    return ret;
}

errno_t
sbus_conn_register_iface_map(struct sbus_connection *conn,
                             struct sbus_iface_map *map,
                             void *pvt)
{
    errno_t ret;
    int i;

    for (i = 0; map[i].path != NULL; i++) {
        ret = sbus_conn_register_iface(conn, map[i].vtable, map[i].path, pvt);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

void
sbus_conn_register_nodes(struct sbus_connection *conn,
                         const char *path,
                         sbus_nodes_fn nodes_fn,
                         void *data)
{
    errno_t ret;

    ret = sbus_nodes_hash_add(conn->nodes_fns, path, nodes_fn, data);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to register node function with "
              "%s. Introspection may not work correctly.\n", path);
    }
}

errno_t
sbus_conn_reregister_paths(struct sbus_connection *conn)
{
    hash_key_t *keys = NULL;
    unsigned long count;
    unsigned long i;
    errno_t ret;
    int hret;

    hret = hash_keys(conn->managed_paths, &count, &keys);
    if (hret != HASH_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        ret = sbus_conn_register_path(conn, keys[i].str);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(keys);
    return ret;
}

static void
sbus_message_handler_got_caller_id(struct tevent_req *req);

static DBusHandlerResult
sbus_message_handler(DBusConnection *dbus_conn,
                     DBusMessage *message,
                     void *handler_data)
{
    struct tevent_req *req;
    struct sbus_connection *conn;
    struct sbus_interface *iface;
    struct sbus_request *sbus_req;
    const struct sbus_method_meta *method;
    const char *iface_name;
    const char *method_name;
    const char *path;
    const char *sender;

    conn = talloc_get_type(handler_data, struct sbus_connection);

    /* header information */
    iface_name = dbus_message_get_interface(message);
    method_name = dbus_message_get_member(message);
    path = dbus_message_get_path(message);
    sender = dbus_message_get_sender(message);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Received SBUS method %s.%s on path %s\n",
          iface_name, method_name, path);

    /* try to find the interface */
    iface = sbus_opath_hash_lookup_iface(conn->managed_paths,
                                         path, iface_name);
    if (iface == NULL) {
        goto fail;
    }

    method = sbus_meta_find_method(iface->vtable->meta, method_name);
    if (method == NULL || method->vtable_offset == 0) {
        goto fail;
    }

    /* we have a valid handler, create D-Bus request */
    sbus_req = sbus_new_request(conn, iface, message);
    if (sbus_req == NULL) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    sbus_req->method = method;

    /* now get the sender ID */
    req = sbus_get_sender_id_send(sbus_req, conn->ev, conn, sender);
    if (req == NULL) {
        talloc_free(sbus_req);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    tevent_req_set_callback(req, sbus_message_handler_got_caller_id, sbus_req);

    if (conn->last_request_time != NULL) {
        *conn->last_request_time = time(NULL);
    }

    return DBUS_HANDLER_RESULT_HANDLED;

fail: ;
    DBusMessage *reply;

    DEBUG(SSSDBG_CRIT_FAILURE, "No matching handler found for method %s.%s "
          "on path %s\n", iface_name, method_name, path);

    reply = dbus_message_new_error(message, DBUS_ERROR_UNKNOWN_METHOD, NULL);
    sbus_conn_send_reply(conn, reply);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static void
sbus_message_handler_got_caller_id(struct tevent_req *req)
{
    struct sbus_request *sbus_req;
    const struct sbus_method_meta *method;
    sbus_msg_handler_fn handler;
    sbus_method_invoker_fn invoker;
    void *pvt;
    DBusError *error;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);
    method = sbus_req->method;

    ret = sbus_get_sender_id_recv(req, &sbus_req->client);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to "
                               "resolve caller's ID: %s\n", sss_strerror(ret));
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    handler = VTABLE_FUNC(sbus_req->intf->vtable, method->vtable_offset);
    invoker = method->invoker;
    pvt = sbus_req->intf->handler_data;

    sbus_request_invoke_or_finish(sbus_req, handler, pvt, invoker);
    return;
}
