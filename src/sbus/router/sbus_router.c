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
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_private.h"

static errno_t
sbus_router_register_std(struct sbus_router *router)
{
    errno_t ret;

    ret = sbus_register_introspection(router);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to register org.freedesktop.DBus.Introspectable.\n");
        return ret;
    }

    ret = sbus_register_properties(router);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to register org.freedesktop.DBus.Properties.\n");
        return ret;
    }

    return EOK;
}

errno_t
sbus_router_add_path(struct sbus_router *router,
                     const char *path,
                     struct sbus_interface *iface)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Registering interface %s on path %s\n",
          iface->name, path);

    ret = sbus_router_paths_add(router->paths, path, iface);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add new path [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

errno_t
sbus_router_add_path_map(struct sbus_router *router,
                         struct sbus_path *map)
{
    errno_t ret;
    int i;

    for (i = 0; map[i].path != NULL; i++) {
        ret = sbus_router_add_path(router, map[i].path, map[i].iface);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

char *
sbus_router_signal_rule(TALLOC_CTX *mem_ctx,
                        const char *interface,
                        const char *signal_name)
{
    return talloc_asprintf(mem_ctx, "type='signal',interface='%s',member='%s'",
                           interface, signal_name);
}

errno_t
sbus_router_signal_parse(TALLOC_CTX *mem_ctx,
                         const char *qualified_signal,
                         char **_interface,
                         char **_signal_name)
{
    char *signal_name;
    char *dot;
    char *dup;

    dup = talloc_strdup(mem_ctx, qualified_signal);
    if (dup == NULL) {
        return ENOMEM;
    }

    /* Split the duplicate into interface and signal name parts. */
    dot = strrchr(dup, '.');
    if (dot == NULL) {
        talloc_free(dup);
        return EINVAL;
    }
    *dot = '\0';

    signal_name = talloc_strdup(mem_ctx, dot + 1);
    if (signal_name == NULL) {
        talloc_free(dup);
        return ENOMEM;
    }

    *_interface = dup;
    *_signal_name = signal_name;

    return EOK;
}

static void
sbus_router_signal_match(struct sbus_router *router,
                         DBusConnection *conn,
                         const char *interface,
                         const char *signal_name)
{
    char *rule;

    rule = sbus_router_signal_rule(NULL, interface, signal_name);
    if (rule == NULL) {
        /* There is nothing we can do. */
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return;
    }

    /* If error is not NULL D-Bus will block. There is nothing to do anyway,
     * so we just won't detect errors here. */
    dbus_bus_add_match(conn, rule, NULL);
    talloc_free(rule);
}

errno_t
sbus_router_listen(struct sbus_connection *conn,
                   struct sbus_listener *listener)
{
    bool signal_known;
    errno_t ret;

    /* We can't register signal listener on this connection. */
    if (conn->type == SBUS_CONNECTION_CLIENT) {
        return EOK;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Registering signal listener %s.%s on path %s\n",
          listener->interface, listener->signal_name,
          (listener->object_path == NULL ? "<ALL>" : listener->object_path));

    ret = sbus_router_listeners_add(conn->router->listeners,
                                    listener->interface,
                                    listener->signal_name,
                                    listener, &signal_known);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add new listener [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    if (signal_known) {
        /* This signal listener is already registered. */
        return EOK;
    }

    sbus_router_signal_match(conn->router, conn->connection,
                             listener->interface, listener->signal_name);

    return ret;
}

errno_t
sbus_router_listen_map(struct sbus_connection *conn,
                       struct sbus_listener *map)
{
    errno_t ret;
    int i;

    for (i = 0; map[i].interface != NULL; i++) {
        ret = sbus_router_listen(conn, &map[i]);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

errno_t
sbus_router_add_node(struct sbus_connection *conn,
                     struct sbus_node *node)
{
    errno_t ret;

    if (node->path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: path cannot be NULL!\n");
        return ERR_INTERNAL;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Adding new node: %s\n", node->path);

    ret = sbus_router_nodes_add(conn->router->nodes, node);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add node %s [%d]: %s\n",
              node->path, ret, sss_strerror(ret));
    }

    return ret;
}

errno_t
sbus_router_add_node_map(struct sbus_connection *conn,
                         struct sbus_node *map)
{
    errno_t ret;
    int i;

    for (i = 0; map[i].path != NULL; i++) {
        ret = sbus_router_add_node(conn, &map[i]);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

static bool
sbus_router_filter_add(struct sbus_router *router)
{
    dbus_bool_t dbret;

    /* Add a connection filter that is used to process input messages. */
    dbret = dbus_connection_add_filter(router->conn->connection,
                                       sbus_connection_filter,
                                       router->conn, NULL);
    if (dbret == false) {
        return false;
    }

    return true;
}

int sbus_router_destructor(struct sbus_router *router)
{
    dbus_connection_remove_filter(router->conn->connection,
                                  sbus_connection_filter, router->conn);

    return 0;
}

struct sbus_router *
sbus_router_init(TALLOC_CTX *mem_ctx,
                 struct sbus_connection *conn)
{
    struct sbus_router *router;
    errno_t ret;
    bool bret;

    router = talloc_zero(mem_ctx, struct sbus_router);
    if (router == NULL) {
        return NULL;
    }

    router->conn = conn;

    router->paths = sbus_router_paths_init(router);
    if (router->paths == NULL) {
        goto fail;
    }

    router->nodes = sbus_router_nodes_init(router);
    if (router->paths == NULL) {
        goto fail;
    }

    /* Register standard interfaces. */
    ret = sbus_router_register_std(router);
    if (ret != EOK) {
        goto fail;
    }

    /* This is a server-side router. */
    if (conn == NULL) {
        return router;
    }

    router->listeners = sbus_router_listeners_init(router, conn);
    if (router->listeners == NULL) {
        goto fail;
    }

    bret = sbus_router_filter_add(router);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register message filter!\n");
        goto fail;
    }

    talloc_set_destructor(router, sbus_router_destructor);

    return router;

fail:
    talloc_free(router);
    return NULL;
}

static errno_t
sbus_router_reset_listeners(struct sbus_connection *conn)
{
    TALLOC_CTX *tmp_ctx;
    hash_key_t *keys;
    char *interface;
    char *name;
    unsigned long count;
    unsigned long i;
    errno_t ret;
    int hret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    hret = hash_keys(conn->router->listeners, &count, &keys);
    if (hret != HASH_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    talloc_steal(tmp_ctx, keys);

    for (i = 0; i < count; i++) {
        ret = sbus_router_signal_parse(tmp_ctx, keys[i].str, &interface, &name);
        if (ret != EOK) {
            goto done;
        }

        sbus_router_signal_match(conn->router, conn->connection,
                                 interface, name);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sbus_router_reset(struct sbus_connection *conn)
{
    errno_t ret;
    bool bret;

    bret = sbus_router_filter_add(conn->router);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register message filter!\n");
        return EFAULT;
    }

    ret = sbus_router_reset_listeners(conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to reset router listeners "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}
