/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>
        Simo Sorce <ssorce@redhat.com>

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
#include <dhash.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <tevent.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "sbus/sbus_private.h"
#include "sbus/interface_dbus/sbus_dbus_server.h"

static errno_t
sbus_server_bus_hello(TALLOC_CTX *mem_ctx,
                      struct sbus_request *sbus_req,
                      struct sbus_server *server,
                      const char **_out)
{
    struct sbus_connection *conn;
    uint32_t attempts;
    errno_t ret;
    char *name;

    /* Generation of unique names is inspired by libdbus source:
     * create_unique_client_name() from bus/driver.c */

    conn = sbus_req->conn;
    if (conn->unique_name != NULL) {
        return EEXIST;
    }

    for (attempts = 0; attempts < server->max_connections; attempts++) {
        server->name.minor++;
        if (server->name.minor == 0) {
            /* Overflow of minor version. Increase major version. */
            server->name.major++;
            server->name.minor = 1;
            if (server->name.major == 0) {
                /* Overflow of major version. D-Bus would die here,
                 * we will just start over. */
                server->name.major = 1;
                server->name.minor = 0;
                continue;
            }
        }

        name = talloc_asprintf(NULL, ":%u.%u",
                               server->name.major, server->name.minor);
        if (name == NULL) {
            return ENOMEM;
        }

        ret = sss_ptr_hash_add(server->names, name, conn,
                               struct sbus_connection);
        if (ret == EEXIST) {
            talloc_free(name);
            continue;
        }

        DEBUG(SSSDBG_TRACE_ALL, "Assigning unique name %s to connection %p\n",
              name, conn);

        conn->unique_name = talloc_steal(conn, name);
        sbus_server_name_acquired(server, conn, name);
        *_out = name;

        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "Maximum number [%u] of active connections "
          "has been reached.\n", server->max_connections);

    return ERR_SBUS_CONNECTION_LIMIT;
}

static errno_t
sbus_server_bus_request_name(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct sbus_server *server,
                             const char *name,
                             uint32_t flags,
                             uint32_t *_result)
{
    struct sbus_connection *conn;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Requesting name: %s\n", name);

    if (name[0] == ':') {
        DEBUG(SSSDBG_OP_FAILURE, "Can not assign unique name: %s\n", name);
        return EINVAL;
    }

    conn = sss_ptr_hash_lookup(server->names, name, struct sbus_connection);
    if (conn == NULL) {
        /* We want to remember only the first well known name. */
        if (sbus_req->conn->wellknown_name == NULL) {
            ret = sbus_connection_set_name(sbus_req->conn, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set well known name "
                      "[%d]: %s\n", ret, sss_strerror(ret));
                return ret;
            }
        }

        ret = sss_ptr_hash_add(server->names, name, sbus_req->conn,
                               struct sbus_connection);
        if (ret == EOK) {
            sbus_server_name_acquired(server, sbus_req->conn, name);
            *_result = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
        }

        return ret;
    }

    if (conn == sbus_req->conn) {
        *_result = DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
        return EOK;
    }

    *_result = DBUS_REQUEST_NAME_REPLY_EXISTS;
    return EOK;
}

static errno_t
sbus_server_bus_release_name(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct sbus_server *server,
                             const char *name,
                             uint32_t *_result)
{
    struct sbus_connection *conn;

    if (name[0] == ':') {
        DEBUG(SSSDBG_OP_FAILURE, "Can not release unique name: %s\n", name);
        return EINVAL;
    }

    conn = sss_ptr_hash_lookup(server->names, name, struct sbus_connection);
    if (conn == NULL) {
        *_result = DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
        return EOK;
    }

    if (conn != sbus_req->conn) {
        *_result = DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
        return EOK;
    }

    sss_ptr_hash_delete(server->names, name, false);
    sbus_server_name_lost(server, conn, name);
    *_result = DBUS_RELEASE_NAME_REPLY_RELEASED;
    return EOK;
}

static errno_t
sbus_server_bus_name_has_owner(TALLOC_CTX *mem_ctx,
                               struct sbus_request *sbus_req,
                               struct sbus_server *server,
                               const char *name,
                               bool *_result)
{
    struct sbus_connection *conn;

    conn = sss_ptr_hash_lookup(server->names, name, struct sbus_connection);
    if (conn == NULL) {
        *_result = false;
        return EOK;
    }

    *_result = true;
    return EOK;
}

static errno_t
sbus_server_bus_list_names(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct sbus_server *server,
                           const char ***_names)
{
    hash_key_t *keys;
    const char **names;
    unsigned long count;
    unsigned long i;
    int hret;

    hret = hash_keys(server->names, &count, &keys);
    if (hret != HASH_SUCCESS) {
        return ENOMEM;
    }

    names = talloc_zero_array(mem_ctx, const char *, count + 2);
    if (names == NULL) {
        talloc_free(keys);
        return ENOMEM;
    }

    names[0] = DBUS_SERVICE_DBUS;
    for (i = 1; i < count + 1; i++) {
        names[i] = keys[i - 1].str;
    }

    *_names = names;

    talloc_free(keys);

    return EOK;
}

static errno_t
sbus_server_bus_list_activatable_names(TALLOC_CTX *mem_ctx,
                                       struct sbus_request *sbus_req,
                                       struct sbus_server *server,
                                       const char ***_names)
{
    /* We do not support activatable services. */
    *_names = NULL;

    return EOK;
}

static errno_t
sbus_server_bus_get_name_owner(TALLOC_CTX *mem_ctx,
                               struct sbus_request *sbus_req,
                               struct sbus_server *server,
                               const char *name,
                               const char **_unique_name)
{
    struct sbus_connection *conn;

    /* The bus service owns itself. */
    if (strcmp(name, DBUS_SERVICE_DBUS) == 0) {
        *_unique_name = DBUS_SERVICE_DBUS;
        return EOK;
    }

    conn = sss_ptr_hash_lookup(server->names, name, struct sbus_connection);
    if (conn == NULL) {
        return ERR_SBUS_UNKNOWN_OWNER;
    }

    *_unique_name = conn->unique_name;
    return EOK;
}

static errno_t
sbus_server_bus_list_queued_owners(TALLOC_CTX *mem_ctx,
                                   struct sbus_request *sbus_req,
                                   struct sbus_server *server,
                                   const char *name,
                                   const char ***_names)
{
    /* We do not support queued name requests. */
    *_names = NULL;

    return EOK;
}

static errno_t
sbus_server_bus_get_connection_unix_user(TALLOC_CTX *mem_ctx,
                                         struct sbus_request *sbus_req,
                                         struct sbus_server *server,
                                         const char *name,
                                         uint32_t *_uid)
{
    struct sbus_connection *conn;
    unsigned long uid;
    dbus_bool_t dbret;

    if (strcmp(name, DBUS_SERVICE_DBUS) == 0) {
        *_uid = geteuid();
        return EOK;
    }

    conn = sss_ptr_hash_lookup(server->names, name, struct sbus_connection);
    if (conn == NULL) {
        return ERR_SBUS_UNKNOWN_OWNER;
    }

    dbret = dbus_connection_get_unix_user(conn->connection, &uid);
    if (!dbret) {
        return EIO;
    }

    *_uid = (uint32_t)uid;
    return EOK;
}

static errno_t
sbus_server_bus_get_connection_unix_process_id(TALLOC_CTX *mem_ctx,
                                               struct sbus_request *sbus_req,
                                               struct sbus_server *server,
                                               const char *name,
                                               uint32_t *_pid)
{
    struct sbus_connection *conn;
    unsigned long pid;
    dbus_bool_t dbret;

    if (strcmp(name, DBUS_SERVICE_DBUS) == 0) {
        *_pid = getpid();
        return EOK;
    }

    conn = sss_ptr_hash_lookup(server->names, name, struct sbus_connection);
    if (conn == NULL) {
        return ERR_SBUS_UNKNOWN_OWNER;
    }

    dbret = dbus_connection_get_unix_process_id(conn->connection, &pid);
    if (!dbret) {
        return EIO;
    }

    *_pid = (uint32_t)pid;
    return EOK;
}

static errno_t
sbus_server_bus_start_service_by_name(TALLOC_CTX *mem_ctx,
                                      struct sbus_request *sbus_req,
                                      struct sbus_server *server,
                                      const char *name,
                                      uint32_t flags,
                                      uint32_t *_result)
{
    struct sbus_connection *conn;

    if (strcmp(name, DBUS_SERVICE_DBUS) == 0) {
        *_result = DBUS_START_REPLY_ALREADY_RUNNING;
        return EOK;
    }

    conn = sss_ptr_hash_lookup(server->names, name, struct sbus_connection);
    if (conn == NULL) {
        return ERR_SBUS_UNKNOWN_OWNER;
    }

    *_result = DBUS_START_REPLY_ALREADY_RUNNING;
    return EOK;
}

static errno_t
sbus_server_bus_add_match(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct sbus_server *server,
                          const char *rule)
{
    return sbus_server_add_match(server, sbus_req->conn, rule);
}

static errno_t
sbus_server_bus_remove_match(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct sbus_server *server,
                             const char *rule)
{
    return sbus_server_remove_match(server, sbus_req->conn, rule);
}

errno_t
sbus_server_setup_interface(struct sbus_server *server)
{
    errno_t ret;

    SBUS_INTERFACE(bus,
        org_freedesktop_DBus,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, org_freedesktop_DBus, Hello, sbus_server_bus_hello, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, RequestName, sbus_server_bus_request_name, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, ReleaseName, sbus_server_bus_release_name, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, NameHasOwner, sbus_server_bus_name_has_owner, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, ListNames, sbus_server_bus_list_names, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, ListActivatableNames, sbus_server_bus_list_activatable_names, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, GetNameOwner, sbus_server_bus_get_name_owner, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, ListQueuedOwners, sbus_server_bus_list_queued_owners, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, GetConnectionUnixUser, sbus_server_bus_get_connection_unix_user, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, GetConnectionUnixProcessID, sbus_server_bus_get_connection_unix_process_id, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, StartServiceByName, sbus_server_bus_start_service_by_name, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, AddMatch, sbus_server_bus_add_match, server),
            SBUS_SYNC(METHOD, org_freedesktop_DBus, RemoveMatch, sbus_server_bus_remove_match, server)
        ),
        SBUS_SIGNALS(
            SBUS_EMITS(org_freedesktop_DBus, NameOwnerChanged),
            SBUS_EMITS(org_freedesktop_DBus, NameAcquired),
            SBUS_EMITS(org_freedesktop_DBus, NameLost)
        ),
        SBUS_WITHOUT_PROPERTIES
    );

    /* Here we register interfaces on some object paths. */
    struct sbus_path paths[] = {
        {DBUS_PATH_DBUS, &bus},
        {NULL, NULL}
    };

    ret = sbus_router_add_path_map(server->router, paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add paths [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}
