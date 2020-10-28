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
#include <string.h>
#include <limits.h>
#include <tevent.h>
#include <talloc.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "sbus/sbus_private.h"

struct sbus_server_on_connection {
    const char *name;
    sbus_server_on_connection_cb callback;
    sbus_server_on_connection_data data;
};

static const char *
sbus_server_get_filename(const char *address)
{
    const char *filename;

    filename = strchr(address, '/');
    if (filename == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected dbus address [%s].\n", address);
        return NULL;
    }

    return filename;
}

static errno_t
sbus_server_get_socket(TALLOC_CTX *mem_ctx,
                       const char *address,
                       const char **_socket_address,
                       const char **_filename)
{
    const char *socket_address;
    const char *filename;

    /* Get D-Bus socket address. */
    socket_address = talloc_strdup(mem_ctx, address);
    if (socket_address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    /* Get system files names. */
    filename = sbus_server_get_filename(socket_address);
    if (filename == NULL) {
        return EINVAL;
    }

    if (_socket_address != NULL) {
        *_socket_address = socket_address;
    }

    if (_filename != NULL) {
        *_filename = filename;
    }

    return EOK;
}

static DBusServer *
sbus_server_socket_listen(const char *socket_address)
{
    DBusServer *server;
    DBusError error;
    char *server_address;

    dbus_error_init(&error);

    server = dbus_server_listen(socket_address, &error);
    if (server == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to start a D-Bus server at "
              "%s [%s]: %s\n", socket_address, error.name, error.message);
    }

    dbus_error_free(&error);

    server_address = dbus_server_get_address(server);
    DEBUG(SSSDBG_TRACE_FUNC, "D-BUS Server listening on %s\n", server_address);
    free(server_address);

    return server;
}

static errno_t
sbus_server_check_file(const char *filename, uid_t uid, gid_t gid)
{
    struct stat stat_buf;
    errno_t ret;

    /* Both check_file and chmod can handle both the symlink and the socket */
    ret = check_file(filename, getuid(), getgid(), S_IFSOCK, S_IFMT,
                     &stat_buf, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_file failed for [%s].\n", filename);
        return ret;
    }

    if ((stat_buf.st_mode & ~S_IFMT) != (S_IRUSR | S_IWUSR)) {
        ret = chmod(filename, (S_IRUSR | S_IWUSR));
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "chmod failed for [%s] [%d]: %s\n",
                  filename, ret, sss_strerror(ret));
            return ret;
        }
    }

    if (stat_buf.st_uid != uid || stat_buf.st_gid != gid) {
        ret = chown(filename, uid, gid);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "chown failed for [%s] [%d]: %s\n",
                  filename, ret, sss_strerror(ret));
            return ret;
        }
    }

    return EOK;
}

static DBusServer *
sbus_server_setup_dbus(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       const char *address,
                       uid_t uid,
                       gid_t gid)
{
    TALLOC_CTX *tmp_ctx;
    DBusServer *dbus_server = NULL;
    const char *socket_address;
    const char *filename;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return NULL;
    }

    /* Get socket address. */
    ret = sbus_server_get_socket(tmp_ctx, address,
                                 &socket_address, &filename);
    if (ret != EOK) {
        goto done;
    }

    /* Start listening on this socket. This will also create the socket. */
    dbus_server = sbus_server_socket_listen(socket_address);
    if (dbus_server == NULL) {
        ret = EIO;
        goto done;
    }

    /* Check file permissions and setup proper owner. */
    ret = sbus_server_check_file(filename, uid, gid);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK && dbus_server != NULL) {
        dbus_server_disconnect(dbus_server);
        dbus_server_unref(dbus_server);

        return NULL;
    }

    return dbus_server;
}

static bool
sbus_server_filter_add(struct sbus_server *server,
                       DBusConnection *dbus_conn)
{
    dbus_bool_t dbret;

    /* Add a connection filter that is used to process input messages. */
    dbret = dbus_connection_add_filter(dbus_conn, sbus_server_filter,
                                       server, NULL);
    if (dbret == false) {
        return false;
    }

    return true;
}

static dbus_bool_t
sbus_server_check_connection_uid(DBusConnection *dbus_conn,
                                 unsigned long uid,
                                 void *data)
{
    struct sbus_server *sbus_server;

    sbus_server = talloc_get_type(data, struct sbus_server);

    if (uid == 0 || uid == sbus_server->uid) {
        return true;
    }

    return false;
}

static void
sbus_server_new_connection(DBusServer *dbus_server,
                           DBusConnection *dbus_conn,
                           void *data)
{
    struct sbus_server *sbus_server;
    struct sbus_connection *sbus_conn;
    dbus_bool_t dbret;
    errno_t ret;
    bool bret;

    sbus_server = talloc_get_type(data, struct sbus_server);

    DEBUG(SSSDBG_FUNC_DATA, "Adding connection %p.\n", dbus_conn);

    /* Allow access from uid that is associated with this sbus server. */
    dbus_connection_set_unix_user_function(dbus_conn,
                                           sbus_server_check_connection_uid,
                                           sbus_server, NULL);

    /* First, add a message filter that will take care of routing messages
     * between connections. */
    bret = sbus_server_filter_add(sbus_server, dbus_conn);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add server filter!\n");
        return;
    }

    /**
     * @dbus_conn is unreferenced in libdbus by the caller of this new
     * connection function thus we must not unreference it here. Its
     * reference counter is increased in @sbus_connection_init.
     */

    sbus_conn = sbus_connection_init(sbus_server, sbus_server->ev, dbus_conn,
                                     NULL, NULL, SBUS_CONNECTION_CLIENT,
                                     NULL);
    if (sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Closing connection, unable to setup\n");
        dbus_connection_close(dbus_conn);
        return;
    }

    dbret = dbus_connection_set_data(dbus_conn, sbus_server->data_slot,
                                     sbus_conn, NULL);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Closing connection, unable to set data\n");
        talloc_free(sbus_conn);
        return;
    }

    if (sbus_server->on_connection->callback != NULL) {
        ret = sbus_server->on_connection->callback(sbus_conn,
                  sbus_server->on_connection->data);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Closing connection, new connection "
                  "callback failed [%d]: %s\n", ret, sss_strerror(ret));
            talloc_free(sbus_conn);
            return;
        }
    }
}

static errno_t
sbus_server_tevent_enable(struct sbus_server *server)
{
    errno_t ret;

    ret = sbus_watch_server(server, server->ev, server->server,
                            &server->watch_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup D-Bus watch [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    /* Set function that is called each time a new client is connected. */
    dbus_server_set_new_connection_function(server->server,
                                            sbus_server_new_connection,
                                            server, NULL);

    return EOK;
}

static void
sbus_server_tevent_disable(struct sbus_server *server)
{
    dbus_server_set_new_connection_function(server->server, NULL, NULL, NULL);
    talloc_zfree(server->watch_ctx);
}

static void
sbus_server_name_owner_changed(struct sbus_server *server,
                               const char *name,
                               const char *new_owner,
                               const char *old_owner)
{
    DBusMessage *message;

    /* We can't really send signals when the server is being destroyed. */
    if (server == NULL || server->disconnecting) {
        return;
    }

    message = sbus_signal_create(NULL, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS,
                                 "NameOwnerChanged",
                                 DBUS_TYPE_STRING, &name,
                                 DBUS_TYPE_STRING, &new_owner,
                                 DBUS_TYPE_STRING, &old_owner);
    if (message == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return;
    }

    dbus_message_set_sender(message, DBUS_SERVICE_DBUS);

    /* Send the signal. */
    sbus_server_matchmaker(server, NULL, name, message);
}

void
sbus_server_name_acquired(struct sbus_server *server,
                          struct sbus_connection *conn,
                          const char *name)
{
    DBusMessage *message;

    message = sbus_signal_create(NULL, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS,
                                 "NameAcquired", DBUS_TYPE_STRING, &name);
    if (message == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return;
    }

    dbus_message_set_sender(message, DBUS_SERVICE_DBUS);
    dbus_message_set_destination(message, conn->unique_name);
    dbus_connection_send(conn->connection, message, NULL);

    sbus_server_name_owner_changed(server, name, name, "");
}

void
sbus_server_name_lost(struct sbus_server *server,
                      struct sbus_connection *conn,
                      const char *name)
{
    DBusMessage *message;

    if (name[0] == ':') {
        /* The connection is being terminated. Do not send the signal. */
        return;
    }

    message = sbus_signal_create(NULL, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS,
                                 "NameLost", DBUS_TYPE_STRING, &name);
    if (message == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return;
    }

    dbus_message_set_sender(message, DBUS_SERVICE_DBUS);
    dbus_message_set_destination(message, conn->unique_name);
    dbus_connection_send(conn->connection, message, NULL);

    sbus_server_name_owner_changed(server, name, "", name);
}

static void
sbus_server_name_remove_from_table_cb(hash_entry_t *item,
                                   hash_destroy_enum type,
                                   void *pvt)
{
    struct sbus_server *server;
    const char *name;

    /* We can't really send signals when the server is being destroyed. */
    if (type == HASH_TABLE_DESTROY) {
        return;
    }

    server = talloc_get_type(pvt, struct sbus_server);
    name = item->key.str;

    sbus_server_name_owner_changed(server, name, "", name);
}

static int sbus_server_destructor(struct sbus_server *server)
{
    if (server->server == NULL) {
        return 0;
    }

    server->disconnecting = true;

    /* Remove tevent integration first. */
    sbus_server_tevent_disable(server);

    if (server->data_slot != -1) {
        dbus_connection_free_data_slot(&server->data_slot);
    }

    /* Release server. */
    dbus_server_disconnect(server->server);
    dbus_server_unref(server->server);

    return 0;
}

struct sbus_server *
sbus_server_create(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   const char *address,
                   uint32_t max_connections,
                   uid_t uid,
                   gid_t gid,
                   sbus_server_on_connection_cb on_conn_cb,
                   sbus_server_on_connection_data on_conn_data)
{
    DBusServer *dbus_server;
    struct sbus_server *sbus_server;
    dbus_bool_t dbret;
    errno_t ret;

    sbus_server = talloc_zero(mem_ctx, struct sbus_server);
    if (sbus_server == NULL) {
        return NULL;
    }

    sbus_server->data_slot = -1;
    talloc_set_destructor(sbus_server, sbus_server_destructor);

    dbus_server = sbus_server_setup_dbus(sbus_server, ev, address,
                                         uid, gid);
    if (dbus_server == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup a D-Bus server!\n");
        ret = ENOMEM;
        goto done;
    }

    sbus_server->ev = ev;
    sbus_server->server = dbus_server;
    sbus_server->max_connections = max_connections;
    sbus_server->name.major = 1;
    sbus_server->name.minor = 0;
    sbus_server->uid = uid;
    sbus_server->gid = gid;

    sbus_server->on_connection = talloc_zero(sbus_server,
                                             struct sbus_server_on_connection);
    if (sbus_server->on_connection == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (on_conn_cb != NULL) {
        _sbus_server_set_on_connection(sbus_server, "on-connection", on_conn_cb,
                                       on_conn_data);
    }

    sbus_server->names = sss_ptr_hash_create(sbus_server,
                             sbus_server_name_remove_from_table_cb, sbus_server);
    if (sbus_server->names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sbus_server->match_rules = sss_ptr_hash_create(sbus_server, NULL, NULL);
    if (sbus_server->match_rules == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sbus_server->router = sbus_router_init(sbus_server, NULL);
    if (sbus_server->router == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_server_setup_interface(sbus_server);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup bus interface [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    dbret = dbus_connection_allocate_data_slot(&sbus_server->data_slot);
    if (!dbret) {
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_server_tevent_enable(sbus_server);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to integrate with tevent [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sbus_server);
        return NULL;
    }

    return sbus_server;
}

struct sbus_connection *
sbus_server_find_connection(struct sbus_server *server, const char *name)
{
    return sss_ptr_hash_lookup(server->names, name, struct sbus_connection);
}

void
_sbus_server_set_on_connection(struct sbus_server *server,
                               const char *name,
                               sbus_server_on_connection_cb on_connection_cb,
                               sbus_server_on_connection_data data)
{
    if (server == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: server is NULL\n");
        return;
    }

    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name is NULL\n");
        return;
    }

    if (on_connection_cb == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Unsetting on connectoin callback\n");
        server->on_connection->callback = NULL;
        server->on_connection->data = NULL;
        server->on_connection->name = NULL;
        return;
    }

    if (server->on_connection->callback != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: on connection callback is "
              "already set to %s\n", server->on_connection->name);
        return;
    }

    server->on_connection->callback = on_connection_cb;
    server->on_connection->data = data;
    server->on_connection->name = name;
}
