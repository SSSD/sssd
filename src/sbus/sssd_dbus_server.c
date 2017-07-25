/*
   SSSD

   Service monitor - D-BUS features

   Copyright (C) Stephen Gallagher         2008

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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <tevent.h>
#include <dbus/dbus.h>
#include <limits.h>

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

static int sbus_server_destructor(void *ctx);

struct new_connection_data {
    struct sbus_connection *server;
    void *client_destructor_data;
};

/*
 * new_connection_callback
 * Actions to be run upon each new client connection
 * Must either perform dbus_connection_ref() on the
 * new connection or else close the connection with
 * dbus_connection_close()
 */
static void sbus_server_init_new_connection(DBusServer *dbus_server,
                                            DBusConnection *dbus_conn,
                                            void *data)
{
    struct new_connection_data *ncd;
    struct sbus_connection *conn;
    int ret;

    DEBUG(SSSDBG_FUNC_DATA,"Entering.\n");
    ncd = talloc_get_type(data, struct new_connection_data);
    if (!ncd) {
        return;
    }

    DEBUG(SSSDBG_FUNC_DATA,"Adding connection %p.\n", dbus_conn);
    ret = sbus_init_connection(ncd->server, ncd->server->ev, dbus_conn,
                               SBUS_CONN_TYPE_PRIVATE, NULL,
                               ncd->client_destructor_data, &conn);
    if (ret != 0) {
        dbus_connection_close(dbus_conn);
        DEBUG(SSSDBG_FUNC_DATA, "Closing connection (failed setup)\n");
        return;
    }

    dbus_connection_ref(dbus_conn);

    DEBUG(SSSDBG_FUNC_DATA,"Got a connection\n");

    /*
     * Initialize connection-specific features
     * This function (or its callbacks) should also
     * set up connection-specific methods.
     */
    ret = ncd->server->srv_init_fn(conn, ncd->server->srv_init_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,"Initialization failed!\n");
        dbus_connection_close(dbus_conn);
        talloc_zfree(conn);
    }
}

const char *
get_socket_address(TALLOC_CTX *mem_ctx, const char *address, bool use_symlink)
{
    if (!use_symlink) {
        return talloc_strdup(mem_ctx, address);
    }

    return talloc_asprintf(mem_ctx,
                           "%s.%lu", address, (unsigned long) getpid());
}

static errno_t
create_socket_symlink(const char *filename, const char *symlink_filename)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_LIBS, "Symlinking the dbus path %s to a link %s\n",
              filename, symlink_filename);
    errno = 0;
    ret = symlink(filename, symlink_filename);
    if (ret != 0 && errno == EEXIST) {
        /* Perhaps cruft after a previous server? */
        errno = 0;
        ret = unlink(symlink_filename);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot remove old symlink '%s': [%d][%s].\n",
                  symlink_filename, ret, strerror(ret));
            return EIO;
        }
        errno = 0;
        ret = symlink(filename, symlink_filename);
    }

    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "symlink() failed on file '%s': [%d][%s].\n",
                  filename, ret, strerror(ret));
        return EIO;
    }

    return EOK;
}

static errno_t
remove_socket_symlink(const char *symlink_name)
{
    errno_t ret;
    char target[PATH_MAX];
    char pidpath[PATH_MAX];
    ssize_t numread = 0;

    errno = 0;
    numread = readlink(symlink_name, target, PATH_MAX-1);
    if (numread < 0) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "readlink failed [%d]: %s\n", ret, strerror(ret));
        return ret;
    }
    target[numread] = '\0';
    DEBUG(SSSDBG_TRACE_ALL, "The symlink points to [%s]\n", target);

    /* We can only remove the symlink if it points to a socket with
     * the same PID */
    ret = snprintf(pidpath, PATH_MAX, "%s.%lu",
                   symlink_name, (unsigned long) getpid());
    if (ret < 0) {
        DEBUG(SSSDBG_OP_FAILURE, "snprintf failed\n");
        return EIO;
    } else if (ret >= PATH_MAX) {
        DEBUG(SSSDBG_OP_FAILURE, "path too long?!?!\n");
        return EIO;
    }
    DEBUG(SSSDBG_TRACE_ALL, "The path including our pid is [%s]\n", pidpath);

    if (strcmp(pidpath, target) != 0) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Will not remove symlink, seems to be owned by "
                  "another process\n");
        return EOK;
    }

    ret = unlink(symlink_name);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "unlink failed to remove [%s] [%d]: %s\n",
               symlink_name, ret, strerror(ret));
        return ret;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Removed the symlink\n");
    return EOK;
}

/*
 * dbus_new_server
 * Set up a D-BUS server, integrate with the event loop
 * for handling file descriptor and timed events
 */
int sbus_new_server(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    const char *address,
                    uid_t uid, gid_t gid,
                    bool use_symlink,
                    struct sbus_connection **_server,
                    sbus_server_conn_init_fn init_fn,
                    void *init_pvt_data,
                    void *client_destructor_data)
{
    struct sbus_connection *server;
    DBusServer *dbus_server;
    DBusError dbus_error;
    dbus_bool_t dbret;
    char *tmp;
    int ret, tmp_ret;
    char *filename;
    char *symlink_filename = NULL;
    const char *socket_address;
    struct stat stat_buf;
    TALLOC_CTX *tmp_ctx;
    struct new_connection_data *ncd;

    *_server = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    socket_address = get_socket_address(tmp_ctx, address, use_symlink);
    if (!socket_address) {
        ret = ENOMEM;
        goto done;
    }

    /* Set up D-BUS server */
    dbus_error_init(&dbus_error);
    dbus_server = dbus_server_listen(socket_address, &dbus_error);
    if (!dbus_server) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "dbus_server_listen failed! (name=%s, message=%s)\n",
                 dbus_error.name, dbus_error.message);
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        ret = EIO;
        goto done;
    }

    filename = strchr(socket_address, '/');
    if (filename == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected dbus address [%s].\n", socket_address);
        ret = EIO;
        goto done;
    }

    if (use_symlink) {
        symlink_filename = strchr(address, '/');
        if (symlink_filename == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected dbus address [%s].\n", address);
            ret = EIO;
            goto done;
        }

        ret = create_socket_symlink(filename, symlink_filename);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not create symlink [%d]: %s\n",
                      ret, strerror(ret));
            ret = EIO;
            goto done;
        }
    }

    /* Both check_file and chmod can handle both the symlink and
     * the socket */
    ret = check_file(filename,
                     getuid(), getgid(), S_IFSOCK, S_IFMT, &stat_buf, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_file failed for [%s].\n", filename);
        ret = EIO;
        goto done;
    }

    if ((stat_buf.st_mode & ~S_IFMT) != (S_IRUSR|S_IWUSR)) {
        ret = chmod(filename, (S_IRUSR|S_IWUSR));
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "chmod failed for [%s]: [%d][%s].\n", filename, ret,
                                                        sss_strerror(ret));
            ret = EIO;
            goto done;
        }
    }

    if (stat_buf.st_uid != uid || stat_buf.st_gid != gid) {
        ret = chown(filename, uid, gid);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "chown failed for [%s]: [%d][%s].\n", filename, ret,
                                                        sss_strerror(ret));
            ret = EIO;
            goto done;
        }
    }

    tmp = dbus_server_get_address(dbus_server);
    DEBUG(SSSDBG_TRACE_FUNC, "D-BUS Server listening on %s\n", tmp);
    free(tmp);

    server = talloc_zero(tmp_ctx, struct sbus_connection);
    if (!server) {
        ret = ENOMEM;
        goto done;
    }

    server->ev = ev;
    server->type = SBUS_SERVER;
    server->dbus.server = dbus_server;
    server->srv_init_fn = init_fn;
    server->srv_init_data = init_pvt_data;

    talloc_set_destructor((TALLOC_CTX *)server, sbus_server_destructor);

    if (use_symlink) {
        server->symlink = talloc_strdup(server, symlink_filename);
        if (!server->symlink) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* This structure must be alive while server is alive. That's the
     * reason for using server as its talloc context.
     */
    ncd = talloc_zero((TALLOC_CTX *)server, struct new_connection_data);
    if (!ncd) {
        ret = ENOMEM;
        goto done;
    }
    ncd->server = server;
    ncd->client_destructor_data = client_destructor_data;

    /* Set up D-BUS new connection handler */
    dbus_server_set_new_connection_function(server->dbus.server,
                                            sbus_server_init_new_connection,
                                            ncd, NULL);

    /* Set up DBusWatch functions */
    dbret = dbus_server_set_watch_functions(server->dbus.server,
                                            sbus_add_watch,
                                            sbus_remove_watch,
                                            sbus_toggle_watch,
                                            server, NULL);
    if (!dbret) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Error setting up D-BUS server watch functions\n");
        ret = EIO;
        goto done;
    }

    /* Set up DBusTimeout functions */
    dbret = dbus_server_set_timeout_functions(server->dbus.server,
                                              sbus_add_timeout,
                                              sbus_remove_timeout,
                                              sbus_toggle_timeout,
                                              server, NULL);
    if (!dbret) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Error setting up D-BUS server timeout functions\n");
        dbus_server_set_watch_functions(server->dbus.server,
                                        NULL, NULL, NULL, NULL, NULL);
        ret = EIO;
        goto done;
    }

    *_server = talloc_steal(mem_ctx, server);
    ret = EOK;

done:
    if (ret != EOK && symlink_filename) {
        tmp_ret = unlink(symlink_filename);
        /* non-fatal failure */
        if (tmp_ret != EOK) {
            tmp_ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to remove symbolic link '%s': %d [%s]!\n",
                  symlink_filename, tmp_ret, sss_strerror(tmp_ret));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static int sbus_server_destructor(void *ctx)
{
    struct sbus_connection *server;
    errno_t ret;

    server = talloc_get_type(ctx, struct sbus_connection);
    dbus_server_disconnect(server->dbus.server);

    if (server->symlink) {
        ret = remove_socket_symlink(server->symlink);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not remove the server symlink\n");
        }
    }

    return 0;
}
