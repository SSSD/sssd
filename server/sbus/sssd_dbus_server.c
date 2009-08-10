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
#include "tevent.h"
#include "util/util.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

static int sbus_server_destructor(void *ctx);

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
    struct sbus_connection *server;
    struct sbus_connection *conn;
    int ret;

    DEBUG(5,("Entering.\n"));
    server = talloc_get_type(data, struct sbus_connection);
    if (!server) {
        return;
    }

    DEBUG(5,("Adding connection %p.\n", dbus_conn));
    ret = sbus_init_connection(server, server->ev,
                               dbus_conn, server->server_intf,
                               SBUS_CONN_TYPE_PRIVATE, &conn);
    if (ret != 0) {
        dbus_connection_close(dbus_conn);
        DEBUG(5,("Closing connection (failed setup)"));
        return;
    }

    dbus_connection_ref(dbus_conn);

    DEBUG(5,("Got a connection\n"));

    /*
     * Initialize connection-specific features
     * This may set a more detailed destructor, but
     * the default destructor will always be chained
     * to handle connection cleanup.
     * This function (or its callbacks) should also
     * set up connection-specific methods.
     */
    ret = server->srv_init_fn(conn, server->srv_init_data);
    if (ret != EOK) {
        DEBUG(1,("Initialization failed!\n"));
        dbus_connection_close(dbus_conn);
        talloc_zfree(conn);
    }
}

/*
 * dbus_new_server
 * Set up a D-BUS server, integrate with the event loop
 * for handling file descriptor and timed events
 */
int sbus_new_server(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    const char *address,
                    struct sbus_interface *intf,
                    struct sbus_connection **_server,
                    sbus_server_conn_init_fn init_fn, void *init_pvt_data)
{
    struct sbus_connection *server;
    DBusServer *dbus_server;
    DBusError dbus_error;
    dbus_bool_t dbret;
    char *tmp;

    *_server = NULL;

    /* Set up D-BUS server */
    dbus_error_init(&dbus_error);
    dbus_server = dbus_server_listen(address, &dbus_error);
    if (!dbus_server) {
        DEBUG(1,("dbus_server_listen failed! (name=%s, message=%s)\n",
                 dbus_error.name, dbus_error.message));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        return EIO;
    }

    tmp = dbus_server_get_address(dbus_server);
    DEBUG(3, ("D-BUS Server listening on %s\n", tmp));
    free(tmp);

    server = talloc_zero(mem_ctx, struct sbus_connection);
    if (!server) {
        return ENOMEM;
    }

    server->ev = ev;
    server->type = SBUS_SERVER;
    server->dbus.server = dbus_server;
    server->server_intf = intf;
    server->srv_init_fn = init_fn;
    server->srv_init_data = init_pvt_data;

    talloc_set_destructor((TALLOC_CTX *)server, sbus_server_destructor);

    /* Set up D-BUS new connection handler */
    dbus_server_set_new_connection_function(server->dbus.server,
                                            sbus_server_init_new_connection,
                                            server, NULL);

    /* Set up DBusWatch functions */
    dbret = dbus_server_set_watch_functions(server->dbus.server,
                                            sbus_add_watch,
                                            sbus_remove_watch,
                                            sbus_toggle_watch,
                                            server, NULL);
    if (!dbret) {
        DEBUG(4, ("Error setting up D-BUS server watch functions"));
        talloc_free(server);
        return EIO;
    }

    /* Set up DBusTimeout functions */
    dbret = dbus_server_set_timeout_functions(server->dbus.server,
                                              sbus_add_timeout,
                                              sbus_remove_timeout,
                                              sbus_toggle_timeout,
                                              server, NULL);
    if (!dbret) {
        DEBUG(4,("Error setting up D-BUS server timeout functions"));
        dbus_server_set_watch_functions(server->dbus.server,
                                        NULL, NULL, NULL, NULL, NULL);
        talloc_free(server);
        return EIO;
    }

    *_server = server;
    return EOK;
}

static int sbus_server_destructor(void *ctx)
{
    struct sbus_connection *server;

    server = talloc_get_type(ctx, struct sbus_connection);
    dbus_server_disconnect(server->dbus.server);
    return 0;
}
