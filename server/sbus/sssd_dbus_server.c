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

/* Types */
struct sbus_srv_ctx {
    DBusServer *dbus_server;
    /*
     * sd_ctx here describes the object path that will be
     * presented to all clients of this server. Additional
     * connection-specific paths can be specified by the
     * init_fn, which is called every time a new connection
     * is established.
     * There should only be one global object path (for
     * simplicity's sake)
     */
    struct tevent_context *ev;
    struct sbus_method_ctx *sd_ctx;
    sbus_server_conn_init_fn init_fn;
    void *init_pvt_data;
};

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
    struct sbus_srv_ctx *srv_ctx;
    struct sbus_connection *conn;
    struct sbus_method_ctx *iter;
    int ret;

    DEBUG(5,("Entering.\n"));
    srv_ctx = talloc_get_type(data, struct sbus_srv_ctx);
    if (srv_ctx == NULL) {
        return;
    }

    DEBUG(5,("Adding connection %lX.\n", conn));
    ret = sbus_add_connection(srv_ctx, srv_ctx->ev, dbus_conn,
                              &conn, SBUS_CONN_TYPE_PRIVATE);
    if (ret != 0) {
        dbus_connection_close(dbus_conn);
        DEBUG(5,("Closing connection (failed setup)"));
        return;
    }

    dbus_connection_ref(dbus_conn);

    DEBUG(5,("Got a connection\n"));

    /* Set up global methods */
    iter = srv_ctx->sd_ctx;
    while (iter != NULL) {
        sbus_conn_add_method_ctx(conn, iter);
        iter = iter->next;
    }

    /*
     * Initialize connection-specific features
     * This may set a more detailed destructor, but
     * the default destructor will always be chained
     * to handle connection cleanup.
     * This function (or its callbacks) should also
     * set up connection-specific methods.
     */
    ret = srv_ctx->init_fn(conn, srv_ctx->init_pvt_data);
    if (ret != EOK) {
        DEBUG(1,("Initialization failed!\n"));
    }
}

/*
 * dbus_new_server
 * Set up a D-BUS server, integrate with the event loop
 * for handling file descriptor and timed events
 */
int sbus_new_server(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev, struct sbus_method_ctx *ctx,
                    struct sbus_srv_ctx **_srv_ctx, const char *address,
                    sbus_server_conn_init_fn init_fn, void *init_pvt_data)
{
    struct sbus_generic_dbus_ctx *gen_ctx;
    struct sbus_srv_ctx *srv_ctx;
    DBusServer *dbus_server;
    DBusError dbus_error;
    dbus_bool_t dbret;
    char *tmp;

    *_srv_ctx = NULL;

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

    srv_ctx = talloc_zero(mem_ctx, struct sbus_srv_ctx);
    if (!srv_ctx) {
        return ENOMEM;
    }

    srv_ctx->ev = ev;
    srv_ctx->dbus_server = dbus_server;
    srv_ctx->sd_ctx = ctx;
    srv_ctx->init_fn = init_fn;
    srv_ctx->init_pvt_data = init_pvt_data;

    gen_ctx = talloc_zero(srv_ctx, struct sbus_generic_dbus_ctx);
    if (!gen_ctx) {
        talloc_free(srv_ctx);
        return ENOMEM;
    }
    gen_ctx->ev = ev;
    gen_ctx->type = SBUS_SERVER;
    gen_ctx->dbus.server = dbus_server;

    talloc_set_destructor((TALLOC_CTX *)srv_ctx, sbus_server_destructor);

    /* Set up D-BUS new connection handler */
    dbus_server_set_new_connection_function(srv_ctx->dbus_server,
                                            sbus_server_init_new_connection,
                                            srv_ctx, NULL);

    /* Set up DBusWatch functions */
    dbret = dbus_server_set_watch_functions(srv_ctx->dbus_server,
                                            sbus_add_watch,
                                            sbus_remove_watch,
                                            sbus_toggle_watch,
                                            gen_ctx, NULL);
    if (!dbret) {
        DEBUG(4, ("Error setting up D-BUS server watch functions"));
        talloc_free(srv_ctx);
        return EIO;
    }

    /* Set up DBusTimeout functions */
    dbret = dbus_server_set_timeout_functions(srv_ctx->dbus_server,
                                              sbus_add_timeout,
                                              sbus_remove_timeout,
                                              sbus_toggle_timeout,
                                              gen_ctx, NULL);
    if (!dbret) {
        DEBUG(4,("Error setting up D-BUS server timeout functions"));
        dbus_server_set_watch_functions(srv_ctx->dbus_server,
                                        NULL, NULL, NULL, NULL, NULL);
        talloc_free(srv_ctx);
        return EIO;
    }

    *_srv_ctx = srv_ctx;
    return EOK;
}

static int sbus_server_destructor(void *ctx)
{
    struct sbus_srv_ctx *srv_ctx = talloc_get_type(ctx, struct sbus_srv_ctx);
    dbus_server_disconnect(srv_ctx->dbus_server);
    return 0;
}
