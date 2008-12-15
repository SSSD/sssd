/*
   SSSD

   Data Provider

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include "popt.h"
#include "ldb.h"
#include "ldb_errors.h"
#include "util/util.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus_interfaces.h"
#include "util/btreemap.h"
#include "data_provider.h"
#include "util/service_helpers.h"

struct dp_backend;
struct dp_frontend;

struct dp_ctx {
    struct event_context *ev;
    struct confdb_ctx *cdb;
    struct ldb_context *ldb;
    struct service_sbus_ctx *ss_ctx;
    struct sbus_srv_ctx *sbus_srv;
    struct dp_backend *be_list;
    struct dp_frontend *fe_list;
};

struct dp_client {
    struct dp_ctx *dpctx;
    struct sbus_conn_ctx *conn_ctx;
    const char *domain;
};

struct dp_backend {
    struct dp_backend *prev;
    struct dp_backend *next;
    char *name;
    char *domain;
    struct dp_client *dpcli;
};

struct dp_frontend {
    struct dp_frontend *prev;
    struct dp_frontend *next;
    char *name;
    uint16_t flags;
    struct dp_client *dpcli;
};

static int dp_backend_destructor(void *ctx);
static int dp_frontend_destructor(void *ctx);

static int service_identity(DBusMessage *message, void *data, DBusMessage **r);
static int service_pong(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method mon_sbus_methods[] = {
    {SERVICE_METHOD_IDENTITY, service_identity},
    {SERVICE_METHOD_PING, service_pong},
    {NULL, NULL}
};

struct sbus_method dp_sbus_methods[] = {
    {NULL, NULL}
};

static int service_identity(DBusMessage *message, void *data, DBusMessage **r)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    const char *name = DATA_PROVIDER_SERVICE_NAME;
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    *r = reply;
    return EOK;
}

static int service_pong(DBusMessage *message, void *data, DBusMessage **r)
{
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply, DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    *r = reply;
    return EOK;
}

static int dp_monitor_init(struct dp_ctx *dpctx)
{
    struct service_sbus_ctx *ss_ctx;

    /* Set up SBUS connection to the monitor */
    ss_ctx = sssd_service_sbus_init(dpctx, dpctx->ev, dpctx->cdb,
                                    mon_sbus_methods, NULL);
    if (ss_ctx == NULL) {
        DEBUG(0, ("Could not initialize D-BUS.\n"));
        return ENOMEM;
    }

    /* Set up DP-specific listeners */
    /* None currently used */

    dpctx->ss_ctx = ss_ctx;

    return EOK;
}

static int dp_db_init(struct dp_ctx *dpctx)
{
    TALLOC_CTX *ctx;
    char *ldb_file;
    char *default_db_file;
    int ret;

    ctx = talloc_new(dpctx);
    if(ctx == NULL) {
        return ENOMEM;
    }

    default_db_file = talloc_asprintf(ctx, "%s/%s", DB_PATH, DATA_PROVIDER_DB_FILE);
    if (default_db_file == NULL) {
        talloc_free(ctx);
        return ENOMEM;
    }

    ret = confdb_get_string(dpctx->cdb, ctx,
                            DATA_PROVIDER_DB_CONF_SEC, "ldbFile",
                            default_db_file, &ldb_file);
    if (ret != EOK) {
        talloc_free(ctx);
        return ret;
    }

    dpctx->ldb = ldb_init(ctx, dpctx->ev);
    if (!dpctx->ldb) {
        talloc_free(ctx);
        return EIO;
    }

    ret = ldb_connect(dpctx->ldb, ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(ctx);
        return EIO;
    }

    talloc_steal(dpctx,dpctx->ldb);
    talloc_free(ctx);

    return EOK;
}

static void identity_check(DBusPendingCall *pending, void *data);
static void online_check(DBusPendingCall *pending, void *data);

static int dbus_dp_init(struct sbus_conn_ctx *conn_ctx, void *data)
{
    struct dp_ctx *dpctx;
    struct dp_client *dpcli;
    DBusMessage *msg;
    DBusPendingCall *pending_reply;
    DBusConnection *conn;
    DBusError dbus_error;
    dbus_bool_t dbret;

    dpctx = talloc_get_type(data, struct dp_ctx);
    conn = sbus_get_connection(conn_ctx);
    dbus_error_init(&dbus_error);

    /* hang off this memory to the connection so that when the connection
     * is freed we can potentially call a destructor */

    dpcli = talloc(conn_ctx, struct dp_client);
    if (!dpcli) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_free(conn_ctx);
        return ENOMEM;
    }
    dpcli->dpctx = dpctx;
    dpcli->conn_ctx = conn_ctx;

    /* Attach the client context to the connection context, so that it is
     * always available when we need to manage the connection. */
    sbus_conn_set_private_data(conn_ctx, dpcli);

    /* identify the connecting client */
    msg = dbus_message_new_method_call(NULL,
                                       DP_CLI_PATH,
                                       DP_CLI_INTERFACE,
                                       DP_CLI_METHOD_IDENTITY);
    if (msg == NULL) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_free(conn_ctx);
        return ENOMEM;
    }
    dbret = dbus_connection_send_with_reply(conn, msg, &pending_reply,
                                            -1 /* TODO: set timeout */);
    if (!dbret) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         * We'll drop it using the default destructor.
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        talloc_free(conn_ctx);
        dbus_message_unref(msg);
        return EIO;
    }

    /* Set up the reply handler */
    dbus_pending_call_set_notify(pending_reply, identity_check, dpcli, NULL);
    dbus_message_unref(msg);

    return EOK;
}

static void identity_check(DBusPendingCall *pending, void *data)
{
    struct dp_backend *dpbe;
    struct dp_frontend *dpfe;
    struct dp_client *dpcli;
    DBusMessage *reply;
    DBusConnection *conn;
    DBusError dbus_error;
    dbus_uint16_t cli_ver;
    dbus_uint16_t cli_type;
    char *cli_name;
    char *cli_domain;
    dbus_bool_t ret;
    int type;

    dpcli = talloc_get_type(data, struct dp_client);
    conn = sbus_get_connection(dpcli->conn_ctx);
    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(0, ("Serious error. A reply callback was called but no reply was received and no timeout occurred\n"));

        /* Destroy this connection */
        sbus_disconnect(dpcli->conn_ctx);
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dbus_message_get_args(reply, &dbus_error,
                                    DBUS_TYPE_UINT16, &cli_type,
                                    DBUS_TYPE_UINT16, &cli_ver,
                                    DBUS_TYPE_STRING, &cli_name,
                                    DBUS_TYPE_STRING, &cli_domain,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1,("Failed, to parse message, killing connection\n"));
            sbus_disconnect(dpcli->conn_ctx);
            goto done;
        }

        switch (cli_type && DP_CLI_TYPE_MASK) {
        case DP_CLI_BACKEND:
            dpbe = talloc_zero(dpcli->dpctx, struct dp_backend);
            if (!dpbe) {
                DEBUG(0, ("Out of memory!\n"));
                sbus_disconnect(dpcli->conn_ctx);
                goto done;
            }

            dpbe->name = talloc_strdup(dpbe, cli_name);
            dpbe->domain = talloc_strdup(dpbe, cli_domain);
            if (!dpbe->name || !dpbe->domain) {
                DEBUG(0, ("Out of memory!\n"));
                sbus_disconnect(dpcli->conn_ctx);
                goto done;
            }

            dpbe->dpcli = dpcli;

            DLIST_ADD(dpcli->dpctx->be_list, dpbe);

            talloc_set_destructor((TALLOC_CTX *)dpbe, dp_backend_destructor);
            break;

        case DP_CLI_FRONTEND:
            dpfe = talloc_zero(dpcli->dpctx, struct dp_frontend);
            if (!dpfe) {
                DEBUG(0, ("Out of memory!\n"));
                sbus_disconnect(dpcli->conn_ctx);
                goto done;
            }

            dpfe->name = talloc_strdup(dpfe, cli_name);
            if (!dpfe->name) {
                DEBUG(0, ("Out of memory!\n"));
                sbus_disconnect(dpcli->conn_ctx);
                goto done;
            }

            dpfe->dpcli = dpcli;

            DLIST_ADD(dpcli->dpctx->fe_list, dpfe);

            talloc_set_destructor((TALLOC_CTX *)dpfe, dp_frontend_destructor);
            break;

        default:
            DEBUG(1, ("Unknown client type, killing connection\n"));
            sbus_disconnect(dpcli->conn_ctx);
            goto done;
        }

        /* Set up the destructor for this service */
        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(0,("getIdentity returned an error [%s], closing connection.\n",
                 dbus_message_get_error_name(reply)));
        /* Falling through to default intentionally*/
    default:
        /*
         * Timeout or other error occurred or something
         * unexpected happened.
         * It doesn't matter which, because either way we
         * know that this connection isn't trustworthy.
         * We'll destroy it now.
         */
        sbus_disconnect(dpcli->conn_ctx);
    }

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
}

static void online_check(DBusPendingCall *pending, void *data)
{
    return;
}

static int dp_backend_destructor(void *ctx)
{
    struct dp_backend *dpbe = talloc_get_type(ctx, struct dp_backend);
    if (dpbe->dpcli && dpbe->dpcli &&
        dpbe->dpcli->dpctx && dpbe->dpcli->dpctx->be_list) {
        DLIST_REMOVE(dpbe->dpcli->dpctx->be_list, dpbe);
    }
    return 0;
}

static int dp_frontend_destructor(void *ctx)
{
    struct dp_frontend *dpfe = talloc_get_type(ctx, struct dp_frontend);
    if (dpfe->dpcli && dpfe->dpcli &&
        dpfe->dpcli->dpctx && dpfe->dpcli->dpctx->fe_list) {
        DLIST_REMOVE(dpfe->dpcli->dpctx->fe_list, dpfe);
    }
    return 0;
}

/* monitor_dbus_init
 * Set up the monitor service as a D-BUS Server */
static int dp_srv_init(struct dp_ctx *dpctx)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_srv_ctx *sbus_srv;
    struct sbus_method_ctx *sd_ctx;
    char *dpbus_address;
    char *default_dp_address;
    int ret;

    tmp_ctx = talloc_new(dpctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    DEBUG(3, ("Initializing Data Provider D-BUS Server\n"));
    default_dp_address = talloc_asprintf(tmp_ctx, "unix:path=%s/%s",
                                         PIPE_PATH, DATA_PROVIDER_PIPE);
    if (default_dp_address == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_get_string(dpctx->cdb, tmp_ctx,
                            "config/services/dataprovider", "dpbusAddress",
                            default_dp_address, &dpbus_address);
    if (ret != EOK) goto done;

    sd_ctx = talloc_zero(tmp_ctx, struct sbus_method_ctx);
    if (!sd_ctx) {
        ret = ENOMEM;
        goto done;
    }

    /* Set up globally-available D-BUS methods */
    sd_ctx->interface = talloc_strdup(sd_ctx, DATA_PROVIDER_DBUS_INTERFACE);
    if (!sd_ctx->interface) {
        ret = ENOMEM;
        goto done;
    }
    sd_ctx->path = talloc_strdup(sd_ctx, DATA_PROVIDER_DBUS_PATH);
    if (!sd_ctx->path) {
        ret = ENOMEM;
        goto done;
    }
    sd_ctx->methods = dp_sbus_methods;
    sd_ctx->message_handler = sbus_message_handler;

    ret = sbus_new_server(dpctx->ev, sd_ctx,
                          &sbus_srv, dpbus_address,
                          dbus_dp_init, dpctx);
    if (ret != EOK) {
        goto done;
    }
    dpctx->sbus_srv = sbus_srv;
    talloc_steal(dpctx, sd_ctx);

done:
    talloc_free(tmp_ctx);
    return ret;
}

int dp_process_init(TALLOC_CTX *mem_ctx,
                    struct event_context *ev,
                    struct confdb_ctx *cdb)
{
    struct dp_ctx *dpctx;
    int ret;

    dpctx = talloc_zero(mem_ctx, struct dp_ctx);
    if (!dpctx) {
        DEBUG(0, ("fatal error initializing dp_ctx\n"));
        return ENOMEM;
    }
    dpctx->ev = ev;
    dpctx->cdb = cdb;

    ret = dp_db_init(dpctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error opening database\n"));
        return ret;
    }

    ret = dp_monitor_init(dpctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up monitor bus\n"));
        return ret;
    }

    ret = dp_srv_init(dpctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up server bus\n"));
        return ret;
    }

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
        SSSD_MAIN_OPTS
		{ NULL }
	};

	pc = poptGetContext(argv[0], argc, argv, long_options, 0);
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		default:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				  poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			return 1;
		}
	}

	poptFreeContext(pc);

    /* set up things like debug , signals, daemonization, etc... */
    ret = server_setup("sssd[dp]", 0, &main_ctx);
    if (ret != EOK) return 2;

    ret = dp_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

