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
#include "ldb.h"
#include "ldb_errors.h"
#include "util/util.h"
#include "service.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus_interfaces.h"
#include "util/btreemap.h"
#include "data_provider.h"

static int provide_identity(DBusMessage *message, void *data, DBusMessage **r);
static int reply_ping(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method mon_sbus_methods[] = {
    {SERVICE_METHOD_IDENTITY, provide_identity},
    {SERVICE_METHOD_PING, reply_ping},
    {NULL, NULL}
};

static int provide_identity(DBusMessage *message, void *data, DBusMessage **r)
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

static int reply_ping(DBusMessage *message, void *data, DBusMessage **r)
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
    struct sbus_method_ctx *cli_sm_ctx;
    struct sbus_method_ctx *srv_sm_ctx;
    struct dp_sbus_ctx *sbus_ctx;
    DBusConnection *dbus_conn;
    char *sbus_address;
    int ret;

    ret = confdb_get_string(dpctx->cdb, dpctx,
                            "config/services/monitor", "sbusAddress",
                            DEFAULT_SBUS_ADDRESS, &sbus_address);
    if (ret != EOK) {
        return ret;
    }

    sbus_ctx = talloc(dpctx, struct dp_sbus_ctx);
    if (!sbus_ctx) {
        return ENOMEM;
    }
    sbus_ctx->ev = dpctx->ev;

    ret = sbus_new_connection(sbus_ctx, sbus_ctx->ev,
                              sbus_address,
                              &sbus_ctx->scon_ctx, NULL);
    if (ret != EOK) {
        talloc_free(sbus_ctx);
        return ret;
    }
    dbus_conn = sbus_get_connection(sbus_ctx->scon_ctx);
    dbus_connection_set_exit_on_disconnect(dbus_conn, TRUE);

    /* set up handler for service methods */
    srv_sm_ctx = talloc_zero(sbus_ctx, struct sbus_method_ctx);
    if (!srv_sm_ctx) {
        talloc_free(sbus_ctx);
        return ENOMEM;
    }
    srv_sm_ctx->interface = talloc_strdup(srv_sm_ctx, SERVICE_INTERFACE);
    srv_sm_ctx->path = talloc_strdup(srv_sm_ctx, SERVICE_PATH);
    if (!srv_sm_ctx->interface || !srv_sm_ctx->path) {
        talloc_free(sbus_ctx);
        return ENOMEM;
    }
    srv_sm_ctx->methods = mon_sbus_methods;
    sbus_conn_add_method_ctx(sbus_ctx->scon_ctx, srv_sm_ctx);

    /* set up client stuff */
    cli_sm_ctx = talloc(sbus_ctx, struct sbus_method_ctx);
    if (!cli_sm_ctx) {
        talloc_free(sbus_ctx);
        return ENOMEM;
    }
    cli_sm_ctx->interface = talloc_strdup(cli_sm_ctx, MONITOR_DBUS_INTERFACE);
    cli_sm_ctx->path = talloc_strdup(cli_sm_ctx, MONITOR_DBUS_PATH);
    if (!cli_sm_ctx->interface || !cli_sm_ctx->path) {
        talloc_free(sbus_ctx);
        return ENOMEM;
    }
    sbus_ctx->sm_ctx = cli_sm_ctx;

    dpctx->sbus_ctx = sbus_ctx;

    return EOK;
}

static int dp_db_init(struct dp_ctx *dpctx)
{
    char *ldb_file;
    int ret;

    ret = confdb_get_string(dpctx->cdb, dpctx,
                            DATA_PROVIDER_DB_CONF_SEC, "ldbFile",
                            DATA_PROVIDER_DEF_DB_FILE, &ldb_file);
    if (ret != EOK) {
        return ret;
    }

    dpctx->ldb = ldb_init(dpctx, dpctx->ev);
    if (!dpctx->ldb) {
        return EIO;
    }

    ret = ldb_connect(dpctx->ldb, ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(dpctx->ldb);
        return EIO;
    }

    return EOK;
}

static int check_online(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method dp_sbus_methods[] = {
    { DP_METHOD_CHECK_ONLINE, check_online },
    { NULL, NULL }
};

static int dbus_dp_init(struct sbus_conn_ctx *conn_ctx, void *data)
{
    struct dp_ctx *dpctx;
    struct dp_client *dpcli;
    DBusConnection *conn;
    DBusError dbus_error;

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
    dpcli->conn = conn;

    /* Attach the client context to the connection context, so that it is
     * always available when we need to manage the connection. */
    sbus_conn_set_private_data(conn_ctx, dpcli);

    return EOK;
}

/* monitor_dbus_init
 * Set up the monitor service as a D-BUS Server */
static int dp_srv_init(struct dp_ctx *dpctx)
{
    struct sbus_method_ctx *sd_ctx;
    char *dpbus_address;
    int ret;

    DEBUG(3, ("Initializing Data Provider D-BUS Server\n"));

    ret = confdb_get_string(dpctx->cdb, dpctx,
                            "config/services/dataprovider", "dpbusAddress",
                            DATA_PROVIDER_ADDRESS, &dpbus_address);
    if (ret != EOK) {
        return ret;
    }

    sd_ctx = talloc_zero(dpctx, struct sbus_method_ctx);
    if (!sd_ctx) {
        talloc_free(dpbus_address);
        return ENOMEM;
    }

    /* Set up globally-available D-BUS methods */
    sd_ctx->interface = talloc_strdup(sd_ctx, DATA_PROVIDER_DBUS_INTERFACE);
    if (!sd_ctx->interface) {
        talloc_free(dpbus_address);
        talloc_free(sd_ctx);
        return ENOMEM;
    }
    sd_ctx->path = talloc_strdup(sd_ctx, DATA_PROVIDER_DBUS_PATH);
    if (!sd_ctx->path) {
        talloc_free(dpbus_address);
        talloc_free(sd_ctx);
        return ENOMEM;
    }
    sd_ctx->methods = dp_sbus_methods;
    sd_ctx->message_handler = sbus_message_handler;

    ret = sbus_new_server(dpctx->ev, sd_ctx, dpbus_address,
                          dbus_dp_init, dpctx);

    return ret;
}

static int check_online(DBusMessage *message, void *data, DBusMessage **r)
{
    return EOK;
}

/* find list of backends */
/* find library implementing them */
/* dload() said library and set up a structure to hold pointers */

static int init_data_providers(struct dp_ctx *dpctx)
{
    TALLOC_CTX *tmp_ctx;
    struct dp_module *module;
    char **doms;
    char *sec;
    char *mod_name;
    char *path;
    void *handle;
    char *mod_init_fn_name;
    sssm_init_fn_t mod_init_fn;
    int num_mods;
    int i, ret;

    tmp_ctx = talloc_new(dpctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = confdb_get_domains(dpctx->cdb, tmp_ctx, &doms);
    if (ret != EOK) {
        DEBUG(2, ("No domains configured!\n"));
        return ret;
    }

    num_mods = 0;
    for (i = 0; doms[i]; i++) {
        sec = talloc_asprintf(tmp_ctx, "config/domains/%s", doms[i]);
        if (!sec) {
            ret = ENOMEM;
            goto done;
        }
        ret = confdb_get_string(dpctx->cdb, tmp_ctx, sec,
                                "provider", NULL, &mod_name);
        if (ret != EOK) {
            goto done;
        }

        /* the LOCAL domain does not have a backend at the moment */
        if (strcasecmp(mod_name, "LOCAL") == 0) {
            continue;
        }

        path = talloc_asprintf(tmp_ctx, "%s/libsss_%s.so",
                               DATA_PROVIDER_PLUGINS_PATH, mod_name);

        handle = dlopen(path, RTLD_NOW);
        if (!handle) {
            DEBUG(0, ("Unable to load %s module with path (%s), error: %s\n",
                      mod_name, path, dlerror()));
            ret = ELIBACC;
            goto done;
        }

        mod_init_fn_name = talloc_asprintf(tmp_ctx, "sssm_%s_init", mod_name);
        if (!mod_init_fn_name) {
            ret = ENOMEM;
            goto done;
        }

        mod_init_fn = (sssm_init_fn_t)dlsym(handle, mod_init_fn_name);
        if (!mod_init_fn) {
            DEBUG(0, ("Unable to load init fn from module %s, error: %s\n",
                      mod_name, dlerror()));
            ret = ELIBBAD;
            goto done;
        }

        dpctx->modules = talloc_array(tmp_ctx, struct dp_module *, num_mods +1);
        if (!dpctx->modules) {
            ret = ENOMEM;
            goto done;
        }
        module = talloc(dpctx->modules, struct dp_module);
        if (!module) {
            ret = ENOMEM;
            goto done;
        }
        dpctx->modules[num_mods] = module;

        module->domain = talloc_strdup(dpctx->modules, doms[i]);
        module->name = talloc_steal(dpctx->modules, mod_name);

        ret = mod_init_fn(module, &module->ops, &module->pvt_data);
        if (ret != EOK) {
            DEBUG(0, ("Error (%d) in module (%s) initialization!\n",
                      ret, mod_name));
            continue;
        }

        num_mods++;
    }

    ret = EOK;

done:
    talloc_free(doms);
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

    ret = init_data_providers(dpctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing data providers\n"));
        return ret;
    }

    return EOK;
}
