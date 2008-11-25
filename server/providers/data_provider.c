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
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus_interfaces.h"
#include "util/btreemap.h"
#include "data_provider.h"
#include "util/service_helpers.h"

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
    struct service_sbus_ctx *ss_ctx;

    /* Set up SBUS connection to the monitor */
    ss_ctx = sssd_service_sbus_init(dpctx, dpctx->ev, dpctx->cdb,
                                    provide_identity,
                                    reply_ping);
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
    TALLOC_CTX *tmp_ctx;
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

    ret = sbus_new_server(dpctx->ev, sd_ctx, dpbus_address,
                          dbus_dp_init, dpctx);
    if (ret != EOK) {
        goto done;
    }
    talloc_steal(dpctx, sd_ctx);

done:
    talloc_free(tmp_ctx);
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
    struct dp_mod_ctx *module;
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

        dpctx->modules = talloc_array(tmp_ctx, struct dp_mod_ctx *, num_mods +1);
        if (!dpctx->modules) {
            ret = ENOMEM;
            goto done;
        }
        module = talloc(dpctx->modules, struct dp_mod_ctx);
        if (!module) {
            ret = ENOMEM;
            goto done;
        }
        dpctx->modules[num_mods] = module;

        module->dp_ctx = dpctx;
        module->domain = talloc_strdup(dpctx->modules, doms[i]);
        module->name = talloc_steal(dpctx->modules, mod_name);

        ret = mod_init_fn(module);
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
