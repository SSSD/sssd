/*
   SSSD

   Data Provider Runner

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
#include "providers/data_provider.h"
#include "util/service_helpers.h"

struct be_ctx {
    struct event_context *ev;
    struct confdb_ctx *cdb;
    struct ldb_context *ldb;
    struct service_sbus_ctx *ss_ctx;
    struct service_sbus_ctx *dp_ctx;
    const char *name;
    const char *domain;
    const char *identity;
    struct dp_be_mod_ops *ops;
    void *pvt_data;
};

typedef int (*be_init_fn_t)(TALLOC_CTX *, struct dp_be_mod_ops **, void **);

static int service_identity(DBusMessage *message, void *data, DBusMessage **r);
static int service_pong(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method mon_sbus_methods[] = {
    {SERVICE_METHOD_IDENTITY, service_identity},
    {SERVICE_METHOD_PING, service_pong},
    {NULL, NULL}
};

static int be_identity(DBusMessage *message, void *data, DBusMessage **r);
static int check_online(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method be_methods[] = {
    { DP_CLI_METHOD_IDENTITY, be_identity },
    { DP_CLI_METHOD_ONLINE, check_online },
    { NULL, NULL }
};

static int service_identity(DBusMessage *message, void *data, DBusMessage **r)
{
    dbus_uint16_t version = BE_VERSION;
    struct sbus_message_handler_ctx *smh_ctx;
    struct be_ctx *ctx;
    DBusMessage *reply;
    dbus_bool_t ret;
    void *user_data;

    if (!data) return EINVAL;
    smh_ctx = talloc_get_type(data, struct sbus_message_handler_ctx);
    if (!smh_ctx) return EINVAL;
    user_data = sbus_conn_get_private_data(smh_ctx->conn_ctx);
    if (!user_data) return EINVAL;
    ctx = talloc_get_type(user_data, struct be_ctx);
    if (!ctx) return EINVAL;

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_STRING, &ctx->identity,
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

static int be_identity(DBusMessage *message, void *data, DBusMessage **r)
{
    dbus_uint16_t version = BE_VERSION;
    dbus_uint16_t clitype = DP_CLI_BACKEND;
    struct sbus_message_handler_ctx *smh_ctx;
    struct be_ctx *ctx;
    DBusMessage *reply;
    dbus_bool_t ret;
    void *user_data;

    if (!data) return EINVAL;
    smh_ctx = talloc_get_type(data, struct sbus_message_handler_ctx);
    if (!smh_ctx) return EINVAL;
    user_data = sbus_conn_get_private_data(smh_ctx->conn_ctx);
    if (!user_data) return EINVAL;
    ctx = talloc_get_type(user_data, struct be_ctx);
    if (!ctx) return EINVAL;

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_UINT16, &clitype,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_STRING, &ctx->name,
                                   DBUS_TYPE_STRING, &ctx->domain,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    *r = reply;
    return EOK;
}

static int check_online(DBusMessage *message, void *data, DBusMessage **r)
{
    struct sbus_message_handler_ctx *smh_ctx;
    struct be_ctx *ctx;
    DBusMessage *reply;
    dbus_bool_t dbret;
    void *user_data;
    int online = 0;
    int ret;

    if (!data) return EINVAL;
    smh_ctx = talloc_get_type(data, struct sbus_message_handler_ctx);
    if (!smh_ctx) return EINVAL;
    user_data = sbus_conn_get_private_data(smh_ctx->conn_ctx);
    if (!user_data) return EINVAL;
    ctx = talloc_get_type(user_data, struct be_ctx);
    if (!ctx) return EINVAL;

    ret = ctx->ops->check_online(ctx->pvt_data, &online);
    if (ret != EOK) return ret;

    reply = dbus_message_new_method_return(message);
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &online,
                                     DBUS_TYPE_INVALID);
    if (!dbret) return EIO;

    *r = reply;
    return EOK;
}

/* mon_cli_init
 * sbus channel to the monitor daemon */
static int mon_cli_init(struct be_ctx *ctx)
{
    struct service_sbus_ctx *ss_ctx;

   /* Set up SBUS connection to the monitor */
    ss_ctx = sssd_service_sbus_init(ctx, ctx->ev, ctx->cdb,
                                    mon_sbus_methods, NULL);
    if (ss_ctx == NULL) {
        DEBUG(0, ("Could not initialize D-BUS.\n"));
        return ENOMEM;
    }

    ctx->ss_ctx = ss_ctx;

    /* attach be context to the connection */
    sbus_conn_set_private_data(ss_ctx->scon_ctx, ctx);

    return EOK;
}

static int be_dp_sbus_init(TALLOC_CTX *mem_ctx,
                           struct event_context *ev,
                           struct confdb_ctx *cdb,
                           const char *address,
                           struct sbus_method *methods,
                           struct service_sbus_ctx **srvs_ctx)
{
    struct service_sbus_ctx *ss_ctx;
    struct sbus_method_ctx *sm_ctx;
    TALLOC_CTX *tmp_ctx;
    char *default_monitor_address;
    char *sbus_address;
    DBusConnection *conn;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ss_ctx = talloc_zero(tmp_ctx, struct service_sbus_ctx);
    if (ss_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
    ss_ctx->ev = ev;

    default_monitor_address = talloc_asprintf(tmp_ctx, "unix:path=%s/%s",
                                              PIPE_PATH, SSSD_SERVICE_PIPE);
    if (default_monitor_address == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_get_string(cdb, tmp_ctx,
                            "config/services/monitor", "sbusAddress",
                            default_monitor_address, &sbus_address);
    if (ret != EOK) goto done;

    ret = sbus_new_connection(ss_ctx, ss_ctx->ev,
                              sbus_address, &ss_ctx->scon_ctx,
                              NULL);
    if (ret != EOK) goto done;

    conn = sbus_get_connection(ss_ctx->scon_ctx);

    /* set up handler for service methods */
    sm_ctx = talloc_zero(ss_ctx, struct sbus_method_ctx);
    if (sm_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sm_ctx->interface = talloc_strdup(sm_ctx, SERVICE_INTERFACE);
    sm_ctx->path = talloc_strdup(sm_ctx, SERVICE_PATH);
    if (!sm_ctx->interface || !sm_ctx->path) {
        ret = ENOMEM;
        goto done;
    }

    /* Set up required monitor methods */
    sm_ctx->methods = methods;

    sm_ctx->message_handler = sbus_message_handler;
    sbus_conn_add_method_ctx(ss_ctx->scon_ctx, sm_ctx);

    talloc_steal(mem_ctx, ss_ctx);
    *srvs_ctx = ss_ctx;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* be_cli_init
 * sbus channel to the data provider daemon */
static int be_cli_init(struct be_ctx *ctx)
{
    struct service_sbus_ctx *dp_ctx;
    char *default_dp_address;
    int ret;

    default_dp_address = talloc_asprintf(ctx, "unix:path=%s/%s",
                                         PIPE_PATH, DATA_PROVIDER_PIPE);
    if (!default_dp_address) return ENOMEM;

    ret = be_dp_sbus_init(ctx, ctx->ev, ctx->cdb,
                          default_dp_address, be_methods,
                          &dp_ctx);
    if (ret != EOK) {
        talloc_free(default_dp_address);
        return ret;
    }

    ctx->dp_ctx = dp_ctx;

    /* attach be context to the connection */
    sbus_conn_set_private_data(dp_ctx->scon_ctx, ctx);

    talloc_free(default_dp_address);
    return EOK;
}

static int be_db_init(struct be_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    char *ldb_file;
    char *default_db_file;
    int ret;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    default_db_file = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, DATA_PROVIDER_DB_FILE);
    if (!default_db_file) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    ret = confdb_get_string(ctx->cdb, tmp_ctx,
                            DATA_PROVIDER_DB_CONF_SEC, "ldbFile",
                            default_db_file, &ldb_file);
    if (ret != EOK) {
        talloc_free(tmp_ctx);
        return ret;
    }

    ctx->ldb = ldb_init(tmp_ctx, ctx->ev);
    if (!ctx->ldb) {
        talloc_free(tmp_ctx);
        return EIO;
    }

    ret = ldb_connect(ctx->ldb, ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(tmp_ctx);
        return EIO;
    }

    talloc_steal(ctx, ctx->ldb);

    talloc_free(tmp_ctx);
    return EOK;
}

static int load_backend(struct be_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    char *path;
    void *handle;
    char *mod_init_fn_name;
    be_init_fn_t mod_init_fn;
    int ret;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    path = talloc_asprintf(tmp_ctx, "%s/libsss_%s.so",
                           DATA_PROVIDER_PLUGINS_PATH, ctx->name);
    if (!path) {
        ret = ENOMEM;
        goto done;
    }

    handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        DEBUG(0, ("Unable to load %s module with path (%s), error: %s\n",
                  ctx->name, path, dlerror()));
        ret = ELIBACC;
        goto done;
    }

    mod_init_fn_name = talloc_asprintf(tmp_ctx, "sssm_%s_init", ctx->name);
    if (!mod_init_fn_name) {
        ret = ENOMEM;
        goto done;
    }

    mod_init_fn = (be_init_fn_t)dlsym(handle, mod_init_fn_name);
    if (!mod_init_fn) {
        DEBUG(0, ("Unable to load init fn from module %s, error: %s\n",
                  ctx->name, dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ret = mod_init_fn(ctx, &ctx->ops, &ctx->pvt_data);
    if (ret != EOK) {
        DEBUG(0, ("Error (%d) in module (%s) initialization!\n",
                  ret, ctx->name));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int be_process_init(TALLOC_CTX *mem_ctx,
                    const char *be_name,
                    const char *be_domain,
                    struct event_context *ev,
                    struct confdb_ctx *cdb)
{
    struct be_ctx *ctx;
    int ret;

    ctx = talloc_zero(mem_ctx, struct be_ctx);
    if (!ctx) {
        DEBUG(0, ("fatal error initializing be_ctx\n"));
        return ENOMEM;
    }
    ctx->ev = ev;
    ctx->cdb = cdb;
    ctx->name = talloc_strdup(ctx, be_name);
    ctx->domain = talloc_strdup(ctx, be_domain);
    ctx->identity = talloc_asprintf(ctx, "%%BE_%s", be_domain);
    if (!ctx->name || !ctx->domain || !ctx->identity) {
        DEBUG(0, ("Out of memory!?\n"));
        return ENOMEM;
    }

    ret = be_db_init(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error opening database\n"));
        return ret;
    }

    ret = mon_cli_init(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up monitor bus\n"));
        return ret;
    }

    ret = be_cli_init(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up server bus\n"));
        return ret;
    }

    ret = load_backend(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing data providers\n"));
        return ret;
    }

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *be_name;
    char *be_domain;
    char *srv_name;
    struct main_context *main_ctx;
    int ret;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
        SSSD_MAIN_OPTS
        {"provider", 0, POPT_ARG_STRING, &be_name, 0,
         "Information Provider", NULL },
        {"domain", 0, POPT_ARG_STRING, &be_domain, 0,
         "Domain of the information provider", NULL },
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
    srv_name = talloc_asprintf(NULL, "sssd[be[%s]]", be_name);
    if (!srv_name) return 2;

    ret = server_setup(srv_name, 0, &main_ctx);
    if (ret != EOK) return 2;

    ret = be_process_init(main_ctx,
                          be_name, be_domain,
                          main_ctx->event_ctx,
                          main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

