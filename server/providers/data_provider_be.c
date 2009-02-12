/*
   SSSD

   Data Provider Process

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
#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "util/btreemap.h"
#include "providers/dp_backend.h"
#include "providers/dp_sbus.h"
#include "monitor/monitor_sbus.h"
#include "monitor/monitor_interfaces.h"


typedef int (*be_init_fn_t)(TALLOC_CTX *, struct be_mod_ops **, void **);

static int service_identity(DBusMessage *message, void *data, DBusMessage **r);
static int service_pong(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method mon_sbus_methods[] = {
    { SERVICE_METHOD_IDENTITY, service_identity },
    { SERVICE_METHOD_PING, service_pong },
    { NULL, NULL }
};

static int be_identity(DBusMessage *message, void *data, DBusMessage **r);
static int be_check_online(DBusMessage *message, void *data, DBusMessage **r);
static int be_get_account_info(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method be_methods[] = {
    { DP_CLI_METHOD_IDENTITY, be_identity },
    { DP_CLI_METHOD_ONLINE, be_check_online },
    { DP_CLI_METHOD_GETACCTINFO, be_get_account_info },
    { NULL, NULL }
};

static int service_identity(DBusMessage *message, void *data, DBusMessage **r)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
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

    DEBUG(4,("Sending ID reply: (%s,%d)\n", ctx->identity, version));

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
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
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

    DEBUG(4,("Sending ID reply: (%d,%d,%s,%s)\n",
             clitype, version, ctx->name, ctx->domain));

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

static int be_check_online(DBusMessage *message, void *data, DBusMessage **r)
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

    ret = ctx->ops->check_online(ctx, &online);
    if (ret != EOK) return ret;

    reply = dbus_message_new_method_return(message);
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &online,
                                     DBUS_TYPE_INVALID);
    if (!dbret) return EIO;

    *r = reply;
    return EOK;
}

static int be_get_account_info(DBusMessage *message, void *data, DBusMessage **r)
{
    struct sbus_message_handler_ctx *smh_ctx;
    struct be_ctx *ctx;
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_bool_t dbret;
    void *user_data;
    uint32_t type;
    char *attrs, *filter;
    int attr_type, filter_type;
    char *filter_val;
    int ret;
    dbus_uint16_t err_maj = 0;
    dbus_uint32_t err_min = 0;
    const char *err_msg = "Success";

    *r = NULL;

    if (!data) return EINVAL;
    smh_ctx = talloc_get_type(data, struct sbus_message_handler_ctx);
    if (!smh_ctx) return EINVAL;
    user_data = sbus_conn_get_private_data(smh_ctx->conn_ctx);
    if (!user_data) return EINVAL;
    ctx = talloc_get_type(user_data, struct be_ctx);
    if (!ctx) return EINVAL;

    dbus_error_init(&dbus_error);

    ret = dbus_message_get_args(message, &dbus_error,
                                DBUS_TYPE_UINT32, &type,
                                DBUS_TYPE_STRING, &attrs,
                                DBUS_TYPE_STRING, &filter,
                                DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1,("Failed, to parse message!\n"));
        return EIO;
    }

    DEBUG(4, ("Got request for [%u][%s][%s]\n", type, attrs, filter));

    reply = dbus_message_new_method_return(message);

    if (attrs) {
        if (strcmp(attrs, "core") == 0) attr_type = BE_ATTR_CORE;
        else if (strcmp(attrs, "membership") == 0) attr_type = BE_ATTR_MEM;
        else if (strcmp(attrs, "all") == 0) attr_type = BE_ATTR_ALL;
        else {
            err_maj = DP_ERR_FATAL;
            err_min = EINVAL;
            err_msg = "Invalid Attrs Parameter";
            goto done;
        }
    } else {
        err_maj = DP_ERR_FATAL;
        err_min = EINVAL;
        err_msg = "Missing Attrs Parameter";
        goto done;
    }

    if (filter) {
        if (strncmp(filter, "name=", 5) == 0) {
            filter_type = BE_FILTER_NAME;
            filter_val = &filter[5];
        } else if (strncmp(filter, "idnumber=", 9) == 0) {
            filter_type = BE_FILTER_IDNUM;
            filter_val = &filter[9];
        } else {
            err_maj = DP_ERR_FATAL;
            err_min = EINVAL;
            err_msg = "Invalid Filter";
            goto done;
        }
    } else {
        err_maj = DP_ERR_FATAL;
        err_min = EINVAL;
        err_msg = "Missing Filter Parameter";
        goto done;
    }

    /* process request */
    ret = ctx->ops->get_account_info(ctx, type, attr_type,
                                     filter_type, filter_val);
    if (ret != EOK) {
        err_maj = DP_ERR_FATAL;
        err_min = ret;
        err_msg = "Backend error";
        goto done;
    }

done:
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &err_maj,
                                     DBUS_TYPE_UINT32, &err_min,
                                     DBUS_TYPE_STRING, &err_msg,
                                     DBUS_TYPE_INVALID);
    if (!dbret) return EIO;

    DEBUG(4, ("Request processed. Returned %d,%d,%s\n",
              err_maj, err_min, err_msg));

    *r = reply;
    return EOK;
}

/* mon_cli_init
 * sbus channel to the monitor daemon */
static int mon_cli_init(struct be_ctx *ctx)
{
    int ret;
    char *sbus_address;
    struct service_sbus_ctx *ss_ctx;
    struct sbus_method_ctx *sm_ctx;

    /* Set up SBUS connection to the monitor */
    ret = monitor_get_sbus_address(ctx, ctx->cdb, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate monitor address.\n"));
        return ret;
    }

    ret = monitor_init_sbus_methods(ctx, mon_sbus_methods, &sm_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize SBUS methods.\n"));
        return ret;
    }

    ret = sbus_client_init(ctx, ctx->ev,
                           sbus_address, sm_ctx,
                           ctx /* Private Data */,
                           NULL /* Destructor */,
                           &ss_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

    ctx->ss_ctx = ss_ctx;

    return EOK;
}

/* be_cli_init
 * sbus channel to the data provider daemon */
static int be_cli_init(struct be_ctx *ctx)
{
    int ret;
    char *sbus_address;
    struct sbus_method_ctx *sm_ctx;

    /* Set up SBUS connection to the monitor */
    ret = dp_get_sbus_address(ctx, ctx->cdb, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate monitor address.\n"));
        return ret;
    }

    ret = dp_init_sbus_methods(ctx, be_methods, &sm_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize SBUS methods.\n"));
        return ret;
    }

    ret = sbus_client_init(ctx, ctx->ev,
                           sbus_address, sm_ctx,
                           ctx /* Private Data */,
                           NULL /* Destructor */,
                           &ctx->dp_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

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
    ctx->conf_path = talloc_asprintf(ctx, "config/domains/%s", be_domain);
    if (!ctx->name || !ctx->domain || !ctx->identity || !ctx->conf_path) {
        DEBUG(0, ("Out of memory!?\n"));
        return ENOMEM;
    }

    ret = sysdb_init(ctx, ev, cdb, &ctx->sysdb);
    if (ret != EOK) {
        DEBUG(0, ("fatal error opening cache database\n"));
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

    DEBUG(1, ("Backend provider %s(%s) started!\n", be_name, be_domain));

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

