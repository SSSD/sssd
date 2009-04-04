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
#include <dlfcn.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

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
#include "../sss_client/sss_cli.h"

#define BE_CONF_ENTRY "config/domains/%s"

static int service_identity(DBusMessage *message, struct sbus_conn_ctx *sconn);
static int service_pong(DBusMessage *message, struct sbus_conn_ctx *sconn);

struct sbus_method mon_sbus_methods[] = {
    { SERVICE_METHOD_IDENTITY, service_identity },
    { SERVICE_METHOD_PING, service_pong },
    { NULL, NULL }
};

static int be_identity(DBusMessage *message, struct sbus_conn_ctx *sconn);
static int be_check_online(DBusMessage *message, struct sbus_conn_ctx *sconn);
static int be_get_account_info(DBusMessage *message, struct sbus_conn_ctx *sconn);
static int be_pam_handler(DBusMessage *message, struct sbus_conn_ctx *sconn);

struct sbus_method be_methods[] = {
    { DP_CLI_METHOD_IDENTITY, be_identity },
    { DP_CLI_METHOD_ONLINE, be_check_online },
    { DP_CLI_METHOD_GETACCTINFO, be_get_account_info },
    { DP_CLI_METHOD_PAMHANDLER, be_pam_handler },
    { NULL, NULL }
};

static int service_identity(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    struct be_ctx *ctx;
    DBusMessage *reply;
    dbus_bool_t ret;
    void *user_data;

    user_data = sbus_conn_get_private_data(sconn);
    if (!user_data) return EINVAL;
    ctx = talloc_get_type(user_data, struct be_ctx);
    if (!ctx) return EINVAL;

    DEBUG(4,("Sending ID reply: (%s,%d)\n", ctx->identity, version));

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_STRING, &ctx->identity,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static int service_pong(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply, DBUS_TYPE_INVALID);
    if (!ret) {
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static int be_identity(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    dbus_uint16_t clitype = DP_CLI_BACKEND;
    struct be_ctx *ctx;
    DBusMessage *reply;
    dbus_bool_t ret;
    void *user_data;

    user_data = sbus_conn_get_private_data(sconn);
    if (!user_data) return EINVAL;
    ctx = talloc_get_type(user_data, struct be_ctx);
    if (!ctx) return EINVAL;

    DEBUG(4,("Sending ID reply: (%d,%d,%s,%s)\n",
             clitype, version, ctx->name, ctx->domain));

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_UINT16, &clitype,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_STRING, &ctx->name,
                                   DBUS_TYPE_STRING, &ctx->domain,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}

struct be_async_req {
    be_req_fn_t fn;
    struct be_req *req;
};

static void be_async_req_handler(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv, void *pvt)
{
    struct be_async_req *async_req;

    async_req = talloc_get_type(pvt, struct be_async_req);

    async_req->fn(async_req->req);
}

static int be_file_request(struct be_ctx *ctx,
                           be_req_fn_t fn,
                           struct be_req *req)
{
    struct be_async_req *areq;
    struct tevent_timer *te;
    struct timeval tv;

    if (!fn || !req) return EINVAL;

    areq = talloc(req, struct be_async_req);
    if (!areq) {
        return ENOMEM;
    }
    areq->fn = fn;
    areq->req = req;

    /* fire immediately */
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    te = tevent_add_timer(ctx->ev, req, tv, be_async_req_handler, areq);
    if (te == NULL) {
        return EIO;
    }

    return EOK;
}

static void online_chk_callback(struct be_req *req, int status,
                                const char *errstr)
{
    struct be_online_req *oreq;
    DBusMessage *reply;
    DBusConnection *conn;
    dbus_bool_t dbret;
    dbus_uint16_t online;
    dbus_uint16_t err_maj = 0;
    dbus_uint32_t err_min = 0;
    const char *err_msg = "Success";

    oreq = talloc_get_type(req->req_data, struct be_online_req);

    if (status != EOK) {
        online = MOD_OFFLINE;
        err_maj = DP_ERR_FATAL;
        err_min = status;
        err_msg = errstr;
    }

    online = oreq->online;
    reply = (DBusMessage *)req->pvt;

    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &online,
                                     DBUS_TYPE_UINT16, &err_maj,
                                     DBUS_TYPE_UINT32, &err_min,
                                     DBUS_TYPE_STRING, &err_msg,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(1, ("Failed to generate dbus reply\n"));
        return;
    }

    conn = sbus_get_connection(req->be_ctx->dp_ctx->scon_ctx);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);

    DEBUG(4, ("Request processed. Returned %d,%d,%s\n",
              err_maj, err_min, err_msg));

    /* finally free the request */
    talloc_free(req);
}


static int be_check_online(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    struct be_online_req *req;
    struct be_req *be_req;
    struct be_ctx *ctx;
    DBusMessage *reply;
    dbus_bool_t dbret;
    void *user_data;
    int ret;
    dbus_uint16_t online;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    const char *err_msg;

    user_data = sbus_conn_get_private_data(sconn);
    if (!user_data) return EINVAL;
    ctx = talloc_get_type(user_data, struct be_ctx);
    if (!ctx) return EINVAL;

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    /* process request */
    be_req = talloc(ctx, struct be_req);
    if (!be_req) {
        online = MOD_OFFLINE;
        err_maj = DP_ERR_FATAL;
        err_min = ENOMEM;
        err_msg = "Out of memory";
        goto done;
    }
    be_req->be_ctx = ctx;
    be_req->fn = online_chk_callback;
    be_req->pvt = reply;

    req = talloc(be_req, struct be_online_req);
    if (!req) {
        online = MOD_OFFLINE;
        err_maj = DP_ERR_FATAL;
        err_min = ENOMEM;
        err_msg = "Out of memory";
        goto done;
    }
    req->online = 0;

    be_req->req_data = req;

    ret = be_file_request(ctx, ctx->id_ops->check_online, be_req);
    if (ret != EOK) {
        online = MOD_OFFLINE;
        err_maj = DP_ERR_FATAL;
        err_min = ret;
        err_msg = "Failed to file request";
        goto done;
    }

    return EOK;

done:
    if (be_req) {
        talloc_free(be_req);
    }

    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &online,
                                     DBUS_TYPE_UINT16, &err_maj,
                                     DBUS_TYPE_UINT32, &err_min,
                                     DBUS_TYPE_STRING, &err_msg,
                                     DBUS_TYPE_INVALID);
    if (!dbret) return EIO;

    /* send reply back */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}


static void acctinfo_callback(struct be_req *req, int status,
                              const char *errstr)
{
    DBusMessage *reply;
    DBusConnection *conn;
    dbus_bool_t dbret;
    dbus_uint16_t err_maj = 0;
    dbus_uint32_t err_min = 0;
    const char *err_msg = "Success";

    if (status != EOK) {
        err_maj = DP_ERR_FATAL;
        err_min = status;
        err_msg = errstr;
    }

    reply = (DBusMessage *)req->pvt;

    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &err_maj,
                                     DBUS_TYPE_UINT32, &err_min,
                                     DBUS_TYPE_STRING, &err_msg,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(1, ("Failed to generate dbus reply\n"));
        return;
    }

    conn = sbus_get_connection(req->be_ctx->dp_ctx->scon_ctx);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);

    DEBUG(4, ("Request processed. Returned %d,%d,%s\n",
              err_maj, err_min, err_msg));

    /* finally free the request */
    talloc_free(req);
}

static int be_get_account_info(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    struct be_acct_req *req;
    struct be_req *be_req;
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
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    const char *err_msg;

    be_req = NULL;

    user_data = sbus_conn_get_private_data(sconn);
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
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        return EIO;
    }

    DEBUG(4, ("Got request for [%u][%s][%s]\n", type, attrs, filter));

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

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
    be_req = talloc(ctx, struct be_req);
    if (!be_req) {
        err_maj = DP_ERR_FATAL;
        err_min = ENOMEM;
        err_msg = "Out of memory";
        goto done;
    }
    be_req->be_ctx = ctx;
    be_req->fn = acctinfo_callback;
    be_req->pvt = reply;

    req = talloc(be_req, struct be_acct_req);
    if (!req) {
        err_maj = DP_ERR_FATAL;
        err_min = ENOMEM;
        err_msg = "Out of memory";
        goto done;
    }
    req->entry_type = type;
    req->attr_type = attr_type;
    req->filter_type = filter_type;
    req->filter_value = talloc_strdup(req, filter_val);

    be_req->req_data = req;

    ret = be_file_request(ctx, ctx->id_ops->get_account_info, be_req);
    if (ret != EOK) {
        err_maj = DP_ERR_FATAL;
        err_min = ret;
        err_msg = "Failed to file request";
        goto done;
    }

    return EOK;

done:
    if (be_req) {
        talloc_free(be_req);
    }

    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &err_maj,
                                     DBUS_TYPE_UINT32, &err_min,
                                     DBUS_TYPE_STRING, &err_msg,
                                     DBUS_TYPE_INVALID);
    if (!dbret) return EIO;

    DEBUG(4, ("Request processed. Returned %d,%d,%s\n",
              err_maj, err_min, err_msg));

    /* send reply back */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static void be_pam_handler_callback(struct be_req *req, int status,
                                const char *errstr) {
    struct pam_data *pd;
    DBusMessage *reply;
    DBusConnection *conn;
    dbus_bool_t dbret;

    pd = talloc_get_type(req->req_data, struct pam_data);

    DEBUG(4, ("Sending result [%d][%s]\n", pd->pam_status, pd->domain));
    reply = (DBusMessage *)req->pvt;
    dbret = dp_pack_pam_response(reply, pd);
    if (!dbret) {
        DEBUG(1, ("Failed to generate dbus reply\n"));
        return;
    }

    conn = sbus_get_connection(req->be_ctx->dp_ctx->scon_ctx);
    dbus_connection_send(conn, reply, NULL);
    dbus_message_unref(reply);

    DEBUG(4, ("Sent result [%d][%s]\n", pd->pam_status, pd->domain));

    talloc_free(req);
}

static int be_pam_handler(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusError dbus_error;
    DBusMessage *reply;
    struct be_ctx *ctx;
    struct be_req *be_req;
    dbus_bool_t ret;
    void *user_data;
    struct pam_data *pd;
    uint32_t pam_status=99;

    user_data = sbus_conn_get_private_data(sconn);
    if (!user_data) return EINVAL;
    ctx = talloc_get_type(user_data, struct be_ctx);
    if (!ctx) return EINVAL;

    pd = talloc_zero(ctx, struct pam_data);
    if (!pd) return ENOMEM;

    dbus_error_init(&dbus_error);

    reply = dbus_message_new_method_return(message);
    if (!reply) {
        DEBUG(1, ("dbus_message_new_method_return failed, cannot send reply.\n"));
        talloc_free(pd);
        return ENOMEM;
    }

    ret = dp_unpack_pam_request(message, pd, &dbus_error);
    if (!ret) {
        DEBUG(1,("Failed, to parse message!\n"));
        talloc_free(pd);
        return EIO;
    }

    DEBUG(4, ("Got request with the following data\n"));
    DEBUG_PAM_DATA(4, pd);

    be_req = talloc(ctx, struct be_req);
    if (!be_req) {
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    be_req->be_ctx = ctx;
    be_req->fn = be_pam_handler_callback;
    be_req->pvt = reply;
    be_req->req_data = pd;

    ret = be_file_request(ctx, ctx->auth_ops->pam_handler, be_req);
    if (ret != EOK) {
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    return EOK;

done:
    if (be_req) {
        talloc_free(be_req);
    }

    DEBUG(4, ("Sending result [%d][%s]\n", pam_status, ctx->domain));
    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_UINT32, &pam_status,
                                   DBUS_TYPE_STRING, &ctx->domain,
                                   DBUS_TYPE_INVALID);
    if (!ret) return EIO;

    /* send reply back immediately */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    talloc_free(pd);
    return EOK;
}

/* mon_cli_init
 * sbus channel to the monitor daemon */
static int mon_cli_init(struct be_ctx *ctx)
{
    int ret;
    char *sbus_address;
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
                           &ctx->ss_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

    return EOK;
}

static void be_cli_reconnect_init(struct sbus_conn_ctx *sconn, int status, void *pvt);

/* be_cli_init
 * sbus channel to the data provider daemon */
static int be_cli_init(struct be_ctx *ctx)
{
    int ret, max_retries;
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

    /* Enable automatic reconnection to the Data Provider */
    ret = confdb_get_int(ctx->cdb, ctx, ctx->conf_path,
                         "retries", 3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        return ret;
    }

    sbus_reconnect_init(ctx->dp_ctx->scon_ctx, max_retries,
                        be_cli_reconnect_init, ctx);

    return EOK;
}

static int be_finalize(struct be_ctx *ctx);
static void be_shutdown(struct be_req *req, int status, const char *errstr);

static void be_cli_reconnect_init(struct sbus_conn_ctx *sconn, int status, void *pvt)
{
    int ret;
    struct be_ctx *be_ctx = talloc_get_type(pvt, struct be_ctx);

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        /* Add the methods back to the new connection */
        ret = sbus_conn_add_method_ctx(be_ctx->dp_ctx->scon_ctx,
                                       be_ctx->dp_ctx->sm_ctx);
        if (ret != EOK) {
            DEBUG(0, ("Could not re-add methods on reconnection.\n"));
            ret = be_finalize(be_ctx);
            if (ret != EOK) {
                DEBUG(0, ("Finalizing back-end failed with error [%d] [%s]", ret, strerror(ret)));
                be_shutdown(NULL, ret, NULL);
            }
            return;
        }

        DEBUG(1, ("Reconnected to the Data Provider.\n"));
        return;
    }

    /* Handle failure */
    DEBUG(0, ("Could not reconnect to data provider.\n"));
    /* Kill the backend and let the monitor restart it */
    ret = be_finalize(be_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Finalizing back-end failed with error [%d] [%s]\n",
                  ret, strerror(ret)));
        be_shutdown(NULL, ret, NULL);
    }
}

static void be_shutdown(struct be_req *req, int status, const char *errstr)
{
    /* Nothing left to do but exit() */
    if (status == EOK)
        exit(0);

    /* Something went wrong in finalize */
    DEBUG(0, ("Finalizing auth module failed with error [%d] [%s]\n",
              status, errstr ? : strerror(status)));

    exit(1);
}

static void be_id_shutdown(struct be_req *req, int status, const char *errstr)
{
    struct be_req *shutdown_req;
    struct be_ctx *ctx;
    int ret;

    if (status != EOK) {
        /* Something went wrong in finalize */
        DEBUG(0, ("Finalizing auth module failed with error [%d] [%s]\n",
                  status, errstr ? : strerror(status)));
    }

    ctx = req->be_ctx;

    /* Now shutdown the id module too */
    shutdown_req = talloc_zero(ctx, struct be_req);
    if (!shutdown_req) {
        ret = ENOMEM;
        goto fail;
    }

    shutdown_req->be_ctx = ctx;
    shutdown_req->fn = be_id_shutdown;

    shutdown_req->pvt = ctx->pvt_id_data;

    ret = be_file_request(ctx, ctx->id_ops->finalize, shutdown_req);
    if (ret == EOK)
        return;

fail:
    /* If we got here, we couldn't shut down cleanly. */
    be_shutdown(NULL, ret, NULL);
}

static int be_finalize(struct be_ctx *ctx)
{
    struct be_req *shutdown_req;
    int ret;

    shutdown_req = talloc_zero(ctx, struct be_req);
    if (!shutdown_req) {
        ret = ENOMEM;
        goto fail;
    }

    shutdown_req->be_ctx = ctx;
    shutdown_req->fn = be_id_shutdown;
    shutdown_req->pvt = ctx->pvt_auth_data;

    ret = be_file_request(ctx, ctx->auth_ops->finalize, shutdown_req);
    if (ret == EOK) return EOK;

fail:
    /* If we got here, we couldn't shut down cleanly. */
    DEBUG(0, ("ERROR: could not shut down cleanly.\n"));
    return ret;
}

static int load_id_backend(struct be_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    char *path;
    void *handle;
    char *mod_init_fn_name;
    be_id_init_fn_t mod_init_fn;
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

    mod_init_fn = (be_id_init_fn_t)dlsym(handle, mod_init_fn_name);
    if (!mod_init_fn) {
        DEBUG(0, ("Unable to load init fn from module %s, error: %s\n",
                  ctx->name, dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ret = mod_init_fn(ctx, &ctx->id_ops, &ctx->pvt_id_data);
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

static int load_auth_backend(struct be_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    char *mod_name;
    char *path;
    void *handle;
    char *mod_init_fn_name;
    be_auth_init_fn_t mod_init_fn;
    int ret;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = confdb_get_string(ctx->cdb, tmp_ctx, ctx->conf_path,
                            "auth-module", NULL, &mod_name);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }
    if (!mod_name) {
        ret = ENOENT;
        goto done;
    }

    path = talloc_asprintf(tmp_ctx, "%s/libsss_%s.so",
                           DATA_PROVIDER_PLUGINS_PATH, mod_name);
    if (!path) {
        ret = ENOMEM;
        goto done;
    }

    handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        DEBUG(0, ("Unable to load %s module with path (%s), error: %s\n",
                  mod_name, path, dlerror()));
        ret = ELIBACC;
        goto done;
    }

    mod_init_fn_name = talloc_asprintf(tmp_ctx, "sssm_%s_auth_init", mod_name);
    if (!mod_init_fn_name) {
        ret = ENOMEM;
        goto done;
    }

    mod_init_fn = (be_auth_init_fn_t)dlsym(handle, mod_init_fn_name);
    if (!mod_init_fn) {
        DEBUG(0, ("Unable to load init fn from module %s, error: %s\n",
                  mod_name, dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ret = mod_init_fn(ctx, &ctx->auth_ops, &ctx->pvt_auth_data);
    if (ret != EOK) {
        DEBUG(0, ("Error (%d) in module (%s) initialization!\n",
                  ret, mod_name));
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
                    struct tevent_context *ev,
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

    ret = sysdb_init(ctx, ev, cdb, NULL, &ctx->sysdb);
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

    ret = load_id_backend(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing data providers\n"));
        return ret;
    }

    ret = load_auth_backend(ctx);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(0, ("fatal error initializing data providers\n"));
            return ret;
        }
        DEBUG(1, ("No authentication module provided for [%s] !!\n",
                  be_domain));
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
    char *conf_entry;
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

    conf_entry = talloc_asprintf(NULL, BE_CONF_ENTRY, be_domain);
    if (!conf_entry) return 2;

    ret = server_setup(srv_name, 0, conf_entry, &main_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up mainloop [%d]\n", ret));
        return 2;
    }

    ret = be_process_init(main_ctx,
                          be_name, be_domain,
                          main_ctx->event_ctx,
                          main_ctx->confdb_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize backend [%d]\n", ret));
        return 3;
    }

    DEBUG(1, ("Backend provider %s(%s) started!\n", be_name, be_domain));

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

