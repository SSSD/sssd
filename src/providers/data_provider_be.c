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
#include "providers/dp_backend.h"
#include "providers/fail_over.h"
#include "resolv/async_resolv.h"
#include "monitor/monitor_interfaces.h"

#define MSG_TARGET_NO_CONFIGURED "sssd_be: The requested target is not configured"

#define ACCESS_PERMIT "permit"
#define ACCESS_DENY "deny"
#define NO_PROVIDER "none"

static int data_provider_res_init(DBusMessage *message,
                                  struct sbus_connection *conn);
static int data_provider_go_offline(DBusMessage *message,
                                    struct sbus_connection *conn);
static int data_provider_reset_offline(DBusMessage *message,
                                       struct sbus_connection *conn);

struct sbus_method monitor_be_methods[] = {
    { MON_CLI_METHOD_PING, monitor_common_pong },
    { MON_CLI_METHOD_RES_INIT, data_provider_res_init },
    { MON_CLI_METHOD_OFFLINE, data_provider_go_offline },
    { MON_CLI_METHOD_RESET_OFFLINE, data_provider_reset_offline },
    { MON_CLI_METHOD_ROTATE, monitor_common_rotate_logs },
    { NULL, NULL }
};

struct sbus_interface monitor_be_interface = {
    MONITOR_INTERFACE,
    MONITOR_PATH,
    SBUS_DEFAULT_VTABLE,
    monitor_be_methods,
    NULL
};

static int client_registration(DBusMessage *message, struct sbus_connection *conn);
static int be_check_online(DBusMessage *message, struct sbus_connection *conn);
static int be_get_account_info(DBusMessage *message, struct sbus_connection *conn);
static int be_pam_handler(DBusMessage *message, struct sbus_connection *conn);

struct sbus_method be_methods[] = {
    { DP_METHOD_REGISTER, client_registration },
    { DP_METHOD_ONLINE, be_check_online },
    { DP_METHOD_GETACCTINFO, be_get_account_info },
    { DP_METHOD_PAMHANDLER, be_pam_handler },
    { NULL, NULL }
};

struct sbus_interface be_interface = {
    DP_INTERFACE,
    DP_PATH,
    SBUS_DEFAULT_VTABLE,
    be_methods,
    NULL
};

static struct bet_data bet_data[] = {
    {BET_NULL, NULL, NULL},
    {BET_ID, CONFDB_DOMAIN_ID_PROVIDER, "sssm_%s_id_init"},
    {BET_AUTH, CONFDB_DOMAIN_AUTH_PROVIDER, "sssm_%s_auth_init"},
    {BET_ACCESS, CONFDB_DOMAIN_ACCESS_PROVIDER, "sssm_%s_access_init"},
    {BET_CHPASS, CONFDB_DOMAIN_CHPASS_PROVIDER, "sssm_%s_chpass_init"},
    {BET_MAX, NULL, NULL}
};

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

bool be_is_offline(struct be_ctx *ctx)
{
    time_t now = time(NULL);

    /* check if we are past the offline blackout timeout */
    /* FIXME: get offline_timeout from configuration */
    if (ctx->offstat.went_offline + 60 < now) {
        ctx->offstat.offline = false;
    }

    return ctx->offstat.offline;
}

void be_mark_offline(struct be_ctx *ctx)
{
    DEBUG(8, ("Going offline!\n"));

    ctx->offstat.went_offline = time(NULL);
    ctx->offstat.offline = true;
    ctx->run_online_cb = true;
    be_run_offline_cb(ctx);
}

void be_reset_offline(struct be_ctx *ctx)
{
    DEBUG(8, ("Going back online!\n"));

    ctx->offstat.offline = false;
    be_run_online_cb(ctx);
}

static int be_check_online(DBusMessage *message, struct sbus_connection *conn)
{
    struct be_client *becli;
    DBusMessage *reply;
    DBusConnection *dbus_conn;
    dbus_bool_t dbret;
    void *user_data;
    dbus_uint16_t online;
    dbus_uint16_t err_maj = 0;
    dbus_uint32_t err_min = 0;
    static const char *err_msg = "Success";

    user_data = sbus_conn_get_private_data(conn);
    if (!user_data) return EINVAL;
    becli = talloc_get_type(user_data, struct be_client);
    if (!becli) return EINVAL;

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    if (be_is_offline(becli->bectx)) {
        online = MOD_OFFLINE;
    } else {
        online = MOD_ONLINE;
    }

    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &online,
                                     DBUS_TYPE_UINT16, &err_maj,
                                     DBUS_TYPE_UINT32, &err_min,
                                     DBUS_TYPE_STRING, &err_msg,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(1, ("Failed to generate dbus reply\n"));
        return EIO;
    }

    dbus_conn = sbus_get_connection(becli->conn);
    dbus_connection_send(dbus_conn, reply, NULL);
    dbus_message_unref(reply);

    DEBUG(4, ("Request processed. Returned %d,%d,%s\n",
              err_maj, err_min, err_msg));

    return EOK;
}

static char *dp_err_to_string(TALLOC_CTX *memctx, int dp_err_type, int errnum)
{
    switch (dp_err_type) {
    case DP_ERR_OK:
        return talloc_strdup(memctx, "Success");
        break;

    case DP_ERR_OFFLINE:
        return talloc_asprintf(memctx,
                               "Provider is Offline (%s)",
                               strerror(errnum));
        break;

    case DP_ERR_TIMEOUT:
        return talloc_asprintf(memctx,
                               "Request timed out (%s)",
                               strerror(errnum));
        break;

    case DP_ERR_FATAL:
    default:
        return talloc_asprintf(memctx,
                               "Internal Error (%s)",
                               strerror(errnum));
        break;
    }

    return NULL;
}


static void acctinfo_callback(struct be_req *req,
                              int dp_err_type,
                              int errnum,
                              const char *errstr)
{
    DBusMessage *reply;
    DBusConnection *dbus_conn;
    dbus_bool_t dbret;
    dbus_uint16_t err_maj = 0;
    dbus_uint32_t err_min = 0;
    const char *err_msg = NULL;

    reply = (DBusMessage *)req->pvt;

    if (reply) {
        /* Return a reply if one was requested
         * There may not be one if this request began
         * while we were offline
         */

        err_maj = dp_err_type;
        err_min = errnum;
        if (errstr) {
            err_msg = errstr;
        } else {
            err_msg = dp_err_to_string(req, dp_err_type, errnum);
        }
        if (!err_msg) {
            DEBUG(1, ("Failed to set err_msg, Out of memory?\n"));
            err_msg = "OOM";
        }

        dbret = dbus_message_append_args(reply,
                                         DBUS_TYPE_UINT16, &err_maj,
                                         DBUS_TYPE_UINT32, &err_min,
                                         DBUS_TYPE_STRING, &err_msg,
                                         DBUS_TYPE_INVALID);
        if (!dbret) {
            DEBUG(1, ("Failed to generate dbus reply\n"));
            return;
        }

        dbus_conn = sbus_get_connection(req->becli->conn);
        dbus_connection_send(dbus_conn, reply, NULL);
        dbus_message_unref(reply);

        DEBUG(4, ("Request processed. Returned %d,%d,%s\n",
                  err_maj, err_min, err_msg));
    }

    /* finally free the request */
    talloc_free(req);
}

static int be_get_account_info(DBusMessage *message, struct sbus_connection *conn)
{
    struct be_acct_req *req;
    struct be_req *be_req;
    struct be_client *becli;
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_bool_t dbret;
    void *user_data;
    uint32_t type;
    char *filter;
    int filter_type;
    uint32_t attr_type;
    char *filter_val;
    int ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    const char *err_msg;

    be_req = NULL;

    user_data = sbus_conn_get_private_data(conn);
    if (!user_data) return EINVAL;
    becli = talloc_get_type(user_data, struct be_client);
    if (!becli) return EINVAL;

    dbus_error_init(&dbus_error);

    ret = dbus_message_get_args(message, &dbus_error,
                                DBUS_TYPE_UINT32, &type,
                                DBUS_TYPE_UINT32, &attr_type,
                                DBUS_TYPE_STRING, &filter,
                                DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1,("Failed, to parse message!\n"));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        return EIO;
    }

    DEBUG(4, ("Got request for [%u][%d][%s]\n", type, attr_type, filter));

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    /* If we are offline and fast reply was requested
     * return offline immediately
     */
    if ((type & BE_REQ_FAST) && becli->bectx->offstat.offline) {
        /* Send back an immediate reply */
        err_maj = DP_ERR_OFFLINE;
        err_min = EAGAIN;
        err_msg = "Fast reply - offline";

        dbret = dbus_message_append_args(reply,
                                         DBUS_TYPE_UINT16, &err_maj,
                                         DBUS_TYPE_UINT32, &err_min,
                                         DBUS_TYPE_STRING, &err_msg,
                                         DBUS_TYPE_INVALID);
        if (!dbret) return EIO;

        DEBUG(4, ("Request processed. Returned %d,%d,%s\n",
                  err_maj, err_min, err_msg));

        sbus_conn_send_reply(conn, reply);
        dbus_message_unref(reply);
        reply = NULL;
        /* This reply will be queued and sent
         * when we reenter the mainloop.
         *
         * Continue processing in case we are
         * going back online.
         */
    }

    if ((attr_type != BE_ATTR_CORE) &&
        (attr_type != BE_ATTR_MEM) &&
        (attr_type != BE_ATTR_ALL)) {
        /* Unrecognized attr type */
        err_maj = DP_ERR_FATAL;
        err_min = EINVAL;
        err_msg = "Invalid Attrs Parameter";
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
    be_req = talloc_zero(becli, struct be_req);
    if (!be_req) {
        err_maj = DP_ERR_FATAL;
        err_min = ENOMEM;
        err_msg = "Out of memory";
        goto done;
    }
    be_req->becli = becli;
    be_req->be_ctx = becli->bectx;
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
    req->attr_type = (int)attr_type;
    req->filter_type = filter_type;
    req->filter_value = talloc_strdup(req, filter_val);

    be_req->req_data = req;

    ret = be_file_request(becli->bectx,
                          becli->bectx->bet_info[BET_ID].bet_ops->handler,
                          be_req);
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

    if (reply) {
        dbret = dbus_message_append_args(reply,
                                         DBUS_TYPE_UINT16, &err_maj,
                                         DBUS_TYPE_UINT32, &err_min,
                                         DBUS_TYPE_STRING, &err_msg,
                                         DBUS_TYPE_INVALID);
        if (!dbret) return EIO;

        DEBUG(4, ("Request processed. Returned %d,%d,%s\n",
                  err_maj, err_min, err_msg));

        /* send reply back */
        sbus_conn_send_reply(conn, reply);
        dbus_message_unref(reply);
    }

    return EOK;
}

static void be_pam_handler_callback(struct be_req *req,
                                    int dp_err_type,
                                    int errnum,
                                    const char *errstr)
{
    struct pam_data *pd;
    DBusMessage *reply;
    DBusConnection *dbus_conn;
    dbus_bool_t dbret;

    DEBUG(4, ("Backend returned: (%d, %d, %s) [%s]\n",
              dp_err_type, errnum, errstr?errstr:"<NULL>",
              dp_err_to_string(req, dp_err_type, errnum)));

    pd = talloc_get_type(req->req_data, struct pam_data);

    DEBUG(4, ("Sending result [%d][%s]\n", pd->pam_status, pd->domain));
    reply = (DBusMessage *)req->pvt;
    dbret = dp_pack_pam_response(reply, pd);
    if (!dbret) {
        DEBUG(1, ("Failed to generate dbus reply\n"));
        dbus_message_unref(reply);
        return;
    }

    dbus_conn = sbus_get_connection(req->becli->conn);
    dbus_connection_send(dbus_conn, reply, NULL);
    dbus_message_unref(reply);

    DEBUG(4, ("Sent result [%d][%s]\n", pd->pam_status, pd->domain));

    talloc_free(req);
}

static int be_pam_handler(DBusMessage *message, struct sbus_connection *conn)
{
    DBusError dbus_error;
    DBusMessage *reply;
    struct be_client *becli;
    dbus_bool_t ret;
    void *user_data;
    struct pam_data *pd = NULL;
    struct be_req *be_req = NULL;
    enum bet_type target = BET_NULL;

    user_data = sbus_conn_get_private_data(conn);
    if (!user_data) return EINVAL;
    becli = talloc_get_type(user_data, struct be_client);
    if (!becli) return EINVAL;

    reply = dbus_message_new_method_return(message);
    if (!reply) {
        DEBUG(1, ("dbus_message_new_method_return failed, cannot send reply.\n"));
        return ENOMEM;
    }

    be_req = talloc_zero(becli, struct be_req);
    if (!be_req) {
        DEBUG(7, ("talloc_zero failed.\n"));
        dbus_message_unref(reply);
        return ENOMEM;
    }

    be_req->becli = becli;
    be_req->be_ctx = becli->bectx;
    be_req->fn = be_pam_handler_callback;
    be_req->pvt = reply;

    dbus_error_init(&dbus_error);

    ret = dp_unpack_pam_request(message, be_req, &pd, &dbus_error);
    if (!ret) {
        DEBUG(1,("Failed, to parse message!\n"));
        talloc_free(be_req);
        return EIO;
    }

    pd->pam_status = PAM_SYSTEM_ERR;
    pd->domain = talloc_strdup(pd, becli->bectx->domain->name);
    if (pd->domain == NULL) {
        talloc_free(be_req);
        return ENOMEM;
    }


    DEBUG(4, ("Got request with the following data\n"));
    DEBUG_PAM_DATA(4, pd);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            target = BET_AUTH;
            break;
        case SSS_PAM_ACCT_MGMT:
            target = BET_ACCESS;
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            target = BET_CHPASS;
            break;
        case SSS_PAM_SETCRED:
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_CLOSE_SESSION:
            pd->pam_status = PAM_SUCCESS;
            goto done;
            break;
        default:
            DEBUG(7, ("Unsupported PAM command [%d].\n", pd->cmd));
            pd->pam_status = PAM_MODULE_UNKNOWN;
            goto done;
    }

    /* return an error if corresponding backend target is not configured */
    if (!becli->bectx->bet_info[target].bet_ops) {
        DEBUG(7, ("Undefined backend target.\n"));
        pd->pam_status = PAM_MODULE_UNKNOWN;
        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(MSG_TARGET_NO_CONFIGURED),
                               (const uint8_t *) MSG_TARGET_NO_CONFIGURED);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }
        goto done;
    }

    be_req->req_data = pd;

    ret = be_file_request(becli->bectx,
                          becli->bectx->bet_info[target].bet_ops->handler,
                          be_req);
    if (ret != EOK) {
        DEBUG(7, ("be_file_request failed.\n"));
        goto done;
    }

    return EOK;

done:

    DEBUG(4, ("Sending result [%d][%s]\n",
              pd->pam_status, pd->domain));

    ret = dp_pack_pam_response(reply, pd);
    if (!ret) {
        DEBUG(1, ("Failed to generate dbus reply\n"));
        talloc_free(be_req);
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back immediately */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    talloc_free(be_req);

    return EOK;
}

static int be_client_destructor(void *ctx)
{
    struct be_client *becli = talloc_get_type(ctx, struct be_client);
    if (becli->bectx) {
        if (becli->bectx->nss_cli == becli) {
            DEBUG(4, ("Removed NSS client\n"));
            becli->bectx->nss_cli = NULL;
        } else if (becli->bectx->pam_cli == becli) {
            DEBUG(4, ("Removed PAM client\n"));
            becli->bectx->pam_cli = NULL;
        } else {
            DEBUG(2, ("Unknown client removed ...\n"));
        }
    }
    return 0;
}

static int client_registration(DBusMessage *message,
                               struct sbus_connection *conn)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    struct be_client *becli;
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_uint16_t cli_ver;
    char *cli_name;
    dbus_bool_t dbret;
    void *data;

    data = sbus_conn_get_private_data(conn);
    becli = talloc_get_type(data, struct be_client);
    if (!becli) {
        DEBUG(0, ("Connection holds no valid init data\n"));
        return EINVAL;
    }

    /* First thing, cancel the timeout */
    DEBUG(4, ("Cancel DP ID timeout [%p]\n", becli->timeout));
    talloc_zfree(becli->timeout);

    dbus_error_init(&dbus_error);

    dbret = dbus_message_get_args(message, &dbus_error,
                                  DBUS_TYPE_UINT16, &cli_ver,
                                  DBUS_TYPE_STRING, &cli_name,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(1, ("Failed to parse message, killing connection\n"));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        sbus_disconnect(conn);
        /* FIXME: should we just talloc_zfree(conn) ? */
        return EIO;
    }

    if (strcasecmp(cli_name, "NSS") == 0) {
        becli->bectx->nss_cli = becli;
    } else if (strcasecmp(cli_name, "PAM") == 0) {
        becli->bectx->pam_cli = becli;
    } else {
        DEBUG(1, ("Unknown client! [%s]\n", cli_name));
    }
    talloc_set_destructor((TALLOC_CTX *)becli, be_client_destructor);

    DEBUG(4, ("Added Frontend client [%s]\n", cli_name));

    /* reply that all is ok */
    reply = dbus_message_new_method_return(message);
    if (!reply) {
        DEBUG(0, ("Dbus Out of memory!\n"));
        return ENOMEM;
    }

    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &version,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(0, ("Failed to build dbus reply\n"));
        dbus_message_unref(reply);
        sbus_disconnect(conn);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    becli->initialized = true;
    return EOK;
}

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr)
{
    struct be_client *becli;

    DEBUG(2, ("Client timed out before Identification [%p]!\n", te));

    becli = talloc_get_type(ptr, struct be_client);

    sbus_disconnect(becli->conn);
    talloc_zfree(becli);
}

static int be_client_init(struct sbus_connection *conn, void *data)
{
    struct be_ctx *bectx;
    struct be_client *becli;
    struct timeval tv;

    bectx = talloc_get_type(data, struct be_ctx);

    /* hang off this memory to the connection so that when the connection
     * is freed we can potentially call a destructor */

    becli = talloc(conn, struct be_client);
    if (!becli) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    becli->bectx = bectx;
    becli->conn = conn;
    becli->initialized = false;

    /* 5 seconds should be plenty */
    tv = tevent_timeval_current_ofs(5, 0);

    becli->timeout = tevent_add_timer(bectx->ev, becli,
                                      tv, init_timeout, becli);
    if (!becli->timeout) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    DEBUG(4, ("Set-up Backend ID timeout [%p]\n", becli->timeout));

    /* Attach the client context to the connection context, so that it is
     * always available when we need to manage the connection. */
    sbus_conn_set_private_data(conn, becli);

    return EOK;
}

/* be_srv_init
 * set up per-domain sbus channel */
static int be_srv_init(struct be_ctx *ctx)
{
    char *sbus_address;
    int ret;

    /* Set up SBUS connection to the monitor */
    ret = dp_get_sbus_address(ctx, &sbus_address, ctx->domain->name);
    if (ret != EOK) {
        DEBUG(0, ("Could not get sbus backend address.\n"));
        return ret;
    }

    ret = sbus_new_server(ctx, ctx->ev, sbus_address,
                          &be_interface, &ctx->sbus_srv,
                          be_client_init, ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up sbus server.\n"));
        return ret;
    }

    return EOK;
}

/* mon_cli_init
 * sbus channel to the monitor daemon */
static int mon_cli_init(struct be_ctx *ctx)
{
    char *sbus_address;
    int ret;

    /* Set up SBUS connection to the monitor */
    ret = monitor_get_sbus_address(ctx, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate monitor address.\n"));
        return ret;
    }

    ret = sbus_client_init(ctx, ctx->ev, sbus_address,
                           &monitor_be_interface, &ctx->mon_conn,
                           NULL, ctx);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

    /* Identify ourselves to the monitor */
    ret = monitor_common_send_id(ctx->mon_conn,
                                 ctx->identity,
                                 DATA_PROVIDER_VERSION);
    if (ret != EOK) {
        DEBUG(0, ("Failed to identify to the monitor!\n"));
        return ret;
    }

    return EOK;
}

static void be_target_access_permit(struct be_req *be_req)
{
    struct pam_data *pd = talloc_get_type(be_req->req_data, struct pam_data);
    DEBUG(9, ("be_target_access_permit called, returning PAM_SUCCESS.\n"));

    pd->pam_status = PAM_SUCCESS;
    be_req->fn(be_req, DP_ERR_OK, PAM_SUCCESS, NULL);
}

static struct bet_ops be_target_access_permit_ops = {
    .check_online = NULL,
    .handler = be_target_access_permit,
    .finalize = NULL
};

static void be_target_access_deny(struct be_req *be_req)
{
    struct pam_data *pd = talloc_get_type(be_req->req_data, struct pam_data);
    DEBUG(9, ("be_target_access_deny called, returning PAM_PERM_DENIED.\n"));

    pd->pam_status = PAM_PERM_DENIED;
    be_req->fn(be_req, DP_ERR_OK, PAM_PERM_DENIED, NULL);
}

static struct bet_ops be_target_access_deny_ops = {
    .check_online = NULL,
    .handler = be_target_access_deny,
    .finalize = NULL
};

static int load_backend_module(struct be_ctx *ctx,
                               enum bet_type bet_type,
                               struct bet_info *bet_info,
                               const char *default_mod_name)
{
    TALLOC_CTX *tmp_ctx;
    int ret = EINVAL;
    bool already_loaded = false;
    int lb=0;
    char *mod_name = NULL;
    char *path = NULL;
    void *handle;
    char *mod_init_fn_name = NULL;
    bet_init_fn_t mod_init_fn = NULL;

    (*bet_info).mod_name = NULL;
    (*bet_info).bet_ops = NULL;
    (*bet_info).pvt_bet_data = NULL;

    if (bet_type <= BET_NULL || bet_type >= BET_MAX ||
        bet_type != bet_data[bet_type].bet_type) {
        DEBUG(2, ("invalid bet_type or bet_data corrupted.\n"));
        return EINVAL;
    }

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        DEBUG(7, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    ret = confdb_get_string(ctx->cdb, tmp_ctx, ctx->conf_path,
                            bet_data[bet_type].option_name, NULL,
                            &mod_name);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }
    if (!mod_name) {
        if (default_mod_name != NULL) {
            DEBUG(5, ("no module name found in confdb, using [%s].\n",
                      default_mod_name));
            mod_name = talloc_strdup(ctx, default_mod_name);
        } else {
            ret = ENOENT;
            goto done;
        }
    }

    if (strcasecmp(mod_name, NO_PROVIDER) == 0) {
        ret = ENOENT;
        goto done;
    }

    if (bet_type == BET_ACCESS) {
        if (strcmp(mod_name, ACCESS_PERMIT) == 0) {
            (*bet_info).bet_ops = &be_target_access_permit_ops;
            (*bet_info).pvt_bet_data = NULL;
            (*bet_info).mod_name = talloc_strdup(ctx, ACCESS_PERMIT);

            ret = EOK;
            goto done;
        }
        if (strcmp(mod_name, ACCESS_DENY) == 0) {
            (*bet_info).bet_ops = &be_target_access_deny_ops;
            (*bet_info).pvt_bet_data = NULL;
            (*bet_info).mod_name = talloc_strdup(ctx, ACCESS_DENY);

            ret = EOK;
            goto done;
        }
    }

    mod_init_fn_name = talloc_asprintf(tmp_ctx,
                                       bet_data[bet_type].mod_init_fn_name_fmt,
                                       mod_name);
    if (mod_init_fn_name == NULL) {
        DEBUG(7, ("talloc_asprintf failed\n"));
        ret = ENOMEM;
        goto done;
    }


    lb = 0;
    while(ctx->loaded_be[lb].be_name != NULL) {
        if (strncmp(ctx->loaded_be[lb].be_name, mod_name,
                    strlen(mod_name)) == 0) {
            DEBUG(7, ("Backend [%s] already loaded.\n", mod_name));
            already_loaded = true;
            break;
        }

        ++lb;
        if (lb >= BET_MAX) {
            DEBUG(2, ("Backend context corrupted.\n"));
            ret = EINVAL;
            goto done;
        }
    }

    if (!already_loaded) {
        path = talloc_asprintf(tmp_ctx, "%s/libsss_%s.so",
                               DATA_PROVIDER_PLUGINS_PATH, mod_name);
        if (!path) {
            ret = ENOMEM;
            goto done;
        }

        DEBUG(7, ("Loading backend [%s] with path [%s].\n", mod_name, path));
        handle = dlopen(path, RTLD_NOW);
        if (!handle) {
            DEBUG(0, ("Unable to load %s module with path (%s), error: %s\n",
                      mod_name, path, dlerror()));
            ret = ELIBACC;
            goto done;
        }

        ctx->loaded_be[lb].be_name = talloc_strdup(ctx, mod_name);
        ctx->loaded_be[lb].handle = handle;
    }

    mod_init_fn = (bet_init_fn_t)dlsym(ctx->loaded_be[lb].handle,
                                           mod_init_fn_name);
    if (mod_init_fn == NULL) {
        if (default_mod_name != NULL &&
            strcmp(default_mod_name, mod_name) == 0 ) {
            /* If the default is used and fails we indicate this to the caller
             * by returning ENOENT. Ths way the caller can decide how to
             * handle the different types of error conditions. */
            ret = ENOENT;
        } else {
            DEBUG(0, ("Unable to load init fn %s from module %s, error: %s\n",
                      mod_init_fn_name, mod_name, dlerror()));
            ret = ELIBBAD;
        }
        goto done;
    }

    ret = mod_init_fn(ctx, &(*bet_info).bet_ops, &(*bet_info).pvt_bet_data);
    if (ret != EOK) {
        DEBUG(0, ("Error (%d) in module (%s) initialization (%s)!\n",
                  ret, mod_name, mod_init_fn_name));
        goto done;
    }

    (*bet_info).mod_name = talloc_strdup(ctx, mod_name);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void signal_be_offline(struct tevent_context *ev,
                              struct tevent_signal *se,
                              int signum,
                              int count,
                              void *siginfo,
                              void *private_data)
{
    struct be_ctx *ctx = talloc_get_type(private_data, struct be_ctx);
    be_mark_offline(ctx);
}

int be_process_init(TALLOC_CTX *mem_ctx,
                    const char *be_domain,
                    struct tevent_context *ev,
                    struct confdb_ctx *cdb)
{
    struct be_ctx *ctx;
    struct tevent_signal *tes;
    int ret;

    ctx = talloc_zero(mem_ctx, struct be_ctx);
    if (!ctx) {
        DEBUG(0, ("fatal error initializing be_ctx\n"));
        return ENOMEM;
    }
    ctx->ev = ev;
    ctx->cdb = cdb;
    ctx->identity = talloc_asprintf(ctx, "%%BE_%s", be_domain);
    ctx->conf_path = talloc_asprintf(ctx, CONFDB_DOMAIN_PATH_TMPL, be_domain);
    if (!ctx->identity || !ctx->conf_path) {
        DEBUG(0, ("Out of memory!?\n"));
        return ENOMEM;
    }

    ret = be_init_failover(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing failover context\n"));
        return ret;
    }

    ret = confdb_get_domain(cdb, be_domain, &ctx->domain);
    if (ret != EOK) {
        DEBUG(0, ("fatal error retrieving domain configuration\n"));
        return ret;
    }

    ret = sysdb_domain_init(ctx, ctx->domain, DB_PATH, &ctx->sysdb);
    if (ret != EOK) {
        DEBUG(0, ("fatal error opening cache database\n"));
        return ret;
    }

    ret = mon_cli_init(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up monitor bus\n"));
        return ret;
    }

    ret = be_srv_init(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up server bus\n"));
        return ret;
    }

    ret = load_backend_module(ctx, BET_ID,
                              &ctx->bet_info[BET_ID], NULL);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing data providers\n"));
        return ret;
    }
    DEBUG(9, ("ID backend target successfully loaded from provider [%s].\n",
              ctx->bet_info[BET_ID].mod_name));

    ret = load_backend_module(ctx, BET_AUTH,
                              &ctx->bet_info[BET_AUTH],
                              ctx->bet_info[BET_ID].mod_name);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(0, ("fatal error initializing data providers\n"));
            return ret;
        }
        DEBUG(1, ("No authentication module provided for [%s] !!\n",
                  be_domain));
    } else {
        DEBUG(9, ("AUTH backend target successfully loaded "
                  "from provider [%s].\n", ctx->bet_info[BET_AUTH].mod_name));
    }

    ret = load_backend_module(ctx, BET_ACCESS, &ctx->bet_info[BET_ACCESS],
                              ACCESS_PERMIT);
    if (ret != EOK) {
        DEBUG(0, ("Failed to setup ACCESS backend.\n"));
        return ret;
    }
    DEBUG(9, ("ACCESS backend target successfully loaded "
              "from provider [%s].\n", ctx->bet_info[BET_ACCESS].mod_name));

    ret = load_backend_module(ctx, BET_CHPASS,
                              &ctx->bet_info[BET_CHPASS],
                              ctx->bet_info[BET_AUTH].mod_name);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(0, ("fatal error initializing data providers\n"));
            return ret;
        }
        DEBUG(1, ("No change password module provided for [%s] !!\n",
                  be_domain));
    } else {
        DEBUG(9, ("CHPASS backend target successfully loaded "
                  "from provider [%s].\n", ctx->bet_info[BET_CHPASS].mod_name));
    }

    /* Handle SIGUSR1 to force offline behavior */
    BlockSignals(false, SIGUSR1);
    tes = tevent_add_signal(ctx->ev, ctx, SIGUSR1, 0,
                            signal_be_offline, ctx);
    if (tes == NULL) {
        return EIO;
    }

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *be_domain = NULL;
    char *srv_name = NULL;
    char *conf_entry = NULL;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        {"domain", 0, POPT_ARG_STRING, &be_domain, 0,
         _("Domain of the information provider (mandatory)"), NULL },
        POPT_TABLEEND
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

    if (be_domain == NULL) {
        fprintf(stderr, "\nMissing option, --domain is a mandatory option.\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
    }

    poptFreeContext(pc);


    /* set up things like debug , signals, daemonization, etc... */
    debug_log_file = talloc_asprintf(NULL, "sssd_%s", be_domain);
    if (!debug_log_file) return 2;

    srv_name = talloc_asprintf(NULL, "sssd[be[%s]]", be_domain);
    if (!srv_name) return 2;

    conf_entry = talloc_asprintf(NULL, CONFDB_DOMAIN_PATH_TMPL, be_domain);
    if (!conf_entry) return 2;

    ret = server_setup(srv_name, 0, conf_entry, &main_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up mainloop [%d]\n", ret));
        return 2;
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    ret = be_process_init(main_ctx,
                          be_domain,
                          main_ctx->event_ctx,
                          main_ctx->confdb_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize backend [%d]\n", ret));
        return 3;
    }

    DEBUG(1, ("Backend provider (%s) started!\n", be_domain));

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

static int data_provider_res_init(DBusMessage *message,
                                  struct sbus_connection *conn)
{
    resolv_reread_configuration();

    return monitor_common_res_init(message, conn);
}

static int data_provider_go_offline(DBusMessage *message,
                                    struct sbus_connection *conn)
{
    struct be_ctx *be_ctx;
    be_ctx = talloc_get_type(sbus_conn_get_private_data(conn), struct be_ctx);
    be_mark_offline(be_ctx);
    return monitor_common_pong(message, conn);
}

static int data_provider_reset_offline(DBusMessage *message,
                                       struct sbus_connection *conn)
{
    struct be_ctx *be_ctx;
    be_ctx = talloc_get_type(sbus_conn_get_private_data(conn), struct be_ctx);
    be_reset_offline(be_ctx);
    return monitor_common_pong(message, conn);
}
