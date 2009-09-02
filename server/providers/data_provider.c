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
#include <security/pam_modules.h>

#include "popt.h"
#include "util/util.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "util/btreemap.h"
#include "data_provider.h"
#include "dp_interfaces.h"
#include "monitor/monitor_interfaces.h"

#define DP_CONF_ENTRY "config/services/dp"

struct dp_backend;
struct dp_frontend;

struct dp_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    struct sbus_connection *sbus_srv;
    struct dp_backend *be_list;
    struct dp_frontend *fe_list;
};

struct dp_client {
    struct dp_ctx *dpctx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
    bool initialized;
};

struct dp_backend {
    struct dp_backend *prev;
    struct dp_backend *next;
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

static int service_reload(DBusMessage *message, struct sbus_connection *conn);

struct sbus_method monitor_dp_methods[] = {
    { MON_CLI_METHOD_PING, monitor_common_pong },
    { MON_CLI_METHOD_RELOAD, service_reload },
    { MON_CLI_METHOD_RES_INIT, monitor_common_res_init },
    { NULL, NULL }
};

struct sbus_interface monitor_dp_interface = {
    MONITOR_INTERFACE,
    MONITOR_PATH,
    SBUS_DEFAULT_VTABLE,
    monitor_dp_methods,
    NULL
};

static int client_registration(DBusMessage *message,
                               struct sbus_connection *conn);
static int dp_get_account_info(DBusMessage *message,
                               struct sbus_connection *conn);
static int dp_pamhandler(DBusMessage *message, struct sbus_connection *conn);

struct sbus_method dp_methods[] = {
    { DP_SRV_METHOD_REGISTER, client_registration },
    { DP_SRV_METHOD_GETACCTINFO, dp_get_account_info },
    { DP_SRV_METHOD_PAMHANDLER, dp_pamhandler },
    { NULL, NULL }
};

struct sbus_interface dp_interface = {
    DP_SRV_INTERFACE,
    DP_SRV_PATH,
    SBUS_DEFAULT_VTABLE,
    dp_methods,
    NULL
};

struct dp_request {
    /* reply message to send when request is done */
    DBusMessage *reply;
    /* frontend client that made the request */
    struct dp_client *src_cli;

    int pending_replies;
};

struct dp_be_request {
    struct dp_request *req;
    struct dp_backend *be;
};

static int service_reload(DBusMessage *message, struct sbus_connection *conn)
{
    /* Monitor calls this function when we need to reload
     * our configuration information. Perform whatever steps
     * are needed to update the configuration objects.
     */

    /* Send an empty reply to acknowledge receipt */
    return monitor_common_pong(message, conn);
}

static int dp_monitor_init(struct dp_ctx *dpctx)
{
    struct sbus_connection *conn;
    char *sbus_address;
    int ret;

    /* Set up SBUS connection to the monitor */
    ret = monitor_get_sbus_address(dpctx, dpctx->cdb, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate monitor address.\n"));
        return ret;
    }

    ret = sbus_client_init(dpctx, dpctx->ev, sbus_address,
                           &monitor_dp_interface, &conn,
                           NULL, NULL);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

    /* Identify ourselves to the monitor */
    ret = monitor_common_send_id(conn,
                                 DATA_PROVIDER_SERVICE_NAME,
                                 DATA_PROVIDER_VERSION);
    if (ret != EOK) {
        DEBUG(0, ("Failed to identify to the monitor!\n"));
        return ret;
    }

    return EOK;
}

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr)
{
    struct dp_client *dpcli;

    DEBUG(2, ("Client timed out before Identification [%p]!\n", te));

    dpcli = talloc_get_type(ptr, struct dp_client);

    sbus_disconnect(dpcli->conn);
    talloc_zfree(dpcli);
}

static int dp_client_init(struct sbus_connection *conn, void *data)
{
    struct dp_ctx *dpctx;
    struct dp_client *dpcli;
    struct timeval tv;

    dpctx = talloc_get_type(data, struct dp_ctx);

    /* hang off this memory to the connection so that when the connection
     * is freed we can potentially call a destructor */

    dpcli = talloc(conn, struct dp_client);
    if (!dpcli) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    dpcli->dpctx = dpctx;
    dpcli->conn = conn;
    dpcli->initialized = false;

    /* 5 seconds should be plenty */
    tv = tevent_timeval_current_ofs(5, 0);

    dpcli->timeout = tevent_add_timer(dpctx->ev, dpcli,
                                      tv, init_timeout, dpcli);
    if (!dpcli->timeout) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    DEBUG(4, ("Set-up DP ID timeout [%p]\n", dpcli->timeout));

    /* Attach the client context to the connection context, so that it is
     * always available when we need to manage the connection. */
    sbus_conn_set_private_data(conn, dpcli);

    return EOK;
}

static int client_registration(DBusMessage *message,
                               struct sbus_connection *conn)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    struct dp_backend *dpbe;
    struct dp_frontend *dpfe;
    struct dp_client *dpcli;
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_uint16_t cli_ver;
    dbus_uint16_t cli_type;
    char *cli_name;
    char *cli_domain;
    dbus_bool_t dbret;
    void *data;

    data = sbus_conn_get_private_data(conn);
    dpcli = talloc_get_type(data, struct dp_client);
    if (!dpcli) {
        DEBUG(0, ("Connection holds no valid init data\n"));
        return EINVAL;
    }

    /* First thing, cancel the timeout */
    DEBUG(4, ("Cancel DP ID timeout [%p]\n", dpcli->timeout));
    talloc_zfree(dpcli->timeout);

    dbus_error_init(&dbus_error);

    dbret = dbus_message_get_args(message, &dbus_error,
                                  DBUS_TYPE_UINT16, &cli_type,
                                  DBUS_TYPE_UINT16, &cli_ver,
                                  DBUS_TYPE_STRING, &cli_name,
                                  DBUS_TYPE_STRING, &cli_domain,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(1, ("Failed to parse message, killing connection\n"));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        sbus_disconnect(conn);
        /* FIXME: should we just talloc_zfree(conn) ? */
        return EIO;
    }

    switch (cli_type & DP_CLI_TYPE_MASK) {
    case DP_CLI_BACKEND:
        dpbe = talloc_zero(dpcli->dpctx, struct dp_backend);
        if (!dpbe) {
            DEBUG(0, ("Out of memory!\n"));
            sbus_disconnect(conn);
            return ENOMEM;
        }

        dpbe->domain = talloc_strdup(dpbe, cli_domain);
        if (!dpbe->domain) {
            DEBUG(0, ("Out of memory!\n"));
            sbus_disconnect(conn);
            return ENOMEM;
        }

        dpbe->dpcli = dpcli;

        DLIST_ADD(dpcli->dpctx->be_list, dpbe);

        DEBUG(4, ("Added Backend client for domain [%s]\n", dpbe->domain));

        talloc_set_destructor((TALLOC_CTX *)dpbe, dp_backend_destructor);
        break;

    case DP_CLI_FRONTEND:
        dpfe = talloc_zero(dpcli->dpctx, struct dp_frontend);
        if (!dpfe) {
            DEBUG(0, ("Out of memory!\n"));
            sbus_disconnect(conn);
            return ENOMEM;
        }

        dpfe->name = talloc_strdup(dpfe, cli_name);
        if (!dpfe->name) {
            DEBUG(0, ("Out of memory!\n"));
            sbus_disconnect(conn);
            return ENOMEM;
        }

        dpfe->dpcli = dpcli;

        DLIST_ADD(dpcli->dpctx->fe_list, dpfe);

        DEBUG(4, ("Added Frontend client [%s]\n", dpfe->name));

        talloc_set_destructor((TALLOC_CTX *)dpfe, dp_frontend_destructor);
        break;

    default:
        DEBUG(1, ("Unknown client type, killing connection\n"));
        sbus_disconnect(conn);
        return EIO;
    }

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

    dpcli->initialized = true;
    return EOK;
}

static void be_got_account_info(DBusPendingCall *pending, void *data)
{
    struct dp_be_request *bereq;
    DBusMessage *reply;
    DBusConnection *dbus_conn;
    DBusError dbus_error;
    dbus_uint16_t err_maj = 0;
    dbus_uint32_t err_min = 0;
    const char *err_msg;
    dbus_bool_t ret;
    int type;

    bereq = talloc_get_type(data, struct dp_be_request);
    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(0, ("Severe error. A reply callback was called but no reply was received and no timeout occurred\n"));

        /* Destroy this connection */
        sbus_disconnect(bereq->be->dpcli->conn);
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dbus_message_get_args(reply, &dbus_error,
                                    DBUS_TYPE_UINT16, &err_maj,
                                    DBUS_TYPE_UINT32, &err_min,
                                    DBUS_TYPE_STRING, &err_msg,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1,("Failed to parse message, killing connection\n"));
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            sbus_disconnect(bereq->be->dpcli->conn);
            goto done;
        }

        DEBUG(4, ("Got reply (%u, %u, %s) from (%s)\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg,
                  bereq->be->domain));

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(0,("The Data Provider returned an error [%s], closing connection.\n",
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
        sbus_disconnect(bereq->be->dpcli->conn);
    }

    if (err_maj) {
        DEBUG(1, ("Backend returned an error: %d,%d(%s),%s\n",
                  err_maj, err_min, strerror(err_min), err_msg));
        /* TODO: handle errors !! */
    }

    if (bereq->req->pending_replies > 1) {
        bereq->req->pending_replies--;
        talloc_free(bereq);
    } else {
        dbus_conn = sbus_get_connection(bereq->req->src_cli->conn);
        err_maj = 0;
        err_min = 0;
        err_msg = "Success";
        ret = dbus_message_append_args(bereq->req->reply,
                                       DBUS_TYPE_UINT16, &err_maj,
                                       DBUS_TYPE_UINT32, &err_min,
                                       DBUS_TYPE_STRING, &err_msg,
                                       DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1, ("Failed to build reply ... frontend will wait for timeout ...\n"));
            talloc_free(bereq->req);
            goto done;
        }

        /* finally send it */
        dbus_connection_send(dbus_conn, bereq->req->reply, NULL);
        dbus_message_unref(bereq->req->reply);
        talloc_free(bereq->req);
    }

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
}

static int dp_send_acct_req(struct dp_be_request *bereq,
                            uint32_t type, char *attrs, char *filter)
{
    DBusMessage *msg;
    DBusPendingCall *pending_reply;
    DBusConnection *dbus_conn;
    dbus_bool_t ret;

    dbus_conn = sbus_get_connection(bereq->be->dpcli->conn);

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_CLI_PATH,
                                       DP_CLI_INTERFACE,
                                       DP_CLI_METHOD_GETACCTINFO);
    if (msg == NULL) {
        DEBUG(0,("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending request for [%u][%s][%s]\n", type, attrs, filter));

    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_UINT32, &type,
                                   DBUS_TYPE_STRING, &attrs,
                                   DBUS_TYPE_STRING, &filter,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1,("Failed to build message\n"));
        return EIO;
    }

    ret = dbus_connection_send_with_reply(dbus_conn, msg, &pending_reply,
                                            600000 /* TODO: set timeout */);
    if (!ret || pending_reply == NULL) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         * We'll drop it using the default destructor.
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        dbus_message_unref(msg);
        return EIO;
    }

    /* Set up the reply handler */
    dbus_pending_call_set_notify(pending_reply, be_got_account_info,
                                 bereq, NULL);
    dbus_message_unref(msg);

    return EOK;
}

static int dp_get_account_info(DBusMessage *message, struct sbus_connection *conn)
{
    struct dp_client *dpcli;
    struct dp_be_request *bereq;
    struct dp_request *dpreq = NULL;
    struct dp_backend *dpbe;
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_bool_t dbret;
    void *user_data;
    uint32_t type;
    char *domain, *attrs, *filter;
    const char *errmsg = NULL;
    int dpret = 0, ret = 0;

    user_data = sbus_conn_get_private_data(conn);
    if (!user_data) return EINVAL;
    dpcli = talloc_get_type(user_data, struct dp_client);
    if (!dpcli) return EINVAL;

    dbus_error_init(&dbus_error);

    ret = dbus_message_get_args(message, &dbus_error,
                                DBUS_TYPE_STRING, &domain,
                                DBUS_TYPE_UINT32, &type,
                                DBUS_TYPE_STRING, &attrs,
                                DBUS_TYPE_STRING, &filter,
                                DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1,("Failed, to parse message!\n"));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        return EIO;
    }

    DEBUG(4, ("Got request for [%s][%u][%s][%s]\n",
              domain, type, attrs, filter));

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    /* search for domain */
    if (!domain) {
        dpret = DP_ERR_FATAL;
        errmsg = "Invalid Domain";
        ret = EINVAL;
        goto respond;
    }

    /* all domains, fire off a request for each backend */
    if (strcmp(domain, "*") == 0) {
        dpreq = talloc(dpcli->dpctx, struct dp_request);
        if (!dpreq) {
            dpret = DP_ERR_FATAL;
            errmsg = "Out of memory";
            ret = ENOMEM;
            goto respond;
        }

        dpreq->reply = reply;
        dpreq->src_cli = dpcli;
        dpreq->pending_replies = 0;

        /* now fire off requests */
        dpbe = dpcli->dpctx->be_list;
        while (dpbe) {
            bereq = talloc(dpreq, struct dp_be_request);
            if (!bereq) {
                DEBUG(1, ("Out of memory while sending requests\n"));
                dpbe = dpbe->next;
                continue;
            }
            bereq->req = dpreq;
            bereq->be = dpbe;
            DEBUG(4, ("Sending wildcard request to [%s]\n", dpbe->domain));
            ret = dp_send_acct_req(bereq, type, attrs, filter);
            if (ret != EOK) {
                DEBUG(2,("Failed to dispatch request to %s\n", dpbe->domain));
                dpbe = dpbe->next;
                continue;
            }
            dpreq->pending_replies++;
            dpbe = dpbe->next;
        }

        if (dpreq->pending_replies == 0) {
            dpret = DP_ERR_FATAL;
            errmsg = "Unable to contact backends";
            ret = EIO;
            talloc_free(dpreq);
            goto respond;
        }

        return EOK;
    }

    dpbe = dpcli->dpctx->be_list;
    while (dpbe) {
        if (strcasecmp(dpbe->domain, domain) == 0) {
            break;
        }

        dpbe = dpbe->next;
    }

    if (dpbe) {
        dpreq = talloc(dpcli->dpctx, struct dp_request);
        if (!dpreq) {
            DEBUG(1, ("Out of memory while sending request\n"));
            dpret = DP_ERR_FATAL;
            errmsg = "Out of memory";
            ret = ENOMEM;
            goto respond;
        }

        dpreq->reply = reply;
        dpreq->src_cli = dpcli;
        dpreq->pending_replies = 1;

        bereq = talloc(dpreq, struct dp_be_request);
        if (!bereq) {
            DEBUG(1, ("Out of memory while sending request\n"));
            dpret = DP_ERR_FATAL;
            errmsg = "Out of memory";
            ret = ENOMEM;
            talloc_free(dpreq);
            goto respond;
        }
        bereq->req = dpreq;
        bereq->be = dpbe;

        ret = dp_send_acct_req(bereq, type, attrs, filter);
        if (ret != EOK) {
            DEBUG(2,("Failed to dispatch request to %s\n", dpbe->domain));
            dpret = DP_ERR_FATAL;
            errmsg = "Dispatch Failed";
            talloc_free(dpreq);
            goto respond;
        }

    } else {

        dpret = DP_ERR_FATAL;
        errmsg = "Invalid Domain";
        ret = EINVAL;
        goto respond;
    }

    return EOK;

respond:
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT16, &dpret,
                                     DBUS_TYPE_UINT32, &ret,
                                     DBUS_TYPE_STRING, &errmsg,
                                     DBUS_TYPE_INVALID);
    if (!dbret) return EIO;

    /* send reply back immediately */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static void be_got_pam_reply(DBusPendingCall *pending, void *data)
{
    struct dp_be_request *bereq;
    DBusMessage *reply;
    DBusConnection *dbus_conn;
    DBusError dbus_error;
    dbus_bool_t ret;
    struct pam_data *pd = NULL;
    int type;

    bereq = talloc_get_type(data, struct dp_be_request);
    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(0, ("Severe error. A reply callback was called but no reply was received and no timeout occurred\n"));

        /* Destroy this connection */
        sbus_disconnect(bereq->be->dpcli->conn);
        goto done;
    }

    pd = talloc_zero(bereq, struct pam_data);
    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dp_unpack_pam_response(reply, pd, &dbus_error);
        if (!ret) {
            DEBUG(1,("Failed to parse message, killing connection\n"));
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            sbus_disconnect(bereq->be->dpcli->conn);
            pd->pam_status = PAM_SYSTEM_ERR;
            pd->domain = talloc_strdup(pd, "");
            goto done;
        }

        DEBUG(4, ("Got reply (%d, %s) from (%s)\n", pd->pam_status, pd->domain,
                  bereq->be->domain));

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(0,("The Data Provider returned an error [%s], closing connection.\n",
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
        DEBUG(1,("Maybe timeout?\n"));
        sbus_disconnect(bereq->be->dpcli->conn);
        goto done;
    }

    dbus_conn = sbus_get_connection(bereq->req->src_cli->conn);

    ret = dp_pack_pam_response(bereq->req->reply, pd);
    if (!ret) {
        DEBUG(1, ("Failed to build reply ... frontend will wait for timeout ...\n"));
        talloc_free(bereq->req);
        goto done;
    }

    /* finally send it */
    dbus_connection_send(dbus_conn, bereq->req->reply, NULL);
    dbus_message_unref(bereq->req->reply);
    talloc_free(bereq->req);

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
}

static int dp_call_pamhandler(struct dp_be_request *bereq, struct pam_data *pd)
{
    DBusMessage *msg;
    DBusPendingCall *pending_reply;
    DBusConnection *dbus_conn;
    dbus_bool_t ret;

    dbus_conn = sbus_get_connection(bereq->be->dpcli->conn);

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_CLI_PATH,
                                       DP_CLI_INTERFACE,
                                       DP_CLI_METHOD_PAMHANDLER);
    if (msg == NULL) {
        DEBUG(0,("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending request with to following data\n"));
    DEBUG_PAM_DATA(4, pd);

    ret = dp_pack_pam_request(msg, pd);
    if (!ret) {
        DEBUG(1,("Failed to build message\n"));
        return EIO;
    }

    ret = dbus_connection_send_with_reply(dbus_conn, msg, &pending_reply,
                                          600000 /* TODO: set timeout */);
    if (!ret || pending_reply == NULL) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         * We'll drop it using the default destructor.
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        dbus_message_unref(msg);
        return EIO;
    }

    /* Set up the reply handler */
    dbus_pending_call_set_notify(pending_reply, be_got_pam_reply,
                                 bereq, NULL);
    dbus_message_unref(msg);

    return EOK;
}

static int dp_pamhandler(DBusMessage *message, struct sbus_connection *conn)
{
    DBusMessage *reply;
    DBusError dbus_error;
    struct dp_client *dpcli;
    struct dp_backend *dpbe;
    struct dp_be_request *bereq;
    struct dp_request *dpreq = NULL;
    dbus_bool_t dbret;
    void *user_data;
    int ret;
    struct pam_data *pd;
    int pam_status=PAM_SUCCESS;
    int domain_found=0;

    user_data = sbus_conn_get_private_data(conn);
    if (!user_data) return EINVAL;
    dpcli = talloc_get_type(user_data, struct dp_client);
    if (!dpcli) return EINVAL;

/* FIXME: free arrays returned by dbus_message_get_args() */
    pd = talloc(NULL, struct pam_data);
    if (!pd) return ENOMEM;

    dbus_error_init(&dbus_error);

    ret = dp_unpack_pam_request(message, pd, &dbus_error);
    if (!ret) {
        DEBUG(0,("Failed, to parse message!\n"));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        talloc_free(pd);
        return EIO;
    }

    DEBUG(4, ("Got the following data:\n"));
    DEBUG_PAM_DATA(4, pd);

    reply = dbus_message_new_method_return(message);
    if (!reply) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_free(pd);
        return ENOMEM;
    }

    dpreq = talloc(dpcli->dpctx, struct dp_request);
    if (!dpreq) {
        ret = ENOMEM;
        pam_status = PAM_ABORT;
        goto respond;
    }

    dpreq->reply = reply;
    dpreq->src_cli = dpcli;
    dpreq->pending_replies = 0;
    /* FIXME: add handling of default domain */
    dpbe = dpcli->dpctx->be_list;
    while (dpbe) {
        DEBUG(4, ("Checking [%s][%s]\n", pd->domain, dpbe->domain));
        if (strcasecmp(dpbe->domain, pd->domain) == 0 ) {
            domain_found=1;
            bereq = talloc(dpreq, struct dp_be_request);
            if (!bereq) {
                DEBUG(1, ("Out of memory while sending requests\n"));
                dpbe = dpbe->next;
                continue;
            }
            bereq->req = dpreq;
            bereq->be = dpbe;
            DEBUG(4, ("Sending wildcard request to [%s]\n", dpbe->domain));
            ret = dp_call_pamhandler(bereq, pd);
            if (ret != EOK) {
                DEBUG(2,("Failed to dispatch request to %s\n", dpbe->domain));
                dpbe = dpbe->next;
                continue;
            }
            dpreq->pending_replies++;
        }
        dpbe = dpbe->next;
    }

    if (domain_found) {
        talloc_free(pd);
        return EOK;
    }

    pam_status = PAM_MODULE_UNKNOWN;

respond:
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT32, &pam_status,
                                     DBUS_TYPE_STRING, &(pd->domain),
                                     DBUS_TYPE_INVALID);
    if (!dbret) return EIO;

    /* send reply back immediately */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    talloc_free(pd);
    return EOK;
}

static int dp_backend_destructor(void *ctx)
{
    struct dp_backend *dpbe = talloc_get_type(ctx, struct dp_backend);
    if (dpbe->dpcli && dpbe->dpcli->dpctx && dpbe->dpcli->dpctx->be_list) {
        DLIST_REMOVE(dpbe->dpcli->dpctx->be_list, dpbe);
        DEBUG(4, ("Removed Backend client for domain [%s]\n",
                  dpbe->domain));
    }
    return 0;
}

static int dp_frontend_destructor(void *ctx)
{
    struct dp_frontend *dpfe = talloc_get_type(ctx, struct dp_frontend);
    if (dpfe->dpcli && dpfe->dpcli->dpctx && dpfe->dpcli->dpctx->fe_list) {
        DLIST_REMOVE(dpfe->dpcli->dpctx->fe_list, dpfe);
        DEBUG(4, ("Removed Frontend client [%s]\n", dpfe->name));
    }
    return 0;
}

/* monitor_dbus_init
 * Set up the monitor service as a D-BUS Server */
static int dp_srv_init(struct dp_ctx *dpctx)
{
    char *dpbus_address;
    char *default_dp_address;
    int ret;

    DEBUG(3, ("Initializing Data Provider D-BUS Server\n"));
    default_dp_address = talloc_asprintf(dpctx, "unix:path=%s/%s",
                                         PIPE_PATH, DATA_PROVIDER_PIPE);
    if (default_dp_address == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_get_string(dpctx->cdb, dpctx,
                            DP_CONF_ENTRY, "dpbusAddress",
                            default_dp_address, &dpbus_address);
    if (ret != EOK) goto done;

    ret = sbus_new_server(dpctx, dpctx->ev, dpbus_address,
                          &dp_interface, &dpctx->sbus_srv,
                          dp_client_init, dpctx);
    if (ret != EOK) {
        goto done;
    }

done:
    talloc_free(default_dp_address);
    return ret;
}

static int dp_process_init(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
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
    ret = server_setup("sssd[dp]", 0, DP_CONF_ENTRY, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    ret = dp_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

