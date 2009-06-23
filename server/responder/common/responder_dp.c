
#include <sys/time.h>
#include <time.h>
#include "util/util.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "sbus/sbus_client.h"
#include "providers/dp_sbus.h"

struct sss_dp_pvt_ctx {
    struct resp_ctx *rctx;
    struct sbus_method *methods;
    time_t last_retry;
    int retries;
};

static int sss_dp_conn_destructor(void *data);
static void sss_dp_reconnect(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval tv, void *data);

static void sss_dp_conn_reconnect(struct sss_dp_pvt_ctx *pvt)
{
    struct resp_ctx *rctx;
    struct tevent_timer *te;
    struct timeval tv;
    struct sbus_method_ctx *sm_ctx;
    char *sbus_address;
    time_t now;
    int ret;

    now = time(NULL);

    /* reset retry if last reconnect was > 60 sec. ago */
    if (pvt->last_retry + 60 < now) pvt->retries = 0;
    if (pvt->retries >= 3) {
        DEBUG(4, ("Too many reconnect retries! Giving up\n"));
        return;
    }

    pvt->last_retry = now;
    pvt->retries++;

    rctx = pvt->rctx;

    ret = dp_get_sbus_address(rctx, rctx->cdb, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate data provider address.\n"));
        return;
    }

    ret = dp_init_sbus_methods(rctx, pvt->methods, &sm_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize SBUS methods.\n"));
        return;
    }

    ret = sbus_client_init(rctx, rctx->ev,
                           sbus_address, sm_ctx,
                           pvt, sss_dp_conn_destructor,
                           &rctx->dp_ctx);
    if (ret != EOK) {
        DEBUG(4, ("Failed to reconnect [%d(%s)]!\n", ret, strerror(ret)));

        tv.tv_sec = now +5;
        tv.tv_usec = 0;
        te = tevent_add_timer(rctx->ev, rctx, tv, sss_dp_reconnect, pvt);
        if (te == NULL) {
            DEBUG(4, ("Failed to add timed event! Giving up\n"));
        } else {
            DEBUG(4, ("Retrying in 5 seconds\n"));
        }
    }
}

static void sss_dp_reconnect(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval tv, void *data)
{
    struct sss_dp_pvt_ctx *pvt;

    pvt = talloc_get_type(data, struct sss_dp_pvt_ctx);

    sss_dp_conn_reconnect(pvt);
}

int sss_dp_conn_destructor(void *data)
{
    struct sss_dp_pvt_ctx *pvt;
    struct sbus_conn_ctx *scon;

    scon = talloc_get_type(data, struct sbus_conn_ctx);
    if (!scon) return 0;

    /* if this is a regular disconnect just quit */
    if (sbus_conn_disconnecting(scon)) return 0;

    pvt = talloc_get_type(sbus_conn_get_private_data(scon),
                          struct sss_dp_pvt_ctx);
    if (pvt) return 0;

    sss_dp_conn_reconnect(pvt);

    return 0;
}

int sss_dp_init(struct resp_ctx *rctx, struct sbus_method *dp_methods)
{
    struct sss_dp_pvt_ctx *pvt;

    pvt = talloc_zero(rctx, struct sss_dp_pvt_ctx);
    if (!pvt) return ENOMEM;

    pvt->rctx = rctx;
    pvt->methods = dp_methods;

    sss_dp_conn_reconnect(pvt);

    return EOK;
}


struct nss_dp_req {
    nss_dp_callback_t callback;
    void *callback_ctx;
    struct tevent_timer *te;
    DBusPendingCall *pending_reply;
};

static int nss_dp_req_destructor(void *ptr)
{
    struct nss_dp_req *req = talloc_get_type(ptr, struct nss_dp_req);

    if (req->pending_reply) {
        dbus_pending_call_cancel(req->pending_reply);
    }

    return 0;
}

static void nss_dp_send_acct_timeout(struct tevent_context *ev,
                                     struct tevent_timer *te,
                                     struct timeval t, void *data)
{
    struct nss_dp_req *ndp_req;
    dbus_uint16_t err_maj = DP_ERR_TIMEOUT;
    dbus_uint32_t err_min = EIO;
    const char *err_msg = "Request timed out";

    ndp_req = talloc_get_type(data, struct nss_dp_req);

    ndp_req->callback(err_maj, err_min, err_msg, ndp_req->callback_ctx);

    talloc_free(ndp_req);
}

static int nss_dp_get_reply(DBusPendingCall *pending,
                            dbus_uint16_t *err_maj,
                            dbus_uint32_t *err_min,
                            const char **err_msg);

static void nss_dp_send_acct_callback(DBusPendingCall *pending, void *ptr)
{
    struct nss_dp_req *ndp_req;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    const char *err_msg;
    int ret;

    ndp_req = talloc_get_type(ptr, struct nss_dp_req);

    /* free timeout event and remove request destructor */
    talloc_free(ndp_req->te);
    talloc_set_destructor(ndp_req, NULL);

    ret = nss_dp_get_reply(pending, &err_maj, &err_min, &err_msg);
    if (ret != EOK) {
        err_maj = DP_ERR_FATAL;
        err_min = ret;
        err_msg = "Failed to get reply from Data Provider";
    }

    ndp_req->callback(err_maj, err_min, err_msg, ndp_req->callback_ctx);

    talloc_free(ndp_req);
}

int nss_dp_send_acct_req(struct resp_ctx *rctx, TALLOC_CTX *memctx,
                         nss_dp_callback_t callback, void *callback_ctx,
                         int timeout, const char *domain, int type,
                         const char *opt_name, uint32_t opt_id)
{
    struct nss_dp_req *ndp_req;
    DBusMessage *msg;
    DBusPendingCall *pending_reply;
    DBusConnection *conn;
    dbus_bool_t ret;
    uint32_t be_type;
    const char *attrs = "core";
    char *filter;
    struct timeval tv;

    /* either, or, not both */
    if (opt_name && opt_id) {
        return EINVAL;
    }

    if (!domain) {
        return EINVAL;
    }

    switch (type) {
    case NSS_DP_USER:
        be_type = BE_REQ_USER;
        break;
    case NSS_DP_GROUP:
        be_type = BE_REQ_GROUP;
        break;
    case NSS_DP_INITGROUPS:
        be_type = BE_REQ_INITGROUPS;
        break;
    default:
        return EINVAL;
    }

    if (opt_name) {
        filter = talloc_asprintf(memctx, "name=%s", opt_name);
    } else if (opt_id) {
        filter = talloc_asprintf(memctx, "idnumber=%u", opt_id);
    } else {
        filter = talloc_strdup(memctx, "name=*");
    }
    if (!filter) {
        return ENOMEM;
    }

    /* double check dp_ctx has actually been initialized.
     * in some pathological cases it may happen that nss starts up before
     * dp connection code is actually able to establish a connection.
     */
    if (!rctx->dp_ctx) {
        DEBUG(1, ("The Data Provider connection is not available yet!"
                  " This maybe a bug, it shouldn't happen!\n"));
        return EIO;
    }
    conn = sbus_get_connection(rctx->dp_ctx->scon_ctx);

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_CLI_PATH,
                                       DP_CLI_INTERFACE,
                                       DP_SRV_METHOD_GETACCTINFO);
    if (msg == NULL) {
        DEBUG(0,("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending request for [%s][%u][%s][%s]\n",
              domain, be_type, attrs, filter));

    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_STRING, &domain,
                                   DBUS_TYPE_UINT32, &be_type,
                                   DBUS_TYPE_STRING, &attrs,
                                   DBUS_TYPE_STRING, &filter,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1,("Failed to build message\n"));
        return EIO;
    }

    ret = dbus_connection_send_with_reply(conn, msg, &pending_reply,
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

    ndp_req = talloc_zero(memctx, struct nss_dp_req);
    if (!ndp_req) {
        dbus_message_unref(msg);
        return ENOMEM;
    }
    ndp_req->callback = callback;
    ndp_req->callback_ctx = callback_ctx;

    /* set up destructor */
    ndp_req->pending_reply = pending_reply;
    talloc_set_destructor((TALLOC_CTX *)ndp_req, nss_dp_req_destructor);

    /* setup the timeout handler */
    gettimeofday(&tv, NULL);
    tv.tv_sec += timeout/1000;
    tv.tv_usec += (timeout%1000) * 1000;
    ndp_req->te = tevent_add_timer(rctx->ev, memctx, tv,
                                   nss_dp_send_acct_timeout, ndp_req);

    /* Set up the reply handler */
    dbus_pending_call_set_notify(pending_reply,
                                 nss_dp_send_acct_callback,
                                 ndp_req, NULL);
    dbus_message_unref(msg);

    return EOK;
}

static int nss_dp_get_reply(DBusPendingCall *pending,
                            dbus_uint16_t *err_maj,
                            dbus_uint32_t *err_min,
                            const char **err_msg)
{
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_bool_t ret;
    int type;
    int err = EOK;

    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(0, ("Severe error. A reply callback was called but no reply was received and no timeout occurred\n"));

        /* FIXME: Destroy this connection ? */
        err = EIO;
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dbus_message_get_args(reply, &dbus_error,
                                    DBUS_TYPE_UINT16, err_maj,
                                    DBUS_TYPE_UINT32, err_min,
                                    DBUS_TYPE_STRING, err_msg,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1,("Filed to parse message\n"));
            /* FIXME: Destroy this connection ? */
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            err = EIO;
            goto done;
        }

        DEBUG(4, ("Got reply (%u, %u, %s) from Data Provider\n",
                  (unsigned int)*err_maj, (unsigned int)*err_min, *err_msg));

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(0,("The Data Provider returned an error [%s]\n",
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

        /* FIXME: Destroy this connection ? */
        err = EIO;
    }

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);

    return err;
}

