/*
    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <time.h>
#include "util/util.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "sbus/sbus_client.h"

struct sss_dp_req;

struct sss_dp_callback {
    struct sss_dp_callback *prev;
    struct sss_dp_callback *next;

    struct tevent_req *req;
    struct sss_dp_req *sdp_req;
};

struct sss_dp_req {
    struct resp_ctx *rctx;
    struct tevent_context *ev;
    DBusPendingCall *pending_reply;

    hash_key_t *key;

    struct tevent_timer *tev;
    struct sss_dp_callback *cb_list;

    dbus_uint16_t dp_err;
    dbus_uint32_t dp_ret;
    char *err_msg;
};

static int sss_dp_callback_destructor(void *ptr)
{
    struct sss_dp_callback *cb =
            talloc_get_type(ptr, struct sss_dp_callback);

    DLIST_REMOVE(cb->sdp_req->cb_list, cb);

    return EOK;
}

static int sss_dp_req_destructor(void *ptr)
{
    struct sss_dp_callback *cb;
    struct sss_dp_req *sdp_req = talloc_get_type(ptr, struct sss_dp_req);
    struct sss_dp_req_state *state;
    int hret;

    /* Cancel Dbus pending reply if still pending */
    if (sdp_req->pending_reply) {
        dbus_pending_call_cancel(sdp_req->pending_reply);
        sdp_req->pending_reply = NULL;
    }

    /* If there are callbacks that haven't been invoked, return
     * an error now.
     */
    while((cb = sdp_req->cb_list) != NULL) {
        state = tevent_req_data(cb->req, struct sss_dp_req_state);
        state->dp_err = DP_ERR_FATAL;
        state->dp_ret = EIO;

        /* tevent_req_done/error will free cb */
        tevent_req_error(cb->req, EIO);

        /* Freeing the cb removes it from the cb_list.
         * Therefore, the cb_list should now be pointing
         * at a new callback. If it's not, it means the
         * callback handler didn't free cb and may leak
         * memory. Be paranoid and protect against this
         * situation.
         */
        if (cb == sdp_req->cb_list) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("BUG: a callback did not free its request. "
                   "May leak memory\n"));
            /* Skip to the next since a memory leak is non-fatal */
            sdp_req->cb_list = sdp_req->cb_list->next;
        }
    }

    /* Destroy the hash entry */
    DEBUG(SSSDBG_TRACE_FUNC, ("Deleting request: [%s]\n", sdp_req->key->str));
    hret = hash_delete(sdp_req->rctx->dp_request_table, sdp_req->key);
    if (hret != HASH_SUCCESS) {
        /* This should never happen */
        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("BUG: Could not clear [%d:%d:%s] from request queue: [%s]\n",
               sdp_req->key->type, sdp_req->key->ul, sdp_req->key->str,
               hash_error_string(hret)));
        return -1;
    }

    return 0;
}

void handle_requests_after_reconnect(struct resp_ctx *rctx)
{
    int ret;
    hash_value_t *values;
    unsigned long count, i;
    struct sss_dp_req *sdp_req;

    if (!rctx->dp_request_table) {
        DEBUG(7, ("No requests to handle after reconnect\n"));
        return;
    }

    ret = hash_values(rctx->dp_request_table, &count, &values);
    if (ret != HASH_SUCCESS) {
        DEBUG(1, ("hash_values failed, "
                  "not all request might be handled after reconnect.\n"));
        return;
    }

    DEBUG(7, ("Will handle %lu requests after reconnect\n", count));
    for (i=0; i<count; i++) {
        sdp_req = talloc_get_type(values[i].ptr, struct sss_dp_req);
        talloc_free(sdp_req);
    }
}

static int sss_dp_get_reply(DBusPendingCall *pending,
                            dbus_uint16_t *dp_err,
                            dbus_uint32_t *dp_ret,
                            char **err_msg)
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
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Severe error. A reply callback was called but no reply "
               "was received and no timeout occurred\n"));

        /* FIXME: Destroy this connection ? */
        err = EIO;
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dbus_message_get_args(reply, &dbus_error,
                                    DBUS_TYPE_UINT16, dp_err,
                                    DBUS_TYPE_UINT32, dp_ret,
                                    DBUS_TYPE_STRING, err_msg,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1,("Failed to parse message\n"));
            /* FIXME: Destroy this connection ? */
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            err = EIO;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_LIBS,
              ("Got reply from Data Provider - "
               "DP error code: %u errno: %u error message: %s\n",
              (unsigned int)*dp_err, (unsigned int)*dp_ret,
              *err_msg ? *err_msg : "none"));
        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        if (strcmp(dbus_message_get_error_name(reply),
                   DBUS_ERROR_NO_REPLY) == 0) {
            err = ETIME;
            goto done;
        }
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

static struct tevent_req *
sss_dp_internal_get_send(struct resp_ctx *rctx,
                         hash_key_t *key,
                         struct sss_domain_info *dom,
                         DBusMessage *msg);

static void
sss_dp_req_done(struct tevent_req *sidereq);

errno_t
sss_dp_issue_request(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                     const char *strkey, struct sss_domain_info *dom,
                     dbus_msg_constructor msg_create, void *pvt,
                     struct tevent_req *nreq)
{
    int hret;
    hash_value_t value;
    hash_key_t *key;
    struct tevent_req *sidereq;
    struct sss_dp_req *sdp_req;
    struct sss_dp_callback *cb;
    DBusMessage *msg;
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    key = talloc(tmp_ctx, hash_key_t);
    if (!key) {
        ret = ENOMEM;
        goto fail;
    }

    key->type = HASH_KEY_STRING;
    key->str = talloc_asprintf(key, "%p:%s", msg_create, strkey);
    if (!key->str) {
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Issuing request for [%s]\n", key->str));

    /* Check the hash for existing references to this request */
    hret = hash_lookup(rctx->dp_request_table, key, &value);
    switch (hret) {
    case HASH_SUCCESS:
        /* Request already in progress */
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Identical request in progress: [%s]\n", key->str));
        break;

    case HASH_ERROR_KEY_NOT_FOUND:
        /* No such request in progress
         * Create a new request
         */
        msg = msg_create(pvt);
        if (!msg) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot create D-Bus message\n"));
            ret = EIO;
            goto fail;
        }

        value.type = HASH_VALUE_PTR;
        sidereq = sss_dp_internal_get_send(rctx, key, dom, msg);
        dbus_message_unref(msg);
        if (!sidereq) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot send D-Bus message\n"));
            ret = EIO;
            goto fail;
        }
        tevent_req_set_callback(sidereq, sss_dp_req_done, NULL);

        /* We should now be able to find the sdp_req in the hash table */
        hret = hash_lookup(rctx->dp_request_table, key, &value);
        if (hret != HASH_SUCCESS) {
            /* Something must have gone wrong with creating the request */
            DEBUG(SSSDBG_CRIT_FAILURE, ("The request has disappeared?\n"));
            ret = EIO;
            goto fail;
        }
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not query request list (%s)\n",
               hash_error_string(hret)));
        ret = EIO;
        goto fail;
    }

    /* Register this request for results */
    sdp_req = talloc_get_type(value.ptr, struct sss_dp_req);
    if (!sdp_req) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not retrieve DP request context\n"));
        ret = EIO;
        goto fail;
    }

    cb = talloc_zero(mem_ctx, struct sss_dp_callback);
    if (!cb) {
        ret = ENOMEM;
        goto fail;
    }

    cb->req = nreq;
    cb->sdp_req = sdp_req;

    /* Add it to the list of requests to call */
    DLIST_ADD_END(sdp_req->cb_list, cb,
                  struct sss_dp_callback *);
    talloc_set_destructor((TALLOC_CTX *)cb,
                          sss_dp_callback_destructor);

    ret = EOK;
fail:
    talloc_free(tmp_ctx);
    return ret;
}

static void
sss_dp_req_done(struct tevent_req *sidereq)
{
    /* Nothing to do here. The callbacks have already been invoked */
    talloc_zfree(sidereq);
}

errno_t
sss_dp_req_recv(TALLOC_CTX *mem_ctx,
                struct tevent_req *sidereq,
                dbus_uint16_t *dp_err,
                dbus_uint32_t *dp_ret,
                char **err_msg)
{
    struct sss_dp_req_state *state =
            tevent_req_data(sidereq, struct sss_dp_req_state);

    enum tevent_req_state TRROEstate;
    uint64_t TRROEerr;

    *dp_err = state->dp_err;
    *dp_ret = state->dp_ret;
    *err_msg = talloc_steal(mem_ctx, state->err_msg);

    if (tevent_req_is_error(sidereq, &TRROEstate, &TRROEerr)) {
        if (TRROEstate == TEVENT_REQ_USER_ERROR) {
            *dp_err = DP_ERR_FATAL;
            *dp_ret = TRROEerr;
        } else {
            return EIO;
        }
    }

    return EOK;
}

/* Send a request to the data provider
 * Once this function is called, the communication
 * with the data provider will always run to
 * completion. Freeing the returned tevent_req will
 * cancel the notification of completion, but not
 * the data provider action.
 */
static DBusMessage *sss_dp_get_account_msg(void *pvt);

struct sss_dp_account_info {
    struct sss_domain_info *dom;

    bool fast_reply;
    enum sss_dp_acct_type type;
    const char *opt_name;
    const char *extra;
    uint32_t opt_id;
};

struct tevent_req *
sss_dp_get_account_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        enum sss_dp_acct_type type,
                        const char *opt_name,
                        uint32_t opt_id,
                        const char *extra)
{
    errno_t ret;
    struct tevent_req *req;
    struct sss_dp_account_info *info;
    struct sss_dp_req_state *state;
    char *key;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_req_state);
    if (!req) {
        return NULL;
    }

    /* either, or, not both */
    if (opt_name && opt_id) {
        ret = EINVAL;
        goto error;
    }

    if (!dom) {
        ret = EINVAL;
        goto error;
    }

    info = talloc_zero(state, struct sss_dp_account_info);
    info->fast_reply = fast_reply;
    info->type = type;
    info->opt_name = opt_name;
    info->opt_id = opt_id;
    info->extra = extra;
    info->dom = dom;

    if (opt_name) {
        if (extra) {
            key = talloc_asprintf(state, "%d:%s:%s@%s",
                                  type, opt_name, extra, dom->name);
        } else {
            key = talloc_asprintf(state, "%d:%s@%s",
                                  type, opt_name, dom->name);
        }
    } else if (opt_id) {
        if (extra) {
            key = talloc_asprintf(state, "%d:%d:%s@%s",
                                  type, opt_id, extra, dom->name);
        } else {
            key = talloc_asprintf(state, "%d:%d@%s", type, opt_id, dom->name);
        }
    } else {
        key = talloc_asprintf(state, "%d:*@%s", type, dom->name);
    }
    if (!key) {
        ret = ENOMEM;
        goto error;
    }

    ret = sss_dp_issue_request(state, rctx, key, dom, sss_dp_get_account_msg,
                               info, req);
    talloc_free(key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not issue DP request [%d]: %s\n",
               ret, strerror(ret)));
        goto error;
    }

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static DBusMessage *
sss_dp_get_account_msg(void *pvt)
{
    DBusMessage *msg;
    dbus_bool_t dbret;
    struct sss_dp_account_info *info;
    uint32_t be_type;
    uint32_t attrs = BE_ATTR_CORE;
    char *filter;
    const char *dp_method;

    info = talloc_get_type(pvt, struct sss_dp_account_info);

    switch (info->type) {
        case SSS_DP_USER:
            be_type = BE_REQ_USER;
            dp_method = DP_METHOD_GETACCTINFO;
            break;
        case SSS_DP_GROUP:
            be_type = BE_REQ_GROUP;
            dp_method = DP_METHOD_GETACCTINFO;
            break;
        case SSS_DP_INITGROUPS:
            be_type = BE_REQ_INITGROUPS;
            dp_method = DP_METHOD_GETACCTINFO;
            break;
        case SSS_DP_NETGR:
            be_type = BE_REQ_NETGROUP;
            dp_method = DP_METHOD_GETACCTINFO;
            break;
        case SSS_DP_SERVICES:
            be_type = BE_REQ_SERVICES;
            dp_method = DP_METHOD_GETACCTINFO;
            break;
        case SSS_DP_HOST:
            be_type = 0;
            dp_method = DP_METHOD_HOSTHANDLER;
            break;
    }

    if (info->fast_reply) {
        be_type |= BE_REQ_FAST;
    }

    if (info->opt_name) {
        if (info->extra) {
            filter = talloc_asprintf(info, "name=%s:%s",
                                     info->opt_name, info->extra);
        } else {
            filter = talloc_asprintf(info, "name=%s", info->opt_name);
        }
    } else if (info->opt_id) {
        if (info->extra) {
            filter = talloc_asprintf(info, "idnumber=%u:%s",
                                     info->opt_id, info->extra);
        } else {
            filter = talloc_asprintf(info, "idnumber=%u", info->opt_id);
        }
    } else {
        filter = talloc_strdup(info, ENUM_INDICATOR);
    }
    if (!filter) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory?!\n"));
        return NULL;
    }

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       dp_method);
    if (msg == NULL) {
        talloc_free(filter);
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory?!\n"));
        return NULL;
    }

    /* create the message */
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Creating request for [%s][%u][%d][%s]\n",
           info->dom->name, be_type, attrs, filter));

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_UINT32, &be_type,
                                     DBUS_TYPE_UINT32, &attrs,
                                     DBUS_TYPE_STRING, &filter,
                                     DBUS_TYPE_INVALID);
    talloc_free(filter);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to build message\n"));
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

errno_t
sss_dp_get_account_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *dp_err,
                        dbus_uint32_t *dp_ret,
                        char **err_msg)
{
    return sss_dp_req_recv(mem_ctx, req, dp_err, dp_ret, err_msg);
}

struct dp_internal_get_state {
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;

    struct sss_dp_req *sdp_req;
    DBusPendingCall *pending_reply;
};

static void sss_dp_internal_get_done(DBusPendingCall *pending, void *ptr);

static struct tevent_req *
sss_dp_internal_get_send(struct resp_ctx *rctx,
                         hash_key_t *key,
                         struct sss_domain_info *dom,
                         DBusMessage *msg)
{
    errno_t ret;
    int hret;
    struct tevent_req *req;
    struct dp_internal_get_state *state;
    struct be_conn *be_conn;
    hash_value_t value;

    /* Internal requests need to be allocated on the responder context
     * so that they don't go away if a client disconnects. The worst-
     * case scenario here is that the cache is updated without any
     * client expecting a response.
     */
    req = tevent_req_create(rctx,
                            &state,
                            struct dp_internal_get_state);
    if (!req)  return NULL;

    state->rctx = rctx;
    state->dom = dom;

    state->sdp_req = talloc_zero(state, struct sss_dp_req);
    if (!state->sdp_req) {
        ret = ENOMEM;
        goto error;
    }
    state->sdp_req->rctx = rctx;
    state->sdp_req->ev = rctx->ev;

    /* Copy the key to use when calling the destructor
     * It needs to be a copy because the original request
     * might be freed if it no longer cares about the reply.
     */
    state->sdp_req->key = talloc_steal(state->sdp_req, key);

    /* double check dp_ctx has actually been initialized.
     * in some pathological cases it may happen that nss starts up before
     * dp connection code is actually able to establish a connection.
     */
    ret = sss_dp_get_domain_conn(rctx, dom->name, &be_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("BUG: The Data Provider connection for %s is not available!",
               dom->name));
        ret = EIO;
        goto error;
    }

    ret = sbus_conn_send(be_conn->conn, msg,
                         SSS_CLI_SOCKET_TIMEOUT / 2,
                         sss_dp_internal_get_done,
                         req,
                         &state->sdp_req->pending_reply);
    if (ret != EOK) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         */
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("D-BUS send failed.\n"));
        ret = EIO;
        goto error;
    }

    /* Add this sdp_req to the hash table */
    value.type = HASH_VALUE_PTR;
    value.ptr = state->sdp_req;

    DEBUG(SSSDBG_TRACE_FUNC, ("Entering request [%s]\n", key->str));
    hret = hash_enter(rctx->dp_request_table, key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not store request query (%s)\n",
               hash_error_string(hret)));
        ret = EIO;
        goto error;
    }
    talloc_set_destructor((TALLOC_CTX *)state->sdp_req,
                          sss_dp_req_destructor);

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static void sss_dp_internal_get_done(DBusPendingCall *pending, void *ptr)
{
    int ret;
    struct tevent_req *req;
    struct sss_dp_req *sdp_req;
    struct sss_dp_callback *cb;
    struct dp_internal_get_state *state;
    struct sss_dp_req_state *cb_state;

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct dp_internal_get_state);
    sdp_req = state->sdp_req;

    /* prevent trying to cancel a reply that we already received */
    sdp_req->pending_reply = NULL;

    ret = sss_dp_get_reply(pending,
                           &sdp_req->dp_err,
                           &sdp_req->dp_ret,
                           &sdp_req->err_msg);
    if (ret != EOK) {
        if (ret == ETIME) {
            sdp_req->dp_err = DP_ERR_TIMEOUT;
            sdp_req->dp_ret = ret;
            sdp_req->err_msg = talloc_strdup(sdp_req, "Request timed out");
        }
        else {
            sdp_req->dp_err = DP_ERR_FATAL;
            sdp_req->dp_ret = ret;
            sdp_req->err_msg =
                talloc_strdup(sdp_req,
                              "Failed to get reply from Data Provider");
        }
    }

    /* Check whether we need to issue any callbacks */
    while ((cb = sdp_req->cb_list) != NULL) {
        cb_state = tevent_req_data(cb->req, struct sss_dp_req_state);
        cb_state->dp_err = sdp_req->dp_err;
        cb_state->dp_ret = sdp_req->dp_ret;
        cb_state->err_msg = talloc_strdup(cb_state, sdp_req->err_msg);
        /* Don't bother checking for NULL. If it fails due to ENOMEM,
         * we can't really handle it anyway.
         */

        /* tevent_req_done/error will free cb */
        if (ret == EOK) {
            tevent_req_done(cb->req);
        } else {
            tevent_req_error(cb->req, ret);
        }

        /* Freeing the cb removes it from the cb_list.
         * Therefore, the cb_list should now be pointing
         * at a new callback. If it's not, it means the
         * callback handler didn't free cb and may leak
         * memory. Be paranoid and protect against this
         * situation.
         */
        if (cb == sdp_req->cb_list) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("BUG: a callback did not free its request. "
                   "May leak memory\n"));
            /* Skip to the next since a memory leak is non-fatal */
            sdp_req->cb_list = sdp_req->cb_list->next;
        }
    }

    /* We're done with this request. Free the sdp_req
     * This will clean up the hash table entry as well
     */
    talloc_zfree(sdp_req);
}
