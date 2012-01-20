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

hash_table_t *dp_requests = NULL;

struct sss_dp_req;

struct dp_get_account_state {
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    const char *opt_name;
    uint32_t opt_id;
    hash_key_t *key;

    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;
};

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

    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
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
    struct dp_get_account_state *state;

    /* Cancel Dbus pending reply if still pending */
    if (sdp_req->pending_reply) {
        dbus_pending_call_cancel(sdp_req->pending_reply);
        sdp_req->pending_reply = NULL;
    }

    /* If there are callbacks that haven't been invoked, return
     * an error now.
     */
    DLIST_FOR_EACH(cb, sdp_req->cb_list) {
        state = tevent_req_data(cb->req, struct dp_get_account_state);
        state->err_maj = DP_ERR_FATAL;
        state->err_min = EIO;
        tevent_req_error(cb->req, EIO);
    }

    /* Destroy the hash entry */
    int hret = hash_delete(sdp_req->rctx->dp_request_table, sdp_req->key);
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

void handle_requests_after_reconnect(void)
{
    int ret;
    hash_value_t *values;
    unsigned long count, i;
    struct sss_dp_req *sdp_req;

    if (!dp_requests) {
        DEBUG(7, ("No requests to handle after reconnect\n"));
        return;
    }

    ret = hash_values(dp_requests, &count, &values);
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
                            dbus_uint16_t *err_maj,
                            dbus_uint32_t *err_min,
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
                                    DBUS_TYPE_UINT16, err_maj,
                                    DBUS_TYPE_UINT32, err_min,
                                    DBUS_TYPE_STRING, err_msg,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1,("Failed to parse message\n"));
            /* FIXME: Destroy this connection ? */
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            err = EIO;
            goto done;
        }
        DEBUG(4, ("Got reply (%u, %u, %s) from Data Provider\n",
                  (unsigned int)*err_maj, (unsigned int)*err_min, *err_msg));

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
sss_dp_get_account_int_send(struct resp_ctx *rctx,
                            hash_key_t *key,
                            struct sss_domain_info *dom,
                            uint32_t be_type,
                            const char *filter);

static void
sss_dp_get_account_done(struct tevent_req *subreq);

static errno_t
sss_dp_get_account_int_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *err_maj,
                        dbus_uint32_t *err_min,
                        char **err_msg);


/* Send a request to the data provider
 * Once this function is called, the communication
 * with the data provider will always run to
 * completion. Freeing the returned tevent_req will
 * cancel the notification of completion, but not
 * the data provider action.
 */
struct tevent_req *
sss_dp_get_account_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        int type,
                        const char *opt_name,
                        uint32_t opt_id,
                        const char *extra)
{
    errno_t ret;
    int hret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct dp_get_account_state *state;
    struct sss_dp_req *sdp_req;
    struct sss_dp_callback *cb;
    char *filter;
    uint32_t be_type;
    hash_value_t value;

    req = tevent_req_create(mem_ctx, &state, struct dp_get_account_state);
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

    state->rctx = rctx;
    state->dom = dom;

    switch (type) {
    case SSS_DP_USER:
        be_type = BE_REQ_USER;
        break;
    case SSS_DP_GROUP:
        be_type = BE_REQ_GROUP;
        break;
    case SSS_DP_INITGROUPS:
        be_type = BE_REQ_INITGROUPS;
        break;
    case SSS_DP_NETGR:
        be_type = BE_REQ_NETGROUP;
        break;
    default:
        ret = EINVAL;
        goto error;
    }

    if (fast_reply) {
        be_type |= BE_REQ_FAST;
    }

    /* Check whether there's already an identical request in progress */

    state->key = talloc(state, hash_key_t);
    if (!state->key) {
        ret = ENOMEM;
        goto error;
    }

    state->key->type = HASH_KEY_STRING;

    if (opt_name) {
        if (extra) {
            filter = talloc_asprintf(state, "name=%s:%s",
                                     opt_name, extra);
            state->key->str = talloc_asprintf(state->key, "%d:%s:%s@%s",
                                              type, opt_name,
                                              extra, dom->name);
        } else {
            filter = talloc_asprintf(state, "name=%s", opt_name);
            state->key->str = talloc_asprintf(state->key, "%d:%s@%s",
                                              type, opt_name, dom->name);
        }
    } else if (opt_id) {
        if (extra) {
            filter = talloc_asprintf(state, "idnumber=%u:%s",
                                     opt_id, extra);
            state->key->str = talloc_asprintf(state->key, "%d:%d:%s@%s",
                                              type, opt_id,
                                              extra, dom->name);
        } else {
            filter = talloc_asprintf(state, "idnumber=%u", opt_id);
            state->key->str = talloc_asprintf(state->key, "%d:%d@%s",
                                              type, opt_id, dom->name);
        }
    } else {
        filter = talloc_strdup(state, ENUM_INDICATOR);
        state->key->str = talloc_asprintf(state->key, "%d:*@%s",
                                          type, dom->name);
    }
    if (!filter || !state->key->str) {
        ret = ENOMEM;
    }

    /* Check the hash for existing references to this request */
    hret = hash_lookup(rctx->dp_request_table, state->key, &value);
    switch (hret) {
    case HASH_SUCCESS:
        /* Request already in progress */
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Identical request in progress: [%s]\n", state->key->str));
        break;

    case HASH_ERROR_KEY_NOT_FOUND:
        /* No such request in progress
         * Create a new request
         */

        value.type = HASH_VALUE_PTR;
        subreq = sss_dp_get_account_int_send(rctx, state->key, dom,
                                             be_type, filter);
        if (!subreq) {
            ret = ENOMEM;
            goto error;
        }
        tevent_req_set_callback(subreq, sss_dp_get_account_done, NULL);

        /* We should now be able to find the sdp_req in the hash table */
        hret = hash_lookup(rctx->dp_request_table, state->key, &value);
        if (hret != HASH_SUCCESS) {
            /* Something must have gone wrong with creating the request */
            talloc_zfree(subreq);
            ret = EIO;
            goto error;
        }

        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not query request list (%s)\n",
               hash_error_string(hret)));
        ret = EIO;
        goto error;
    }

    /* Register this request for results */
    sdp_req = talloc_get_type(value.ptr, struct sss_dp_req);
    if (!sdp_req) {
        DEBUG(0, ("Could not retrieve DP request context\n"));
        ret = EIO;
        goto error;
    }

    cb = talloc_zero(state, struct sss_dp_callback);
    if (!cb) {
        ret = ENOMEM;
        goto error;
    }

    cb->req = req;
    cb->sdp_req = sdp_req;

    /* Add it to the list of requests to call */
    DLIST_ADD_END(sdp_req->cb_list, cb,
                  struct sss_dp_callback *);
    talloc_set_destructor((TALLOC_CTX *)cb,
                          sss_dp_callback_destructor);

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static void
sss_dp_get_account_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct dp_get_account_state *state =
            tevent_req_data(req, struct dp_get_account_state);

    ret = sss_dp_get_account_int_recv(state, req,
                                      &state->err_maj,
                                      &state->err_min,
                                      &state->err_msg);
    if (ret != EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

errno_t
sss_dp_get_account_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *err_maj,
                        dbus_uint32_t *err_min,
                        char **err_msg)
{
    struct dp_get_account_state *state =
            tevent_req_data(req, struct dp_get_account_state);

    enum tevent_req_state TRROEstate;
    uint64_t TRROEerr;

    *err_maj = state->err_maj;
    *err_min = state->err_min;
    *err_msg = talloc_steal(mem_ctx, state->err_msg);

    if (tevent_req_is_error(req, &TRROEstate, &TRROEerr)) {
        if (TRROEstate == TEVENT_REQ_USER_ERROR) {
            *err_maj = DP_ERR_FATAL;
            *err_min = TRROEerr;
        } else {
            return EIO;
        }
    }

    return EOK;
}

struct dp_get_account_int_state {
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    uint32_t be_type;
    const char *filter;

    struct sss_dp_req *sdp_req;
    DBusPendingCall *pending_reply;
};

static void sss_dp_get_account_int_done(DBusPendingCall *pending, void *ptr);

static struct tevent_req *
sss_dp_get_account_int_send(struct resp_ctx *rctx,
                            hash_key_t *key,
                            struct sss_domain_info *dom,
                            uint32_t be_type,
                            const char *filter)
{
    errno_t ret;
    int hret;
    struct tevent_req *req;
    struct dp_get_account_int_state *state;
    struct be_conn *be_conn;
    DBusMessage *msg;
    dbus_bool_t dbret;
    bool msg_created = false;
    hash_value_t value;
    uint32_t attrs = BE_ATTR_CORE;

    /* Internal requests need to be allocated on the responder context
     * so that they don't go away if a client disconnects. The worst-
     * case scenario here is that the cache is updated without any
     * client expecting a response.
     */
    req = tevent_req_create(rctx,
                            &state,
                            struct dp_get_account_int_state);
    if (!req)  return NULL;

    state->rctx = rctx;
    state->dom = dom;
    state->be_type = be_type;
    state->filter = filter;

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

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_GETACCTINFO);
    if (msg == NULL) {
        DEBUG(0,("Out of memory?!\n"));
        ret = ENOMEM;
        goto error;
    }
    msg_created = true;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Sending request for [%s][%u][%d][%s]\n",
           dom->name, be_type, attrs, filter));

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_UINT32, &be_type,
                                     DBUS_TYPE_UINT32, &attrs,
                                     DBUS_TYPE_STRING, &filter,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(1,("Failed to build message\n"));
        ret = EIO;
        goto error;
    }

    ret = sbus_conn_send(be_conn->conn, msg,
                         SSS_CLI_SOCKET_TIMEOUT / 2,
                         sss_dp_get_account_int_done,
                         req,
                         &state->sdp_req->pending_reply);
    dbus_message_unref(msg);
    msg_created = false;
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
    if (msg_created) {
        dbus_message_unref(msg);
    }

    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static void sss_dp_get_account_int_done(DBusPendingCall *pending, void *ptr)
{
    int ret;
    struct tevent_req *req;
    struct sss_dp_req *sdp_req;
    struct sss_dp_callback *cb, *prevcb = NULL;
    struct dp_get_account_int_state *state;
    struct dp_get_account_state *cb_state;

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct dp_get_account_int_state);
    sdp_req = state->sdp_req;

    /* prevent trying to cancel a reply that we already received */
    sdp_req->pending_reply = NULL;

    ret = sss_dp_get_reply(pending,
                           &sdp_req->err_maj,
                           &sdp_req->err_min,
                           &sdp_req->err_msg);
    if (ret != EOK) {
        if (ret == ETIME) {
            sdp_req->err_maj = DP_ERR_TIMEOUT;
            sdp_req->err_min = ret;
            sdp_req->err_msg = talloc_strdup(sdp_req, "Request timed out");
        }
        else {
            sdp_req->err_maj = DP_ERR_FATAL;
            sdp_req->err_min = ret;
            sdp_req->err_msg =
                talloc_strdup(sdp_req,
                              "Failed to get reply from Data Provider");
        }
    }

    /* Check whether we need to issue any callbacks */
    DLIST_FOR_EACH(cb, sdp_req->cb_list) {
        cb_state = tevent_req_data(cb->req, struct dp_get_account_state);
        cb_state->err_maj = sdp_req->err_maj;
        cb_state->err_min = sdp_req->err_min;
        cb_state->err_msg = talloc_strdup(cb_state, sdp_req->err_msg);
        /* Don't bother checking for NULL. If it fails due to ENOMEM,
         * we can't really handle it annyway.
         */

        if (ret == EOK) {
            tevent_req_done(cb->req);
        } else {
            tevent_req_error(cb->req, ret);
        }

        /* Freeing the request removes it from the list */
        if (prevcb) talloc_free(prevcb);
        prevcb = cb;
    }
    talloc_free(prevcb);

    /* We're done with this request. Free the sdp_req
     * This will clean up the hash table entry as well
     */
    talloc_zfree(sdp_req);
}

static errno_t
sss_dp_get_account_int_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *err_maj,
                        dbus_uint32_t *err_min,
                        char **err_msg)
{
    struct dp_get_account_int_state *state =
            tevent_req_data(req, struct dp_get_account_int_state);

    enum tevent_req_state TRROEstate;
    uint64_t TRROEerr;

    *err_maj = state->sdp_req->err_maj;
    *err_min = state->sdp_req->err_min;
    *err_msg = talloc_steal(mem_ctx, state->sdp_req->err_msg);

    if (tevent_req_is_error(req, &TRROEstate, &TRROEerr)) {
        if (TRROEstate == TEVENT_REQ_USER_ERROR) {
            *err_maj = DP_ERR_FATAL;
            *err_min = TRROEerr;
        } else {
            return EIO;
        }
    }

    return EOK;
}
