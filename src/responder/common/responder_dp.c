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

struct sss_dp_callback {
    struct sss_dp_callback *prev;
    struct sss_dp_callback *next;

    struct sss_dp_req *sdp_req;

    sss_dp_callback_t callback;
    void *callback_ctx;
};

struct sss_dp_req {
    struct tevent_context *ev;
    DBusPendingCall *pending_reply;

    char *key;

    struct tevent_timer *tev;
    struct sss_dp_callback *cb_list;

    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;
};

static int sss_dp_callback_destructor(void *ptr)
{
    struct sss_dp_callback *cb = talloc_get_type(ptr, struct sss_dp_callback);

    DLIST_REMOVE(cb->sdp_req->cb_list, cb);

    return EOK;
}

static int sss_dp_req_destructor(void *ptr)
{
    struct sss_dp_req *sdp_req = talloc_get_type(ptr, struct sss_dp_req);
    struct sss_dp_callback *cb, *next;
    hash_key_t key;

    /* Cancel Dbus pending reply if still pending */
    if (sdp_req->pending_reply) {
        dbus_pending_call_cancel(sdp_req->pending_reply);
        sdp_req->pending_reply = NULL;
    }

    /* Destroy the hash entry */
    key.type = HASH_KEY_STRING;
    key.str = sdp_req->key;
    int hret = hash_delete(dp_requests, &key);
    if (hret != HASH_SUCCESS) {
        /* This should never happen */
        DEBUG(0, ("Could not clear entry from request queue\n"));
    }

    /* Free any remaining callback */
    if (sdp_req->err_maj == DP_ERR_OK) {
        sdp_req->err_maj = DP_ERR_FATAL;
        sdp_req->err_min = EIO;
        sdp_req->err_msg = discard_const_p(char, "Internal Error");
    }

    cb = sdp_req->cb_list;
    while (cb) {
        cb->callback(sdp_req->err_maj,
                     sdp_req->err_min,
                     sdp_req->err_msg,
                     cb->callback_ctx);
        next = cb->next;
        talloc_free(cb);
        cb = next;
    }

    return 0;
}

static void sdp_req_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t, void *ptr)
{
    struct sss_dp_req *sdp_req = talloc_get_type(ptr, struct sss_dp_req);

    sdp_req->err_maj = DP_ERR_FATAL;
    sdp_req->err_min = ETIMEDOUT;
    sdp_req->err_msg = discard_const_p(char, "Timed out");

    /* steal te on NULL because it will be freed as soon as the handler
     * returns. Causing a double free if we don't, as te is allocated on
     * sdp_req and we are just going to free it */
    talloc_steal(NULL, te);

    talloc_free(sdp_req);
}

static int sss_dp_get_reply(DBusPendingCall *pending,
                            dbus_uint16_t *err_maj,
                            dbus_uint32_t *err_min,
                            char **err_msg);

static void sss_dp_invoke_callback(struct tevent_context *ev,
                                   struct tevent_timer *te,
                                   struct timeval t, void *ptr)
{
    struct sss_dp_req *sdp_req = talloc_get_type(ptr, struct sss_dp_req);
    struct sss_dp_callback *cb;
    struct timeval tv;
    struct tevent_timer *tev;

    cb = sdp_req->cb_list;
    /* Remove the callback from the list, the caller may free it, within the
     * callback. */
    talloc_set_destructor((TALLOC_CTX *)cb, NULL);
    DLIST_REMOVE(sdp_req->cb_list, cb);

    cb->callback(sdp_req->err_maj,
                 sdp_req->err_min,
                 sdp_req->err_msg,
                 cb->callback_ctx);

    /* Call the next callback if needed */
    if (sdp_req->cb_list != NULL) {
        tv = tevent_timeval_current();
        tev = tevent_add_timer(sdp_req->ev, sdp_req, tv,
                               sss_dp_invoke_callback, sdp_req);
        if (!te) {
            /* Out of memory or other serious error */
            goto done;
        }

        return;
    }

    /* No more callbacks to invoke. Destroy the request */
done:
    /* steal te on NULL because it will be freed as soon as the handler
     * returns. Causing a double free if we don't, as te is allocated on
     * sdp_req and we are just going to free it */
    talloc_steal(NULL, te);

    talloc_zfree(sdp_req);
}

static void sss_dp_send_acct_callback(DBusPendingCall *pending, void *ptr)
{
    int ret;
    struct sss_dp_req *sdp_req;
    struct sss_dp_callback *cb;
    struct timeval tv;
    struct tevent_timer *te;

    sdp_req = talloc_get_type(ptr, struct sss_dp_req);

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
    cb = sdp_req->cb_list;
    if (sdp_req->cb_list == NULL) {
        if (cb == NULL) {
            /* No callbacks to invoke. Destroy the hash entry */
            talloc_zfree(sdp_req);
            return;
        }
    }

    /* Queue up all callbacks */
    tv = tevent_timeval_current();
    te = tevent_add_timer(sdp_req->ev, sdp_req, tv,
                          sss_dp_invoke_callback, sdp_req);
    if (!te) {
        /* Out of memory or other serious error */
        goto error;
    }

    return;

error:
    talloc_zfree(sdp_req);
}

static int sss_dp_send_acct_req_create(struct resp_ctx *rctx,
                                       TALLOC_CTX *callback_memctx,
                                       const char *domain,
                                       uint32_t be_type,
                                       char *filter,
                                       int timeout,
                                       sss_dp_callback_t callback,
                                       void *callback_ctx,
                                       struct sss_dp_req **ndp);

int sss_dp_send_acct_req(struct resp_ctx *rctx, TALLOC_CTX *callback_memctx,
                         sss_dp_callback_t callback, void *callback_ctx,
                         int timeout, const char *domain,
                         bool fast_reply, int type,
                         const char *opt_name, uint32_t opt_id)
{
    int ret, hret;
    uint32_t be_type;
    char *filter;
    hash_key_t key;
    hash_value_t value;
    TALLOC_CTX *tmp_ctx;
    struct timeval tv;
    struct sss_dp_req *sdp_req = NULL;
    struct sss_dp_callback *cb;

    /* either, or, not both */
    if (opt_name && opt_id) {
        return EINVAL;
    }

    if (!domain) {
        return EINVAL;
    }

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
    default:
        return EINVAL;
    }

    if (fast_reply) {
        be_type |= BE_REQ_FAST;
    }

    if (dp_requests == NULL) {
        /* Create a hash table to handle queued update requests */
        ret = hash_create(10, &dp_requests, NULL, NULL);
        if (ret != HASH_SUCCESS) {
            fprintf(stderr, "cannot create hash table (%s)\n", hash_error_string(ret));
            return EIO;
        }
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    key.type = HASH_KEY_STRING;
    key.str = NULL;

    if (opt_name) {
        filter = talloc_asprintf(tmp_ctx, "name=%s", opt_name);
        key.str = talloc_asprintf(tmp_ctx, "%d%s@%s", type, opt_name, domain);
    } else if (opt_id) {
        filter = talloc_asprintf(tmp_ctx, "idnumber=%u", opt_id);
        key.str = talloc_asprintf(tmp_ctx, "%d%d@%s", type, opt_id, domain);
    } else {
        filter = talloc_strdup(tmp_ctx, "name=*");
        key.str = talloc_asprintf(tmp_ctx, "%d*@%s", type, domain);
    }
    if (!filter || !key.str) {
        talloc_zfree(tmp_ctx);
        return ENOMEM;
    }

    /* Check whether there's already a request in progress */
    hret = hash_lookup(dp_requests, &key, &value);
    switch (hret) {
    case HASH_SUCCESS:
        /* Request already in progress
         * Add an additional callback if needed and return
         */
        DEBUG(2, ("Identical request in progress\n"));

        if (callback) {
            /* We have a new request asking for a callback */
            sdp_req = talloc_get_type(value.ptr, struct sss_dp_req);
            if (!sdp_req) {
                DEBUG(0, ("Could not retrieve DP request context\n"));
                ret = EIO;
                goto done;
            }

            cb = talloc_zero(callback_memctx, struct sss_dp_callback);
            if (!cb) {
                ret = ENOMEM;
                goto done;
            }

            cb->callback = callback;
            cb->callback_ctx = callback_ctx;
            cb->sdp_req = sdp_req;

            DLIST_ADD_END(sdp_req->cb_list, cb, struct sss_dp_callback *);
            talloc_set_destructor((TALLOC_CTX *)cb, sss_dp_callback_destructor);
        }

        ret = EOK;
        break;

    case HASH_ERROR_KEY_NOT_FOUND:
        /* No such request in progress
         * Create a new request
         */
        ret = sss_dp_send_acct_req_create(rctx, callback_memctx, domain,
                                          be_type, filter, timeout,
                                          callback, callback_ctx,
                                          &sdp_req);
        if (ret != EOK) {
            goto done;
        }

        value.type = HASH_VALUE_PTR;
        value.ptr = sdp_req;
        hret = hash_enter(dp_requests, &key, &value);
        if (hret != HASH_SUCCESS) {
            DEBUG(0, ("Could not store request query (%s)\n",
                      hash_error_string(hret)));
            talloc_zfree(sdp_req);
            ret = EIO;
            goto done;
        }

        sdp_req->key = talloc_strdup(sdp_req, key.str);

        tv = tevent_timeval_current_ofs(timeout, 0);
        sdp_req->tev = tevent_add_timer(sdp_req->ev, sdp_req, tv,
                                        sdp_req_timeout, sdp_req);
        if (!sdp_req->tev) {
            DEBUG(0, ("Out of Memory!?\n"));
            talloc_zfree(sdp_req);
            ret = ENOMEM;
            goto done;
        }

        talloc_set_destructor((TALLOC_CTX *)sdp_req, sss_dp_req_destructor);

        ret = EOK;
        break;

    default:
        DEBUG(0,("Could not query request list (%s)\n",
                  hash_error_string(hret)));
        talloc_zfree(sdp_req);
        ret = EIO;
    }

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static int sss_dp_send_acct_req_create(struct resp_ctx *rctx,
                                       TALLOC_CTX *callback_memctx,
                                       const char *domain,
                                       uint32_t be_type,
                                       char *filter,
                                       int timeout,
                                       sss_dp_callback_t callback,
                                       void *callback_ctx,
                                       struct sss_dp_req **ndp)
{
    DBusMessage *msg;
    DBusPendingCall *pending_reply;
    dbus_bool_t dbret;
    struct sss_dp_callback *cb;
    struct sss_dp_req *sdp_req;
    uint32_t attrs = BE_ATTR_CORE;
    struct be_conn *be_conn;
    int ret;

    /* double check dp_ctx has actually been initialized.
     * in some pathological cases it may happen that nss starts up before
     * dp connection code is actually able to establish a connection.
     */
    ret = sss_dp_get_domain_conn(rctx, domain, &be_conn);
    if (ret != EOK) {
        DEBUG(1, ("The Data Provider connection for %s is not available!"
                  " This maybe a bug, it shouldn't happen!\n", domain));
        return EIO;
    }

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_GETACCTINFO);
    if (msg == NULL) {
        DEBUG(0,("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending request for [%s][%u][%d][%s]\n",
              domain, be_type, attrs, filter));

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_UINT32, &be_type,
                                     DBUS_TYPE_UINT32, &attrs,
                                     DBUS_TYPE_STRING, &filter,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(1,("Failed to build message\n"));
        return EIO;
    }

    sdp_req = talloc_zero(rctx, struct sss_dp_req);
    if (!sdp_req) {
        dbus_message_unref(msg);
        return ENOMEM;
    }

    ret = sbus_conn_send(be_conn->conn, msg, timeout,
                         sss_dp_send_acct_callback,
                         sdp_req, &pending_reply);
    dbus_message_unref(msg);
    if (ret != EOK) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         * We'll drop it using the default destructor.
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        return EIO;
    }

    sdp_req->ev = rctx->ev;
    sdp_req->pending_reply = pending_reply;

    if (callback) {
        cb = talloc_zero(callback_memctx, struct sss_dp_callback);
        if (!cb) {
            talloc_zfree(sdp_req);
            return ENOMEM;
        }
        cb->callback = callback;
        cb->callback_ctx = callback_ctx;
        cb->sdp_req = sdp_req;

        DLIST_ADD(sdp_req->cb_list, cb);
        talloc_set_destructor((TALLOC_CTX *)cb, sss_dp_callback_destructor);
    }

    *ndp = sdp_req;

    return EOK;
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

