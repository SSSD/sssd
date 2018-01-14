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
#include "providers/data_provider/dp_responder_iface.h"
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

    /* Do not call callbacks if the responder is shutting down, because
     * the top level responder context (pam_ctx, sudo_ctx, ...) may be
     * already semi-freed and we may end up accessing freed memory.
     */
    if (sdp_req->rctx->shutting_down) {
        return 0;
    }

    /* If there are callbacks that haven't been invoked, return
     * an error now.
     */
    while ((cb = sdp_req->cb_list) != NULL) {
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
                  "BUG: a callback did not free its request. "
                   "May leak memory\n");
            /* Skip to the next since a memory leak is non-fatal */
            sdp_req->cb_list = sdp_req->cb_list->next;
        }
    }

    /* Destroy the hash entry */
    DEBUG(SSSDBG_TRACE_FUNC, "Deleting request: [%s]\n", sdp_req->key->str);
    hret = hash_delete(sdp_req->rctx->dp_request_table, sdp_req->key);
    if (hret != HASH_SUCCESS) {
        /* This should never happen */
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "BUG: Could not clear [%d:%lu:%s] from request queue: [%s]\n",
               sdp_req->key->type, sdp_req->key->ul, sdp_req->key->str,
               hash_error_string(hret));
        return -1;
    }

    return 0;
}

static void sss_dp_req_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval t, void *ptr)
{
    /* ptr is a pointer to sidereq */
    /* Just free it to kill all waiting requests when the timeout fires */
    talloc_zfree(ptr);
}

void handle_requests_after_reconnect(struct resp_ctx *rctx)
{
    int ret;
    hash_value_t *values;
    unsigned long count, i;
    struct sss_dp_req *sdp_req;

    if (!rctx->dp_request_table) {
        DEBUG(SSSDBG_TRACE_LIBS, "No requests to handle after reconnect\n");
        return;
    }

    ret = hash_values(rctx->dp_request_table, &count, &values);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "hash_values failed, "
                  "not all request might be handled after reconnect.\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "Will handle %lu requests after reconnect\n", count);
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
              "Severe error. A reply callback was called but no reply "
               "was received and no timeout occurred\n");

        /* FIXME: Destroy this connection? */
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
            DEBUG(SSSDBG_CRIT_FAILURE,"Failed to parse message\n");
            /* FIXME: Destroy this connection? */
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            err = EIO;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_LIBS,
              "Got reply from Data Provider - "
               "DP error code: %u errno: %u error message: %s\n",
              (unsigned int)*dp_err, (unsigned int)*dp_ret,
              *err_msg ? *err_msg : "none");
        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        if (strcmp(dbus_message_get_error_name(reply),
                   DBUS_ERROR_NO_REPLY) == 0) {
            err = ETIME;
            goto done;
        }

        if (strcmp(dbus_message_get_error_name(reply),
                   SBUS_ERROR_DP_NOTSUP) == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Data Provider does not support this operation.\n");
        } else {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "The Data Provider returned an error [%s]\n",
                  dbus_message_get_error_name(reply));
        }

        /* Falling through to default intentionally*/
        SSS_ATTRIBUTE_FALLTHROUGH;
    default:
        /*
         * Timeout or other error occurred or something
         * unexpected happened.
         * It doesn't matter which, because either way we
         * know that this connection isn't trustworthy.
         * We'll destroy it now.
         */

        /* FIXME: Destroy this connection? */
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

void sss_dp_issue_local_request(struct tevent_context *ev,
                                struct tevent_req *cb_req)
{
    struct sss_dp_req_state *cb_state;

    cb_state = tevent_req_data(cb_req, struct sss_dp_req_state);

    cb_state->dp_err = DP_ERR_OK;
    cb_state->dp_ret = EOK;
    cb_state->err_msg = talloc_strdup(cb_state, "Success");

    tevent_req_done(cb_req);
    tevent_req_post(cb_req, ev);
}

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
    struct tevent_timer *te;
    struct timeval tv;
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

    if (strcasecmp(dom->provider, "local") == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing local provider request for [%s]\n",
              key->str);
        sss_dp_issue_local_request(rctx->ev, nreq);
        return EOK;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing request for [%s]\n", key->str);

    /* Check the hash for existing references to this request */
    hret = hash_lookup(rctx->dp_request_table, key, &value);
    switch (hret) {
    case HASH_SUCCESS:
        /* Request already in progress */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Identical request in progress: [%s]\n", key->str);
        break;

    case HASH_ERROR_KEY_NOT_FOUND:
        /* No such request in progress
         * Create a new request
         */
        msg = msg_create(pvt);
        if (!msg) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create D-Bus message\n");
            ret = EIO;
            goto fail;
        }

        value.type = HASH_VALUE_PTR;
        sidereq = sss_dp_internal_get_send(rctx, key, dom, msg);
        dbus_message_unref(msg);
        if (!sidereq) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot send D-Bus message\n");
            ret = EIO;
            goto fail;
        }
        tevent_req_set_callback(sidereq, sss_dp_req_done, NULL);

        /* add timeout handling so we do not hang forever should something
         * go wrong in the provider. Use 2 sec less than the idle timeout to
         * give it a chance to reply to the client before closing the
         * connection. */
        tv = tevent_timeval_current_ofs(rctx->client_idle_timeout - 2, 0);
        te = tevent_add_timer(rctx->ev, sidereq, tv,
                              sss_dp_req_timeout, sidereq);
        if (!te) {
            /* Nothing much we can do */
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
            ret = ENOMEM;
            goto fail;
        }

        /* We should now be able to find the sdp_req in the hash table */
        hret = hash_lookup(rctx->dp_request_table, key, &value);
        if (hret != HASH_SUCCESS) {
            /* Something must have gone wrong with creating the request */
            DEBUG(SSSDBG_CRIT_FAILURE, "The request has disappeared?\n");
            ret = EIO;
            goto fail;
        }
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not query request list (%s)\n",
               hash_error_string(hret));
        ret = EIO;
        goto fail;
    }

    /* Register this request for results */
    sdp_req = talloc_get_type(value.ptr, struct sss_dp_req);
    if (!sdp_req) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not retrieve DP request context\n");
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
    uint64_t TRROEuint64;
    errno_t TRROEerr;

    *dp_err = state->dp_err;
    *dp_ret = state->dp_ret;
    *err_msg = talloc_steal(mem_ctx, state->err_msg);

    if (tevent_req_is_error(sidereq, &TRROEstate, &TRROEuint64)) {
        TRROEerr = (errno_t)TRROEuint64;

        if (TRROEstate == TEVENT_REQ_USER_ERROR) {
            if (TRROEerr == 0) {
                return ERR_INTERNAL;
            }
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

static int sss_dp_account_files_params(struct sss_domain_info *dom,
                                       enum sss_dp_acct_type type_in,
                                       const char *opt_name_in,
                                       enum sss_dp_acct_type *_type_out,
                                       const char **_opt_name_out);

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

    if (NEED_CHECK_PROVIDER(dom->provider) == false) {
        if (strcmp(dom->provider, "files") == 0) {
            /* This is a special case. If the files provider is just being updated,
             * we issue an enumeration request. We always use the same request type
             * (user enumeration) to make sure concurrent requests are just chained
             * in the Data Provider
             */
            ret = sss_dp_account_files_params(dom, type, opt_name,
                                              &type, &opt_name);
            if (ret == EOK) {
                goto error;
            } else if (ret != EAGAIN) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to set files provider update: %d: %s\n",
                      ret, sss_strerror(ret));
                goto error;
            }
            /* EAGAIN, fall through to issuing the request */
        } else {
            DEBUG(SSSDBG_TRACE_INTERNAL, "Domain %s does not check DP\n", dom->name);
            ret = EOK;
            goto error;
        }
    }

    info = talloc_zero(state, struct sss_dp_account_info);
    if (info == NULL) {
        ret = ENOMEM;
        goto error;
    }
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
              "Could not issue DP request [%d]: %s\n",
               ret, strerror(ret));
        goto error;
    }

    return req;

error:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, rctx->ev);
    return req;
}

static int sss_dp_account_files_params(struct sss_domain_info *dom,
                                       enum sss_dp_acct_type type_in,
                                       const char *opt_name_in,
                                       enum sss_dp_acct_type *_type_out,
                                       const char **_opt_name_out)
{
#if 0
    if (sss_domain_get_state(dom) != DOM_INCONSISTENT) {
        return EOK;
    }
#endif

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Domain files is not consistent, issuing update\n");

    switch(type_in) {
    case SSS_DP_USER:
    case SSS_DP_GROUP:
        *_type_out = type_in;
        *_opt_name_out = NULL;
        return EAGAIN;
    case SSS_DP_INITGROUPS:
        /* There is no initgroups enumeration so let's use a dummy
         * name to let the DP chain the requests
         */
        *_type_out = type_in;
        *_opt_name_out = DP_REQ_OPT_FILES_INITGR;
        return EAGAIN;
    /* These are not handled by the files provider, just fall back */
    case SSS_DP_NETGR:
    case SSS_DP_SERVICES:
    case SSS_DP_SECID:
    case SSS_DP_USER_AND_GROUP:
    case SSS_DP_CERT:
    case SSS_DP_WILDCARD_USER:
    case SSS_DP_WILDCARD_GROUP:
        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "Unhandled type %d\n", type_in);
    return EINVAL;
}

static DBusMessage *
sss_dp_get_account_msg(void *pvt)
{
    DBusMessage *msg;
    dbus_bool_t dbret;
    struct sss_dp_account_info *info;
    uint32_t dp_flags;
    uint32_t entry_type;
    char *filter;

    info = talloc_get_type(pvt, struct sss_dp_account_info);

    switch (info->type) {
        case SSS_DP_USER:
        case SSS_DP_WILDCARD_USER:
            entry_type = BE_REQ_USER;
            break;
        case SSS_DP_GROUP:
        case SSS_DP_WILDCARD_GROUP:
            entry_type = BE_REQ_GROUP;
            break;
        case SSS_DP_INITGROUPS:
            entry_type = BE_REQ_INITGROUPS;
            break;
        case SSS_DP_NETGR:
            entry_type = BE_REQ_NETGROUP;
            break;
        case SSS_DP_SERVICES:
            entry_type = BE_REQ_SERVICES;
            break;
        case SSS_DP_SECID:
            entry_type = BE_REQ_BY_SECID;
            break;
        case SSS_DP_USER_AND_GROUP:
            entry_type = BE_REQ_USER_AND_GROUP;
            break;
        case SSS_DP_CERT:
            entry_type = BE_REQ_BY_CERT;
            break;
    }

    dp_flags = info->fast_reply ? DP_FAST_REPLY : 0;

    if (info->opt_name) {
        if (info->type == SSS_DP_SECID) {
            filter = talloc_asprintf(info, "%s=%s", DP_SEC_ID,
                                     info->opt_name);
        } else if (info->type == SSS_DP_CERT) {
            filter = talloc_asprintf(info, "%s=%s", DP_CERT,
                                     info->opt_name);
        } else if (info->type == SSS_DP_WILDCARD_USER ||
                   info->type == SSS_DP_WILDCARD_GROUP) {
            filter = talloc_asprintf(info, "%s=%s", DP_WILDCARD,
                                     info->opt_name);
        } else {
            filter = talloc_asprintf(info, "name=%s", info->opt_name);
        }
    } else if (info->opt_id) {
        filter = talloc_asprintf(info, "idnumber=%u", info->opt_id);
    } else {
        filter = talloc_strdup(info, ENUM_INDICATOR);
    }
    if (!filter) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return NULL;
    }

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       IFACE_DP,
                                       IFACE_DP_GETACCOUNTINFO);
    if (msg == NULL) {
        talloc_free(filter);
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return NULL;
    }

    /* create the message */
    DEBUG(SSSDBG_TRACE_FUNC,
          "Creating request for [%s][%#x][%s][%s:%s]\n",
          info->dom->name, entry_type, be_req2str(entry_type),
          filter, info->extra == NULL ? "-" : info->extra);

    if (info->extra == NULL) {
        /* D-Bus can't deal with NULL. */
        info->extra = "";
    }

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_UINT32, &dp_flags,
                                     DBUS_TYPE_UINT32, &entry_type,
                                     DBUS_TYPE_STRING, &filter,
                                     DBUS_TYPE_STRING, &info->dom->name,
                                     DBUS_TYPE_STRING, &info->extra,
                                     DBUS_TYPE_INVALID);
    talloc_free(filter);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
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
    ret = sss_dp_get_domain_conn(rctx, dom->conn_name, &be_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "BUG: The Data Provider connection for %s is not available!\n",
              dom->name);
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
              "D-BUS send failed.\n");
        ret = EIO;
        goto error;
    }

    /* Add this sdp_req to the hash table */
    value.type = HASH_VALUE_PTR;
    value.ptr = state->sdp_req;

    DEBUG(SSSDBG_TRACE_FUNC, "Entering request [%s]\n", key->str);
    hret = hash_enter(rctx->dp_request_table, key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not store request query (%s)\n",
               hash_error_string(hret));
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
                  "BUG: a callback did not free its request. "
                   "May leak memory\n");
            /* Skip to the next since a memory leak is non-fatal */
            sdp_req->cb_list = sdp_req->cb_list->next;
        }
    }

    /* We're done with this request. Free the sdp_req
     * This will clean up the hash table entry as well
     */
    talloc_zfree(sdp_req);

    /* Free the sidereq to free the rest of the memory allocated with the
     * internal dp request. */
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}
