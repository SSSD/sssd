/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com> - 2009

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

#include <ctype.h>
#include "util/util.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_req_wrap.h"

#define REALM_SEPARATOR '@'
#define REPLY_REALLOC_INCREMENT 10

void make_realm_upper_case(const char *upn)
{
    char *c;

    c = strchr(upn, REALM_SEPARATOR);
    if (c == NULL) {
        DEBUG(9, ("No realm delimiter found in upn [%s].\n", upn));
        return;
    }

    while(*(++c) != '\0') {
        c[0] = toupper(*c);
    }

    return;
}

/* ==LDAP-Memory-Handling================================================= */

static int lmsg_destructor(void *mem)
{
    ldap_msgfree((LDAPMessage *)mem);
    return 0;
}

static int sdap_msg_attach(TALLOC_CTX *memctx, LDAPMessage *msg)
{
    void *h;

    if (!msg) return EINVAL;

    h = sss_mem_attach(memctx, msg, lmsg_destructor);
    if (!h) return ENOMEM;

    return EOK;
}

/* ==sdap-hanlde-utility-functions======================================== */

static inline void sdap_handle_release(struct sdap_handle *sh);
static int sdap_handle_destructor(void *mem);

struct sdap_handle *sdap_handle_create(TALLOC_CTX *memctx)
{
    struct sdap_handle *sh;

    sh = talloc_zero(memctx, struct sdap_handle);
    if (!sh) return NULL;

    talloc_set_destructor((TALLOC_CTX *)sh, sdap_handle_destructor);

    return sh;
}

static int sdap_handle_destructor(void *mem)
{
    struct sdap_handle *sh = talloc_get_type(mem, struct sdap_handle);

    /* if the structure is currently locked, then mark it to be released
     * and prevent talloc from freeing the memory */
    if (sh->destructor_lock) {
        sh->release_memory = true;
        return -1;
    }

    sdap_handle_release(sh);
    return 0;
}

static void sdap_handle_release(struct sdap_handle *sh)
{
    struct sdap_op *op;

    DEBUG(8, ("Trace: sh[%p], connected[%d], ops[%p], ldap[%p], "
              "destructor_lock[%d], release_memory[%d]\n",
              sh, (int)sh->connected, sh->ops, sh->ldap,
              (int)sh->destructor_lock, (int)sh->release_memory));

    if (sh->destructor_lock) return;
    sh->destructor_lock = true;

    /* make sure nobody tries to reuse this connection from now on */
    sh->connected = false;

    remove_ldap_connection_callbacks(sh);

    while (sh->ops) {
        op = sh->ops;
        op->callback(op, NULL, EIO, op->data);
        /* calling the callback may result in freeing the op */
        /* check if it is still the same or avoid freeing */
        if (op == sh->ops) talloc_free(op);
    }

    if (sh->ldap) {
        ldap_unbind_ext(sh->ldap, NULL, NULL);
        sh->ldap = NULL;
    }

    /* ok, we have done the job, unlock now */
    sh->destructor_lock = false;

    /* finally if a destructor was ever called, free sh before
     * exiting */
    if (sh->release_memory) {
        /* neutralize the destructor as we already handled
         * all was needed to be released */
        talloc_set_destructor((TALLOC_CTX *)sh, NULL);
        talloc_free(sh);
    }
}

/* ==Parse-Results-And-Handle-Disconnections============================== */
static void sdap_finish_bind(struct ldap_cb_data *cb_data,
                             struct tevent_fd *fde);
static void sdap_process_message(struct tevent_context *ev,
                                 struct sdap_handle *sh, LDAPMessage *msg);
static void sdap_process_result(struct tevent_context *ev, void *pvt);
static void sdap_process_next_reply(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt);

void sdap_async_ldap_result(struct tevent_context *ev,
                            struct tevent_fd *fde,
                            uint16_t flags, void *pvt)
{
    struct ldap_cb_data *cb_data = talloc_get_type(pvt, struct ldap_cb_data);

    if (flags & TEVENT_FD_WRITE) {
        sdap_finish_bind(cb_data, fde);
    }

    if (flags & TEVENT_FD_READ) {
        sdap_process_result(ev, cb_data->sh);
    }
}


void sdap_ldap_result(struct tevent_context *ev, struct tevent_fd *fde,
                      uint16_t flags, void *pvt)
{
    sdap_process_result(ev, pvt);
}

static void sdap_ldap_next_result(struct tevent_context *ev,
                                  struct tevent_timer *te,
                                  struct timeval tv, void *pvt)
{
    sdap_process_result(ev, pvt);
}

static void sdap_finish_bind(struct ldap_cb_data *cb_data,
                             struct tevent_fd *fde)
{
    struct fd_event_item *fd_event_item;
    struct request_spy *spy;
    struct fd_event_item *spy_ptr;

    DEBUG(8, ("Trace: sh[%p], ldap[%p], fde[%p]\n",
              cb_data->sh, cb_data->sh->ldap, fde));

    DLIST_FOR_EACH(fd_event_item, cb_data->fd_list) {
        if (fd_event_item->fde == fde) {
            break;
        }
    }
    if (fd_event_item != NULL && fd_event_item->fd_wakeup_cb != NULL) {
        if (fd_event_item->spy) {
            /* We have to clear the spy in case it is triggered so that
             * it does not free fd_event_item. But we will back it up so
             * we can restore it in case the wakeup callback signals it
             * has not yet finished. */
            spy_ptr = fd_event_item->spy->ptr;
            spy = fd_event_item->spy;

            fd_event_item->spy->ptr = NULL;
            fd_event_item->spy = NULL;
        } else {
            spy = NULL;
        }
        if (fd_event_item->fd_wakeup_cb(fd_event_item->fd_wakeup_cb_data)) {
            fd_event_item->fd_wakeup_cb = NULL;
            fd_event_item->fd_wakeup_cb_data = NULL;
            talloc_zfree(fd_event_item->timeout_watcher);
        } else {
            /* Restore the spy. */
            if (spy) {
                fd_event_item->spy = spy;
                spy->ptr = spy_ptr;
            }
            return;
        }
    } else if (fd_event_item == NULL) {
        DEBUG(1, ("Bug: Couldn't find fd_event_item\n"));
    }

    TEVENT_FD_NOT_WRITEABLE(fde);
}

struct conn_timeout {
    struct ldap_cb_data *cb_data;
    struct fd_event_item *fd_event_item;
};

static void sdap_check_connection_timeout(struct tevent_context *ev,
                                          struct tevent_timer *te,
                                          struct timeval current_time,
                                          void *private_data)
{
    struct conn_timeout *ct = talloc_get_type(private_data, struct conn_timeout);

    ct->fd_event_item->timeout_watcher = NULL;
    sdap_finish_bind(ct->cb_data, ct->fd_event_item->fde);
}

void sdap_add_timeout_watcher(struct ldap_cb_data *cb_data,
                              struct fd_event_item *fd_event_item)
{
    struct conn_timeout *ct;
    struct timeval tv;
    struct timeval *timeout;
    int ret;

    ct = talloc(fd_event_item, struct conn_timeout);
    if (!ct) goto fail;
    ct->cb_data = cb_data;
    ct->fd_event_item = fd_event_item;

    ret = ldap_get_option(cb_data->sh->ldap,
                          LDAP_OPT_NETWORK_TIMEOUT, &timeout);
    if (ret == LDAP_OPT_SUCCESS) {
        tv = tevent_timeval_current_ofs(timeout->tv_sec + 1, 0);
        ldap_memfree(timeout);
    } else {
        DEBUG(1, ("Couldn't get network timeout from ldap\n"));
        tv = tevent_timeval_current_ofs(1, 0);
    }

    fd_event_item->timeout_watcher = tevent_add_timer(cb_data->ev,
            fd_event_item, tv, sdap_check_connection_timeout, ct);
    if (!fd_event_item->timeout_watcher) goto fail;

    return;

fail:
    DEBUG(1, ("Out of memory\n"));
}

static void sdap_process_result(struct tevent_context *ev, void *pvt)
{
    struct sdap_handle *sh = talloc_get_type(pvt, struct sdap_handle);
    struct timeval no_timeout = {0, 0};
    struct tevent_timer *te;
    LDAPMessage *msg;
    int ret;

    DEBUG(8, ("Trace: sh[%p], connected[%d], ops[%p], ldap[%p]\n",
              sh, (int)sh->connected, sh->ops, sh->ldap));

    if (!sh->connected || !sh->ldap) {
        DEBUG(2, ("ERROR: LDAP connection is not connected!\n"));
        return;
    }

    ret = ldap_result(sh->ldap, LDAP_RES_ANY, 0, &no_timeout, &msg);
    if (ret == 0) {
        /* this almost always means we have reached the end of
         * the list of received messages */
        DEBUG(8, ("Trace: ldap_result found nothing!\n"));
        return;
    }

    if (ret == -1) {
        DEBUG(4, ("ldap_result gave -1, something bad happend!\n"));
        sdap_handle_release(sh);
        return;
    }

    /* We don't know if this will be the last result.
     *
     * important: we must do this before actually processing the message
     * because the message processing might even free the sdap_handler
     * so it must be the last operation.
     * FIXME: use tevent_immediate/tevent_queues, when avilable */
    memset(&no_timeout, 0, sizeof(struct timeval));

    te = tevent_add_timer(ev, sh, no_timeout, sdap_ldap_next_result, sh);
    if (!te) {
        DEBUG(1, ("Failed to add critical timer to fetch next result!\n"));
    }

    /* now process this message */
    sdap_process_message(ev, sh, msg);
}

/* process a messgae calling the right operation callback.
 * msg is completely taken care of (including freeeing it)
 * NOTE: this function may even end up freeing the sdap_handle
 * so sdap_hanbdle must not be used after this function is called
 */
static void sdap_process_message(struct tevent_context *ev,
                                 struct sdap_handle *sh, LDAPMessage *msg)
{
    struct sdap_msg *reply;
    struct sdap_op *op;
    int msgid;
    int msgtype;
    int ret;

    msgid = ldap_msgid(msg);
    if (msgid == -1) {
        DEBUG(2, ("can't fire callback, message id invalid!\n"));
        ldap_msgfree(msg);
        return;
    }

    msgtype = ldap_msgtype(msg);

    for (op = sh->ops; op; op = op->next) {
        if (op->msgid == msgid) break;
    }

    if (op == NULL) {
        DEBUG(2, ("Unmatched msgid, discarding message (type: %0x)\n",
                  msgtype));
        ldap_msgfree(msg);
        return;
    }

    /* shouldn't happen */
    if (op->done) {
        DEBUG(2, ("Operation [%p] already handled (type: %0x)\n", op, msgtype));
        ldap_msgfree(msg);
        return;
    }

    switch (msgtype) {
    case LDAP_RES_SEARCH_ENTRY:
        /* go and process entry */
        break;

    case LDAP_RES_SEARCH_REFERENCE:
        /* more ops to come with this msgid */
        /* just ignore */
        ldap_msgfree(msg);
        return;

    case LDAP_RES_BIND:
    case LDAP_RES_SEARCH_RESULT:
    case LDAP_RES_MODIFY:
    case LDAP_RES_ADD:
    case LDAP_RES_DELETE:
    case LDAP_RES_MODDN:
    case LDAP_RES_COMPARE:
    case LDAP_RES_EXTENDED:
    case LDAP_RES_INTERMEDIATE:
        /* no more results expected with this msgid */
        op->done = true;
        break;

    default:
        /* unkwon msg type ?? */
        DEBUG(1, ("Couldn't figure out the msg type! [%0x]\n", msgtype));
        ldap_msgfree(msg);
        return;
    }

    reply = talloc_zero(op, struct sdap_msg);
    if (!reply) {
        ldap_msgfree(msg);
        ret = ENOMEM;
    } else {
        reply->msg = msg;
        ret = sdap_msg_attach(reply, msg);
        if (ret != EOK) {
            ldap_msgfree(msg);
            talloc_zfree(reply);
        }
    }

    if (op->list) {
        /* list exist, queue it */

        op->last->next = reply;
        op->last = reply;

    } else {
        /* create list, then call callback */
        op->list = op->last = reply;

        /* must be the last operation as it may end up freeing all memory
         * including all ops handlers */
        op->callback(op, reply, ret, op->data);
    }
}

static void sdap_unlock_next_reply(struct sdap_op *op)
{
    struct timeval tv;
    struct tevent_timer *te;
    struct sdap_msg *next_reply;

    if (op->list) {
        next_reply = op->list->next;
        /* get rid of the previous reply, it has been processed already */
        talloc_zfree(op->list);
        op->list = next_reply;
    }

    /* if there are still replies to parse, queue a new operation */
    if (op->list) {
        /* use a very small timeout, so that fd operations have a chance to be
         * served while processing a long reply */
        tv = tevent_timeval_current();

        /* wait 5 microsecond */
        tv.tv_usec += 5;
        tv.tv_sec += tv.tv_usec / 1000000;
        tv.tv_usec = tv.tv_usec % 1000000;

        te = tevent_add_timer(op->ev, op, tv,
                              sdap_process_next_reply, op);
        if (!te) {
            DEBUG(1, ("Failed to add critical timer for next reply!\n"));
            op->callback(op, NULL, EFAULT, op->data);
        }
    }
}

static void sdap_process_next_reply(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt)
{
    struct sdap_op *op = talloc_get_type(pvt, struct sdap_op);

    op->callback(op, op->list, EOK, op->data);
}

/* ==LDAP-Operations-Helpers============================================== */

static int sdap_op_destructor(void *mem)
{
    struct sdap_op *op = (struct sdap_op *)mem;

    DLIST_REMOVE(op->sh->ops, op);

    if (op->done) return 0;

    /* we don't check the result here, if a message was really abandoned,
     * hopefully the server will get an abandon.
     * If the operation was already fully completed, this is going to be
     * just a noop */
    ldap_abandon_ext(op->sh->ldap, op->msgid, NULL, NULL);

    return 0;
}

static void sdap_op_timeout(struct tevent_req *req)
{
    struct sdap_op *op = tevent_req_callback_data(req, struct sdap_op);

    /* should never happen, but just in case */
    if (op->done) {
        DEBUG(2, ("Timeout happened after op was finished !?\n"));
        return;
    }

    /* signal the caller that we have a timeout */
    op->callback(op, NULL, ETIMEDOUT, op->data);
}

int sdap_op_add(TALLOC_CTX *memctx, struct tevent_context *ev,
                struct sdap_handle *sh, int msgid,
                sdap_op_callback_t *callback, void *data,
                int timeout, struct sdap_op **_op)
{
    struct sdap_op *op;

    op = talloc_zero(memctx, struct sdap_op);
    if (!op) return ENOMEM;

    op->sh = sh;
    op->msgid = msgid;
    op->callback = callback;
    op->data = data;
    op->ev = ev;

    /* check if we need to set a timeout */
    if (timeout) {
        struct tevent_req *req;
        struct timeval tv;

        tv = tevent_timeval_current();
        tv = tevent_timeval_add(&tv, timeout, 0);

        /* allocate on op, so when it get freed the timeout is removed */
        req = tevent_wakeup_send(op, ev, tv);
        if (!req) {
            talloc_zfree(op);
            return ENOMEM;
        }
        tevent_req_set_callback(req, sdap_op_timeout, op);
    }

    DLIST_ADD(sh->ops, op);

    talloc_set_destructor((TALLOC_CTX *)op, sdap_op_destructor);

    *_op = op;
    return EOK;
}

/* ==Modify-Password====================================================== */

struct sdap_exop_modify_passwd_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;

    struct sdap_op *op;

    int result;
    char *user_error_message;
};

static void sdap_exop_modify_passwd_step(struct tevent_req *subreq);

struct tevent_req *sdap_exop_modify_passwd_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           char *user_dn,
                                           char *password,
                                           char *new_password)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq;
    struct sdap_exop_modify_passwd_state *state;
    int ret;
    BerElement *ber = NULL;
    struct berval *bv = NULL;
    LDAPControl *request_controls[2];

    req = tevent_req_create(memctx, &state,
                            struct sdap_exop_modify_passwd_state);
    if (!req) return NULL;

    state->ev = ev;
    state->sh = sh;
    state->user_error_message = NULL;

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        DEBUG(7, ("ber_alloc_t failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    ret = ber_printf( ber, "{tststs}", LDAP_TAG_EXOP_MODIFY_PASSWD_ID,
                     user_dn,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_OLD, password,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, new_password);
    if (ret == -1) {
        DEBUG(1, ("ber_printf failed.\n"));
        ber_free(ber, 1);
        talloc_zfree(req);
        return NULL;
    }

    ret = ber_flatten(ber, &bv);
    ber_free(ber, 1);
    if (ret == -1) {
        DEBUG(1, ("ber_flatten failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                  0, NULL, 0, &request_controls[0]);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("sss_ldap_control_create failed.\n"));
        goto fail;
    }
    request_controls[1] = NULL;

    DEBUG(4, ("Executing extended operation\n"));

    subreq = ldap_extended_operation_send(state, ev, state->sh,
                                          LDAP_EXOP_MODIFY_PASSWD, bv,
                                          request_controls, NULL);
    ber_bvfree(bv);
    ldap_control_free(request_controls[0]);

    if (!subreq) {
        DEBUG(1, ("ldap_extended_operation_send failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, sdap_exop_modify_passwd_step, req);

    return req;

fail:
    tevent_req_error(req, EIO);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_exop_modify_passwd_done(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt);

static void sdap_exop_modify_passwd_step(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_exop_modify_passwd_state *state;
    int ret;
    int msgid;
    int ldap_ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_exop_modify_passwd_state);

    ret = ldap_extended_operation_recv(subreq, &ldap_ret, &msgid);
    talloc_zfree(subreq);
    if (ret != EOK) goto fail;

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, state->ev, state->sh, msgid,
                      sdap_exop_modify_passwd_done, req, 5, &state->op);
    if (ret != EOK) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return;

fail:
    tevent_req_error(req, ret);
}

static void sdap_exop_modify_passwd_done(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);
    char *errmsg = NULL;
    int ret;
    LDAPControl **response_controls = NULL;
    int c;
    ber_int_t pp_grace;
    ber_int_t pp_expire;
    LDAPPasswordPolicyError pp_error;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    ret = ldap_parse_result(state->sh->ldap, reply->msg,
                            &state->result, NULL, &errmsg, NULL,
                            &response_controls, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
        ret = EIO;
        goto done;
    }

    if (response_controls == NULL) {
        DEBUG(5, ("Server returned no controls.\n"));
    } else {
        for (c = 0; response_controls[c] != NULL; c++) {
            DEBUG(9, ("Server returned control [%s].\n",
                      response_controls[c]->ldctl_oid));
            if (strcmp(response_controls[c]->ldctl_oid,
                       LDAP_CONTROL_PASSWORDPOLICYRESPONSE) == 0) {
                ret = ldap_parse_passwordpolicy_control(state->sh->ldap,
                                                        response_controls[c],
                                                        &pp_expire, &pp_grace,
                                                        &pp_error);
                if (ret != LDAP_SUCCESS) {
                    DEBUG(1, ("ldap_parse_passwordpolicy_control failed.\n"));
                    ret = EIO;
                    goto done;
                }

                DEBUG(7, ("Password Policy Response: expire [%d] grace [%d] "
                          "error [%s].\n", pp_expire, pp_grace,
                          ldap_passwordpolicy_err2txt(pp_error)));
            }
        }
    }

    DEBUG(3, ("ldap_extended_operation result: %s(%d), %s\n",
              ldap_err2string(state->result), state->result, errmsg));

    if (state->result != LDAP_SUCCESS) {
        if (errmsg) {
            state->user_error_message = talloc_strdup(state, errmsg);
            if (state->user_error_message == NULL) {
                DEBUG(1, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
        }
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    ldap_controls_free(response_controls);
    ldap_memfree(errmsg);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

int sdap_exop_modify_passwd_recv(struct tevent_req *req,
                                 TALLOC_CTX * mem_ctx,
                                 enum sdap_result *result,
                                 char **user_error_message)
{
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);

    *result = SDAP_ERROR;
    *user_error_message = talloc_steal(mem_ctx, state->user_error_message);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->result == LDAP_SUCCESS) {
        *result = SDAP_SUCCESS;
    }

    return EOK;
}

/* ==Fetch-RootDSE============================================= */

struct sdap_get_rootdse_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sysdb_attrs *rootdse;
};

static void sdap_get_rootdse_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_rootdse_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_rootdse_state *state;
    const char *attrs[] = {
	    "*",
	    "altServer",
	    "namingContexts",
	    "supportedControl",
	    "supportedExtension",
	    "supportedFeatures",
	    "supportedLDAPVersion",
	    "supportedSASLMechanisms",
	    NULL
    };

    DEBUG(9, ("Getting rootdse\n"));

    req = tevent_req_create(memctx, &state, struct sdap_get_rootdse_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->rootdse = NULL;

    subreq = sdap_get_generic_send(state, ev, opts, sh,
                                   "", LDAP_SCOPE_BASE,
                                   "(objectclass=*)", attrs, NULL, 0);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_rootdse_done, req);

    return req;
}

static void sdap_get_rootdse_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_rootdse_state *state = tevent_req_data(req,
                                             struct sdap_get_rootdse_state);
    struct sysdb_attrs **results;
    size_t num_results;
    int ret;

    ret = sdap_get_generic_recv(subreq, state, &num_results, &results);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (num_results == 0 || !results) {
        DEBUG(2, ("RootDSE could not be retrieved. "
                  "Please check that anonymous access to RootDSE is allowed\n"
              ));
        tevent_req_error(req, ENOENT);
        return;
    }

    if (num_results > 1) {
        DEBUG(2, ("Multiple replies when searching for RootDSE ??\n"));
        tevent_req_error(req, EIO);
        return;
    }

    state->rootdse = talloc_steal(state, results[0]);
    talloc_zfree(results);

    DEBUG(9, ("Got rootdse\n"));

    tevent_req_done(req);
}

int sdap_get_rootdse_recv(struct tevent_req *req,
                          TALLOC_CTX *memctx,
                          struct sysdb_attrs **rootdse)
{
    struct sdap_get_rootdse_state *state = tevent_req_data(req,
                                             struct sdap_get_rootdse_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *rootdse = talloc_steal(memctx, state->rootdse);

    return EOK;
}

/* ==Generic Search============================================ */

struct sdap_get_generic_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sdap_attr_map *map;
    int map_num_attrs;

    struct sdap_op *op;

    size_t reply_max;
    size_t reply_count;
    struct sysdb_attrs **reply;
};

static errno_t add_to_reply(struct sdap_get_generic_state *state,
                            struct sysdb_attrs *msg);

static void sdap_get_generic_step(struct tevent_req *subreq);

struct tevent_req *sdap_get_generic_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh,
                                         const char *search_base,
                                         int scope,
                                         const char *filter,
                                         const char **attrs,
                                         struct sdap_attr_map *map,
                                         int map_num_attrs)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_get_generic_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_generic_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->map = map;
    state->map_num_attrs = map_num_attrs;
    state->op = NULL;
    state->reply_max = 0;
    state->reply_count = 0;
    state->reply = NULL;

    DEBUG(6, ("calling ldap_search_ext with [%s][%s].\n", filter,
                                                          search_base));
    if (debug_level >= 7) {
        int i;

        if (attrs) {
            for (i = 0; attrs[i]; i++) {
                DEBUG(7, ("Requesting attrs: [%s]\n", attrs[i]));
            }
        }
    }

    subreq = ldap_search_ext_send(state, ev, sh, search_base, scope, filter,
                                  attrs, false, NULL, NULL, NULL, 0);
    if (!subreq) goto fail;
    tevent_req_set_callback(subreq, sdap_get_generic_step, req);

    return req;

fail:
    tevent_req_error(req, ENOMEM);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_get_generic_done(struct sdap_op *op,
                                  struct sdap_msg *reply,
                                  int error, void *pvt);

static void sdap_get_generic_step(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_get_generic_state *state;
    int ret;
    int msgid;
    int ldap_ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_get_generic_state);

    ret = ldap_search_ext_recv(subreq, &ldap_ret, &msgid);
    talloc_zfree(subreq);
    if (ret != EOK) goto fail;

    ret = sdap_op_add(state, state->ev, state->sh, msgid,
                      sdap_get_generic_done, req,
                      dp_opt_get_int(state->opts->basic,
                                     SDAP_SEARCH_TIMEOUT),
                      &state->op);
    if (ret != EOK) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return;

fail:
    tevent_req_error(req, ret);
}

static void sdap_get_generic_done(struct sdap_op *op,
                                 struct sdap_msg *reply,
                                 int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_generic_state *state = tevent_req_data(req,
                                            struct sdap_get_generic_state);
    struct sysdb_attrs *attrs;
    char *errmsg;
    int result;
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    switch (ldap_msgtype(reply->msg)) {
    case LDAP_RES_SEARCH_REFERENCE:
        /* ignore references for now */
        talloc_free(reply);

        /* unlock the operation so that we can proceed with the next result */
        sdap_unlock_next_reply(state->op);
        break;

    case LDAP_RES_SEARCH_ENTRY:
        ret = sdap_parse_entry(state, state->sh, reply,
                               state->map, state->map_num_attrs,
                               &attrs, NULL);
        if (ret != EOK) {
            DEBUG(1, ("sdap_parse_generic_entry failed.\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }

        ret = add_to_reply(state, attrs);
        if (ret != EOK) {
            DEBUG(1, ("add_to_reply failed.\n"));
            tevent_req_error(req, ret);
            return;
        }

        sdap_unlock_next_reply(state->op);
        break;

    case LDAP_RES_SEARCH_RESULT:
        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, NULL, NULL, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(6, ("Search result: %s(%d), %s\n",
                  ldap_err2string(result), result, errmsg));

        if (result != LDAP_SUCCESS && result != LDAP_NO_SUCH_OBJECT) {
            DEBUG(2, ("Unexpected result from ldap: %s(%d), %s\n",
                      ldap_err2string(result), result, errmsg));
        }

        tevent_req_done(req);
        return;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static errno_t add_to_reply(struct sdap_get_generic_state *state,
                            struct sysdb_attrs *msg)
{
    if (state->reply == NULL || state->reply_max == state->reply_count) {
        state->reply_max += REPLY_REALLOC_INCREMENT;
        state->reply = talloc_realloc(state, state->reply,
                                      struct sysdb_attrs *,
                                      state->reply_max);
        if (state->reply == NULL) {
            DEBUG(1, ("talloc_realloc failed.\n"));
            return ENOMEM;
        }
    }

    state->reply[state->reply_count++] = talloc_steal(state->reply, msg);

    return EOK;
}

int sdap_get_generic_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          size_t *reply_count,
                          struct sysdb_attrs ***reply)
{
    struct sdap_get_generic_state *state = tevent_req_data(req,
                                            struct sdap_get_generic_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->reply_count;
    *reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}

