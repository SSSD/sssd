/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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
#include <sasl/sasl.h>
#include <krb5/krb5.h>

#include "db/sysdb.h"
#include "providers/ldap/sdap_async.h"
#include "util/util.h"

#define REALM_SEPARATOR '@'

#define LDAP_X_SSSD_PASSWORD_EXPIRED 0x555D

static void make_realm_upper_case(const char *upn)
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

static struct sdap_handle *sdap_handle_create(TALLOC_CTX *memctx)
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

    sdap_handle_release(sh);

    return 0;
}

static void sdap_handle_release(struct sdap_handle *sh)
{
    DEBUG(8, ("Trace: sh[%p], connected[%d], ops[%p], fde[%p], ldap[%p]\n",
              sh, (int)sh->connected, sh->ops, sh->fde, sh->ldap));

    if (sh->connected) {
        struct sdap_op *op;

        talloc_zfree(sh->fde);

        while (sh->ops) {
            op = sh->ops;
            op->callback(op, NULL, EIO, op->data);
            talloc_free(op);
        }

        ldap_unbind_ext(sh->ldap, NULL, NULL);
        sh->connected = false;
        sh->ldap = NULL;
        sh->ops = NULL;
    }
}

static int get_fd_from_ldap(LDAP *ldap, int *fd)
{
    int ret;

    ret = ldap_get_option(ldap, LDAP_OPT_DESC, fd);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to get fd from ldap!!\n"));
        *fd = -1;
        return EIO;
    }

    return EOK;
}

/* ==Parse-Results-And-Handle-Disconnections============================== */
static void sdap_process_message(struct tevent_context *ev,
                                 struct sdap_handle *sh, LDAPMessage *msg);
static void sdap_process_result(struct tevent_context *ev, void *pvt);
static void sdap_process_next_reply(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt);

static void sdap_ldap_result(struct tevent_context *ev,
                             struct tevent_fd *fde,
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

static void sdap_process_result(struct tevent_context *ev, void *pvt)
{
    struct sdap_handle *sh = talloc_get_type(pvt, struct sdap_handle);
    struct timeval no_timeout = {0, 0};
    struct tevent_timer *te;
    LDAPMessage *msg;
    int ret;

    DEBUG(8, ("Trace: sh[%p], connected[%d], ops[%p], fde[%p], ldap[%p]\n",
              sh, (int)sh->connected, sh->ops, sh->fde, sh->ldap));

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

static int sdap_install_ldap_callbacks(struct sdap_handle *sh,
                                       struct tevent_context *ev)
{
    int fd;
    int ret;

    ret = get_fd_from_ldap(sh->ldap, &fd);
    if (ret) return ret;

    sh->fde = tevent_add_fd(ev, sh, fd, TEVENT_FD_READ, sdap_ldap_result, sh);
    if (!sh->fde) return ENOMEM;

    DEBUG(8, ("Trace: sh[%p], connected[%d], ops[%p], fde[%p], ldap[%p]\n",
              sh, (int)sh->connected, sh->ops, sh->fde, sh->ldap));

    return EOK;
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

static int sdap_op_add(TALLOC_CTX *memctx, struct tevent_context *ev,
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

/* ==Connect-to-LDAP-Server=============================================== */

struct sdap_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sdap_op *op;

    struct sdap_msg *reply;
    int result;
};

static void sdap_connect_done(struct sdap_op *op,
                              struct sdap_msg *reply,
                              int error, void *pvt);

struct tevent_req *sdap_connect_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sdap_options *opts,
                                     bool use_start_tls)
{
    struct tevent_req *req;
    struct sdap_connect_state *state;
    struct timeval tv;
    int ver;
    int lret;
    int ret = EOK;
    int msgid;

    req = tevent_req_create(memctx, &state, struct sdap_connect_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sdap_handle_create(state);
    if (!state->sh) {
        talloc_zfree(req);
        return NULL;
    }
    /* Initialize LDAP handler */
    lret = ldap_initialize(&state->sh->ldap,
                           sdap_go_get_string(opts->basic, SDAP_URI));
    if (lret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_initialize failed: %s\n", ldap_err2string(ret)));
        goto fail;
    }

    /* Force ldap version to 3 */
    ver = LDAP_VERSION3;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set ldap version to 3\n"));
        goto fail;
    }

    /* Set Network Timeout */
    tv.tv_sec = sdap_go_get_int(opts->basic, SDAP_NETWORK_TIMEOUT);
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set network timeout to %d\n",
                  sdap_go_get_int(opts->basic, SDAP_NETWORK_TIMEOUT)));
        goto fail;
    }

    /* Set Default Timeout */
    tv.tv_sec = sdap_go_get_int(opts->basic, SDAP_OPT_TIMEOUT);
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set default timeout to %d\n",
                  sdap_go_get_int(opts->basic, SDAP_OPT_TIMEOUT)));
        goto fail;
    }

    /* if we do not use start_tls the connection is not really connected yet
     * just fake an async procedure and leave connection to the bind call */
    if (!use_start_tls) {
        tevent_req_post(req, ev);
        return req;
    }

    DEBUG(4, ("Executing START TLS\n"));

    lret = ldap_start_tls(state->sh->ldap, NULL, NULL, &msgid);
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_start_tls failed: [%s]", ldap_err2string(ret)));
        goto fail;
    }

    state->sh->connected = true;
    ret = sdap_install_ldap_callbacks(state->sh, state->ev);
    if (ret) goto fail;

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, state->sh, msgid,
                      sdap_connect_done, req, 5, &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    if (ret) {
        tevent_req_error(req, ret);
    } else {
        if (lret == LDAP_SERVER_DOWN) {
            tevent_req_error(req, ETIMEDOUT);
        } else {
            tevent_req_error(req, EIO);
        }
    }
    tevent_req_post(req, ev);
    return req;
}

static void sdap_connect_done(struct sdap_op *op,
                              struct sdap_msg *reply,
                              int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_connect_state *state = tevent_req_data(req,
                                          struct sdap_connect_state);
    char *errmsg;
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    ret = ldap_parse_result(state->sh->ldap, state->reply->msg,
                            &state->result, NULL, &errmsg, NULL, NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(3, ("START TLS result: %s(%d), %s\n",
              ldap_err2string(state->result), state->result, errmsg));

    if (ldap_tls_inplace(state->sh->ldap)) {
        DEBUG(9, ("SSL/TLS handler already in place.\n"));
        tevent_req_done(req);
        return;
    }

/* FIXME: take care that ldap_install_tls might block */
    ret = ldap_install_tls(state->sh->ldap);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_install_tls failed: [%d][%s]\n", ret,
                  ldap_err2string(ret)));
        state->result = ret;
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

int sdap_connect_recv(struct tevent_req *req,
                      TALLOC_CTX *memctx,
                      struct sdap_handle **sh)
{
    struct sdap_connect_state *state = tevent_req_data(req,
                                                  struct sdap_connect_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        /* if tstate shows in progress, it is because
         * we did not ask to perform tls, just pretend all is fine */
        if (tstate != TEVENT_REQ_IN_PROGRESS) {
            return err;
        }
    }

    *sh = talloc_steal(memctx, state->sh);
    if (!*sh) {
        return ENOMEM;
    }
    return EOK;
}

/* ==Simple-Bind========================================================== */

struct simple_bind_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    const char *user_dn;
    struct berval *pw;

    struct sdap_op *op;

    struct sdap_msg *reply;
    int result;
};

static void simple_bind_done(struct sdap_op *op,
                             struct sdap_msg *reply,
                             int error, void *pvt);

static struct tevent_req *simple_bind_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           const char *user_dn,
                                           struct berval *pw)
{
    struct tevent_req *req;
    struct simple_bind_state *state;
    int ret = EOK;
    int msgid;
    int ldap_err;
    LDAPControl *request_controls[2];

    req = tevent_req_create(memctx, &state, struct simple_bind_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

    state->ev = ev;
    state->sh = sh;
    state->user_dn = user_dn;
    state->pw = pw;

    ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                  0, NULL, 0, &request_controls[0]);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("sss_ldap_control_create failed.\n"));
        goto fail;
    }
    request_controls[1] = NULL;

    DEBUG(4, ("Executing simple bind as: %s\n", state->user_dn));

    ret = ldap_sasl_bind(state->sh->ldap, state->user_dn, LDAP_SASL_SIMPLE,
                         state->pw, request_controls, NULL, &msgid);
    ldap_control_free(request_controls[0]);
    if (ret == -1 || msgid == -1) {
        ret = ldap_get_option(state->sh->ldap,
                              LDAP_OPT_RESULT_CODE, &ldap_err);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_bind failed (couldn't get ldap error)\n"));
            ret = LDAP_LOCAL_ERROR;
        } else {
            DEBUG(1, ("ldap_bind failed (%d)[%s]\n",
                      ldap_err, ldap_err2string(ldap_err)));
            ret = ldap_err;
        }
        goto fail;
    }
    DEBUG(8, ("ldap simple bind sent, msgid = %d\n", msgid));

    if (!sh->connected) {
        sh->connected = true;
        ret = sdap_install_ldap_callbacks(sh, ev);
        if (ret) goto fail;
    }

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, sh, msgid,
                      simple_bind_done, req, 5, &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    if (ret == LDAP_SERVER_DOWN) {
        tevent_req_error(req, ETIMEDOUT);
    } else {
        tevent_req_error(req, EIO);
    }
    tevent_req_post(req, ev);
    return req;
}

static void simple_bind_done(struct sdap_op *op,
                             struct sdap_msg *reply,
                             int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct simple_bind_state *state = tevent_req_data(req,
                                            struct simple_bind_state);
    char *errmsg;
    int ret;
    LDAPControl **response_controls;
    int c;
    ber_int_t pp_grace;
    ber_int_t pp_expire;
    LDAPPasswordPolicyError pp_error;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    ret = ldap_parse_result(state->sh->ldap, state->reply->msg,
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

                if (state->result == LDAP_SUCCESS &&
                    (pp_error == PP_changeAfterReset || pp_grace > 0)) {
                    DEBUG(4, ("User must set a new password.\n"));
                    state->result = LDAP_X_SSSD_PASSWORD_EXPIRED;
                }
            }
        }
    }

    DEBUG(3, ("Bind result: %s(%d), %s\n",
              ldap_err2string(state->result), state->result, errmsg));

    ret = LDAP_SUCCESS;
done:
    ldap_controls_free(response_controls);

    if (ret == LDAP_SUCCESS) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static int simple_bind_recv(struct tevent_req *req, int *ldaperr)
{
    struct simple_bind_state *state = tevent_req_data(req,
                                            struct simple_bind_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        *ldaperr = LDAP_OTHER;
        if (err) return err;
        return EIO;
    }

    *ldaperr = state->result;
    return EOK;
}

/* ==SASL-Bind============================================================ */

struct sasl_bind_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;

    const char *sasl_mech;
    const char *sasl_user;
    struct berval *sasl_cred;

    int result;
};

static int sdap_sasl_interact(LDAP *ld, unsigned flags,
                              void *defaults, void *interact);

static struct tevent_req *sasl_bind_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_handle *sh,
                                         const char *sasl_mech,
                                         const char *sasl_user,
                                         struct berval *sasl_cred)
{
    struct tevent_req *req;
    struct sasl_bind_state *state;
    int ret = EOK;

    req = tevent_req_create(memctx, &state, struct sasl_bind_state);
    if (!req) return NULL;

    state->ev = ev;
    state->sh = sh;
    state->sasl_mech = sasl_mech;
    state->sasl_user = sasl_user;
    state->sasl_cred = sasl_cred;

    DEBUG(4, ("Executing sasl bind mech: %s, user: %s\n",
              sasl_mech, sasl_user));

    /* FIXME: Warning, this is a sync call!
     * No async variant exist in openldap libraries yet */

    ret = ldap_sasl_interactive_bind_s(state->sh->ldap, NULL,
                                       sasl_mech, NULL, NULL,
                                       LDAP_SASL_QUIET,
                                       (*sdap_sasl_interact), state);
    state->result = ret;
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_sasl_bind failed (%d)[%s]\n",
                  ret, ldap_err2string(ret)));
        goto fail;
    }

    if (!sh->connected) {
        sh->connected = true;
        ret = sdap_install_ldap_callbacks(sh, ev);
        if (ret) goto fail;
    }

    tevent_req_post(req, ev);
    return req;

fail:
    if (ret == LDAP_SERVER_DOWN) {
        tevent_req_error(req, ETIMEDOUT);
    } else {
        tevent_req_error(req, EIO);
    }
    tevent_req_post(req, ev);
    return req;
}

static int sdap_sasl_interact(LDAP *ld, unsigned flags,
                              void *defaults, void *interact)
{
    struct sasl_bind_state *state = talloc_get_type(defaults,
                                                    struct sasl_bind_state);
    sasl_interact_t *in = (sasl_interact_t *)interact;

    if (!ld) return LDAP_PARAM_ERROR;

    while (in->id != SASL_CB_LIST_END) {

        switch (in->id) {
        case SASL_CB_GETREALM:
        case SASL_CB_AUTHNAME:
        case SASL_CB_PASS:
            if (in->defresult) {
                in->result = in->defresult;
            } else {
                in->result = "";
            }
            in->len = strlen(in->result);
            break;
        case SASL_CB_USER:
            if (state->sasl_user) {
                in->result = state->sasl_user;
            } else if (in->defresult) {
                in->result = in->defresult;
            } else {
                in->result = "";
            }
            in->len = strlen(in->result);
            break;
        case SASL_CB_NOECHOPROMPT:
        case SASL_CB_ECHOPROMPT:
            goto fail;
        }

        in++;
    }

    return LDAP_SUCCESS;

fail:
    return LDAP_UNAVAILABLE;
}

static int sasl_bind_recv(struct tevent_req *req, int *ldaperr)
{
    struct sasl_bind_state *state = tevent_req_data(req,
                                            struct sasl_bind_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (tstate != TEVENT_REQ_IN_PROGRESS) {
            *ldaperr = LDAP_OTHER;
            if (err) return err;
            return EIO;
        }
    }

    *ldaperr = state->result;
    return EOK;
}

/* ==Perform-Kinit-given-keytab-and-principal============================= */

static int sdap_krb5_get_tgt_sync(TALLOC_CTX *memctx,
                                  const char *realm_str,
                                  const char *princ_str,
                                  const char *keytab_name)
{
    char *ccname;
    char *realm_name = NULL;
    char *full_princ = NULL;
    krb5_context context = NULL;
    krb5_keytab keytab = NULL;
    krb5_ccache ccache = NULL;
    krb5_principal kprinc;
    krb5_creds my_creds;
    krb5_get_init_creds_opt options;
    krb5_error_code krberr;
    int ret;

    krberr = krb5_init_context(&context);
    if (krberr) {
        DEBUG(2, ("Failed to init kerberos context\n"));
        return EFAULT;
    }

    if (!realm_str) {
        krberr = krb5_get_default_realm(context, &realm_name);
        if (krberr) {
            DEBUG(2, ("Failed to get default realm name: %s\n",
                      krb5_get_error_message(context, krberr)));
            ret = EFAULT;
            goto done;
        }
    } else {
        realm_name = talloc_strdup(memctx, realm_str);
        if (!realm_name) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (princ_str) {
        if (!strchr(princ_str, '@')) {
            full_princ = talloc_asprintf(memctx, "%s@%s",
                                         princ_str, realm_name);
        } else {
            full_princ = talloc_strdup(memctx, princ_str);
        }
    } else {
        char hostname[512];

        ret = gethostname(hostname, 511);
        if (ret == -1) {
            ret = errno;
            goto done;
        }
        hostname[511] = '\0';

        full_princ = talloc_asprintf(memctx, "host/%s@%s",
                                     hostname, realm_name);
    }
    if (!full_princ) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(1, ("Principal name is: [%s]\n", full_princ));

    krberr = krb5_parse_name(context, full_princ, &kprinc);
    if (krberr) {
        DEBUG(2, ("Unable to build principal: %s\n",
                  krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    if (keytab_name) {
        krberr = krb5_kt_resolve(context, keytab_name, &keytab);
    } else {
        krberr = krb5_kt_default(context, &keytab);
    }
    if (krberr) {
        DEBUG(2, ("Failed to read keytab file: %s\n",
                  krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    ccname = talloc_asprintf(memctx, "FILE:%s/ccache_%s", DB_PATH, realm_name);
    if (!ccname) {
        ret = ENOMEM;
        goto done;
    }

    ret = setenv("KRB5CCNAME", ccname, 1);
    if (ret == -1) {
        DEBUG(2, ("Unable to set env. variable KRB5CCNAME!\n"));
        ret = EFAULT;
        goto done;
    }

    krberr = krb5_cc_resolve(context, ccname, &ccache);
    if (krberr) {
        DEBUG(2, ("Failed to set cache name: %s\n",
                  krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    memset(&my_creds, 0, sizeof(my_creds));
    memset(&options, 0, sizeof(options));

    krb5_get_init_creds_opt_set_address_list(&options, NULL);
    krb5_get_init_creds_opt_set_forwardable(&options, 0);
    krb5_get_init_creds_opt_set_proxiable(&options, 0);
    /* set a very short lifetime, we don't keep the ticket around */
    krb5_get_init_creds_opt_set_tkt_life(&options, 300);

    krberr = krb5_get_init_creds_keytab(context, &my_creds, kprinc,
                                        keytab, 0, NULL, &options);

    if (krberr) {
        DEBUG(2, ("Failed to init credentials: %s\n",
                  krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    krberr = krb5_cc_initialize(context, ccache, kprinc);
    if (krberr) {
        DEBUG(2, ("Failed to init ccache: %s\n",
                  krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    krberr = krb5_cc_store_cred(context, ccache, &my_creds);
    if (krberr) {
        DEBUG(2, ("Failed to store creds: %s\n",
                  krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    ret = EOK;

done:
    if (keytab) krb5_kt_close(context, keytab);
    if (context) krb5_free_context(context);
    return ret;
}

struct sdap_kinit_state {
    int result;
};

/* TODO: make it really async */
struct tevent_req *sdap_kinit_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_handle *sh,
                                   const char *keytab,
                                   const char *principal,
                                   const char *realm)
{
    struct tevent_req *req;
    struct sdap_kinit_state *state;
    int ret;

    DEBUG(6, ("Attempting kinit (%s, %s, %s)\n", keytab, principal, realm));

    req = tevent_req_create(memctx, &state, struct sdap_kinit_state);
    if (!req) return NULL;

    state->result = SDAP_AUTH_FAILED;

    if (keytab) {
        ret = setenv("KRB5_KTNAME", keytab, 1);
        if (ret == -1) {
            DEBUG(2, ("Failed to set KRB5_KTNAME to %s\n", keytab));
            ret = EFAULT;
            goto fail;
        }
    }

    ret = sdap_krb5_get_tgt_sync(state, realm, principal, keytab);
    if (ret == EOK) {
        state->result = SDAP_AUTH_SUCCESS;
    } else {
        goto fail;
    }

    tevent_req_post(req, ev);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

int sdap_kinit_recv(struct tevent_req *req, enum sdap_result *result)
{
    struct sdap_kinit_state *state = tevent_req_data(req,
                                                struct sdap_kinit_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (tstate != TEVENT_REQ_IN_PROGRESS) {
            *result = SDAP_ERROR;
            if (err) return err;
            return EIO;
        }
    }

    *result = state->result;
    return EOK;
}


/* ==Authenticaticate-User-by-DN========================================== */

struct sdap_auth_state {
    const char *user_dn;
    struct berval pw;

    int result;
    bool is_sasl;
};

static void sdap_auth_done(struct tevent_req *subreq);

/* TODO: handle sasl_cred */
struct tevent_req *sdap_auth_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_handle *sh,
                                  const char *sasl_mech,
                                  const char *sasl_user,
                                  const char *user_dn,
                                  const char *authtok_type,
                                  struct sdap_blob authtok)
{
    struct tevent_req *req, *subreq;
    struct sdap_auth_state *state;

    if (authtok_type != NULL && strcasecmp(authtok_type,"password") != 0) {
        DEBUG(1,("Authentication token type [%s] is not supported"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct sdap_auth_state);
    if (!req) return NULL;

    state->user_dn = user_dn;
    state->pw.bv_val = (char *)authtok.data;
    state->pw.bv_len = authtok.length;

    if (sasl_mech) {
        state->is_sasl = true;
        subreq = sasl_bind_send(state, ev, sh, sasl_mech, sasl_user, NULL);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return tevent_req_post(req, ev);
        }
    } else {
        state->is_sasl = false;
        subreq = simple_bind_send(state, ev, sh, user_dn, &state->pw);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return tevent_req_post(req, ev);
        }
    }

    tevent_req_set_callback(subreq, sdap_auth_done, req);
    return req;
}

static void sdap_auth_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_auth_state *state = tevent_req_data(req,
                                                 struct sdap_auth_state);
    int ret;

    if (state->is_sasl) {
        ret = sasl_bind_recv(subreq, &state->result);
    } else {
        ret = simple_bind_recv(subreq, &state->result);
    }
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_auth_recv(struct tevent_req *req, enum sdap_result *result)
{
    struct sdap_auth_state *state = tevent_req_data(req,
                                                 struct sdap_auth_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        *result = SDAP_ERROR;
        return err;
    }
    switch (state->result) {
        case LDAP_SUCCESS:
            *result = SDAP_AUTH_SUCCESS;
            break;
        case LDAP_INVALID_CREDENTIALS:
            *result = SDAP_AUTH_FAILED;
            break;
        case LDAP_X_SSSD_PASSWORD_EXPIRED:
            *result = SDAP_AUTH_PW_EXPIRED;
            break;
        default:
            *result = SDAP_ERROR;
    }
    return EOK;
}


/* ==Save-User-Entry====================================================== */

struct sdap_save_user_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sss_domain_info *dom;

    const char *name;
    struct sysdb_attrs *attrs;
    char *timestamp;
};

static void sdap_save_user_done(struct tevent_req *subreq);

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static struct tevent_req *sdap_save_user_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sysdb_handle *handle,
                                              struct sdap_options *opts,
                                              struct sss_domain_info *dom,
                                              struct sdap_handle *sh,
                                              struct sdap_msg *entry)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_user_state *state;
    struct ldb_message_element *el;
    int ret;
    const char *pwd;
    const char *gecos;
    const char *homedir;
    const char *shell;
    long int l;
    uid_t uid;
    gid_t gid;
    struct sysdb_attrs *user_attrs;
    char *upn = NULL;

    req = tevent_req_create(memctx, &state, struct sdap_save_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->sh = sh;
    state->dom = dom;
    state->opts = opts;
    state->timestamp = NULL;

    ret = sdap_parse_user(state, state->opts, state->sh,
                          entry, &state->attrs, NULL);
    if (ret) goto fail;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_NAME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        ret = EINVAL;
        goto fail;
    }
    state->name = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_PWD].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) pwd = NULL;
    else pwd = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_GECOS].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) gecos = NULL;
    else gecos = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_HOME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) homedir = NULL;
    else homedir = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_SHELL].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) shell = NULL;
    else shell = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_UID].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        DEBUG(1, ("no uid provided for [%s] in domain [%s].\n",
                  state->name, dom->name));
        ret = EINVAL;
        goto fail;
    }
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    uid = l;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_GID].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        DEBUG(1, ("no gid provided for [%s] in domain [%s].\n",
                  state->name, dom->name));
        ret = EINVAL;
        goto fail;
    }
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    gid = l;

    user_attrs = sysdb_new_attrs(state);
    if (user_attrs == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_get_el(state->attrs, SYSDB_ORIG_DN, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original DN is not available for [%s].\n", state->name));
    } else {
        DEBUG(7, ("Adding original DN [%s] to attributes of [%s].\n",
                  el->values[0].data, state->name));
        ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_DN,
                                     (const char *) el->values[0].data);
        if (ret) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(state->attrs,
                      opts->user_map[SDAP_AT_USER_MODSTAMP].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original mod-Timestamp is not available for [%s].\n",
                  state->name));
    } else {
        ret = sysdb_attrs_add_string(user_attrs,
                          opts->user_map[SDAP_AT_USER_MODSTAMP].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
        state->timestamp = talloc_strdup(state,
                                         (const char*)el->values[0].data);
        if (!state->timestamp) {
            ret = ENOMEM;
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_PRINC].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("User principle is not available for [%s].\n", state->name));
    } else {
        upn = talloc_strdup(user_attrs, (const char*) el->values[0].data);
        if (!upn) {
            ret = ENOMEM;
            goto fail;
        }
        if (sdap_go_get_bool(opts->basic, SDAP_FORCE_UPPER_CASE_REALM)) {
            make_realm_upper_case(upn);
        }
        DEBUG(7, ("Adding user principle [%s] to attributes of [%s].\n",
                  upn, state->name));
        ret = sysdb_attrs_add_string(user_attrs, SYSDB_UPN, upn);
        if (ret) {
            goto fail;
        }
    }

    DEBUG(6, ("Storing info for user %s\n", state->name));

    subreq = sysdb_store_user_send(state, state->ev, state->handle,
                                   state->dom, state->name, pwd,
                                   uid, gid, gecos, homedir, shell,
                                   user_attrs);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_save_user_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_save_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_save_user_state *state = tevent_req_data(req,
                                            struct sdap_save_user_state);
    int ret;

    ret = sysdb_store_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Failed to save user %s\n", state->name));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_save_user_recv(struct tevent_req *req,
                               TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_save_user_state *state = tevent_req_data(req,
                                            struct sdap_save_user_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (!err) return EIO;
        return err;
    }

    *timestamp = talloc_steal(mem_ctx, state->timestamp);

    return EOK;
}


/* ==Save-Group-Entry===================================================== */

struct sdap_save_group_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sss_domain_info *dom;

    const char *name;
    struct sysdb_attrs *attrs;
    char *timestamp;
};

static void sdap_save_group_done(struct tevent_req *subreq);

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static struct tevent_req *sdap_save_group_send(TALLOC_CTX *memctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct sdap_options *opts,
                                               struct sss_domain_info *dom,
                                               struct sdap_handle *sh,
                                               struct sdap_msg *entry)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_group_state *state;
    struct ldb_message_element *el;
    const char **member_groups = NULL;
    const char **member_users = NULL;
    struct sysdb_attrs *group_attrs;
    int mu, mg;
    int i;
    long int l;
    gid_t gid;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_save_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->sh = sh;
    state->dom = dom;
    state->opts = opts;
    state->timestamp = NULL;

    ret = sdap_parse_group(state, state->opts, state->sh,
                           entry, &state->attrs, NULL);
    if (ret) goto fail;

    ret = sysdb_attrs_get_el(state->attrs,
                          opts->group_map[SDAP_AT_GROUP_NAME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        ret = EINVAL;
        goto fail;
    }
    state->name = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                          opts->group_map[SDAP_AT_GROUP_GID].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        DEBUG(1, ("no gid provided for [%s] in domain [%s].\n",
                  state->name, dom->name));
        ret = EINVAL;
        goto fail;
    }
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    gid = l;

    group_attrs = sysdb_new_attrs(state);
    if (!group_attrs) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_get_el(state->attrs,
                      opts->group_map[SDAP_AT_GROUP_MODSTAMP].sys_name, &el);
    if (ret) {
        goto fail;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original mod-Timestamp is not available for [%s].\n",
                  state->name));
    } else {
        ret = sysdb_attrs_add_string(group_attrs,
                          opts->group_map[SDAP_AT_GROUP_MODSTAMP].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto fail;
        }
        state->timestamp = talloc_strdup(state,
                                         (const char*)el->values[0].data);
        if (!state->timestamp) {
            ret = ENOMEM;
            goto fail;
        }
    }

    switch (opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:

        ret = sysdb_attrs_get_el(state->attrs,
                        opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
        if (ret) goto fail;
        if (el->num_values == 0) {
            DEBUG(7, ("[RFC2307bis] No members for group [%s]\n", state->name));
            break;
        }

        DEBUG(7, ("[RFC2307] Adding member users to group [%s]\n",
                  state->name));

        member_users = talloc_array(state, const char *,
                                    el->num_values +1);
        if (!member_users) {
            ret = ENOMEM;
            goto fail;
        }
        for (i = 0; i < el->num_values; i++) {
            member_users[i] = (char *)el->values[i].data;
            DEBUG(7, ("    member user %d: [%s]\n", i, member_users[i]));
        }
        member_users[i] =  NULL;

        break;

    case SDAP_SCHEMA_RFC2307BIS:
    case SDAP_SCHEMA_IPA_V1:

        /* if this is the first time we are called, check if users and
         * groups base DNs are set, if not do it */
        if (!opts->users_base) {
            opts->users_base = ldb_dn_new_fmt(opts,
                                    sysdb_handle_get_ldb(state->handle), "%s",
                                    sdap_go_get_string(opts->basic,
                                                      SDAP_USER_SEARCH_BASE));
            if (!opts->users_base) {
                DEBUG(1, ("Unable to get casefold Users Base DN from [%s]\n",
                          sdap_go_get_string(opts->basic,
                                             SDAP_USER_SEARCH_BASE)));
                DEBUG(1, ("Out of memory?!\n"));
                ret = ENOMEM;
                goto fail;
            }
        }
        if (!opts->groups_base) {
            opts->groups_base = ldb_dn_new_fmt(state->handle,
                                    sysdb_handle_get_ldb(state->handle), "%s",
                                    sdap_go_get_string(opts->basic,
                                                      SDAP_GROUP_SEARCH_BASE));
            if (!opts->users_base) {
                DEBUG(1, ("Unable to get casefold Users Base DN from [%s]\n",
                          sdap_go_get_string(opts->basic,
                                             SDAP_GROUP_SEARCH_BASE)));
                DEBUG(1, ("Out of memory?!\n"));
                ret = ENOMEM;
                goto fail;
            }
        }

        ret = sysdb_attrs_get_el(state->attrs,
                        opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
        if (ret) goto fail;
        if (el->num_values == 0) {
            DEBUG(7, ("[RFC2307bis] No members for group [%s]\n", state->name));
            break;
        }

        /* this will hold both lists,
         * users filling up from top and groups from bottom,
         * so the array will need 2 slots for NULL terminating element */
        member_users = talloc_zero_array(state, const char *,
                                         el->num_values +2);
        if (!member_users) {
            ret = ENOMEM;
            goto fail;
        }

        mg = el->num_values;
        mu = 0;

        DEBUG(7, ("[RFC2307bis] Adding members to group [%s]\n", state->name));

        for (i = 0; i < el->num_values; i++) {

            struct ldb_dn *tmp_dn = NULL;
            const struct ldb_val *v;


            /* parse out DN */
            tmp_dn = ldb_dn_new_fmt(member_users,
                                    sysdb_handle_get_ldb(state->handle),
                                    "%.*s",
                                    (int)el->values[i].length,
                                    (char *)el->values[i].data);
            if (!tmp_dn) {
                DEBUG(1, ("Unable to parse DN: [%.*s]\n",
                          (int)el->values[i].length,
                          (char *)el->values[i].data));
                continue;
            }
            v = ldb_dn_get_rdn_val(tmp_dn);
            if (!v) {
                DEBUG(1, ("Unable to parse DN: [%.*s]\n",
                          (int)el->values[i].length,
                          (char *)el->values[i].data));
                continue;
            }
            DEBUG(9, ("Member DN [%.*s], RDN [%.*s]\n",
                      (int)el->values[i].length, (char *)el->values[i].data,
                      (int)v->length, (char *)v->data));

            if (ldb_dn_compare_base(opts->users_base, tmp_dn) == 0) {
                member_users[mu] = talloc_asprintf(member_users,
                                                   "%.*s",
                                                   (int)v->length,
                                                   (char *)v->data);
                if (!member_users[mu]) {
                    DEBUG(1, ("Out of memory?!\n"));
                    continue;
                }

                DEBUG(7, ("    member user %d: [%s]\n", i, member_users[mu]));

                mu++;

            } else if (ldb_dn_compare_base(opts->groups_base, tmp_dn) == 0) {
                member_users[mg] = talloc_asprintf(member_users,
                                                   "%.*s",
                                                   (int)v->length,
                                                   (char *)v->data);
                if (!member_users[mg]) {
                    DEBUG(1, ("Out of memory?!\n"));
                    continue;
                }

                DEBUG(7, ("    member group %d: [%s]\n", i, member_users[mg]));

                mg--;

            } else {
                DEBUG(1, ("Unkown Member type for DN: [%s]\n",
                          (int)el->values[i].length,
                          (char *)el->values[i].data));
                continue;
            }
            if (mu > mg) { /* shouldn't be possible */
                DEBUG(0, ("Fatal Internal error: aborting\n"));
                ret = EFAULT;
                goto fail;
            }
        }

        /* if there are groups, set member_groups */
        if (mg != el->num_values) {
            member_groups = &member_users[mg+1];
        }

        /* if there are no users, reset member_users */
        if (mu == 0) {
            member_users = NULL;
        }

        break;

    default:
        DEBUG(0, ("FATAL ERROR: Unhandled schema type! (%d)\n",
                  opts->schema_type));
        ret = EFAULT;
        goto fail;
    }

    DEBUG(6, ("Storing info for group %s\n", state->name));

    subreq = sysdb_store_group_send(state, state->ev,
                                    state->handle, state->dom,
                                    state->name, gid,
                                    member_users, member_groups,
                                    group_attrs);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_save_group_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_save_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_save_group_state *state = tevent_req_data(req,
                                            struct sdap_save_group_state);
    int ret;

    ret = sysdb_store_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Failed to save group %s [%d]\n", state->name, ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_save_group_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_save_group_state *state = tevent_req_data(req,
                                            struct sdap_save_group_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (!err) return EIO;
        return err;
    }

    if ( timestamp ) {
        *timestamp = talloc_steal(mem_ctx, state->timestamp);
    }

    return EOK;
}


/* ==Search-Users-with-filter============================================= */

struct sdap_get_users_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    const char **attrs;
    const char *filter;

    struct sysdb_handle *handle;
    struct sdap_op *op;

    char *higher_timestamp;
};

static void sdap_get_users_transaction(struct tevent_req *subreq);
static void sdap_get_users_done(struct sdap_op *op,
                                struct sdap_msg *reply,
                                int error, void *pvt);
static void sdap_get_users_save_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_users_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_users_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->filter = filter;
    state->attrs = attrs;
    state->higher_timestamp = NULL;

    subreq = sysdb_transaction_send(state, state->ev, sysdb);
    if (!subreq) return NULL;
    tevent_req_set_callback(subreq, sdap_get_users_transaction, req);

    return req;
}

static void sdap_get_users_transaction(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    int lret, ret;
    int msgid;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(5, ("calling ldap_search_ext with [%s].\n", state->filter));

    lret = ldap_search_ext(state->sh->ldap,
                           sdap_go_get_string(state->opts->basic,
                                              SDAP_USER_SEARCH_BASE),
                           LDAP_SCOPE_SUBTREE, state->filter,
                           discard_const(state->attrs),
                           false, NULL, NULL, NULL, 0, &msgid);
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", ldap_err2string(lret)));
        tevent_req_error(req, EIO);
        return;
    }
    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", msgid));

    /* FIXME: get timeouts from configuration, for now 10 minutes */
    ret = sdap_op_add(state, state->ev, state->sh, msgid,
                      sdap_get_users_done, req,
                      sdap_go_get_int(state->opts->basic,
                                      SDAP_SEARCH_TIMEOUT),
                      &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        tevent_req_error(req, ret);
    }
}

static void sdap_get_users_done(struct sdap_op *op,
                                struct sdap_msg *reply,
                                int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    struct tevent_req *subreq;
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

        subreq = sdap_save_user_send(state, state->ev, state->handle,
                                     state->opts, state->dom,
                                     state->sh, reply);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_users_save_done, req);

        break;

    case LDAP_RES_SEARCH_RESULT:
        /* End of the story */

        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, NULL, NULL, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(3, ("Search result: %s(%d), %s\n",
                  ldap_err2string(result), result, errmsg));

        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
        break;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static void sdap_get_users_save_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    char *timestamp = NULL;
    int ret;

    ret = sdap_save_user_recv(subreq, state, &timestamp);
    talloc_zfree(subreq);

    /* Do not fail completely on errors.
     * Just report the failure to save and go on */
    if (ret) {
        DEBUG(2, ("Failed to store user. Ignoring.\n"));
        timestamp = NULL;
    }

    if (timestamp) {
        if (state->higher_timestamp) {
            if (strcmp(timestamp, state->higher_timestamp) > 0) {
                talloc_zfree(state->higher_timestamp);
                state->higher_timestamp = timestamp;
            } else {
                talloc_zfree(timestamp);
            }
        } else {
            state->higher_timestamp = timestamp;
        }
    }

    /* unlock the operation so that we can proceed with the next result */
    sdap_unlock_next_reply(state->op);
}

int sdap_get_users_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    if (timestamp) {
        *timestamp = talloc_steal(mem_ctx, state->higher_timestamp);
    }

    return EOK;
}

/* ==Search-Groups-with-filter============================================ */

struct sdap_get_groups_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    const char **attrs;
    const char *filter;

    struct sysdb_handle *handle;
    struct sdap_op *op;
    char *higher_timestamp;
};

static void sdap_get_groups_transaction(struct tevent_req *subreq);
static void sdap_get_groups_done(struct sdap_op *op,
                                 struct sdap_msg *reply,
                                 int error, void *pvt);
static void sdap_get_groups_save_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_groups_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_groups_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->filter = filter;
    state->attrs = attrs;
    state->higher_timestamp = NULL;

    subreq = sysdb_transaction_send(state, state->ev, sysdb);
    if (!subreq) return NULL;
    tevent_req_set_callback(subreq, sdap_get_groups_transaction, req);

    return req;
}

static void sdap_get_groups_transaction(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                               struct sdap_get_groups_state);
    int ret, lret;
    int msgid;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(7, ("calling ldap_search_ext with [%s].\n", state->filter));
    if (debug_level >= 7) {
        int i;

        for (i = 0; state->attrs[i]; i++) {
            DEBUG(7, ("Requesting attrs: [%s]\n", state->attrs[i]));
        }
    }

    lret = ldap_search_ext(state->sh->ldap,
                           sdap_go_get_string(state->opts->basic,
                                              SDAP_GROUP_SEARCH_BASE),
                           LDAP_SCOPE_SUBTREE, state->filter,
                           discard_const(state->attrs),
                           false, NULL, NULL, NULL, 0, &msgid);
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", ldap_err2string(lret)));
        tevent_req_error(req, EIO);
        return;
    }
    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", msgid));

    /* FIXME: get timeouts from configuration, for now 10 minutes */
    ret = sdap_op_add(state, state->ev, state->sh, msgid,
                      sdap_get_groups_done, req,
                      sdap_go_get_int(state->opts->basic,
                                      SDAP_SEARCH_TIMEOUT),
                      &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        tevent_req_error(req, ret);
    }
}

static void sdap_get_groups_done(struct sdap_op *op,
                                 struct sdap_msg *reply,
                                 int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    struct tevent_req *subreq;
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

        /* FIXME: we should do this in 2 steps:
         * first save groups, then add all memberships
         * otherwise nested memberships may go missing
         * if the member group is added only after the
         * parent group is added */
        subreq = sdap_save_group_send(state, state->ev, state->handle,
                                      state->opts, state->dom,
                                      state->sh, reply);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_groups_save_done, req);

        break;

    case LDAP_RES_SEARCH_RESULT:
        /* End of the story */

        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, NULL, NULL, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(3, ("Search result: %s(%d), %s\n",
                  ldap_err2string(result), result, errmsg));

        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
        break;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static void sdap_get_groups_save_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    char *timestamp;
    int ret;

    ret = sdap_save_group_recv(subreq, state, &timestamp);
    talloc_zfree(subreq);

    /* Do not fail completely on errors.
     * Just report the failure to save and go on */

    if (ret) {
        DEBUG(2, ("Failed to store group. Ignoring.\n"));
        timestamp = NULL;
    }

    if (timestamp) {
        if (state->higher_timestamp) {
            if (strcmp(timestamp, state->higher_timestamp) > 0) {
                talloc_zfree(state->higher_timestamp);
                state->higher_timestamp = timestamp;
            } else {
                talloc_zfree(timestamp);
            }
        } else {
            state->higher_timestamp = timestamp;
        }
    }

    /* unlock the operation so that we can proceed with the next result */
    sdap_unlock_next_reply(state->op);
}

int sdap_get_groups_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx, char **timestamp)
{
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    if (timestamp) {
        *timestamp = talloc_steal(mem_ctx, state->higher_timestamp);
    }

    return EOK;
}

/* ==Initgr-call-(groups-a-user-is-member-of)============================= */

struct sdap_get_initgr_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    const char *name;
    const char **grp_attrs;

    const char *filter;

    struct sysdb_handle *handle;
    struct sdap_op *op;
};

static void sdap_get_initgr_process(struct tevent_req *subreq);
static void sdap_get_initgr_transaction(struct tevent_req *subreq);
static void sdap_get_initgr_done(struct sdap_op *op,
                                 struct sdap_msg *reply,
                                 int error, void *pvt);
static void sdap_get_initgr_save_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_initgr_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sss_domain_info *dom,
                                        struct sysdb_ctx *sysdb,
                                        struct sdap_options *opts,
                                        struct sdap_handle *sh,
                                        const char *name,
                                        const char **grp_attrs)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_initgr_state *state;
    struct timeval tv = {0, 0};
    const char **attrs;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_get_initgr_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->name = name;
    state->grp_attrs = grp_attrs;

    switch (opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:

        subreq = tevent_wakeup_send(state, ev, tv);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_process, req);
        break;

    case SDAP_SCHEMA_RFC2307BIS:

        attrs = talloc_array(state, const char *, 2);
        if (!attrs) {
            ret = ENOMEM;
            goto fail;
        }
        attrs[0] = SYSDB_ORIG_DN;
        attrs[1] = NULL;

        subreq = sysdb_search_user_by_name_send(state, ev, sysdb, NULL,
                                                dom, name, attrs);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_process, req);
        break;

    default:
        ret = EINVAL;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, EIO);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_get_initgr_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    struct ldb_message *msg;
    const char *user_dn;
    int ret;

    switch (state->opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:

        if (!tevent_wakeup_recv(subreq)) {
            tevent_req_error(req, EFAULT);
            return;
        }
        talloc_zfree(subreq);

        state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                           state->opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                           state->name,
                           state->opts->group_map[SDAP_OC_GROUP].name);
        break;

    case SDAP_SCHEMA_RFC2307BIS:

        ret = sysdb_search_user_recv(subreq, state, &msg);
        talloc_zfree(subreq);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }

        user_dn = ldb_msg_find_attr_as_string(msg, SYSDB_ORIG_DN, NULL);
        if (!user_dn) {
            tevent_req_error(req, ENOENT);
            return;
        }

        state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                            state->opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                            user_dn,
                            state->opts->group_map[SDAP_OC_GROUP].name);

        talloc_free(msg);
        break;

    default:
        tevent_req_error(req, EINVAL);
        return;
    }

    if (!state->filter) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_initgr_transaction, req);
}

static void sdap_get_initgr_transaction(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret, lret;
    int msgid;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(5, ("calling ldap_search_ext with filter:[%s].\n", state->filter));

    lret = ldap_search_ext(state->sh->ldap,
                           sdap_go_get_string(state->opts->basic,
                                              SDAP_GROUP_SEARCH_BASE),
                           LDAP_SCOPE_SUBTREE, state->filter,
                           discard_const(state->grp_attrs),
                           false, NULL, NULL, NULL, 0, &msgid);
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", ldap_err2string(lret)));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", msgid));

    /* FIXME: get timeouts from configuration, for now 10 minutes */
    ret = sdap_op_add(state, state->ev, state->sh, msgid,
                      sdap_get_initgr_done, req,
                      sdap_go_get_int(state->opts->basic,
                                      SDAP_SEARCH_TIMEOUT),
                      &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        tevent_req_error(req, ret);
    }
}

static void sdap_get_initgr_done(struct sdap_op *op,
                                 struct sdap_msg *reply,
                                 int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    struct tevent_req *subreq;
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

        subreq = sdap_save_group_send(state, state->ev, state->handle,
                                     state->opts, state->dom,
                                     state->sh, reply);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_save_done, req);

        break;

    case LDAP_RES_SEARCH_RESULT:
        /* End of the story */

        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, NULL, NULL, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(3, ("Search result: %s(%d), %s\n",
                  ldap_err2string(result), result, errmsg));

        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
        break;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static void sdap_get_initgr_save_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret;

    ret = sdap_save_group_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);

    /* Do not fail completely on errors.
     * Just report the failure to save and go on */
    if (ret) {
        DEBUG(2, ("Failed to store group. Ignoring.\n"));
    }

    /* unlock the operation so that we can proceed with the next result */
    sdap_unlock_next_reply(state->op);
}

int sdap_get_initgr_recv(struct tevent_req *req)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    return EOK;
}

struct sdap_exop_modify_passwd_state {
    struct sdap_handle *sh;

    struct sdap_op *op;

    int result;
};

static void sdap_exop_modify_passwd_done(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt);

struct tevent_req *sdap_exop_modify_passwd_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           char *user_dn,
                                           char *password,
                                           char *new_password)
{
    struct tevent_req *req = NULL;
    struct sdap_exop_modify_passwd_state *state;
    int ret;
    BerElement *ber = NULL;
    struct berval *bv = NULL;
    int msgid;
    LDAPControl *request_controls[2];

    req = tevent_req_create(memctx, &state,
                            struct sdap_exop_modify_passwd_state);
    if (!req) return NULL;

    state->sh = sh;

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

    ret = ldap_extended_operation(state->sh->ldap, LDAP_EXOP_MODIFY_PASSWD,
                                  bv, request_controls, NULL, &msgid);
    ber_bvfree(bv);
    ldap_control_free(request_controls[0]);
    if (ret == -1 || msgid == -1) {
        DEBUG(1, ("ldap_extended_operation failed\n"));
        goto fail;
    }
    DEBUG(8, ("ldap_extended_operation sent, msgid = %d\n", msgid));

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, state->sh, msgid,
                      sdap_exop_modify_passwd_done, req, 5, &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, EIO);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_exop_modify_passwd_done(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);
    char *errmsg;
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

    ret = LDAP_SUCCESS;
done:
    ldap_controls_free(response_controls);

    if (ret == LDAP_SUCCESS) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

int sdap_exop_modify_passwd_recv(struct tevent_req *req,
                                 enum sdap_result *result)
{
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);
    enum tevent_req_state tstate;
    uint64_t err;

    *result = SDAP_ERROR;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    if (state->result == LDAP_SUCCESS) {
        *result = SDAP_SUCCESS;
    }

    return EOK;
}

/* ==Client connect============================================ */

struct sdap_cli_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;

    struct sdap_handle *sh;
};

static void sdap_cli_connect_done(struct tevent_req *subreq);
static void sdap_cli_kinit_done(struct tevent_req *subreq);
static void sdap_cli_bind_done(struct tevent_req *subreq);

struct tevent_req *sdap_cli_connect_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts)
{
    struct tevent_req *req, *subreq;
    struct sdap_cli_connect_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_cli_connect_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;

    subreq = sdap_connect_send(state, ev, opts,
                               sdap_go_get_bool(opts->basic, SDAP_ID_TLS));
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_cli_connect_done, req);

    return req;
}

static void sdap_cli_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                                struct sdap_cli_connect_state);
    const char *sasl_mech;
    int ret;

    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    sasl_mech = sdap_go_get_string(state->opts->basic, SDAP_SASL_MECH);
    if (sasl_mech && (strcasecmp(sasl_mech, "GSSAPI") == 0)) {
        if (sdap_go_get_bool(state->opts->basic, SDAP_KRB5_KINIT)) {
            subreq = sdap_kinit_send(state, state->ev, state->sh,
                                sdap_go_get_string(state->opts->basic,
                                                           SDAP_KRB5_KEYTAB),
                                sdap_go_get_string(state->opts->basic,
                                                           SDAP_SASL_AUTHID),
                                sdap_go_get_string(state->opts->basic,
                                                           SDAP_KRB5_REALM));
            if (!subreq) {
                tevent_req_error(req, ENOMEM);
                return;
            }
            tevent_req_set_callback(subreq, sdap_cli_kinit_done, req);
            return;
        }
    }

    subreq = sdap_auth_send(state,
                            state->ev,
                            state->sh,
                            sasl_mech,
                            sdap_go_get_string(state->opts->basic,
                                                        SDAP_SASL_AUTHID),
                            sdap_go_get_string(state->opts->basic,
                                                    SDAP_DEFAULT_BIND_DN),
                            sdap_go_get_string(state->opts->basic,
                                               SDAP_DEFAULT_AUTHTOK_TYPE),
                            sdap_go_get_blob(state->opts->basic,
                                                    SDAP_DEFAULT_AUTHTOK));
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_cli_bind_done, req);
}

static void sdap_cli_kinit_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                                struct sdap_cli_connect_state);
    enum sdap_result result;
    int ret;

    ret = sdap_kinit_recv(subreq, &result);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    if (result != SDAP_AUTH_SUCCESS) {
        tevent_req_error(req, EACCES);
        return;
    }

    subreq = sdap_auth_send(state,
                            state->ev,
                            state->sh,
                            sdap_go_get_string(state->opts->basic,
                                                          SDAP_SASL_MECH),
                            sdap_go_get_string(state->opts->basic,
                                                        SDAP_SASL_AUTHID),
                            sdap_go_get_string(state->opts->basic,
                                                    SDAP_DEFAULT_BIND_DN),
                            sdap_go_get_string(state->opts->basic,
                                               SDAP_DEFAULT_AUTHTOK_TYPE),
                            sdap_go_get_blob(state->opts->basic,
                                                    SDAP_DEFAULT_AUTHTOK));
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_cli_bind_done, req);
}

static void sdap_cli_bind_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    enum sdap_result result;
    int ret;

    ret = sdap_auth_recv(subreq, &result);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    if (result != SDAP_AUTH_SUCCESS) {
        tevent_req_error(req, EACCES);
        return;
    }

    tevent_req_done(req);
}

int sdap_cli_connect_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                          struct sdap_handle **gsh)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                                struct sdap_cli_connect_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    *gsh = talloc_steal(memctx, state->sh);
    if (!*gsh) {
        return ENOMEM;
    }
    return EOK;
}
