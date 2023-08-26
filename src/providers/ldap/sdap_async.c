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
#include "util/strtonum.h"
#include "util/probes.h"
#include "util/sss_chain_id.h"
#include "providers/ldap/sdap_async_private.h"

#define REPLY_REALLOC_INCREMENT 10

struct sdap_op {
    struct sdap_op *prev, *next;
    struct sdap_handle *sh;
    uint64_t chain_id;

    int msgid;
    char *stat_info;
    uint64_t start_time;
    int timeout;
    bool done;

    sdap_op_callback_t *callback;
    void *data;

    struct tevent_context *ev;
    struct sdap_msg *list;
    struct sdap_msg *last;
};

int sdap_op_get_msgid(struct sdap_op *op)
{
    return op != NULL ? op->msgid : 0;
}

/* ==LDAP-Memory-Handling================================================= */

static int lmsg_destructor(void *mem)
{
    ldap_msgfree((LDAPMessage *)mem);
    return 0;
}

/* ==sdap-handle-utility-functions======================================== */

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

static void sdap_call_op_callback(struct sdap_op *op, struct sdap_msg *reply,
                                  int error)
{
    uint64_t time_spend;
    const char *info = (op->stat_info == NULL ? "-" : op->stat_info);

    if (op->start_time != 0) {
        time_spend = get_spend_time_us(op->start_time);
        DEBUG(SSSDBG_PERF_STAT,
              "Handling LDAP operation [%d][%s] took %s.\n",
              op->msgid, info, sss_format_time(time_spend));

        /* time_spend is in us and timeout in s */
        if (op->timeout != 0 && (time_spend / op->timeout) >= (80 * 10000)) {
            DEBUG(SSSDBG_IMPORTANT_INFO, "LDAP operation [%d][%s] seems slow, "
                                         "took more than 80%% of timeout [%d].\n",
                                         op->msgid, info, op->timeout);
        }

        /* Avoid multiple outputs for the same operation if multiple results
         * are returned */
        op->start_time = 0;
    }

    op->callback(op, reply, error, op->data);
}

static void sdap_handle_release(struct sdap_handle *sh)
{
    struct sdap_op *op;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Trace: sh[%p], connected[%d], ops[%p], ldap[%p], "
              "destructor_lock[%d], release_memory[%d]\n",
              sh, (int)sh->connected, sh->ops, sh->ldap,
              (int)sh->destructor_lock, (int)sh->release_memory);

    if (sh->destructor_lock) return;
    sh->destructor_lock = true;

    /* make sure nobody tries to reuse this connection from now on */
    sh->connected = false;

    remove_ldap_connection_callbacks(sh);

    while (sh->ops) {
        op = sh->ops;
        sdap_call_op_callback(op, NULL, EIO);
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
static void sdap_process_message(struct tevent_context *ev,
                                 struct sdap_handle *sh, LDAPMessage *msg);
static void sdap_process_result(struct tevent_context *ev, void *pvt);
static void sdap_process_next_reply(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt);

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

static struct sdap_op *sdap_get_message_op(struct sdap_handle *sh,
                                           LDAPMessage *msg)
{
    struct sdap_op *op;
    int msgid;

    msgid = ldap_msgid(msg);
    if (msgid == -1) {
        DEBUG(SSSDBG_OP_FAILURE, "Invalid message id!\n");
        return NULL;
    }

    for (op = sh->ops; op; op = op->next) {
        if (op->msgid == msgid) {
            return op;
        }
    }

    return NULL;
}

static void sdap_process_result(struct tevent_context *ev, void *pvt)
{
    struct sdap_handle *sh = talloc_get_type(pvt, struct sdap_handle);
    uint64_t old_chain_id;
    struct timeval no_timeout = {0, 0};
    struct tevent_timer *te;
    struct sdap_op *op;
    LDAPMessage *msg;
    int ret;

    /* This is a top level event, always use chain id 0. We set a proper id
     * later in this function once we can match the reply with an operation. */
    old_chain_id = sss_chain_id_set(0);

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Trace: sh[%p], connected[%d], ops[%p], ldap[%p]\n",
              sh, (int)sh->connected, sh->ops, sh->ldap);

    if (!sh->connected || !sh->ldap) {
        DEBUG(SSSDBG_OP_FAILURE, "ERROR: LDAP connection is not connected!\n");
        sdap_handle_release(sh);
        return;
    }

    ret = ldap_result(sh->ldap, LDAP_RES_ANY, 0, &no_timeout, &msg);
    if (ret == 0) {
        /* this almost always means we have reached the end of
         * the list of received messages */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Trace: end of ldap_result list\n");
        return;
    }

    if (ret == -1) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &ret);
        DEBUG(SSSDBG_OP_FAILURE,
              "ldap_result error: [%s]\n", ldap_err2string(ret));
        sdap_handle_release(sh);
        return;
    }

    /* We don't know if this will be the last result.
     *
     * important: we must do this before actually processing the message
     * because the message processing might even free the sdap_handler
     * so it must be the last operation.
     * FIXME: use tevent_immediate/tevent_queues, when available */
    memset(&no_timeout, 0, sizeof(struct timeval));

    te = tevent_add_timer(ev, sh, no_timeout, sdap_ldap_next_result, sh);
    if (!te) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add critical timer to fetch next result!\n");
    }

    /* Set the chain id if we can match the operation. */
    op = sdap_get_message_op(sh, msg);
    if (op != NULL) {
        sss_chain_id_set(op->chain_id);
    }

    /* now process this message */
    sdap_process_message(ev, sh, msg);

    /* Restore the chain id. */
    sss_chain_id_set(old_chain_id);
}

static const char *sdap_ldap_result_str(int msgtype)
{
    switch (msgtype) {
    case LDAP_RES_BIND:
        return "LDAP_RES_BIND";

    case LDAP_RES_SEARCH_ENTRY:
        return "LDAP_RES_SEARCH_ENTRY";

    case LDAP_RES_SEARCH_REFERENCE:
        return "LDAP_RES_SEARCH_REFERENCE";

    case LDAP_RES_SEARCH_RESULT:
        return "LDAP_RES_SEARCH_RESULT";

    case LDAP_RES_MODIFY:
        return "LDAP_RES_MODIFY";

    case LDAP_RES_ADD:
        return "LDAP_RES_ADD";

    case LDAP_RES_DELETE:
        return "LDAP_RES_DELETE";

    case LDAP_RES_MODDN:
    /* These are the same result
    case LDAP_RES_MODRDN:
    case LDAP_RES_RENAME:
    */
        return "LDAP_RES_RENAME";

    case LDAP_RES_COMPARE:
        return "LDAP_RES_COMPARE";

    case LDAP_RES_EXTENDED:
        return "LDAP_RES_EXTENDED";

    case LDAP_RES_INTERMEDIATE:
        return "LDAP_RES_INTERMEDIATE";

    case LDAP_RES_ANY:
        return "LDAP_RES_ANY";

    case LDAP_RES_UNSOLICITED:
        return "LDAP_RES_UNSOLICITED";

    default:
        /* Unmatched, fall through */
        break;
    }

    /* Unknown result type */
    return "Unknown result type!";
}

/* process a message calling the right operation callback.
 * msg is completely taken care of (including freeing it)
 * NOTE: this function may even end up freeing the sdap_handle
 * so sdap_handle must not be used after this function is called
 */
static void sdap_process_message(struct tevent_context *ev,
                                 struct sdap_handle *sh, LDAPMessage *msg)
{
    struct sdap_msg *reply;
    struct sdap_op *op;
    int msgtype;
    int ret;

    msgtype = ldap_msgtype(msg);

    op = sdap_get_message_op(sh, msg);
    if (op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unmatched msgid, discarding message (type: %0x)\n",
              msgtype);
        ldap_msgfree(msg);
        return;
    }

    /* shouldn't happen */
    if (op->done) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Operation [%p] already handled (type: %0x)\n", op, msgtype);
        ldap_msgfree(msg);
        return;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Message type: [%s]\n", sdap_ldap_result_str(msgtype));

    switch (msgtype) {
    case LDAP_RES_SEARCH_ENTRY:
    case LDAP_RES_SEARCH_REFERENCE:
        /* go and process entry */
        break;

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
        /* unknown msg type?? */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Couldn't figure out the msg type! [%0x]\n", msgtype);
        ldap_msgfree(msg);
        return;
    }

    reply = talloc_zero(op, struct sdap_msg);
    if (!reply) {
        ldap_msgfree(msg);
        ret = ENOMEM;
    } else {
        reply->msg = msg;
        ret = sss_mem_attach(reply, msg, lmsg_destructor);
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
        sdap_call_op_callback(op, reply, ret);
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
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add critical timer for next reply!\n");
            sdap_call_op_callback(op, NULL, EFAULT);
        }
    }
}

static void sdap_process_next_reply(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt)
{
    struct sdap_op *op = talloc_get_type(pvt, struct sdap_op);

    sdap_call_op_callback(op, op->list, EOK);
}

/* ==LDAP-Operations-Helpers============================================== */

static int sdap_op_destructor(void *mem)
{
    struct sdap_op *op = (struct sdap_op *)mem;

    DLIST_REMOVE(op->sh->ops, op);

    if (op->done) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Operation %d finished\n", op->msgid);
        return 0;
    }

    /* we don't check the result here, if a message was really abandoned,
     * hopefully the server will get an abandon.
     * If the operation was already fully completed, this is going to be
     * just a noop */
    DEBUG(SSSDBG_TRACE_LIBS, "Abandoning operation %d\n", op->msgid);
    ldap_abandon_ext(op->sh->ldap, op->msgid, NULL, NULL);

    return 0;
}

static void sdap_op_timeout(struct tevent_req *req)
{
    struct sdap_op *op = tevent_req_callback_data(req, struct sdap_op);

    /* should never happen, but just in case */
    if (op->done) {
        DEBUG(SSSDBG_OP_FAILURE, "Timeout happened after op was finished !?\n");
        return;
    }

    /* signal the caller that we have a timeout */
    DEBUG(SSSDBG_TRACE_LIBS, "Issuing timeout [ldap_opt_timeout] for message id %d\n", op->msgid);
    sdap_call_op_callback(op, NULL, ETIMEDOUT);
}

int sdap_op_add(TALLOC_CTX *memctx, struct tevent_context *ev,
                struct sdap_handle *sh, int msgid, const char *stat_info,
                sdap_op_callback_t *callback, void *data,
                int timeout, struct sdap_op **_op)
{
    struct sdap_op *op;

    op = talloc_zero(memctx, struct sdap_op);
    if (!op) return ENOMEM;

    op->start_time = get_start_time();
    op->timeout = timeout;
    op->sh = sh;
    op->msgid = msgid;
    if (stat_info != NULL) {
        op->stat_info = talloc_strdup(op, stat_info);
        if (op->stat_info == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy stat_info, ignored.\n");
        }
    }
    op->callback = callback;
    op->data = data;
    op->ev = ev;
    op->chain_id = sss_chain_id_get();

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "New operation %d timeout %d\n", op->msgid, timeout);

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

static errno_t
sdap_chpass_result(TALLOC_CTX *mem_ctx,
                   int ldap_result,
                   const char *ldap_msg,
                   char **_user_msg)
{
    errno_t ret;

    switch (ldap_result) {
    case LDAP_SUCCESS:
        /* There's no need to set _user_msg here. */
        return EOK;
    case LDAP_CONSTRAINT_VIOLATION:
        if (ldap_msg == NULL || *ldap_msg == '\0') {
            ldap_msg = "Please make sure the password "
                       "meets the complexity constraints.";
        }
        ret = ERR_CHPASS_DENIED;
        break;
    default:
        ret = ERR_NETWORK_IO;
    }

    if (ldap_msg != NULL) {
        *_user_msg = talloc_strdup(mem_ctx, ldap_msg);
        if (*_user_msg == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            return ENOMEM;
        }
    }

    return ret;
}

struct sdap_exop_modify_passwd_state {
    struct sdap_handle *sh;

    struct sdap_op *op;

    char *user_error_message;
};

static void sdap_exop_modify_passwd_done(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt);

struct tevent_req *sdap_exop_modify_passwd_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           char *user_dn,
                                           const char *password,
                                           const char *new_password,
                                           int timeout,
                                           bool use_ppolicy)
{
    struct tevent_req *req = NULL;
    struct sdap_exop_modify_passwd_state *state;
    int ret;
    BerElement *ber = NULL;
    struct berval *bv = NULL;
    int msgid;
    LDAPControl **request_controls = NULL;
    LDAPControl *ctrls[2] = { NULL, NULL };
    char *stat_info;

    req = tevent_req_create(memctx, &state,
                            struct sdap_exop_modify_passwd_state);
    if (!req) return NULL;

    state->sh = sh;
    state->user_error_message = NULL;

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "ber_alloc_t failed.\n");
        talloc_zfree(req);
        return NULL;
    }

    ret = ber_printf( ber, "{tststs}", LDAP_TAG_EXOP_MODIFY_PASSWD_ID,
                     user_dn,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_OLD, password,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, new_password);
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ber_printf failed.\n");
        ber_free(ber, 1);
        talloc_zfree(req);
        return NULL;
    }

    ret = ber_flatten(ber, &bv);
    ber_free(ber, 1);
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ber_flatten failed.\n");
        talloc_zfree(req);
        return NULL;
    }

    if (use_ppolicy) {
        ret = sdap_control_create(state->sh, LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                  0, NULL, 0, &ctrls[0]);
        if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sdap_control_create failed to create "
                                       "Password Policy control.\n");
            ret = ERR_INTERNAL;
            goto fail;
        }
        request_controls = ctrls;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Executing extended operation\n");

    ret = ldap_extended_operation(state->sh->ldap, LDAP_EXOP_MODIFY_PASSWD,
                                  bv, request_controls, NULL, &msgid);
    ber_bvfree(bv);
    if (ctrls[0]) ldap_control_free(ctrls[0]);
    if (ret == -1 || msgid == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_extended_operation failed\n");
        ret = ERR_NETWORK_IO;
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "ldap_extended_operation sent, msgid = %d\n", msgid);

    stat_info = talloc_asprintf(state, "server: [%s] modify passwd dn: [%s]",
                                sdap_get_server_peer_str_safe(state->sh),
                                user_dn);
    if (stat_info == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create info string, ignored.\n");
    }

    ret = sdap_op_add(state, ev, state->sh, msgid, stat_info,
                      sdap_exop_modify_passwd_done, req, timeout, &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
        ret = ERR_INTERNAL;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
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
    char *errmsg = NULL;
    int ret;
    LDAPControl **response_controls = NULL;
    int c;
    ber_int_t pp_grace;
    ber_int_t pp_expire;
    LDAPPasswordPolicyError pp_error;
    int result;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    ret = ldap_parse_result(state->sh->ldap, reply->msg,
                            &result, NULL, &errmsg, NULL,
                            &response_controls, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldap_parse_result failed (%d)\n", state->op->msgid);
        ret = ERR_INTERNAL;
        goto done;
    }

    if (response_controls == NULL) {
        DEBUG(SSSDBG_FUNC_DATA, "Server returned no controls.\n");
    } else {
        for (c = 0; response_controls[c] != NULL; c++) {
            DEBUG(SSSDBG_TRACE_ALL, "Server returned control [%s].\n",
                      response_controls[c]->ldctl_oid);
            if (strcmp(response_controls[c]->ldctl_oid,
                       LDAP_CONTROL_PASSWORDPOLICYRESPONSE) == 0) {
                ret = ldap_parse_passwordpolicy_control(state->sh->ldap,
                                                        response_controls[c],
                                                        &pp_expire, &pp_grace,
                                                        &pp_error);
                if (ret != LDAP_SUCCESS) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "ldap_parse_passwordpolicy_control failed.\n");
                    ret = ERR_NETWORK_IO;
                    goto done;
                }

                DEBUG(SSSDBG_TRACE_LIBS,
                      "Password Policy Response: expire [%d] grace [%d] "
                          "error [%s].\n", pp_expire, pp_grace,
                          ldap_passwordpolicy_err2txt(pp_error));
            }
        }
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "ldap_extended_operation result: %s(%d), %s\n",
            sss_ldap_err2string(result), result, errmsg);

    ret = sdap_chpass_result(state, result, errmsg, &state->user_error_message);

done:
    ldap_controls_free(response_controls);
    ldap_memfree(errmsg);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

errno_t sdap_exop_modify_passwd_recv(struct tevent_req *req,
                                     TALLOC_CTX * mem_ctx,
                                     char **user_error_message)
{
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);

    /* We want to return the error message even on failure */
    *user_error_message = talloc_steal(mem_ctx, state->user_error_message);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_modify_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    struct sdap_op *op;

    int ldap_result;
    char *ldap_msg;
};

static void sdap_modify_done(struct sdap_op *op,
                             struct sdap_msg *reply,
                             int error, void *pvt);

static struct tevent_req *
sdap_modify_send(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 struct sdap_handle *sh,
                 int timeout,
                 const char *dn,
                 char *attr,
                 char **values)
{
    struct tevent_req *req;
    struct sdap_modify_state *state;
    LDAPMod **mods;
    errno_t ret;
    int msgid;
    char *stat_info;

    req = tevent_req_create(mem_ctx, &state, struct sdap_modify_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->sh = sh;

    mods = talloc_zero_array(state, LDAPMod *, 2);
    if (mods == NULL) {
        ret = ENOMEM;
        goto done;
    }

    mods[0] = talloc_zero(mods, LDAPMod);
    if (mods[0] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    mods[0]->mod_op = LDAP_MOD_REPLACE;
    mods[0]->mod_type = attr;
    mods[0]->mod_vals.modv_strvals = values;
    mods[1] = NULL;

    ret = ldap_modify_ext(state->sh->ldap, dn, mods, NULL, NULL, &msgid);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_modify_ext() failed [%d]\n", ret);
        goto done;
    }

    stat_info = talloc_asprintf(state, "server: [%s] modify dn: [%s] attr: [%s]",
                                sdap_get_server_peer_str_safe(state->sh), dn,
                                attr);
    if (stat_info == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create info string, ignored.\n");
    }

    ret = sdap_op_add(state, state->ev, state->sh, msgid, stat_info,
                      sdap_modify_done, req, timeout, &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sdap_modify_done(struct sdap_op *op,
                             struct sdap_msg *reply,
                             int error, void *pvt)
{
    struct tevent_req *req;
    struct sdap_modify_state *state;
    char *errmsg;
    errno_t ret;
    int result;
    int lret;

    req = talloc_get_type(pvt, struct tevent_req);
    state = tevent_req_data(req, struct sdap_modify_state);

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    lret = ldap_parse_result(state->sh->ldap, reply->msg, &result,
                             NULL, &errmsg, NULL, NULL, 0);
    if (lret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldap_parse_result failed (%d)\n",
                                  state->op->msgid);
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "ldap_modify result: %s(%d), %s\n",
                              sss_ldap_err2string(result),
                              result, errmsg);

    state->ldap_result = result;
    if (errmsg != NULL) {
        state->ldap_msg = talloc_strdup(state, errmsg);
        if (state->ldap_msg == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;

done:
    ldap_memfree(errmsg);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static errno_t sdap_modify_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                int *_ldap_result,
                                char **_ldap_msg)
{
    struct sdap_modify_state *state;

    state = tevent_req_data(req, struct sdap_modify_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_ldap_result != NULL) {
        *_ldap_result = state->ldap_result;
    }

    if (_ldap_msg != NULL) {
        *_ldap_msg = talloc_steal(mem_ctx, state->ldap_msg);
    }

    return EOK;
}

struct sdap_modify_passwd_state {
    const char *dn;
    char *user_msg;
};

static void sdap_modify_passwd_done(struct tevent_req *subreq);

struct tevent_req *
sdap_modify_passwd_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sdap_handle *sh,
                        int timeout,
                        char *attr,
                        const char *user_dn,
                        const char *new_password)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_modify_passwd_state *state;
    char **values;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_modify_passwd_state);
    if (req == NULL) {
        return NULL;
    }

    state->dn = user_dn;

    values = talloc_zero_array(state, char *, 2);
    if (values == NULL) {
        ret = ENOMEM;
        goto done;
    }

    values[0] = talloc_strdup(values, new_password);
    if (values[0] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_modify_send(state, ev, sh, timeout, user_dn, attr, values);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_modify_passwd_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sdap_modify_passwd_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_modify_passwd_state *state;
    int ldap_result;
    char *ldap_msg;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_modify_passwd_state);

    ret = sdap_modify_recv(state, subreq, &ldap_result, &ldap_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Password change for [%s] failed [%d]: %s\n",
              state->dn, ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = sdap_chpass_result(state, ldap_result, ldap_msg, &state->user_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Password change for [%s] failed [%d]: %s\n",
              state->dn, ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Password change for [%s] was successful\n",
          state->dn);

    tevent_req_done(req);
}

errno_t sdap_modify_passwd_recv(struct tevent_req *req,
                                TALLOC_CTX * mem_ctx,
                                char **_user_error_message)
{
    struct sdap_modify_passwd_state *state;

    state = tevent_req_data(req, struct sdap_modify_passwd_state);

    /* We want to return the error message even on failure */
    *_user_error_message = talloc_steal(mem_ctx, state->user_msg);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==Update-passwordLastChanged-attribute====================== */
struct sdap_modify_shadow_lastchange_state {
    const char *dn;
};

static void sdap_modify_shadow_lastchange_done(struct tevent_req *subreq);

struct tevent_req *
sdap_modify_shadow_lastchange_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct sdap_handle *sh,
                                   const char *dn,
                                   char *attr)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_modify_shadow_lastchange_state *state;
    char **values;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_modify_shadow_lastchange_state);
    if (req == NULL) {
        return NULL;
    }

    state->dn = dn;
    values = talloc_zero_array(state, char *, 2);
    if (values == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* The attribute contains number of days since the epoch */
    values[0] = talloc_asprintf(values, "%"SPRItime, time(NULL)/86400);
    if (values[0] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_modify_send(state, ev, sh, 5, dn, attr, values);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_modify_shadow_lastchange_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void sdap_modify_shadow_lastchange_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_modify_shadow_lastchange_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_modify_shadow_lastchange_state);

    ret = sdap_modify_recv(state, subreq, NULL, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "shadowLastChange change for [%s] failed [%d]: %s\n",
              state->dn, ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "shadowLastChange change for [%s] was successful\n",
          state->dn);

    tevent_req_done(req);
}

errno_t sdap_modify_shadow_lastchange_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

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
            SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS,
            "supportedControl",
            "supportedExtension",
            "supportedFeatures",
            "supportedLDAPVersion",
            "supportedSASLMechanisms",
            SDAP_ROOTDSE_ATTR_AD_VERSION,
            SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT,
            SDAP_IPA_LAST_USN, SDAP_AD_LAST_USN,
            NULL
    };

    DEBUG(SSSDBG_TRACE_ALL, "Getting rootdse\n");

    req = tevent_req_create(memctx, &state, struct sdap_get_rootdse_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->rootdse = NULL;

    subreq = sdap_get_generic_send(state, ev, opts, sh,
                                   "", LDAP_SCOPE_BASE,
                                   "(objectclass=*)", attrs, NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_rootdse_done, req);

    return req;
}

/* This is not a real attribute, it's just there to avoid
 * actually pulling real data down, to save bandwidth
 */
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
        DEBUG(SSSDBG_OP_FAILURE, "RootDSE could not be retrieved. "
                  "Please check that anonymous access to RootDSE is allowed\n"
              );
        tevent_req_error(req, ENOENT);
        return;
    }

    if (num_results > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Multiple replies when searching for RootDSE??\n");
        tevent_req_error(req, EIO);
        return;
    }

    state->rootdse = talloc_steal(state, results[0]);
    talloc_zfree(results);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Got rootdse\n");

    tevent_req_done(req);
    return;
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

/* ==Helpers for parsing replies============================== */
struct sdap_reply {
    size_t reply_max;
    size_t reply_count;
    struct sysdb_attrs **reply;
};

static errno_t add_to_reply(TALLOC_CTX *mem_ctx,
                            struct sdap_reply *sreply,
                            struct sysdb_attrs *msg)
{
    if (sreply->reply == NULL || sreply->reply_max == sreply->reply_count) {
        sreply->reply_max += REPLY_REALLOC_INCREMENT;
        sreply->reply = talloc_realloc(mem_ctx, sreply->reply,
                                       struct sysdb_attrs *,
                                       sreply->reply_max);
        if (sreply->reply == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_realloc failed.\n");
            return ENOMEM;
        }
    }

    sreply->reply[sreply->reply_count++] = talloc_steal(sreply->reply, msg);

    return EOK;
}

struct sdap_deref_reply {
    size_t reply_max;
    size_t reply_count;
    struct sdap_deref_attrs **reply;
};

static errno_t add_to_deref_reply(TALLOC_CTX *mem_ctx,
                                  int num_maps,
                                  struct sdap_deref_reply *dreply,
                                  struct sdap_deref_attrs **res)
{
    int i;

    if (res == NULL) {
        /* Nothing to add, probably ACIs prevented us from dereferencing
         * the attribute */
        return EOK;
    }

    for (i=0; i < num_maps; i++) {
        if (res[i]->attrs == NULL) continue; /* Nothing in this map */

        if (dreply->reply == NULL ||
            dreply->reply_max == dreply->reply_count) {
            dreply->reply_max += REPLY_REALLOC_INCREMENT;
            dreply->reply = talloc_realloc(mem_ctx, dreply->reply,
                                        struct sdap_deref_attrs *,
                                        dreply->reply_max);
            if (dreply->reply == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_realloc failed.\n");
                return ENOMEM;
            }
        }

        dreply->reply[dreply->reply_count++] =
            talloc_steal(dreply->reply, res[i]);
    }

    return EOK;
}

const char *sdap_get_server_peer_str(struct sdap_handle *sh)
{
    int ret;
    int fd;
    struct sockaddr sa;
    socklen_t sa_len = sizeof(sa);
    char ip[NI_MAXHOST];
    static char out[NI_MAXHOST + 8];
    int port;

    ret = get_fd_from_ldap(sh->ldap, &fd);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "cannot get sdap fd\n");
        return NULL;
    }

    ret = getpeername(fd, &sa, &sa_len);
    if (ret == -1) {
        DEBUG(SSSDBG_MINOR_FAILURE, "getpeername failed\n");
        return NULL;
    }

    switch (sa.sa_family) {
    case AF_INET: {
        struct sockaddr_in in;
        socklen_t in_len = sizeof(in);

        ret = getpeername(fd, (struct sockaddr *)(&in), &in_len);
        if (ret == -1) {
            DEBUG(SSSDBG_MINOR_FAILURE, "getpeername failed\n");
            return NULL;
        }

        ret = getnameinfo((struct sockaddr *)(&in), in_len,
                          ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
        if (ret != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "getnameinfo failed\n");
            return NULL;
        }

        port = ntohs(in.sin_port);
        ret = snprintf(out, sizeof(out), "%s:%d", ip, port);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 in6;
        socklen_t in6_len = sizeof(in6);

        ret = getpeername(fd, (struct sockaddr *)(&in6), &in6_len);
        if (ret == -1) {
            DEBUG(SSSDBG_MINOR_FAILURE, "getpeername failed\n");
            return NULL;
        }

        ret = getnameinfo((struct sockaddr *)(&in6), in6_len,
                          ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
        if (ret != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "getnameinfo failed\n");
            return NULL;
        }

        port = ntohs(in6.sin6_port);
        ret = snprintf(out, sizeof(out), "[%s]:%d", ip, port);
        break;
    }
    case AF_UNIX: {
        struct sockaddr_un un;
        socklen_t un_len = sizeof(un);

        ret = getpeername(fd, (struct sockaddr *)(&un), &un_len);
        if (ret == -1) {
            DEBUG(SSSDBG_MINOR_FAILURE, "getpeername failed\n");
            return NULL;
        }

        ret = snprintf(out, sizeof(out), "%.*s",
            (int)strnlen(un.sun_path, un_len - offsetof(struct sockaddr_un,
                sun_path)), un.sun_path);
        break;
    }
    default:
        return NULL;
    }

    if (ret < 0 || ret >= sizeof(out)) {
        return NULL;
    }

    return out;
}

const char *sdap_get_server_peer_str_safe(struct sdap_handle *sh)
{
    const char *ip = sdap_get_server_peer_str(sh);
    return ip != NULL ? ip : "- IP not available -";
}

static void sdap_print_server(struct sdap_handle *sh)
{
    const char *ip;

    /* The purpose of the call is to add the server IP to the debug output if
     * debug_level is SSSDBG_TRACE_INTERNAL or higher */
    if (DEBUG_IS_SET(SSSDBG_TRACE_INTERNAL)) {
        ip = sdap_get_server_peer_str(sh);
        if (ip != NULL) {
            DEBUG(SSSDBG_TRACE_INTERNAL, "Searching %s\n", ip);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_get_server_peer_str failed.\n");
        }
    }
}

/* ==Generic Search exposing all options======================= */
typedef errno_t (*sdap_parse_cb)(struct sdap_handle *sh,
                                 struct sdap_msg *msg,
                                 void *pvt);

struct sdap_get_generic_ext_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    const char *search_base;
    int scope;
    const char *filter;
    const char **attrs;
    int timeout;
    int sizelimit;

    struct sdap_op *op;

    struct berval cookie;

    LDAPControl **serverctrls;
    int nserverctrls;
    LDAPControl **clientctrls;

    size_t ref_count;
    char **refs;

    sdap_parse_cb parse_cb;
    void *cb_data;

    unsigned int flags;
};

static errno_t sdap_get_generic_ext_step(struct tevent_req *req);

static void sdap_get_generic_op_finished(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt);

enum {
    /* Be silent about exceeded size limit */
    SDAP_SRCH_FLG_SIZELIMIT_SILENT = 1 << 0,

    /* Allow paging */
    SDAP_SRCH_FLG_PAGING           = 1 << 1,

    /* Only attribute descriptions are requested */
    SDAP_SRCH_FLG_ATTRS_ONLY       = 1 << 2,
};

static struct tevent_req *
sdap_get_generic_ext_send(TALLOC_CTX *memctx,
                          struct tevent_context *ev,
                          struct sdap_options *opts,
                          struct sdap_handle *sh,
                          const char *search_base,
                          int scope,
                          const char *filter,
                          const char **attrs,
                          LDAPControl **serverctrls,
                          LDAPControl **clientctrls,
                          int sizelimit,
                          int timeout,
                          sdap_parse_cb parse_cb,
                          void *cb_data,
                          unsigned int flags)
{
    errno_t ret;
    struct sdap_get_generic_ext_state *state;
    struct tevent_req *req;
    int i;
    LDAPControl *control;

    req = tevent_req_create(memctx, &state, struct sdap_get_generic_ext_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->search_base = search_base;
    state->scope = scope;
    state->filter = filter;
    state->attrs = attrs;
    state->op = NULL;
    state->sizelimit = sizelimit;
    state->timeout = timeout;
    state->cookie.bv_len = 0;
    state->cookie.bv_val = NULL;
    state->parse_cb = parse_cb;
    state->cb_data = cb_data;
    state->clientctrls = clientctrls;
    state->flags = flags;

    if (state->sh == NULL || state->sh->ldap == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Trying LDAP search while not connected.\n");
        tevent_req_error(req, EIO);
        tevent_req_post(req, ev);
        return req;
    }

    sdap_print_server(sh);

    /* Be extra careful and never allow paging for BASE searches,
     * even if requested.
     */
    if (scope == LDAP_SCOPE_BASE && (flags & SDAP_SRCH_FLG_PAGING)) {
        /* Disable paging */
        state->flags &= ~SDAP_SRCH_FLG_PAGING;
        DEBUG(SSSDBG_TRACE_FUNC,
              "WARNING: Disabling paging because scope is set to base.\n");
    }

    /* Also check for deref/asq requests and force
     * paging on for those requests
     */
    /* X-DEREF */
    control = ldap_control_find(LDAP_CONTROL_X_DEREF,
                                serverctrls,
                                NULL);
    if (control) {
        state->flags |= SDAP_SRCH_FLG_PAGING;
    }

    /* ASQ */
    control = ldap_control_find(LDAP_SERVER_ASQ_OID,
                                serverctrls,
                                NULL);
    if (control) {
        state->flags |= SDAP_SRCH_FLG_PAGING;
    }

    for (state->nserverctrls=0;
         serverctrls && serverctrls[state->nserverctrls];
         state->nserverctrls++) ;

    /* One extra space for NULL, one for page control */
    state->serverctrls = talloc_array(state, LDAPControl *,
                                      state->nserverctrls+2);
    if (!state->serverctrls) {
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, ev);
        return req;
    }

    for (i=0; i < state->nserverctrls; i++) {
        state->serverctrls[i] = serverctrls[i];
    }
    state->serverctrls[i] = NULL;

    PROBE(SDAP_GET_GENERIC_EXT_SEND, state->search_base,
          state->scope, state->filter, state->attrs);

    ret = sdap_get_generic_ext_step(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
        return req;
    }

    return req;
}

static errno_t sdap_get_generic_ext_step(struct tevent_req *req)
{
    struct sdap_get_generic_ext_state *state =
            tevent_req_data(req, struct sdap_get_generic_ext_state);
    char *errmsg;
    int lret;
    int optret;
    errno_t ret;
    int msgid;
    bool disable_paging;
    char *stat_info;

    LDAPControl *page_control = NULL;

    /* Make sure to free any previous operations so
     * if we are handling a large number of pages we
     * don't waste memory.
     */
    talloc_zfree(state->op);

    DEBUG(SSSDBG_TRACE_FUNC,
         "calling ldap_search_ext with [%s][%s].\n",
          state->filter ? state->filter : "no filter",
          state->search_base);
    if (state->attrs) {
        for (int i = 0; state->attrs[i]; i++) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Requesting attrs: [%s]\n", state->attrs[i]);
        }
    }

    disable_paging = dp_opt_get_bool(state->opts->basic, SDAP_DISABLE_PAGING);

    if (!disable_paging
            && (state->flags & SDAP_SRCH_FLG_PAGING)
            && sdap_is_control_supported(state->sh,
                                         LDAP_CONTROL_PAGEDRESULTS)) {
        lret = ldap_create_page_control(state->sh->ldap,
                                        state->sh->page_size,
                                        state->cookie.bv_val ?
                                            &state->cookie :
                                            NULL,
                                        false,
                                        &page_control);
        if (lret != LDAP_SUCCESS) {
            ret = EIO;
            goto done;
        }
        state->serverctrls[state->nserverctrls] = page_control;
        state->serverctrls[state->nserverctrls+1] = NULL;
    }

    lret = ldap_search_ext(state->sh->ldap, state->search_base,
                           state->scope, state->filter,
                           discard_const(state->attrs),
                           (state->flags & SDAP_SRCH_FLG_ATTRS_ONLY),
                           state->serverctrls,
                           state->clientctrls, NULL, state->sizelimit, &msgid);
    ldap_control_free(page_control);
    state->serverctrls[state->nserverctrls] = NULL;
    if (lret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldap_search_ext failed: %s\n", sss_ldap_err2string(lret));
        if (lret == LDAP_SERVER_DOWN) {
            ret = ETIMEDOUT;
            optret = sss_ldap_get_diagnostic_msg(state, state->sh->ldap,
                                                 &errmsg);
            if (optret == LDAP_SUCCESS) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Connection error: %s\n", errmsg);
                sss_log(SSS_LOG_ERR, "LDAP connection error: %s", errmsg);
            } else {
                sss_log(SSS_LOG_ERR, "LDAP connection error, %s",
                                     sss_ldap_err2string(lret));
            }
        } else if (lret == LDAP_FILTER_ERROR) {
            ret = ERR_INVALID_FILTER;
        } else {
            ret = EIO;
        }
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "ldap_search_ext called, msgid = %d\n", msgid);

    stat_info = talloc_asprintf(state, "server: [%s] filter: [%s] base: [%s]",
                                sdap_get_server_peer_str_safe(state->sh),
                                state->filter, state->search_base);
    if (stat_info == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create info string, ignored.\n");
    }

    ret = sdap_op_add(state, state->ev, state->sh, msgid, stat_info,
                      sdap_get_generic_op_finished, req,
                      state->timeout,
                      &state->op);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
        goto done;
    }

done:
    return ret;
}

static errno_t
sdap_get_generic_ext_add_references(struct sdap_get_generic_ext_state *state,
                                    char **refs)
{
    int i;

    if (refs == NULL) {
        /* Rare, but it's possible that we might get a reference result with
         * no references attached.
         */
        return EOK;
    }

    for (i = 0; refs[i]; i++) {
        DEBUG(SSSDBG_TRACE_LIBS, "Additional References: %s\n", refs[i]);
    }

    /* Extend the size of the ref array */
    state->refs = talloc_realloc(state, state->refs, char *,
                                 state->ref_count + i);
    if (state->refs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "talloc_realloc failed extending ref_array.\n");
        return ENOMEM;
    }

    /* Copy in all the references */
    for (i = 0; refs[i]; i++) {
        state->refs[state->ref_count + i] =
                talloc_strdup(state->refs, refs[i]);

        if (state->refs[state->ref_count + i] == NULL) {
            return ENOMEM;
        }
    }

    state->ref_count += i;

    return EOK;
}

static void sdap_get_generic_op_finished(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_generic_ext_state *state = tevent_req_data(req,
                                            struct sdap_get_generic_ext_state);
    char *errmsg = NULL;
    char **refs = NULL;
    int result;
    int ret;
    int lret;
    ber_int_t total_count;
    struct berval cookie;
    LDAPControl **returned_controls = NULL;
    LDAPControl *page_control;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    switch (ldap_msgtype(reply->msg)) {
    case LDAP_RES_SEARCH_REFERENCE:
        ret = ldap_parse_reference(state->sh->ldap, reply->msg,
                                   &refs, NULL, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ldap_parse_reference failed (%d)\n", state->op->msgid);
            tevent_req_error(req, EIO);
            return;
        }

        ret = sdap_get_generic_ext_add_references(state, refs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_get_generic_ext_add_references failed: %s(%d)\n",
                  sss_strerror(ret), ret);
            ldap_memvfree((void **)refs);
            tevent_req_error(req, ret);
            return;
        }

        /* Remove the original strings */
        ldap_memvfree((void **)refs);

        /* unlock the operation so that we can proceed with the next result */
        sdap_unlock_next_reply(state->op);
        break;

    case LDAP_RES_SEARCH_ENTRY:
        ret = state->parse_cb(state->sh, reply, state->cb_data);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "reply parsing callback failed.\n");
            tevent_req_error(req, ret);
            return;
        }

        sdap_unlock_next_reply(state->op);
        break;

    case LDAP_RES_SEARCH_RESULT:
        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, &refs,
                                &returned_controls, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ldap_parse_result failed (%d)\n", state->op->msgid);
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Search result: %s(%d), %s\n",
                  sss_ldap_err2string(result), result,
                  errmsg ? errmsg : "no errmsg set");

        if (result == LDAP_SIZELIMIT_EXCEEDED
                || result == LDAP_ADMINLIMIT_EXCEEDED) {
            /* Try to return what we've got */

            if ( ! (state->flags & SDAP_SRCH_FLG_SIZELIMIT_SILENT)) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "LDAP sizelimit was exceeded, "
                      "returning incomplete data\n");
            }
        } else if (result == LDAP_INAPPROPRIATE_MATCHING) {
            /* This error should only occur when we're testing for
             * specialized functionality like the LDAP matching rule
             * filter for Active Directory. Warn at a higher log
             * level and return EIO.
             */
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "LDAP_INAPPROPRIATE_MATCHING:  %s\n",
                   errmsg ? errmsg : "no errmsg set");
            ldap_memfree(errmsg);
            tevent_req_error(req, EIO);
            return;
        } else if (result == LDAP_UNAVAILABLE_CRITICAL_EXTENSION) {
            ldap_memfree(errmsg);
            tevent_req_error(req, ENOTSUP);
            return;
        } else if (result == LDAP_REFERRAL) {
            ret = sdap_get_generic_ext_add_references(state, refs);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sdap_get_generic_ext_add_references failed: %s(%d)\n",
                      sss_strerror(ret), ret);
                tevent_req_error(req, ret);
            }
            /* For referrals, we need to fall through as if it was LDAP_SUCCESS */
        } else if (result != LDAP_SUCCESS && result != LDAP_NO_SUCH_OBJECT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unexpected result from ldap: %s(%d), %s\n",
                   sss_ldap_err2string(result), result,
                   errmsg ? errmsg : "no errmsg set");
            ldap_memfree(errmsg);
            tevent_req_error(req, EIO);
            return;
        }
        ldap_memfree(errmsg);

        /* Determine if there are more pages to retrieve */
        page_control = ldap_control_find(LDAP_CONTROL_PAGEDRESULTS,
                                         returned_controls, NULL );
        if (!page_control) {
            /* No paging support. We are done */
            tevent_req_done(req);
            return;
        }

        lret = ldap_parse_pageresponse_control(state->sh->ldap, page_control,
                                               &total_count, &cookie);
        ldap_controls_free(returned_controls);
        if (lret != LDAP_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not determine page control\n");
            tevent_req_error(req, EIO);
            return;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Total count [%d]\n", total_count);

        if (cookie.bv_val != NULL && cookie.bv_len > 0) {
            /* Cookie contains data, which means there are more requests
             * to be processed.
             */
            talloc_zfree(state->cookie.bv_val);
            state->cookie.bv_len = cookie.bv_len;
            state->cookie.bv_val = talloc_memdup(state,
                                                 cookie.bv_val,
                                                 cookie.bv_len);
            if (!state->cookie.bv_val) {
                tevent_req_error(req, ENOMEM);
                return;
            }
            ber_memfree(cookie.bv_val);

            ret = sdap_get_generic_ext_step(req);
            if (ret != EOK) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            return;
        }
        /* The cookie must be freed even if len == 0 */
        ber_memfree(cookie.bv_val);

        /* This was the last page. We're done */

        tevent_req_done(req);
        return;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static int
sdap_get_generic_ext_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          size_t *ref_count,
                          char ***refs)
{
    struct sdap_get_generic_ext_state *state =
            tevent_req_data(req, struct sdap_get_generic_ext_state);

    PROBE(SDAP_GET_GENERIC_EXT_RECV, state->search_base,
          state->scope, state->filter);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (ref_count) {
        *ref_count = state->ref_count;
    }

    if (refs) {
        *refs = talloc_steal(mem_ctx, state->refs);
    }

    return EOK;
}

/* This search handler can be used by most calls */
static void generic_ext_search_handler(struct tevent_req *subreq,
                                       struct sdap_options *opts)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;
    size_t ref_count, i;
    char **refs;

    ret = sdap_get_generic_ext_recv(subreq, req, &ref_count, &refs);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (ret == ETIMEDOUT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_get_generic_ext_recv failed: [%d]: %s "
                  "[ldap_search_timeout]\n",
                  ret, sss_strerror(ret));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_get_generic_ext_recv request failed: [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
        tevent_req_error(req, ret);
        return;
    }

    if (ref_count > 0) {
        /* We will ignore referrals in the generic handler */
        DEBUG(SSSDBG_TRACE_ALL,
              "Request included referrals which were ignored.\n");
        if (debug_level & SSSDBG_TRACE_ALL) {
            for(i = 0; i < ref_count; i++) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "    Ref: %s\n", refs[i]);
            }
        }
    }

    talloc_free(refs);
    tevent_req_done(req);
}

/* ==Generic Search exposing all options======================= */
struct sdap_get_and_parse_generic_state {
    struct sdap_attr_map *map;
    int map_num_attrs;

    struct sdap_reply sreply;
    struct sdap_options *opts;
};

static void sdap_get_and_parse_generic_done(struct tevent_req *subreq);
static errno_t sdap_get_and_parse_generic_parse_entry(struct sdap_handle *sh,
                                                      struct sdap_msg *msg,
                                                      void *pvt);

struct tevent_req *sdap_get_and_parse_generic_send(TALLOC_CTX *memctx,
                                                   struct tevent_context *ev,
                                                   struct sdap_options *opts,
                                                   struct sdap_handle *sh,
                                                   const char *search_base,
                                                   int scope,
                                                   const char *filter,
                                                   const char **attrs,
                                                   struct sdap_attr_map *map,
                                                   int map_num_attrs,
                                                   int attrsonly,
                                                   LDAPControl **serverctrls,
                                                   LDAPControl **clientctrls,
                                                   int sizelimit,
                                                   int timeout,
                                                   bool allow_paging)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_get_and_parse_generic_state *state = NULL;
    unsigned int flags = 0;

    req = tevent_req_create(memctx, &state,
                            struct sdap_get_and_parse_generic_state);
    if (!req) return NULL;

    state->map = map;
    state->map_num_attrs = map_num_attrs;
    state->opts = opts;

    if (allow_paging) {
        flags |= SDAP_SRCH_FLG_PAGING;
    }

    if (attrsonly) {
        flags |= SDAP_SRCH_FLG_ATTRS_ONLY;
    }

    subreq = sdap_get_generic_ext_send(state, ev, opts, sh, search_base,
                                       scope, filter, attrs, serverctrls,
                                       clientctrls, sizelimit, timeout,
                                       sdap_get_and_parse_generic_parse_entry,
                                       state, flags);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_and_parse_generic_done, req);

    return req;
}

static errno_t sdap_get_and_parse_generic_parse_entry(struct sdap_handle *sh,
                                                      struct sdap_msg *msg,
                                                      void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    struct sdap_get_and_parse_generic_state *state =
                talloc_get_type(pvt, struct sdap_get_and_parse_generic_state);

    bool disable_range_rtrvl = dp_opt_get_bool(state->opts->basic,
                                               SDAP_DISABLE_RANGE_RETRIEVAL);

    ret = sdap_parse_entry(state, sh, msg,
                           state->map, state->map_num_attrs,
                           &attrs, disable_range_rtrvl);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_parse_entry failed [%d]: %s\n", ret, strerror(ret));
        return ret;
    }

    ret = add_to_reply(state, &state->sreply, attrs);
    if (ret != EOK) {
        talloc_free(attrs);
        DEBUG(SSSDBG_CRIT_FAILURE, "add_to_reply failed.\n");
        return ret;
    }

    /* add_to_reply steals attrs, no need to free them here */
    return EOK;
}

static void sdap_get_and_parse_generic_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_and_parse_generic_state *state =
                tevent_req_data(req, struct sdap_get_and_parse_generic_state);

    return generic_ext_search_handler(subreq, state->opts);
}

int sdap_get_and_parse_generic_recv(struct tevent_req *req,
                                    TALLOC_CTX *mem_ctx,
                                    size_t *reply_count,
                                    struct sysdb_attrs ***reply)
{
    struct sdap_get_and_parse_generic_state *state = tevent_req_data(req,
                                     struct sdap_get_and_parse_generic_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->sreply.reply_count;
    *reply = talloc_steal(mem_ctx, state->sreply.reply);

    return EOK;
}


/* ==Simple generic search============================================== */
struct sdap_get_generic_state {
    size_t reply_count;
    struct sysdb_attrs **reply;
};

static void sdap_get_generic_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_generic_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh,
                                         const char *search_base,
                                         int scope,
                                         const char *filter,
                                         const char **attrs,
                                         struct sdap_attr_map *map,
                                         int map_num_attrs,
                                         int timeout,
                                         bool allow_paging)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_get_generic_state *state = NULL;

    req = tevent_req_create(memctx, &state, struct sdap_get_generic_state);
    if (!req) return NULL;

    subreq = sdap_get_and_parse_generic_send(memctx, ev, opts, sh, search_base,
                                             scope, filter, attrs,
                                             map, map_num_attrs,
                                             false, NULL, NULL, 0, timeout,
                                             allow_paging);
    if (subreq == NULL) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_generic_done, req);

    return req;
}

static void sdap_get_generic_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_generic_state *state =
                tevent_req_data(req, struct sdap_get_generic_state);
    errno_t ret;

    ret = sdap_get_and_parse_generic_recv(subreq, state,
                                          &state->reply_count, &state->reply);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    tevent_req_done(req);
}

int sdap_get_generic_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          size_t *reply_count,
                          struct sysdb_attrs ***reply)
{
    struct sdap_get_generic_state *state =
                tevent_req_data(req, struct sdap_get_generic_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->reply_count;
    *reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}

/* ==OpenLDAP deref search============================================== */
static int sdap_x_deref_create_control(struct sdap_handle *sh,
                                       const char *deref_attr,
                                       const char **attrs,
                                       LDAPControl **ctrl);

static void sdap_x_deref_search_done(struct tevent_req *subreq);
static int sdap_x_deref_search_ctrls_destructor(void *ptr);

static errno_t sdap_x_deref_parse_entry(struct sdap_handle *sh,
                                        struct sdap_msg *msg,
                                        void *pvt);
struct sdap_x_deref_search_state {
    struct sdap_handle *sh;
    struct sdap_op *op;
    struct sdap_attr_map_info *maps;
    LDAPControl **ctrls;
    struct sdap_options *opts;
    bool ldap_ignore_unreadable_references;

    struct sdap_deref_reply dreply;
    int num_maps;
};

static struct tevent_req *
sdap_x_deref_search_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                         struct sdap_options *opts, struct sdap_handle *sh,
                         const char *base_dn, const char *filter,
                         const char *deref_attr, const char **attrs,
                         struct sdap_attr_map_info *maps, int num_maps,
                         int timeout)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_x_deref_search_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_x_deref_search_state);
    if (!req) return NULL;

    state->sh = sh;
    state->maps = maps;
    state->op = NULL;
    state->opts = opts;
    state->num_maps = num_maps;
    state->ctrls = talloc_zero_array(state, LDAPControl *, 2);
    if (state->ctrls == NULL) {
        talloc_zfree(req);
        return NULL;
    }
    talloc_set_destructor((TALLOC_CTX *) state->ctrls,
                          sdap_x_deref_search_ctrls_destructor);

    state->ldap_ignore_unreadable_references = dp_opt_get_bool(opts->basic,
                                            SDAP_IGNORE_UNREADABLE_REFERENCES);

    ret = sdap_x_deref_create_control(sh, deref_attr,
                                      attrs, &state->ctrls[0]);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not create OpenLDAP deref control\n");
        talloc_zfree(req);
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Dereferencing entry [%s] using OpenLDAP deref\n", base_dn);
    subreq = sdap_get_generic_ext_send(state, ev, opts, sh, base_dn,
                                       filter == NULL ? LDAP_SCOPE_BASE
                                                      : LDAP_SCOPE_SUBTREE,
                                       filter, attrs,
                                       state->ctrls, NULL, 0, timeout,
                                       sdap_x_deref_parse_entry,
                                       state, SDAP_SRCH_FLG_PAGING);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_x_deref_search_done, req);

    return req;
}

static int sdap_x_deref_create_control(struct sdap_handle *sh,
                                       const char *deref_attr,
                                       const char **attrs,
                                       LDAPControl **ctrl)
{
    struct berval derefval;
    int ret;
    struct LDAPDerefSpec ds[2];

    ds[0].derefAttr = discard_const(deref_attr);
    ds[0].attributes = discard_const(attrs);

    ds[1].derefAttr = NULL; /* sentinel */

    ret = ldap_create_deref_control_value(sh->ldap, ds, &derefval);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_create_deref_control_value failed: %s\n",
                  ldap_err2string(ret));
        return ret;
    }

    ret = sdap_control_create(sh, LDAP_CONTROL_X_DEREF,
                              1, &derefval, 1, ctrl);
    ldap_memfree(derefval.bv_val);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_control_create failed %d\n", ret);
        return ret;
    }

    return EOK;
}

static errno_t sdap_x_deref_parse_entry(struct sdap_handle *sh,
                                        struct sdap_msg *msg,
                                        void *pvt)
{
    errno_t ret;
    LDAPControl **ctrls = NULL;
    LDAPControl *derefctrl = NULL;
    LDAPDerefRes    *deref_res = NULL;
    LDAPDerefRes    *dref;
    struct sdap_deref_attrs **res;
    TALLOC_CTX *tmp_ctx;

    struct sdap_x_deref_search_state *state = talloc_get_type(pvt,
                                            struct sdap_x_deref_search_state);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = ldap_get_entry_controls(state->sh->ldap, msg->msg,
                                  &ctrls);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldap_parse_result failed\n");
        goto done;
    }

    if (!ctrls) {
        /* When we attempt to request attributes that are not present in
         * the dereferenced links, some serves might not send the dereference
         * control back at all. Be permissive and treat the search as if
         * it didn't find anything.
         */
        DEBUG(SSSDBG_MINOR_FAILURE, "No controls found for entry\n");
        ret = EOK;
        goto done;
    }

    res = NULL;

    derefctrl = ldap_control_find(LDAP_CONTROL_X_DEREF, ctrls, NULL);
    if (!derefctrl) {
        DEBUG(SSSDBG_FUNC_DATA, "No deref controls found\n");
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got deref control\n");

    ret = ldap_parse_derefresponse_control(state->sh->ldap,
                                            derefctrl,
                                            &deref_res);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldap_parse_derefresponse_control failed: %s\n",
               ldap_err2string(ret));
        goto done;
    }

    for (dref = deref_res; dref; dref=dref->next) {
        ret = sdap_parse_deref(tmp_ctx, state->maps, state->num_maps,
                               dref, &res);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_parse_deref failed [%d]: %s\n",
                  ret, strerror(ret));
            goto done;
        }

        ret = add_to_deref_reply(state, state->num_maps,
                                 &state->dreply, res);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "add_to_deref_reply failed.\n");
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "All deref results from a single control parsed\n");
    ldap_derefresponse_free(deref_res);
    deref_res = NULL;

    ret = EOK;
done:
    if (ret != EOK && ret != ENOMEM) {
        if (state->ldap_ignore_unreadable_references) {
            DEBUG(SSSDBG_TRACE_FUNC, "Ignoring unreadable reference\n");
            ret = EOK;
        }
    }

    talloc_zfree(tmp_ctx);
    ldap_controls_free(ctrls);
    ldap_derefresponse_free(deref_res);
    return ret;
}

static void sdap_x_deref_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_x_deref_search_state *state =
                tevent_req_data(req, struct sdap_x_deref_search_state);

    return generic_ext_search_handler(subreq, state->opts);
}

static int sdap_x_deref_search_ctrls_destructor(void *ptr)
{
    LDAPControl **ctrls = talloc_get_type(ptr, LDAPControl *);

    if (ctrls && ctrls[0]) {
        ldap_control_free(ctrls[0]);
    }

    return 0;
}

static int
sdap_x_deref_search_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx,
                         size_t *reply_count,
                         struct sdap_deref_attrs ***reply)
{
    struct sdap_x_deref_search_state *state = tevent_req_data(req,
                                            struct sdap_x_deref_search_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->dreply.reply_count;
    *reply = talloc_steal(mem_ctx, state->dreply.reply);

    return EOK;
}

/* ==Security Descriptor (ACL) search=================================== */
struct sdap_sd_search_state {
  LDAPControl **ctrls;
  struct sdap_options *opts;
  size_t reply_count;
  struct sysdb_attrs **reply;
  struct sdap_reply sreply;

  /* Referrals returned by the search */
  size_t ref_count;
  char **refs;
};

static int sdap_sd_search_create_control(struct sdap_handle *sh,
					 int val,
					 LDAPControl **ctrl);
static int sdap_sd_search_ctrls_destructor(void *ptr);
static errno_t sdap_sd_search_parse_entry(struct sdap_handle *sh,
                                          struct sdap_msg *msg,
                                          void *pvt);
static void sdap_sd_search_done(struct tevent_req *subreq);

struct tevent_req *
sdap_sd_search_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                     struct sdap_options *opts, struct sdap_handle *sh,
                     const char *base_dn, int sd_flags,
                     const char **attrs, int timeout)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_sd_search_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_sd_search_state);
    if (!req) return NULL;

    state->ctrls = talloc_zero_array(state, LDAPControl *, 2);
    state->opts = opts;
    if (state->ctrls == NULL) {
        ret = EIO;
        goto fail;
    }
    talloc_set_destructor((TALLOC_CTX *) state->ctrls,
                          sdap_sd_search_ctrls_destructor);

    ret = sdap_sd_search_create_control(sh, sd_flags, &state->ctrls[0]);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not create SD control\n");
        ret = EIO;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Searching entry [%s] using SD\n", base_dn);
    subreq = sdap_get_generic_ext_send(state, ev, opts, sh, base_dn,
                                       LDAP_SCOPE_BASE, "(objectclass=*)", attrs,
                                       state->ctrls, NULL, 0, timeout,
                                       sdap_sd_search_parse_entry,
                                       state, SDAP_SRCH_FLG_PAGING);
    if (!subreq) {
        ret = EIO;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_sd_search_done, req);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static int sdap_sd_search_create_control(struct sdap_handle *sh,
					 int val,
					 LDAPControl **ctrl)
{
    struct berval *sdval;
    int ret;
    BerElement *ber = NULL;
    ber = ber_alloc_t(LBER_USE_DER);
    if (ber == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_alloc_t failed.\n");
        return ENOMEM;
    }

    ret = ber_printf(ber, "{i}", val);
    if (ret == -1) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_printf failed.\n");
        ber_free(ber, 1);
        return EIO;
    }

    ret = ber_flatten(ber, &sdval);
    ber_free(ber, 1);
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ber_flatten failed.\n");
        return EIO;
    }

    ret = sdap_control_create(sh, LDAP_SERVER_SD_OID, 1, sdval, 1, ctrl);
    ber_bvfree(sdval);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_control_create failed\n");
        return ret;
    }

    return EOK;
}

static errno_t sdap_sd_search_parse_entry(struct sdap_handle *sh,
                                          struct sdap_msg *msg,
                                          void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    struct sdap_sd_search_state *state =
                talloc_get_type(pvt, struct sdap_sd_search_state);

    bool disable_range_rtrvl = dp_opt_get_bool(state->opts->basic,
                                               SDAP_DISABLE_RANGE_RETRIEVAL);

    ret = sdap_parse_entry(state, sh, msg,
                           NULL, 0,
                           &attrs, disable_range_rtrvl);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_parse_entry failed [%d]: %s\n", ret, strerror(ret));
        return ret;
    }

    ret = add_to_reply(state, &state->sreply, attrs);
    if (ret != EOK) {
        talloc_free(attrs);
        DEBUG(SSSDBG_CRIT_FAILURE, "add_to_reply failed.\n");
        return ret;
    }

    /* add_to_reply steals attrs, no need to free them here */
    return EOK;
}

static void sdap_sd_search_done(struct tevent_req *subreq)
{
    int ret;

    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_sd_search_state *state =
                tevent_req_data(req, struct sdap_sd_search_state);

    ret = sdap_get_generic_ext_recv(subreq, state,
                                    &state->ref_count,
                                    &state->refs);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (ret == ETIMEDOUT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_get_generic_ext_recv request failed: [%d]: %s "
                  "[ldap_network_timeout]\n",
                  ret, sss_strerror(ret));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_get_generic_ext_recv request failed: [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_sd_search_ctrls_destructor(void *ptr)
{
    LDAPControl **ctrls = talloc_get_type(ptr, LDAPControl *);
    if (ctrls && ctrls[0]) {
        ldap_control_free(ctrls[0]);
    }

    return 0;
}

int sdap_sd_search_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        size_t *_reply_count,
                        struct sysdb_attrs ***_reply,
                        size_t *_ref_count,
                        char ***_refs)
{
    struct sdap_sd_search_state *state = tevent_req_data(req,
                                            struct sdap_sd_search_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_reply_count = state->sreply.reply_count;
    *_reply = talloc_steal(mem_ctx, state->sreply.reply);

    if(_ref_count) {
        *_ref_count = state->ref_count;
    }

    if (_refs) {
        *_refs = talloc_steal(mem_ctx, state->refs);
    }

    return EOK;
}

/* ==Attribute scoped search============================================ */
struct sdap_asq_search_state {
    struct sdap_attr_map_info *maps;
    int num_maps;
    LDAPControl **ctrls;
    struct sdap_options *opts;
    bool ldap_ignore_unreadable_references;

    struct sdap_deref_reply dreply;
};

static int sdap_asq_search_create_control(struct sdap_handle *sh,
                                          const char *attr,
                                          LDAPControl **ctrl);
static int sdap_asq_search_ctrls_destructor(void *ptr);
static errno_t sdap_asq_search_parse_entry(struct sdap_handle *sh,
                                           struct sdap_msg *msg,
                                           void *pvt);
static void sdap_asq_search_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_asq_search_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                     struct sdap_options *opts, struct sdap_handle *sh,
                     const char *base_dn, const char *deref_attr,
                     const char **attrs, struct sdap_attr_map_info *maps,
                     int num_maps, int timeout)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_asq_search_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_asq_search_state);
    if (!req) return NULL;

    state->maps = maps;
    state->num_maps = num_maps;
    state->ctrls = talloc_zero_array(state, LDAPControl *, 2);
    state->opts = opts;
    if (state->ctrls == NULL) {
        talloc_zfree(req);
        return NULL;
    }
    talloc_set_destructor((TALLOC_CTX *) state->ctrls,
                          sdap_asq_search_ctrls_destructor);

    state->ldap_ignore_unreadable_references = dp_opt_get_bool(opts->basic,
                                            SDAP_IGNORE_UNREADABLE_REFERENCES);

    ret = sdap_asq_search_create_control(sh, deref_attr, &state->ctrls[0]);
    if (ret != EOK) {
        talloc_zfree(req);
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not create ASQ control\n");
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Dereferencing entry [%s] using ASQ\n", base_dn);
    subreq = sdap_get_generic_ext_send(state, ev, opts, sh, base_dn,
                                       LDAP_SCOPE_BASE, NULL, attrs,
                                       state->ctrls, NULL, 0, timeout,
                                       sdap_asq_search_parse_entry,
                                       state, SDAP_SRCH_FLG_PAGING);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_asq_search_done, req);

    return req;
}


static int sdap_asq_search_create_control(struct sdap_handle *sh,
                                          const char *attr,
                                          LDAPControl **ctrl)
{
    struct berval *asqval;
    int ret;
    BerElement *ber = NULL;

    ber = ber_alloc_t(LBER_USE_DER);
    if (ber == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_alloc_t failed.\n");
        return ENOMEM;
    }

    ret = ber_printf(ber, "{s}", attr);
    if (ret == -1) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_printf failed.\n");
        ber_free(ber, 1);
        return EIO;
    }

    ret = ber_flatten(ber, &asqval);
    ber_free(ber, 1);
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ber_flatten failed.\n");
        return EIO;
    }

    ret = sdap_control_create(sh, LDAP_SERVER_ASQ_OID, 1, asqval, 1, ctrl);
    ber_bvfree(asqval);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_control_create failed\n");
        return ret;
    }

    return EOK;
}

static errno_t sdap_asq_search_parse_entry(struct sdap_handle *sh,
                                           struct sdap_msg *msg,
                                           void *pvt)
{
    errno_t ret;
    struct sdap_asq_search_state *state =
                talloc_get_type(pvt, struct sdap_asq_search_state);
    struct berval **vals;
    int i, mi;
    struct sdap_attr_map *map;
    int num_attrs = 0;
    struct sdap_deref_attrs **res;
    char *tmp;
    char *dn = NULL;
    TALLOC_CTX *tmp_ctx;
    bool disable_range_rtrvl;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    res = talloc_array(tmp_ctx, struct sdap_deref_attrs *,
                       state->num_maps);
    if (!res) {
        ret = ENOMEM;
        goto done;
    }

    for (mi =0; mi < state->num_maps; mi++) {
        res[mi] = talloc_zero(res, struct sdap_deref_attrs);
        if (!res[mi]) {
            ret = ENOMEM;
            goto done;
        }
        res[mi]->map = state->maps[mi].map;
        res[mi]->attrs = NULL;
    }


    tmp = ldap_get_dn(sh->ldap, msg->msg);
    if (!tmp) {
        ret = EINVAL;
        goto done;
    }

    dn = talloc_strdup(tmp_ctx, tmp);
    ldap_memfree(tmp);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    /* Find all suitable maps in the list */
    vals = ldap_get_values_len(sh->ldap, msg->msg, "objectClass");
    if (!vals) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unknown entry type, no objectClass found for DN [%s]!\n", dn);
        ret = EINVAL;
        goto done;
    }
    for (mi =0; mi < state->num_maps; mi++) {
        map = NULL;
        for (i = 0; vals[i]; i++) {
            /* the objectclass is always the first name in the map */
            if (strncasecmp(state->maps[mi].map[0].name,
                            vals[i]->bv_val, vals[i]->bv_len) == 0) {
                /* it's an entry of the right type */
                DEBUG(SSSDBG_TRACE_INTERNAL,
                      "Matched objectclass [%s] on DN [%s], will use associated map\n",
                       state->maps[mi].map[0].name, dn);
                map = state->maps[mi].map;
                num_attrs = state->maps[mi].num_attrs;
                break;
            }
        }
        if (!map) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "DN [%s] did not match the objectClass [%s]\n",
                   dn, state->maps[mi].map[0].name);
            continue;
        }

        disable_range_rtrvl = dp_opt_get_bool(state->opts->basic,
                                              SDAP_DISABLE_RANGE_RETRIEVAL);

        ret = sdap_parse_entry(res[mi], sh, msg,
                               map, num_attrs,
                               &res[mi]->attrs, disable_range_rtrvl);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "sdap_parse_entry failed [%d]: %s\n", ret, strerror(ret));
            goto done;
        }
    }
    ldap_value_free_len(vals);

    ret = add_to_deref_reply(state, state->num_maps,
                             &state->dreply, res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "add_to_deref_reply failed.\n");
        goto done;
    }

    ret = EOK;
done:
    if (ret != EOK && ret != ENOMEM) {
        if (state->ldap_ignore_unreadable_references) {
            DEBUG(SSSDBG_TRACE_FUNC, "Ignoring unreadable reference [%s]\n",
                  dn != NULL ? dn : "(null)");
            ret = EOK;
        }
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

static void sdap_asq_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_asq_search_state *state =
                tevent_req_data(req, struct sdap_asq_search_state);

    return generic_ext_search_handler(subreq, state->opts);
}

static int sdap_asq_search_ctrls_destructor(void *ptr)
{
    LDAPControl **ctrls = talloc_get_type(ptr, LDAPControl *);

    if (ctrls && ctrls[0]) {
        ldap_control_free(ctrls[0]);
    }

    return 0;
}

int sdap_asq_search_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx,
                         size_t *reply_count,
                         struct sdap_deref_attrs ***reply)
{
    struct sdap_asq_search_state *state = tevent_req_data(req,
                                            struct sdap_asq_search_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->dreply.reply_count;
    *reply = talloc_steal(mem_ctx, state->dreply.reply);

    return EOK;
}

/* ==Generic Deref Search============================================ */
enum sdap_deref_type {
    SDAP_DEREF_OPENLDAP,
    SDAP_DEREF_ASQ
};

struct sdap_deref_search_state {
    struct sdap_handle *sh;
    const char *base_dn;
    const char *deref_attr;

    size_t reply_count;
    struct sdap_deref_attrs **reply;
    enum sdap_deref_type deref_type;
    unsigned flags;
};

static void sdap_deref_search_done(struct tevent_req *subreq);
static void sdap_deref_search_with_filter_done(struct tevent_req *subreq);

struct tevent_req *
sdap_deref_search_with_filter_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_options *opts,
                                   struct sdap_handle *sh,
                                   const char *search_base,
                                   const char *filter,
                                   const char *deref_attr,
                                   const char **attrs,
                                   int num_maps,
                                   struct sdap_attr_map_info *maps,
                                   int timeout,
                                   unsigned flags)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_deref_search_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_deref_search_state);
    if (!req) return NULL;

    state->sh = sh;
    state->reply_count = 0;
    state->reply = NULL;
    state->flags = flags;

    if (sdap_is_control_supported(sh, LDAP_CONTROL_X_DEREF)) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Server supports OpenLDAP deref\n");
        state->deref_type = SDAP_DEREF_OPENLDAP;

        subreq = sdap_x_deref_search_send(state, ev, opts, sh, search_base,
                                          filter, deref_attr, attrs, maps,
                                          num_maps, timeout);
        if (!subreq) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot start OpenLDAP deref search\n");
            goto fail;
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "Server does not support any known deref method!\n");
        goto fail;
    }

    tevent_req_set_callback(subreq, sdap_deref_search_with_filter_done, req);
    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void sdap_deref_search_with_filter_done(struct tevent_req *subreq)
{
    sdap_deref_search_done(subreq);
}

int sdap_deref_search_with_filter_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *reply_count,
                                       struct sdap_deref_attrs ***reply)
{
    return sdap_deref_search_recv(req, mem_ctx, reply_count, reply);
}

struct tevent_req *
sdap_deref_search_send(TALLOC_CTX *memctx,
                       struct tevent_context *ev,
                       struct sdap_options *opts,
                       struct sdap_handle *sh,
                       const char *base_dn,
                       const char *deref_attr,
                       const char **attrs,
                       int num_maps,
                       struct sdap_attr_map_info *maps,
                       int timeout)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_deref_search_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_deref_search_state);
    if (!req) return NULL;

    state->sh = sh;
    state->reply_count = 0;
    state->reply = NULL;
    state->base_dn = base_dn;
    state->deref_attr = deref_attr;

    PROBE(SDAP_DEREF_SEARCH_SEND, state->base_dn, state->deref_attr);

    if (sdap_is_control_supported(sh, LDAP_SERVER_ASQ_OID)) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Server supports ASQ\n");
        state->deref_type = SDAP_DEREF_ASQ;

        subreq = sdap_asq_search_send(state, ev, opts, sh, base_dn,
                                      deref_attr, attrs, maps, num_maps,
                                      timeout);
        if (!subreq) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot start ASQ search\n");
            goto fail;
        }
    } else if (sdap_is_control_supported(sh, LDAP_CONTROL_X_DEREF)) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Server supports OpenLDAP deref\n");
        state->deref_type = SDAP_DEREF_OPENLDAP;

        subreq = sdap_x_deref_search_send(state, ev, opts, sh, base_dn, NULL,
                                          deref_attr, attrs, maps, num_maps,
                                          timeout);
        if (!subreq) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot start OpenLDAP deref search\n");
            goto fail;
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "Server does not support any known deref method!\n");
        goto fail;
    }

    tevent_req_set_callback(subreq, sdap_deref_search_done, req);
    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void sdap_deref_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_deref_search_state *state = tevent_req_data(req,
                                            struct sdap_deref_search_state);
    int ret;

    switch (state->deref_type) {
    case SDAP_DEREF_OPENLDAP:
        ret = sdap_x_deref_search_recv(subreq, state,
                &state->reply_count, &state->reply);
        break;
    case SDAP_DEREF_ASQ:
        ret = sdap_asq_search_recv(subreq, state,
                &state->reply_count, &state->reply);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown deref method %d\n", state->deref_type);
        tevent_req_error(req, EINVAL);
        return;
    }

    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "dereference processing failed [%d]: %s\n", ret, strerror(ret));
        if (ret == ENOTSUP) {
            state->sh->disable_deref = true;
        }

        if (!(state->flags & SDAP_DEREF_FLG_SILENT)) {
            if (ret == ENOTSUP) {
                sss_log(SSS_LOG_WARNING,
                        "LDAP server claims to support deref, but deref search "
                        "failed. Disabling deref for further requests. You can "
                        "permanently disable deref by setting "
                        "ldap_deref_threshold to 0 in domain configuration.");
            } else {
                sss_log(SSS_LOG_WARNING,
                        "dereference processing failed : %s", strerror(ret));
            }
        }
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_deref_search_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sdap_deref_attrs ***reply)
{
    struct sdap_deref_search_state *state = tevent_req_data(req,
                                            struct sdap_deref_search_state);

    PROBE(SDAP_DEREF_SEARCH_RECV, state->base_dn, state->deref_attr);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->reply_count;
    *reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}

bool sdap_has_deref_support_ex(struct sdap_handle *sh,
                               struct sdap_options *opts,
                               bool ignore_client)
{
    const char *deref_oids[][2] = { { LDAP_SERVER_ASQ_OID, "ASQ" },
                                    { LDAP_CONTROL_X_DEREF, "OpenLDAP" },
                                    { NULL, NULL }
                                  };
    int i;
    int deref_threshold;

    if (sh->disable_deref) {
        return false;
    }

    if (ignore_client == false) {
        deref_threshold = dp_opt_get_int(opts->basic, SDAP_DEREF_THRESHOLD);
        if (deref_threshold == 0) {
            return false;
        }
    }

    for (i=0; deref_oids[i][0]; i++) {
        if (sdap_is_control_supported(sh, deref_oids[i][0])) {
            DEBUG(SSSDBG_TRACE_FUNC, "The server supports deref method %s\n",
                  deref_oids[i][1]);
            return true;
        }
    }

    return false;
}

bool sdap_has_deref_support(struct sdap_handle *sh, struct sdap_options *opts)
{
    return sdap_has_deref_support_ex(sh, opts, false);
}
