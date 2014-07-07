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
#include "providers/ldap/sdap_async_private.h"

#define REPLY_REALLOC_INCREMENT 10

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

static void sdap_process_result(struct tevent_context *ev, void *pvt)
{
    struct sdap_handle *sh = talloc_get_type(pvt, struct sdap_handle);
    struct timeval no_timeout = {0, 0};
    struct tevent_timer *te;
    LDAPMessage *msg;
    int ret;

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
        DEBUG(SSSDBG_TRACE_INTERNAL, "Trace: ldap_result found nothing!\n");
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
     * FIXME: use tevent_immediate/tevent_queues, when avilable */
    memset(&no_timeout, 0, sizeof(struct timeval));

    te = tevent_add_timer(ev, sh, no_timeout, sdap_ldap_next_result, sh);
    if (!te) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add critical timer to fetch next result!\n");
    }

    /* now process this message */
    sdap_process_message(ev, sh, msg);
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
        DEBUG(SSSDBG_OP_FAILURE, "can't fire callback, message id invalid!\n");
        ldap_msgfree(msg);
        return;
    }

    msgtype = ldap_msgtype(msg);

    for (op = sh->ops; op; op = op->next) {
        if (op->msgid == msgid) break;
    }

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
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add critical timer for next reply!\n");
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
        DEBUG(SSSDBG_OP_FAILURE, "Timeout happened after op was finished !?\n");
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
                                           const char *new_password)
{
    struct tevent_req *req = NULL;
    struct sdap_exop_modify_passwd_state *state;
    int ret;
    BerElement *ber = NULL;
    struct berval *bv = NULL;
    int msgid;
    LDAPControl **request_controls = NULL;
    LDAPControl *ctrls[2] = { NULL, NULL };

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

    ret = sdap_control_create(state->sh, LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                              0, NULL, 0, &ctrls[0]);
    if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_control_create failed to create "
                  "Password Policy control.\n");
        ret = ERR_INTERNAL;
        goto fail;
    }
    request_controls = ctrls;

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

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, state->sh, msgid,
                      sdap_exop_modify_passwd_done, req, 5, &state->op);
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

    switch (result) {
    case LDAP_SUCCESS:
        ret = EOK;
        break;
    case LDAP_CONSTRAINT_VIOLATION:
        state->user_error_message = talloc_strdup(state,
            "Please make sure the password meets the complexity constraints.");
        if (state->user_error_message == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed\n");
            ret = ENOMEM;
            goto done;
        }

        ret = ERR_CHPASS_DENIED;
        break;
    default:
        if (errmsg) {
            state->user_error_message = talloc_strdup(state, errmsg);
            if (state->user_error_message == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        }
        ret = ERR_NETWORK_IO;
        break;
    }

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

    *user_error_message = talloc_steal(mem_ctx, state->user_error_message);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==Update-passwordLastChanged-attribute====================== */
struct update_last_changed_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    struct sdap_op *op;

    const char *dn;
    LDAPMod **mods;
};

static void sdap_modify_shadow_lastchange_done(struct sdap_op *op,
                                               struct sdap_msg *reply,
                                               int error, void *pvt);

struct tevent_req *
sdap_modify_shadow_lastchange_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct sdap_handle *sh,
                                   const char *dn,
                                   char *lastchanged_name)
{
    struct tevent_req *req;
    struct update_last_changed_state *state;
    char **values;
    errno_t ret;
    int msgid;

    req = tevent_req_create(mem_ctx, &state, struct update_last_changed_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->sh = sh;
    state->dn = dn;
    state->mods = talloc_zero_array(state, LDAPMod *, 2);
    if (state->mods == NULL) {
        ret = ENOMEM;
        goto done;
    }
    state->mods[0] = talloc_zero(state->mods, LDAPMod);
    state->mods[1] = talloc_zero(state->mods, LDAPMod);
    if (!state->mods[0] || !state->mods[1]) {
        ret = ENOMEM;
        goto done;
    }
    values = talloc_zero_array(state->mods[0], char *, 2);
    if (values == NULL) {
        ret = ENOMEM;
        goto done;
    }
    /* The attribute contains number of days since the epoch */
    values[0] = talloc_asprintf(values, "%ld", (long)time(NULL)/86400);
    if (values[0] == NULL) {
        ret = ENOMEM;
        goto done;
    }
    state->mods[0]->mod_op = LDAP_MOD_REPLACE;
    state->mods[0]->mod_type = lastchanged_name;
    state->mods[0]->mod_vals.modv_strvals = values;
    state->mods[1] = NULL;

    ret = ldap_modify_ext(state->sh->ldap, state->dn, state->mods,
            NULL, NULL, &msgid);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to send operation!\n");
        goto done;
    }

    ret = sdap_op_add(state, state->ev, state->sh, msgid,
            sdap_modify_shadow_lastchange_done, req, 5, &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void sdap_modify_shadow_lastchange_done(struct sdap_op *op,
                                               struct sdap_msg *reply,
                                               int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct update_last_changed_state *state;
    state = tevent_req_data(req, struct update_last_changed_state);
    char *errmsg;
    int result;
    errno_t ret = EOK;
    int lret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    lret = ldap_parse_result(state->sh->ldap, reply->msg,
                            &result, NULL, &errmsg, NULL,
                            NULL, 0);
    if (lret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldap_parse_result failed (%d)\n",
                                  state->op->msgid);
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Updating lastPwdChange result: %s(%d), %s\n",
                              sss_ldap_err2string(result),
                              result, errmsg);

done:
    ldap_memfree(errmsg);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
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
static void sdap_get_matching_rule_done(struct tevent_req *subreq);

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
#define SDAP_MATCHING_RULE_TEST_ATTR "sssmatchingruletest"

static void sdap_get_rootdse_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_rootdse_state *state = tevent_req_data(req,
                                             struct sdap_get_rootdse_state);
    struct sysdb_attrs **results;
    size_t num_results;
    int ret;
    const char *filter;
    const char *attrs[] = { SDAP_MATCHING_RULE_TEST_ATTR, NULL };

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
              "Multiple replies when searching for RootDSE ??\n");
        tevent_req_error(req, EIO);
        return;
    }

    state->rootdse = talloc_steal(state, results[0]);
    talloc_zfree(results);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Got rootdse\n");

    /* Auto-detect the ldap matching rule if requested */
    if ((!dp_opt_get_bool(state->opts->basic,
                          SDAP_AD_MATCHING_RULE_INITGROUPS))
            && !dp_opt_get_bool(state->opts->basic,
                                SDAP_AD_MATCHING_RULE_GROUPS)) {
        /* This feature is disabled for both groups
         * and initgroups. Skip the auto-detection
         * lookup.
         */
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Skipping auto-detection of match rule\n");
        tevent_req_done(req);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Auto-detecting support for match rule\n");

    /* Create a filter using the matching rule. It need not point
     * at any valid data. We're only going to be looking for the
     * error code.
     */
    filter = "("SDAP_MATCHING_RULE_TEST_ATTR":"
             SDAP_MATCHING_RULE_IN_CHAIN":=)";

    /* Perform a trivial query with the matching rule in play.
     * If it returns success, we know it is available. If it
     * returns EIO, we know it isn't.
     */
    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   "", LDAP_SCOPE_BASE, filter, attrs, NULL,
                                   0, dp_opt_get_int(state->opts->basic,
                                                     SDAP_SEARCH_TIMEOUT),
                                   false);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_matching_rule_done, req);
}

static void sdap_get_matching_rule_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_rootdse_state *state = tevent_req_data(req,
                                             struct sdap_get_rootdse_state);
    size_t num_results;
    struct sysdb_attrs **results;

    ret = sdap_get_generic_recv(subreq, state, &num_results, &results);
    talloc_zfree(subreq);
    if (ret == EOK) {
        /* The search succeeded */
        state->opts->support_matching_rule = true;
    } else if (ret == EIO) {
        /* The search failed. Disable support for
         * matching rule lookups.
         */
        state->opts->support_matching_rule = false;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Unexpected error while testing for matching rule support\n");
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "LDAP server %s the matching rule extension\n",
          state->opts->support_matching_rule
              ? "supports"
              : "does not support");

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
    int attrsonly;
    int sizelimit;

    struct sdap_op *op;

    struct berval cookie;

    LDAPControl **serverctrls;
    int nserverctrls;
    LDAPControl **clientctrls;

    sdap_parse_cb parse_cb;
    void *cb_data;

    bool allow_paging;
};

static errno_t sdap_get_generic_ext_step(struct tevent_req *req);

static void sdap_get_generic_ext_done(struct sdap_op *op,
                                      struct sdap_msg *reply,
                                      int error, void *pvt);

static struct tevent_req *
sdap_get_generic_ext_send(TALLOC_CTX *memctx,
                          struct tevent_context *ev,
                          struct sdap_options *opts,
                          struct sdap_handle *sh,
                          const char *search_base,
                          int scope,
                          const char *filter,
                          const char **attrs,
                          int attrsonly,
                          LDAPControl **serverctrls,
                          LDAPControl **clientctrls,
                          int sizelimit,
                          int timeout,
                          bool allow_paging,
                          sdap_parse_cb parse_cb,
                          void *cb_data)
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
    state->attrsonly = attrsonly;
    state->op = NULL;
    state->sizelimit = sizelimit;
    state->timeout = timeout;
    state->cookie.bv_len = 0;
    state->cookie.bv_val = NULL;
    state->parse_cb = parse_cb;
    state->cb_data = cb_data;
    state->clientctrls = clientctrls;

    if (state->sh == NULL || state->sh->ldap == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Trying LDAP search while not connected.\n");
        tevent_req_error(req, EIO);
        tevent_req_post(req, ev);
        return req;
    }

    /* Be extra careful and never allow paging for BASE searches,
     * even if requested.
     */
    if (scope == LDAP_SCOPE_BASE) {
        state->allow_paging = false;
    } else {
        state->allow_paging = allow_paging;
    }

    /* Also check for deref/asq requests and force
     * paging on for those requests
     */
    /* X-DEREF */
    control = ldap_control_find(LDAP_CONTROL_X_DEREF,
                                serverctrls,
                                NULL);
    if (control) {
        state->allow_paging = true;
    }

    /* ASQ */
    control = ldap_control_find(LDAP_SERVER_ASQ_OID,
                                serverctrls,
                                NULL);
    if (control) {
        state->allow_paging = true;
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
    if (DEBUG_IS_SET(SSSDBG_TRACE_LIBS)) {
        int i;

        if (state->attrs) {
            for (i = 0; state->attrs[i]; i++) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "Requesting attrs: [%s]\n", state->attrs[i]);
            }
        }
    }

    disable_paging = dp_opt_get_bool(state->opts->basic, SDAP_DISABLE_PAGING);

    if (!disable_paging
            && state->allow_paging
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
                           state->attrsonly, state->serverctrls,
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
            }
            else {
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

    ret = sdap_op_add(state, state->ev, state->sh, msgid,
                      sdap_get_generic_ext_done, req,
                      state->timeout,
                      &state->op);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
        goto done;
    }

done:
    return ret;
}

static void sdap_get_generic_ext_done(struct sdap_op *op,
                                      struct sdap_msg *reply,
                                      int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_generic_ext_state *state = tevent_req_data(req,
                                            struct sdap_get_generic_ext_state);
    char *errmsg = NULL;
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
        /* ignore references for now */
        talloc_free(reply);

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
                                &result, NULL, &errmsg, NULL,
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

        if (result == LDAP_SIZELIMIT_EXCEEDED) {
            /* Try to return what we've got */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "LDAP sizelimit was exceeded, returning incomplete data\n");
        } else if (result == LDAP_INAPPROPRIATE_MATCHING) {
            /* This error should only occur when we're testing for
             * specialized functionality like the ldap matching rule
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
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not determine page control");
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
sdap_get_generic_ext_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* ==Generic Search============================================ */
struct sdap_get_generic_state {
    struct sdap_attr_map *map;
    int map_num_attrs;

    struct sdap_reply sreply;
    struct sdap_options *opts;
};

static void sdap_get_generic_done(struct tevent_req *subreq);
static errno_t sdap_get_generic_parse_entry(struct sdap_handle *sh,
                                            struct sdap_msg *msg,
                                            void *pvt);

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

    state->map = map;
    state->map_num_attrs = map_num_attrs;
    state->opts = opts;

    subreq = sdap_get_generic_ext_send(state, ev, opts, sh, search_base,
                                       scope, filter, attrs, false, NULL,
                                       NULL, 0, timeout, allow_paging,
                                       sdap_get_generic_parse_entry, state);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_generic_done, req);

    return req;
}

static errno_t sdap_get_generic_parse_entry(struct sdap_handle *sh,
                                            struct sdap_msg *msg,
                                            void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    struct sdap_get_generic_state *state =
                talloc_get_type(pvt, struct sdap_get_generic_state);

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

static void sdap_get_generic_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_generic_ext_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "sdap_get_generic_ext_recv failed [%d]: %s\n",
                  ret, sss_strerror(ret));
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
    struct sdap_get_generic_state *state = tevent_req_data(req,
                                            struct sdap_get_generic_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->sreply.reply_count;
    *reply = talloc_steal(mem_ctx, state->sreply.reply);

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

    struct sdap_deref_reply dreply;
    int num_maps;
};

static struct tevent_req *
sdap_x_deref_search_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                         struct sdap_options *opts, struct sdap_handle *sh,
                         const char *base_dn, const char *deref_attr,
                         const char **attrs, struct sdap_attr_map_info *maps,
                         int num_maps, int timeout)
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
    state->num_maps = num_maps;
    state->ctrls = talloc_zero_array(state, LDAPControl *, 2);
    if (state->ctrls == NULL) {
        talloc_zfree(req);
        return NULL;
    }
    talloc_set_destructor((TALLOC_CTX *) state->ctrls,
                          sdap_x_deref_search_ctrls_destructor);

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
                                       LDAP_SCOPE_BASE, NULL, attrs,
                                       false, state->ctrls, NULL, 0, timeout,
                                       true, sdap_x_deref_parse_entry,
                                       state);
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
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_ldap_control_create failed: %s\n",
                  ldap_err2string(ret));
        return ret;
    }

    ret = sdap_control_create(sh, LDAP_CONTROL_X_DEREF,
                              1, &derefval, 1, ctrl);
    ldap_memfree(derefval.bv_val);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_ldap_control_create failed\n");
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
        DEBUG(SSSDBG_MINOR_FAILURE, "No controls found for entry\n");
        ret = ENOENT;
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
    talloc_zfree(tmp_ctx);
    ldap_controls_free(ctrls);
    ldap_derefresponse_free(deref_res);
    return ret;
}

static void sdap_x_deref_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_generic_ext_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "sdap_get_generic_ext_recv failed [%d]: %s\n",
                  ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_x_deref_search_ctrls_destructor(void *ptr)
{
    LDAPControl **ctrls = talloc_get_type(ptr, LDAPControl *);;

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
                                       false, state->ctrls, NULL, 0, timeout,
                                       true, sdap_sd_search_parse_entry,
                                       state);
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
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;
    ret = sdap_get_generic_ext_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_get_generic_ext_recv failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_sd_search_ctrls_destructor(void *ptr)
{
    LDAPControl **ctrls = talloc_get_type(ptr, LDAPControl *);;
    if (ctrls && ctrls[0]) {
        ldap_control_free(ctrls[0]);
    }

    return 0;
}

int sdap_sd_search_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        size_t *_reply_count,
                        struct sysdb_attrs ***_reply)
{
    struct sdap_sd_search_state *state = tevent_req_data(req,
                                            struct sdap_sd_search_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_reply_count = state->sreply.reply_count;
    *_reply = talloc_steal(mem_ctx, state->sreply.reply);

    return EOK;
}

/* ==Attribute scoped search============================================ */
struct sdap_asq_search_state {
    struct sdap_attr_map_info *maps;
    int num_maps;
    LDAPControl **ctrls;
    struct sdap_options *opts;

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

    ret = sdap_asq_search_create_control(sh, deref_attr, &state->ctrls[0]);
    if (ret != EOK) {
        talloc_zfree(req);
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not create ASQ control\n");
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Dereferencing entry [%s] using ASQ\n", base_dn);
    subreq = sdap_get_generic_ext_send(state, ev, opts, sh, base_dn,
                                       LDAP_SCOPE_BASE, NULL, attrs,
                                       false, state->ctrls, NULL, 0, timeout,
                                       true, sdap_asq_search_parse_entry,
                                       state);
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
    int num_attrs;
    struct sdap_deref_attrs **res;
    char *tmp;
    char *dn;
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
    talloc_zfree(tmp_ctx);
    return ret;
}

static void sdap_asq_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_generic_ext_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "sdap_get_generic_ext_recv failed [%d]: %s\n",
                  ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_asq_search_ctrls_destructor(void *ptr)
{
    LDAPControl **ctrls = talloc_get_type(ptr, LDAPControl *);;

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

/* ==Posix attribute presence test================================= */
static errno_t sdap_posix_check_next(struct tevent_req *req);
static void sdap_posix_check_done(struct tevent_req *subreq);
static errno_t sdap_posix_check_parse(struct sdap_handle *sh,
                                      struct sdap_msg *msg,
                                      void *pvt);

struct sdap_posix_check_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sdap_search_base **search_bases;
    int timeout;

    const char **attrs;
    const char *filter;
    size_t base_iter;

    bool has_posix;
};

struct tevent_req *
sdap_posix_check_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                      struct sdap_options *opts, struct sdap_handle *sh,
                      struct sdap_search_base **search_bases,
                      int timeout)
{
    struct tevent_req *req = NULL;
    struct sdap_posix_check_state *state;
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct sdap_posix_check_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sh = sh;
    state->opts = opts;
    state->search_bases = search_bases;
    state->timeout = timeout;

    state->attrs = talloc_array(state, const char *, 4);
    if (state->attrs == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    state->attrs[0] = "objectclass";
    state->attrs[1] = opts->user_map[SDAP_AT_USER_UID].name;
    state->attrs[2] = opts->group_map[SDAP_AT_GROUP_GID].name;
    state->attrs[3] = NULL;

    state->filter = talloc_asprintf(state, "(|(%s=*)(%s=*))",
                                    opts->user_map[SDAP_AT_USER_UID].name,
                                    opts->group_map[SDAP_AT_GROUP_GID].name);
    if (state->filter == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sdap_posix_check_next(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t sdap_posix_check_next(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct sdap_posix_check_state *state =
        tevent_req_data(req, struct sdap_posix_check_state);

    DEBUG(SSSDBG_TRACE_FUNC,
          "Searching for POSIX attributes with base [%s]\n",
           state->search_bases[state->base_iter]->basedn);

    subreq = sdap_get_generic_ext_send(state, state->ev, state->opts,
                                 state->sh,
                                 state->search_bases[state->base_iter]->basedn,
                                 LDAP_SCOPE_SUBTREE, state->filter,
                                 state->attrs, false,
                                 NULL, NULL, 1, state->timeout,
                                 false, sdap_posix_check_parse,
                                 state);
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, sdap_posix_check_done, req);

    return EOK;
}

static errno_t sdap_posix_check_parse(struct sdap_handle *sh,
                                      struct sdap_msg *msg,
                                      void *pvt)
{
    struct berval **vals = NULL;
    struct sdap_posix_check_state *state =
        talloc_get_type(pvt, struct sdap_posix_check_state);
    char *dn;
    char *endptr;

    dn = ldap_get_dn(sh->ldap, msg->msg);
    if (dn == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Search did not find any entry with POSIX attributes\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Found [%s] with POSIX attributes\n", dn);
    ldap_memfree(dn);

    vals = ldap_get_values_len(sh->ldap, msg->msg,
                               state->opts->user_map[SDAP_AT_USER_UID].name);
    if (vals == NULL) {
        vals = ldap_get_values_len(sh->ldap, msg->msg,
                               state->opts->group_map[SDAP_AT_GROUP_GID].name);
        if (vals == NULL) {
            DEBUG(SSSDBG_TRACE_LIBS, "Entry does not have POSIX attrs?\n");
            goto done;
        }
    }

    if (vals[0] == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "No value for POSIX attr\n");
        goto done;
    }

    errno = 0;
    strtouint32(vals[0]->bv_val, &endptr, 10);
    if (errno || *endptr || (vals[0]->bv_val == endptr)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "POSIX attribute is not a number: %s\n", vals[0]->bv_val);
        goto done;
    }

    state->has_posix = true;
done:
    ldap_value_free_len(vals);
    return EOK;
}

static void sdap_posix_check_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_posix_check_state *state =
        tevent_req_data(req, struct sdap_posix_check_state);
    errno_t ret;

    ret = sdap_get_generic_ext_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_get_generic_ext_recv failed [%d]: %s\n",
              ret, strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* Positive hit is definitve, no need to search other bases */
    if (state->has_posix == true) {
        DEBUG(SSSDBG_FUNC_DATA, "Server has POSIX attributes\n");
        tevent_req_done(req);
        return;
    }

    state->base_iter++;
    if (state->search_bases[state->base_iter]) {
        /* There are more search bases to try */
        ret = sdap_posix_check_next(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    /* All bases done! */
    DEBUG(SSSDBG_TRACE_LIBS, "Cycled through all bases\n");
    tevent_req_done(req);
}

int sdap_posix_check_recv(struct tevent_req *req,
                          bool *_has_posix)
{
    struct sdap_posix_check_state *state = tevent_req_data(req,
                                            struct sdap_posix_check_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_has_posix = state->has_posix;
    return EOK;
}

/* ==Generic Deref Search============================================ */
enum sdap_deref_type {
    SDAP_DEREF_OPENLDAP,
    SDAP_DEREF_ASQ
};

struct sdap_deref_search_state {
    struct sdap_handle *sh;
    size_t reply_count;
    struct sdap_deref_attrs **reply;
    enum sdap_deref_type deref_type;
};

static void sdap_deref_search_done(struct tevent_req *subreq);

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

        subreq = sdap_x_deref_search_send(state, ev, opts, sh, base_dn,
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown deref method\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "dereference processing failed [%d]: %s\n", ret, strerror(ret));
        if (ret == ENOTSUP) {
            sss_log(SSS_LOG_WARNING,
                "LDAP server claims to support deref, but deref search failed. "
                "Disabling deref for further requests. You can permanently "
                "disable deref by setting ldap_deref_threshold to 0 in domain "
                "configuration.");
            state->sh->disable_deref = true;
        } else {
            sss_log(SSS_LOG_WARNING, "dereference processing failed : %s", strerror(ret));
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
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->reply_count;
    *reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}

bool sdap_has_deref_support(struct sdap_handle *sh, struct sdap_options *opts)
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

    deref_threshold = dp_opt_get_int(opts->basic, SDAP_DEREF_THRESHOLD);
    if (deref_threshold == 0) {
        return false;
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
