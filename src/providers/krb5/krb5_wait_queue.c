/*
    SSSD

    Kerberos 5 Backend Module - Serialize the request of a user

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <tevent.h>
#include <dhash.h>

#include <security/pam_modules.h>

#include "src/providers/krb5/krb5_auth.h"

struct queue_entry {
    struct queue_entry *prev;
    struct queue_entry *next;

    struct be_ctx *be_ctx;
    struct be_req *be_req;
    struct tevent_req *parent_req;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
};

static void wait_queue_auth_done(struct tevent_req *req);

static void krb5_auth_queue_finish(struct tevent_req *req, errno_t ret,
                                   int pam_status, int dp_err);

static void wait_queue_auth(struct tevent_context *ev, struct tevent_timer *te,
                            struct timeval current_time, void *private_data)
{
    struct queue_entry *qe = talloc_get_type(private_data, struct queue_entry);
    struct tevent_req *req;

    req = krb5_auth_send(qe->parent_req, qe->be_ctx->ev,
                         qe->be_ctx, qe->pd, qe->krb5_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_auth_send failed.\n");
    } else {
        tevent_req_set_callback(req, wait_queue_auth_done,
                                qe->parent_req);
    }

    talloc_zfree(qe);
}

static void wait_queue_auth_done(struct tevent_req *req)
{
    struct tevent_req *parent_req = \
                tevent_req_callback_data(req, struct tevent_req);
    int pam_status;
    int dp_err;
    errno_t ret;

    ret = krb5_auth_recv(req, &pam_status, &dp_err);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_auth_recv failed: %d\n", ret);
    }

    krb5_auth_queue_finish(parent_req, ret, pam_status, dp_err);
}

static void wait_queue_del_cb(hash_entry_t *entry, hash_destroy_enum type,
                              void *pvt)
{
    struct queue_entry *head;

    if (entry->value.type == HASH_VALUE_PTR) {
        head = talloc_get_type(entry->value.ptr, struct queue_entry);
        talloc_zfree(head);
        return;
    }

    DEBUG(SSSDBG_CRIT_FAILURE,
          "Unexpected value type [%d].\n", entry->value.type);
}

static errno_t add_to_wait_queue(struct be_ctx *be_ctx,
                                 struct tevent_req *parent_req,
                                 struct pam_data *pd,
                                 struct krb5_ctx *krb5_ctx)
{
    int ret;
    hash_key_t key;
    hash_value_t value;
    struct queue_entry *head;
    struct queue_entry *queue_entry;

    if (krb5_ctx->wait_queue_hash == NULL) {
        ret = sss_hash_create_ex(krb5_ctx, 0,
                                 &krb5_ctx->wait_queue_hash, 0, 0, 0, 0,
                                 wait_queue_del_cb, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_hash_create failed\n");
            return ret;
        }
    }

    key.type = HASH_KEY_STRING;
    key.str = pd->user;

    ret = hash_lookup(krb5_ctx->wait_queue_hash, &key, &value);
    switch (ret) {
        case HASH_SUCCESS:
            if (value.type != HASH_VALUE_PTR) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected hash value type.\n");
                return EINVAL;
            }

            head = talloc_get_type(value.ptr, struct queue_entry);

            queue_entry = talloc_zero(head, struct queue_entry);
            if (queue_entry == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
                return ENOMEM;
            }

            queue_entry->be_ctx = be_ctx;
            queue_entry->parent_req = parent_req;
            queue_entry->pd = pd;
            queue_entry->krb5_ctx = krb5_ctx;

            DLIST_ADD_END(head, queue_entry, struct queue_entry *);

            break;
        case HASH_ERROR_KEY_NOT_FOUND:
            value.type = HASH_VALUE_PTR;
            head = talloc_zero(krb5_ctx->wait_queue_hash, struct queue_entry);
            if (head == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
                return ENOMEM;
            }
            value.ptr = head;

            ret = hash_enter(krb5_ctx->wait_queue_hash, &key, &value);
            if (ret != HASH_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE, "hash_enter failed.\n");
                talloc_free(head);
                return EIO;
            }

            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "hash_lookup failed.\n");
            return EIO;
    }

    if (head->next == NULL) {
        return ENOENT;
    } else {
        return EOK;
    }
}

static void check_wait_queue(struct krb5_ctx *krb5_ctx, char *username)
{
    int ret;
    hash_key_t key;
    hash_value_t value;
    struct queue_entry *head;
    struct queue_entry *queue_entry;
    struct tevent_timer *te;

    if (krb5_ctx->wait_queue_hash == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No wait queue available.\n");
        return;
    }

    key.type = HASH_KEY_STRING;
    key.str = username;

    ret = hash_lookup(krb5_ctx->wait_queue_hash, &key, &value);

    switch (ret) {
        case HASH_SUCCESS:
            if (value.type != HASH_VALUE_PTR) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected hash value type.\n");
                return;
            }

            head = talloc_get_type(value.ptr, struct queue_entry);

            if (head->next == NULL) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "Wait queue for user [%s] is empty.\n", username);
            } else {
                queue_entry = head->next;

                DLIST_REMOVE(head, queue_entry);

                te = tevent_add_timer(queue_entry->be_ctx->ev, krb5_ctx,
                                      tevent_timeval_current(), wait_queue_auth,
                                      queue_entry);
                if (te == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
                } else {
                    return;
                }
            }

            ret = hash_delete(krb5_ctx->wait_queue_hash, &key);
            if (ret != HASH_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to remove wait queue for user [%s].\n",
                          username);
            }

            break;
        case HASH_ERROR_KEY_NOT_FOUND:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "No wait queue for user [%s] found.\n", username);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "hash_lookup failed.\n");
    }

    return;
}

struct krb5_auth_queue_state {
    struct krb5_ctx *krb5_ctx;
    struct pam_data *pd;

    int pam_status;
    int dp_err;
};

static void krb5_auth_queue_done(struct tevent_req *subreq);

struct tevent_req *krb5_auth_queue_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct be_ctx *be_ctx,
                                        struct pam_data *pd,
                                        struct krb5_ctx *krb5_ctx)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct krb5_auth_queue_state *state;

    req = tevent_req_create(mem_ctx, &state, struct krb5_auth_queue_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }
    state->krb5_ctx = krb5_ctx;
    state->pd = pd;

    ret = add_to_wait_queue(be_ctx, req, pd, krb5_ctx);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Request [%p] successfully added to wait queue "
              "of user [%s].\n", req, pd->user);
        ret = EOK;
        goto immediate;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS, "Wait queue of user [%s] is empty, "
              "running request [%p] immediately.\n", pd->user, req);
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to add request to wait queue of user [%s], "
              "running request [%p] immediately.\n", pd->user, req);
    }

    subreq = krb5_auth_send(req, ev, be_ctx, pd, krb5_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_auth_send failed.\n");
        ret = ENOMEM;
        goto immediate;
    }

    tevent_req_set_callback(subreq, krb5_auth_queue_done, req);

    ret = EOK;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void krb5_auth_queue_done(struct tevent_req *subreq)
{
    struct tevent_req *req = \
                tevent_req_callback_data(subreq, struct tevent_req);
    struct krb5_auth_queue_state *state = \
                tevent_req_data(req, struct krb5_auth_queue_state);
    errno_t ret;

    ret = krb5_auth_recv(subreq, &state->pam_status, &state->dp_err);
    talloc_zfree(subreq);

    check_wait_queue(state->krb5_ctx, state->pd->user);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_auth_recv failed with: %d\n", ret);
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "krb5_auth_queue request [%p] done.\n", req);
    tevent_req_done(req);
}

/* This is a violation of the tevent_req style. Ideally, the wait queue would
 * be rewritten to the tevent_req style in the future, expose per-request recv
 * and not hide the request underneath. But this function allows us to expose
 * a tevent_req API for users of this module
 */
static void krb5_auth_queue_finish(struct tevent_req *req,
                                   errno_t ret,
                                   int pam_status,
                                   int dp_err)
{
    struct krb5_auth_queue_state *state = \
                tevent_req_data(req, struct krb5_auth_queue_state);

    check_wait_queue(state->krb5_ctx, state->pd->user);

    state->pam_status = pam_status;
    state->dp_err = dp_err;
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "krb5_auth_queue request [%p] done.\n", req);
        tevent_req_done(req);
    }
}

int krb5_auth_queue_recv(struct tevent_req *req,
                         int *_pam_status,
                         int *_dp_err)
{
    struct krb5_auth_queue_state *state = \
                tevent_req_data(req, struct krb5_auth_queue_state);

    /* Returning values even on failure is not typical, but IPA password migration
     * relies on receiving PAM_CRED_ERR even if the request fails..
     */
    if (_pam_status) {
        *_pam_status = state->pam_status;
    }

    if (_dp_err) {
        *_dp_err = state->dp_err;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
