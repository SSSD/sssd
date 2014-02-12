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

#include "src/providers/krb5/krb5_auth.h"

#define INIT_HASH_SIZE 5

struct queue_entry {
    struct queue_entry *prev;
    struct queue_entry *next;

    struct be_req *be_req;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
};

static void wait_queue_auth(struct tevent_context *ev, struct tevent_timer *te,
                             struct timeval current_time, void *private_data)
{
    struct queue_entry *qe = talloc_get_type(private_data, struct queue_entry);
    struct be_ctx *be_ctx = be_req_get_be_ctx(qe->be_req);
    struct tevent_req *req;

    req = krb5_auth_send(qe->be_req, be_ctx->ev, be_ctx, qe->pd, qe->krb5_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_auth_send failed.\n");
    } else {
        tevent_req_set_callback(req, krb5_pam_handler_auth_done, qe->be_req);
    }

    talloc_zfree(qe);
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

errno_t add_to_wait_queue(struct be_req *be_req, struct pam_data *pd,
                          struct krb5_ctx *krb5_ctx)
{
    int ret;
    hash_key_t key;
    hash_value_t value;
    struct queue_entry *head;
    struct queue_entry *queue_entry;

    if (krb5_ctx->wait_queue_hash == NULL) {
        ret = sss_hash_create_ex(krb5_ctx, INIT_HASH_SIZE,
                                 &krb5_ctx->wait_queue_hash, 0, 0, 0, 0,
                                 wait_queue_del_cb, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_hash_create failed");
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

            queue_entry->be_req = be_req;
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

void check_wait_queue(struct krb5_ctx *krb5_ctx, char *username)
{
    int ret;
    hash_key_t key;
    hash_value_t value;
    struct queue_entry *head;
    struct queue_entry *queue_entry;
    struct tevent_timer *te;
    struct be_ctx *be_ctx;

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

                be_ctx = be_req_get_be_ctx(queue_entry->be_req);
                te = tevent_add_timer(be_ctx->ev, krb5_ctx,
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

