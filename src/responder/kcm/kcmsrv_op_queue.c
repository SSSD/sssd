/*
   SSSD

   KCM Server - the KCM operations wait queue

   Copyright (C) Red Hat, 2017

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

#include "util/util.h"
#include "util/util_creds.h"
#include "responder/kcm/kcmsrv_pvt.h"

struct kcm_ops_queue_entry {
    struct tevent_req *req;

    struct kcm_ops_queue *queue;

    struct kcm_ops_queue_entry *next;
    struct kcm_ops_queue_entry *prev;
};

struct kcm_ops_queue {
    uid_t uid;
    struct tevent_context *ev;
    struct kcm_ops_queue_ctx *qctx;

    struct kcm_ops_queue_entry *head;
};

struct kcm_ops_queue_ctx {
    struct kcm_ctx *kctx;

    /* UID:kcm_ops_queue */
    hash_table_t *wait_queue_hash;
};

/*
 * Per-UID wait queue
 *
 * They key in the hash table is the UID of the peer. The value of each
 * hash table entry is kcm_ops_queue structure which in turn contains a
 * linked list of kcm_ops_queue_entry structures * which primarily hold the
 * tevent request being queued.
 */
struct kcm_ops_queue_ctx *kcm_ops_queue_create(TALLOC_CTX *mem_ctx,
                                               struct kcm_ctx *kctx)
{
    errno_t ret;
    struct kcm_ops_queue_ctx *queue_ctx;

    queue_ctx = talloc_zero(mem_ctx, struct kcm_ops_queue_ctx);
    if (queue_ctx == NULL) {
        return NULL;
    }

    ret = sss_hash_create_ex(mem_ctx, 0,
                             &queue_ctx->wait_queue_hash, 0, 0, 0, 0,
                             NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_hash_create failed [%d]: %s\n", ret, sss_strerror(ret));
        talloc_free(queue_ctx);
        return NULL;
    }

    queue_ctx->kctx = kctx;

    return queue_ctx;
}

void queue_removal_cb(struct tevent_context *ctx,
                      struct tevent_immediate *imm,
                      void *private_data)
{
    struct kcm_ops_queue *kq = talloc_get_type(private_data,
                                               struct kcm_ops_queue);
    int ret;
    hash_key_t key;

    talloc_free(imm);

    if (kq->head != NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "The queue is no longer empty\n");
        return;
    }

    key.type = HASH_KEY_ULONG;
    key.ul = kq->uid;

    /* If this was the last entry, remove the key (the UID) from the
     * hash table to signal the queue is empty
     */
    ret = hash_delete(kq->qctx->wait_queue_hash, &key);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to remove wait queue for user %"SPRIuid"\n",
              kq->uid);
        return;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Removed queue for %"SPRIuid" \n", kq->uid);
    talloc_free(kq);
}

static int kcm_op_queue_entry_destructor(struct kcm_ops_queue_entry *entry)
{
    struct kcm_ops_queue_entry *next_entry;
    struct tevent_immediate *imm;

    if (entry == NULL) {
        return 1;
    /* Prevent use-after-free of req when shutting down with non-empty queue */
    } else if (entry->queue->qctx->kctx->rctx->shutting_down) {
        return 0;
    }

    /* Take the next entry from the queue */
    next_entry = entry->next;

    /* Remove the current entry from the queue */
    DLIST_REMOVE(entry->queue->head, entry);

    if (next_entry == NULL) {
        /* If there was no other entry, schedule removal of the queue. Do it
         * in another tevent tick to avoid issues with callbacks invoking
         * the destructor while another request is touching the queue
         */
        imm = tevent_create_immediate(entry->queue);
        if (imm == NULL) {
            return 1;
        }

        tevent_schedule_immediate(imm, entry->queue->ev, queue_removal_cb, entry->queue);
        return 0;
    }

    /* Otherwise, mark the current head as done to run the next request */
    tevent_req_done(next_entry->req);
    return 0;
}

static struct kcm_ops_queue *kcm_op_queue_get(struct kcm_ops_queue_ctx *qctx,
                                              struct tevent_context *ev,
                                              uid_t uid)
{
    errno_t ret;
    hash_key_t key;
    hash_value_t value;
    struct kcm_ops_queue *kq;

    key.type = HASH_KEY_ULONG;
    key.ul = uid;

    ret = hash_lookup(qctx->wait_queue_hash, &key, &value);
    switch (ret) {
    case HASH_SUCCESS:
        if (value.type != HASH_VALUE_PTR) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected hash value type.\n");
            return NULL;
        }

        kq = talloc_get_type(value.ptr, struct kcm_ops_queue);
        if (kq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid queue pointer\n");
            return NULL;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Found existing queue for this ID\n");
        break;

    case HASH_ERROR_KEY_NOT_FOUND:
        /* No request for this UID yet. Enqueue this request in case
         * another one comes in and return EOK to run the current request
         * immediately
         */
        DEBUG(SSSDBG_TRACE_LIBS, "No existing queue for this ID\n");

        kq = talloc_zero(qctx->wait_queue_hash, struct kcm_ops_queue);
        if (kq == NULL) {
            return NULL;
        }
        kq->uid = uid;
        kq->qctx = qctx;
        kq->ev = ev;

        value.type = HASH_VALUE_PTR;
        value.ptr = kq;

        ret = hash_enter(qctx->wait_queue_hash, &key, &value);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "hash_enter failed.\n");
            return NULL;
        }
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "hash_lookup failed.\n");
        return NULL;
    }

    return kq;
}

struct kcm_op_queue_state {
    struct kcm_ops_queue_entry *entry;
};

static errno_t kcm_op_queue_add_req(struct kcm_ops_queue *kq,
                                    struct tevent_req *req);

/*
 * Enqueue a request.
 *
 * If the request queue /for the given ID/ is empty, that is, if this
 * request is the first one in the queue, run the request immediately.
 *
 * Otherwise just add it to the queue and wait until the previous request
 * finishes and only at that point mark the current request as done, which
 * will trigger calling the recv function and allow the request to continue.
 */
struct tevent_req *kcm_op_queue_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct kcm_ops_queue_ctx *qctx,
                                     struct cli_creds *client)
{
    errno_t ret;
    struct tevent_req *req;
    struct kcm_ops_queue *kq;
    struct kcm_op_queue_state *state;
    uid_t uid;

    uid = cli_creds_get_uid(client);

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_queue_state);
    if (req == NULL) {
        return NULL;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Adding request by %"SPRIuid" to the wait queue\n", uid);

    kq = kcm_op_queue_get(qctx, ev, uid);
    if (kq == NULL) {
        ret = EIO;
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get queue [%d]: %s\n", ret, sss_strerror(ret));
        goto immediate;
    }

    ret = kcm_op_queue_add_req(kq, req);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Queue was empty, running the request immediately\n");
        goto immediate;
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot enqueue request [%d]: %s\n", ret, sss_strerror(ret));
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Waiting our turn in the queue\n");
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t kcm_op_queue_add_req(struct kcm_ops_queue *kq,
                                    struct tevent_req *req)
{
    errno_t ret;
    struct kcm_op_queue_state *state = tevent_req_data(req,
                                                struct kcm_op_queue_state);

    state->entry = talloc_zero(kq->qctx->wait_queue_hash, struct kcm_ops_queue_entry);
    if (state->entry == NULL) {
        return ENOMEM;
    }
    state->entry->req = req;
    state->entry->queue = kq;
    talloc_set_destructor(state->entry, kcm_op_queue_entry_destructor);

    if (kq->head == NULL) {
        /* First entry, will run callback at once */
        ret = EOK;
    } else {
        /* Will wait for the previous callbacks to finish */
        ret = EAGAIN;
    }

    DLIST_ADD_END(kq->head, state->entry, struct kcm_ops_queue_entry *);
    return ret;
}

/*
 * The queue recv function is called when this request is 'activated'. The queue
 * entry should be allocated on the same memory context as the enqueued request
 * to trigger freeing the kcm_ops_queue_entry structure destructor when the
 * parent request is done and its tevent_req freed. This would in turn unblock
 * the next request in the queue
 */
errno_t kcm_op_queue_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          struct kcm_ops_queue_entry **_entry)
{
    struct kcm_op_queue_state *state = tevent_req_data(req,
                                                struct kcm_op_queue_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_entry = talloc_steal(mem_ctx, state->entry);
    return EOK;
}
