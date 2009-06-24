/*
   SSSD

   System Database

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2009

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

#include <time.h>
#include "util/util.h"
#include "util/dlinklist.h"
#include "db/sysdb_private.h"
#include "ldb.h"

struct sysdb_handle {
    struct sysdb_handle *next, *prev;
    struct sysdb_ctx *ctx;
    sysdb_fn_t fn;
    void *pvt;
    int status;
    bool transaction_active;
};

bool sysdb_handle_check_running(struct sysdb_handle *handle)
{
    if (handle->ctx->queue == handle) return true;
    return false;
}

struct sysdb_ctx *sysdb_handle_get_ctx(struct sysdb_handle *handle)
{
    return handle->ctx;
}

static void sysdb_queue_run(struct tevent_context *ev,
                          struct tevent_timer *te,
                          struct timeval tv, void *ptr)
{
    struct sysdb_handle *handle = talloc_get_type(ptr, struct sysdb_handle);

    if (handle != handle->ctx->queue) abort();

    handle->fn(handle, handle->pvt);
}

static int sysdb_queue_schedule(struct sysdb_handle *handle)
{
    struct tevent_timer *te = NULL;
    struct timeval tv;

    /* call it asap */
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    te = tevent_add_timer(handle->ctx->ev, handle, tv, sysdb_queue_run, handle);
    if (te == NULL) {
        return EIO;
    }

    return EOK;
}

static int sysdb_enqueue(struct sysdb_handle *handle)
{
    int ret = EOK;

    DLIST_ADD_END(handle->ctx->queue, handle, struct sysdb_handle *);

    if (handle->ctx->queue == handle) {
        ret = sysdb_queue_schedule(handle);
    }

    return ret;
}

static void sysdb_transaction_end(struct sysdb_handle *handle);

static int sysdb_handle_destructor(void *ptr)
{
    struct sysdb_handle *handle;
    int ret;

    handle = talloc_get_type(ptr, struct sysdb_handle);

    if (handle->ctx->queue != handle) {
        DLIST_REMOVE(handle->ctx->queue, handle);
        return 0;
    }

    /* handle is the currently running operation or
     * scheduled to run operation */

    if (handle->transaction_active) {
        /* freeing before the transaction is complete */
        handle->status = ETIMEDOUT;
        sysdb_transaction_end(handle);
    }

    DLIST_REMOVE(handle->ctx->queue, handle);

    /* make sure we schedule the next in line if any */
    if (handle->ctx->queue) {
        ret = sysdb_queue_schedule(handle->ctx->queue);
        if (ret != EOK) abort();
    }

    return 0;
}

static struct sysdb_handle *sysdb_new_req(TALLOC_CTX *memctx,
                                       struct sysdb_ctx *ctx,
                                       sysdb_fn_t fn, void *pvt)
{
    struct sysdb_handle *handle;

    handle = talloc_zero(memctx, struct sysdb_handle);
    if (!handle) return NULL;

    handle->ctx = ctx;
    handle->fn = fn;
    handle->pvt = pvt;

    talloc_set_destructor((TALLOC_CTX *)handle, sysdb_handle_destructor);

    return handle;
}

static void sysdb_transaction_int(struct sysdb_handle *ihandle, void *pvt)
{
    struct sysdb_handle *handle = talloc_get_type(pvt, struct sysdb_handle);
    int ret;

    /* first of all swap this internal handle with the real one on the queue
     * otherwise request_done() will later abort */
    DLIST_REMOVE(handle->ctx->queue, ihandle);
    DLIST_ADD(handle->ctx->queue, handle);

    if (ihandle->status != EOK) {
        handle->status = ihandle->status;
        handle->fn(handle, handle->pvt);
        return;
    }

    ret = ldb_transaction_start(handle->ctx->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
        handle->status = sysdb_error_to_errno(ret);
    }
    handle->transaction_active = true;

    handle->fn(handle, handle->pvt);
}

static void sysdb_transaction_end(struct sysdb_handle *handle)
{
    int ret;

    if (handle->status == EOK) {
        ret = ldb_transaction_commit(handle->ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
        }
    } else {
        DEBUG(4, ("Canceling transaction (%d[%s])\n",
                  handle->status, strerror(handle->status)));
        ret = ldb_transaction_cancel(handle->ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
            /* FIXME: abort() ? */
        }
    }
    handle->transaction_active = false;
}

int sysdb_transaction(TALLOC_CTX *memctx, struct sysdb_ctx *ctx,
                      sysdb_fn_t fn, void *pvt)
{
    struct sysdb_handle *handle, *ihandle;

    handle = sysdb_new_req(memctx, ctx, fn, pvt);
    if (!handle) return ENOMEM;

    ihandle = sysdb_new_req(handle, ctx, sysdb_transaction_int, handle);
    if (!ihandle) {
        talloc_free(ihandle);
        return ENOMEM;
    }

    return sysdb_enqueue(ihandle);
}

void sysdb_transaction_done(struct sysdb_handle *handle, int status)
{
    int ret;

    if (handle->ctx->queue != handle) abort();
    if (!handle->transaction_active) abort();

    handle->status = status;

    sysdb_transaction_end(handle);

    DLIST_REMOVE(handle->ctx->queue, handle);

    if (handle->ctx->queue) {
        ret = sysdb_queue_schedule(handle->ctx->queue);
        if (ret != EOK) abort();
    }

    talloc_free(handle);
}

int sysdb_operation(TALLOC_CTX *memctx, struct sysdb_ctx *ctx,
                    sysdb_fn_t fn, void *pvt)
{
    struct sysdb_handle *handle;

    handle = sysdb_new_req(memctx, ctx, fn, pvt);
    if (!handle) return ENOMEM;

    return sysdb_enqueue(handle);
}

void sysdb_operation_done(struct sysdb_handle *handle)
{
    int ret;

    if (handle->ctx->queue != handle) abort();

    DLIST_REMOVE(handle->ctx->queue, handle);

    if (handle->ctx->queue) {
        ret = sysdb_queue_schedule(handle->ctx->queue);
        if (ret != EOK) abort();
    }

    talloc_free(handle);
}

