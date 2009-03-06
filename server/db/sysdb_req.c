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

struct sysdb_req {
    struct sysdb_req *next, *prev;
    struct sysdb_ctx *ctx;
    sysdb_req_fn_t fn;
    void *pvt;
    int status;
    bool transaction_active;
};

bool sysdb_req_check_running(struct sysdb_req *req)
{
    if (req->ctx->queue == req) return true;
    return false;
}

struct sysdb_ctx *sysdb_req_get_ctx(struct sysdb_req *req)
{
    return req->ctx;
}

static void sysdb_req_run(struct tevent_context *ev,
                          struct tevent_timer *te,
                          struct timeval tv, void *ptr)
{
    struct sysdb_req *req = talloc_get_type(ptr, struct sysdb_req);

    if (req != req->ctx->queue) abort();

    req->fn(req, req->pvt);
}

static int sysdb_req_schedule(struct sysdb_req *req)
{
    struct tevent_timer *te = NULL;
    struct timeval tv;

    /* call it asap */
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    te = tevent_add_timer(req->ctx->ev, req, tv, sysdb_req_run, req);
    if (te == NULL) {
        return EIO;
    }

    return EOK;
}

static int sysdb_req_enqueue(struct sysdb_req *req)
{
    int ret = EOK;

    DLIST_ADD_END(req->ctx->queue, req, struct sysdb_req *);

    if (req->ctx->queue == req) {
        ret = sysdb_req_schedule(req);
    }

    return ret;
}

static void sysdb_transaction_end(struct sysdb_req *req);

static int sysdb_req_destructor(void *ptr)
{
    struct sysdb_req *req;
    int ret;

    req = talloc_get_type(ptr, struct sysdb_req);

    if (req->ctx->queue != req) {
        DLIST_REMOVE(req->ctx->queue, req);
        return 0;
    }

    /* req is the currently running operation or
     * scheduled to run operation */

    if (req->transaction_active) {
        /* freeing before the transaction is complete */
        req->status = ETIMEDOUT;
        sysdb_transaction_end(req);
    }

    DLIST_REMOVE(req->ctx->queue, req);

    /* make sure we schedule the next in line if any */
    if (req->ctx->queue) {
        ret = sysdb_req_schedule(req->ctx->queue);
        if (ret != EOK) abort();
    }

    return 0;
}

static struct sysdb_req *sysdb_new_req(TALLOC_CTX *memctx,
                                       struct sysdb_ctx *ctx,
                                       sysdb_req_fn_t fn, void *pvt)
{
    struct sysdb_req *req;

    req = talloc_zero(memctx, struct sysdb_req);
    if (!req) return NULL;

    req->ctx = ctx;
    req->fn = fn;
    req->pvt = pvt;

    talloc_set_destructor((TALLOC_CTX *)req, sysdb_req_destructor);

    return req;
}

static void sysdb_transaction_int(struct sysdb_req *intreq, void *pvt)
{
    struct sysdb_req *req = talloc_get_type(pvt, struct sysdb_req);
    int ret;

    /* first of all swap this internal request with the real one on the queue
     * otherwise request_done() will later abort */
    DLIST_REMOVE(req->ctx->queue, intreq);
    DLIST_ADD(req->ctx->queue, req);

    if (intreq->status != EOK) {
        req->status = intreq->status;
        req->fn(req, req->pvt);
        return;
    }

    ret = ldb_transaction_start(req->ctx->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
        req->status = sysdb_error_to_errno(ret);
    }
    req->transaction_active = true;

    req->fn(req, req->pvt);
}

static void sysdb_transaction_end(struct sysdb_req *req)
{
    int ret;

    if (req->status == EOK) {
        ret = ldb_transaction_commit(req->ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
        }
    } else {
        DEBUG(4, ("Canceling transaction (%d[%s])\n",
                  req->status, strerror(req->status)));
        ret = ldb_transaction_cancel(req->ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
            /* FIXME: abort() ? */
        }
    }
    req->transaction_active = false;
}

int sysdb_transaction(TALLOC_CTX *memctx, struct sysdb_ctx *ctx,
                      sysdb_req_fn_t fn, void *pvt)
{
    struct sysdb_req *req, *intreq;

    req = sysdb_new_req(memctx, ctx, fn, pvt);
    if (!req) return ENOMEM;

    intreq = sysdb_new_req(req, ctx, sysdb_transaction_int, req);
    if (!intreq) {
        talloc_free(intreq);
        return ENOMEM;
    }

    return sysdb_req_enqueue(intreq);
}

void sysdb_transaction_done(struct sysdb_req *req, int status)
{
    int ret;

    if (req->ctx->queue != req) abort();
    if (!req->transaction_active) abort();

    req->status = status;

    sysdb_transaction_end(req);

    DLIST_REMOVE(req->ctx->queue, req);

    if (req->ctx->queue) {
        ret = sysdb_req_schedule(req->ctx->queue);
        if (ret != EOK) abort();
    }

    talloc_free(req);
}

int sysdb_operation(TALLOC_CTX *memctx, struct sysdb_ctx *ctx,
                    sysdb_req_fn_t fn, void *pvt)
{
    struct sysdb_req *req;

    req = sysdb_new_req(memctx, ctx, fn, pvt);
    if (!req) return ENOMEM;

    return sysdb_req_enqueue(req);
}

void sysdb_operation_done(struct sysdb_req *req)
{
    int ret;

    if (req->ctx->queue != req) abort();

    DLIST_REMOVE(req->ctx->queue, req);

    if (req->ctx->queue) {
        ret = sysdb_req_schedule(req->ctx->queue);
        if (ret != EOK) abort();
    }

    talloc_free(req);
}

