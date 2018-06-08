/*
    SSSD

    Data Provider Process - Callback

    Authors:

        Stephen Gallagher <sgallagh@redhat.com>
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

#include "util/util.h"
#include "providers/backend.h"

struct be_cb {
    struct be_cb *prev;
    struct be_cb *next;

    be_callback_t cb;
    void *pvt;

    struct be_cb **list;
    struct be_ctx *be;
};

struct be_cb_ctx {
    struct be_ctx *be;
    struct be_cb *callback;
};

static int cb_destructor(TALLOC_CTX *ptr)
{
    struct be_cb *cb = talloc_get_type(ptr, struct be_cb);
    DLIST_REMOVE(*(cb->list), cb);
    return 0;
}

static int be_add_cb(TALLOC_CTX *mem_ctx, struct be_ctx *ctx,
                     be_callback_t cb, void *pvt, struct be_cb **cb_list,
                     struct be_cb **return_cb)
{
    struct be_cb *new_cb;

    if (!ctx || !cb) {
        return EINVAL;
    }

    new_cb = talloc(mem_ctx, struct be_cb);
    if (!new_cb) {
        return ENOMEM;
    }

    new_cb->cb = cb;
    new_cb->pvt = pvt;
    new_cb->list = cb_list;
    new_cb->be = ctx;

    DLIST_ADD(*cb_list, new_cb);

    talloc_set_destructor((TALLOC_CTX *) new_cb, cb_destructor);

    if (return_cb) {
        *return_cb = new_cb;
    }

    return EOK;
}

static void be_run_cb_step(struct tevent_context *ev, struct tevent_timer *te,
                           struct timeval current_time, void *pvt)
{
    struct be_cb_ctx *cb_ctx = talloc_get_type(pvt, struct be_cb_ctx);
    struct be_cb *next_cb;
    struct tevent_timer *tev;
    struct timeval soon;

    /* Store next callback in case this callback frees itself */
    next_cb = cb_ctx->callback->next;

    /* Call the callback */
    cb_ctx->callback->cb(cb_ctx->callback->pvt);

    if (next_cb) {
        cb_ctx->callback = next_cb;

        /* Delay 30ms so we don't block any other events */
        soon = tevent_timeval_current_ofs(0, 30000);
        tev = tevent_add_timer(cb_ctx->be->ev, cb_ctx, soon,
                               be_run_cb_step,
                               cb_ctx);
        if (!tev) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Out of memory. Could not invoke callbacks\n");
            goto final;
        }
        return;
    }

final:
    /* Steal the timer event onto the be_ctx so it doesn't
     * get freed with the cb_ctx
     */
    talloc_steal(cb_ctx->be, te);
    talloc_free(cb_ctx);
}

static errno_t be_run_cb(struct be_ctx *be, struct be_cb *cb_list)
{
    struct timeval soon;
    struct tevent_timer *te;
    struct be_cb_ctx *cb_ctx;

    if (cb_list == NULL) {
        return EOK;
    }

    cb_ctx = talloc(be, struct be_cb_ctx);
    if (!cb_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Out of memory. Could not invoke callbacks\n");
        return ENOMEM;
    }
    cb_ctx->be = be;
    cb_ctx->callback = cb_list;

    /* Delay 30ms so we don't block any other events */
    soon = tevent_timeval_current_ofs(0, 30000);
    te = tevent_add_timer(be->ev, cb_ctx, soon,
                          be_run_cb_step,
                          cb_ctx);
    if (!te) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Out of memory. Could not invoke callbacks\n");
        talloc_free(cb_ctx);
        return ENOMEM;
    }

    return EOK;
}

int be_add_reconnect_cb(TALLOC_CTX *mem_ctx, struct be_ctx *ctx, be_callback_t cb,
                        void *pvt, struct be_cb **reconnect_cb)
{
    int ret;

    ret = be_add_cb(mem_ctx, ctx, cb, pvt, &ctx->reconnect_cb_list, reconnect_cb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_add_cb failed.\n");
        return ret;
    }

    return EOK;
}

void be_run_reconnect_cb(struct be_ctx *be)
{
    struct be_cb *callback = be->reconnect_cb_list;
    struct be_cb *next_cb;

    if (callback) {
        DEBUG(SSSDBG_TRACE_FUNC, "Reconnecting. Running callbacks.\n");

        /**
         * Call the callback: we have to call this right away
         * so the provider doesn't go into offline even for
         * a little while
         */
        do {
            /* Store next callback in case this callback frees itself */
            next_cb = callback->next;

            callback->cb(callback->pvt);
            callback = next_cb;
        } while(callback != NULL);
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Reconnect call back list is empty, nothing to do.\n");
    }
}

int be_add_online_cb(TALLOC_CTX *mem_ctx, struct be_ctx *ctx, be_callback_t cb,
                     void *pvt, struct be_cb **online_cb)
{
    int ret;

    ret = be_add_cb(mem_ctx, ctx, cb, pvt, &ctx->online_cb_list, online_cb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_add_cb failed.\n");
        return ret;
    }

    /* Make sure we run the callback for the first
     * connection after startup.
     */
    ctx->run_online_cb = true;

    return EOK;
}

void be_run_online_cb(struct be_ctx *be) {
    int ret;

    if (be->run_online_cb) {
        /* Reset the flag. We only want to run these
         * callbacks when transitioning to online
         */
        be->run_online_cb = false;

        if (be->online_cb_list) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Going online. Running callbacks.\n");

            ret = be_run_cb(be, be->online_cb_list);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "be_run_cb failed.\n");
            }

        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Online call back list is empty, nothing to do.\n");
        }
    }
}

int be_add_unconditional_online_cb(TALLOC_CTX *mem_ctx, struct be_ctx *ctx,
                                   be_callback_t cb, void *pvt,
                                   struct be_cb **unconditional_online_cb)
{
    return be_add_cb(mem_ctx, ctx, cb, pvt, &ctx->unconditional_online_cb_list,
                     unconditional_online_cb);
}

void be_run_unconditional_online_cb(struct be_ctx *be)
{
    int ret;

    if (be->unconditional_online_cb_list) {
        DEBUG(SSSDBG_TRACE_FUNC, "Running unconditional online callbacks.\n");

        ret = be_run_cb(be, be->unconditional_online_cb_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "be_run_cb failed.\n");
        }

    } else {
        DEBUG(SSSDBG_TRACE_ALL,
              "List of unconditional online callbacks is empty, " \
               "nothing to do.\n");
    }
}

int be_add_offline_cb(TALLOC_CTX *mem_ctx, struct be_ctx *ctx, be_callback_t cb,
                      void *pvt, struct be_cb **offline_cb)
{
    int ret;

    ret = be_add_cb(mem_ctx, ctx, cb, pvt, &ctx->offline_cb_list, offline_cb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_add_cb failed.\n");
        return ret;
    }

    /* Make sure we run the callback when SSSD goes offline */
    ctx->run_offline_cb = true;

    return EOK;
}

void be_run_offline_cb(struct be_ctx *be) {
    int ret;

    if (be->run_offline_cb) {
        /* Reset the flag, we only want to run these callbacks once when going
         * offline */
        be->run_offline_cb = false;

        if (be->offline_cb_list) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Going offline. Running callbacks.\n");

            ret = be_run_cb(be, be->offline_cb_list);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "be_run_cb failed.\n");
            }

        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Offline call back list is empty, nothing to do.\n");
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL,
              "Flag indicates that offline callback were already called.\n");
    }
}
