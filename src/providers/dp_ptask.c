/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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
#include <talloc.h>
#include <time.h>
#include <string.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "providers/dp_ptask.h"

enum be_ptask_schedule {
    BE_PTASK_SCHEDULE_FROM_NOW,
    BE_PTASK_SCHEDULE_FROM_LAST
};

struct be_ptask {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    time_t period;
    time_t enabled_delay;
    time_t timeout;
    enum be_ptask_offline offline;
    be_ptask_send_t send_fn;
    be_ptask_recv_t recv_fn;
    void *pvt;
    const char *name;

    time_t last_execution;  /* last time when send was called */
    struct tevent_req *req; /* active tevent request */
    struct tevent_timer *timer; /* active tevent timer */
    bool enabled;
};

static void be_ptask_schedule(struct be_ptask *task,
                              time_t delay,
                              enum be_ptask_schedule from);

static int be_ptask_destructor(void *pvt)
{
    struct be_ptask *task;

    task = talloc_get_type(pvt, struct be_ptask);
    if (task == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "BUG: task is NULL\n");
        return 0;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Terminating periodic task [%s]\n", task->name);

    return 0;
}

static void be_ptask_online_cb(void *pvt)
{
    struct be_ptask *task = NULL;

    task = talloc_get_type(pvt, struct be_ptask);
    if (task == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "BUG: task is NULL\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Back end is online\n");
    be_ptask_enable(task);
}

static void be_ptask_offline_cb(void *pvt)
{
    struct be_ptask *task = NULL;
    task = talloc_get_type(pvt, struct be_ptask);

    DEBUG(SSSDBG_TRACE_FUNC, "Back end is offline\n");
    be_ptask_disable(task);
}

static void be_ptask_timeout(struct tevent_context *ev,
                             struct tevent_timer *tt,
                             struct timeval tv,
                             void *pvt)
{
    struct be_ptask *task = NULL;
    task = talloc_get_type(pvt, struct be_ptask);

    DEBUG(SSSDBG_OP_FAILURE, "Task [%s]: timed out\n", task->name);

    talloc_zfree(task->req);
    be_ptask_schedule(task, task->period, BE_PTASK_SCHEDULE_FROM_NOW);
}

static void be_ptask_done(struct tevent_req *req);

static void be_ptask_execute(struct tevent_context *ev,
                             struct tevent_timer *tt,
                             struct timeval tv,
                             void *pvt)
{
    struct be_ptask *task = NULL;
    struct tevent_timer *timeout = NULL;

    task = talloc_get_type(pvt, struct be_ptask);
    task->timer = NULL; /* timer is freed by tevent */

    if (be_is_offline(task->be_ctx)) {
        DEBUG(SSSDBG_TRACE_FUNC, "Back end is offline\n");
        switch (task->offline) {
        case BE_PTASK_OFFLINE_SKIP:
            be_ptask_schedule(task, task->period, BE_PTASK_SCHEDULE_FROM_NOW);
            return;
        case BE_PTASK_OFFLINE_DISABLE:
            /* This case is handled by offline callback. */
            return;
        case BE_PTASK_OFFLINE_EXECUTE:
            /* continue */
            break;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Task [%s]: executing task, timeout %lu "
                              "seconds\n", task->name, task->timeout);

    task->last_execution = time(NULL);

    task->req = task->send_fn(task, task->ev, task->be_ctx, task, task->pvt);
    if (task->req == NULL) {
        /* skip this iteration and try again later */
        DEBUG(SSSDBG_OP_FAILURE, "Task [%s]: failed to execute task, "
              "will try again later\n", task->name);

        be_ptask_schedule(task, task->period, BE_PTASK_SCHEDULE_FROM_NOW);
        return;
    }

    tevent_req_set_callback(task->req, be_ptask_done, task);

    /* schedule timeout */
    if (task->timeout > 0) {
        tv = tevent_timeval_current_ofs(task->timeout, 0);
        timeout = tevent_add_timer(task->ev, task->req, tv,
                                   be_ptask_timeout, task);
        if (timeout == NULL) {
            /* If we can't guarantee a timeout,
             * we need to cancel the request. */
            talloc_zfree(task->req);

            DEBUG(SSSDBG_OP_FAILURE, "Task [%s]: failed to set timeout, "
                  "the task will be rescheduled\n", task->name);

            be_ptask_schedule(task, task->period, BE_PTASK_SCHEDULE_FROM_NOW);
        }
    }

    return;
}

static void be_ptask_done(struct tevent_req *req)
{
    struct be_ptask *task = NULL;
    errno_t ret;

    task = tevent_req_callback_data(req, struct be_ptask);

    ret = task->recv_fn(req);
    talloc_zfree(req);
    task->req = NULL;
    switch (ret) {
    case EOK:
        DEBUG(SSSDBG_TRACE_FUNC, "Task [%s]: finished successfully\n",
                                  task->name);

        be_ptask_schedule(task, task->period, BE_PTASK_SCHEDULE_FROM_LAST);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Task [%s]: failed with [%d]: %s\n",
                                  task->name, ret, sss_strerror(ret));

        be_ptask_schedule(task, task->period, BE_PTASK_SCHEDULE_FROM_NOW);
        break;
    }
}

static void be_ptask_schedule(struct be_ptask *task,
                              time_t delay,
                              enum be_ptask_schedule from)
{
    struct timeval tv;

    if (!task->enabled) {
        DEBUG(SSSDBG_TRACE_FUNC, "Task [%s]: disabled\n", task->name);
        return;
    }

    switch (from) {
    case BE_PTASK_SCHEDULE_FROM_NOW:
        tv = tevent_timeval_current_ofs(delay, 0);

        DEBUG(SSSDBG_TRACE_FUNC, "Task [%s]: scheduling task %lu seconds "
              "from now [%lu]\n", task->name, delay, tv.tv_sec);
        break;
    case BE_PTASK_SCHEDULE_FROM_LAST:
        tv = tevent_timeval_set(task->last_execution + delay, 0);

        DEBUG(SSSDBG_TRACE_FUNC, "Task [%s]: scheduling task %lu seconds "
                                  "from last execution time [%lu]\n",
                                  task->name, delay, tv.tv_sec);
        break;
    }

    if (task->timer != NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Task [%s]: another timer is already "
                                     "active?\n", task->name);
        talloc_zfree(task->timer);
    }

    task->timer = tevent_add_timer(task->ev, task, tv, be_ptask_execute, task);
    if (task->timer == NULL) {
        /* nothing we can do about it */
        DEBUG(SSSDBG_CRIT_FAILURE, "FATAL: Unable to schedule task [%s]\n",
                                    task->name);
        be_ptask_disable(task);
    }
}

errno_t be_ptask_create(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        time_t period,
                        time_t first_delay,
                        time_t enabled_delay,
                        time_t timeout,
                        enum be_ptask_offline offline,
                        be_ptask_send_t send_fn,
                        be_ptask_recv_t recv_fn,
                        void *pvt,
                        const char *name,
                        struct be_ptask **_task)
{
    struct be_ptask *task = NULL;
    errno_t ret;

    if (be_ctx == NULL || period == 0 || send_fn == NULL || recv_fn == NULL
        || name == NULL) {
        return EINVAL;
    }

    task = talloc_zero(mem_ctx, struct be_ptask);
    if (task == NULL) {
        ret = ENOMEM;
        goto done;
    }

    task->ev = be_ctx->ev;
    task->be_ctx = be_ctx;
    task->period = period;
    task->enabled_delay = enabled_delay;
    task->timeout = timeout;
    task->offline = offline;
    task->send_fn = send_fn;
    task->recv_fn = recv_fn;
    task->pvt = pvt;
    task->name = talloc_strdup(task, name);
    if (task->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    task->enabled = true;

    talloc_set_destructor((TALLOC_CTX*)task, be_ptask_destructor);

    if (offline == BE_PTASK_OFFLINE_DISABLE) {
        /* install offline and online callbacks */
        ret = be_add_online_cb(task, be_ctx, be_ptask_online_cb, task, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to install online callback "
                                      "[%d]: %s", ret, sss_strerror(ret));
            goto done;
        }

        ret = be_add_offline_cb(task, be_ctx, be_ptask_offline_cb, task, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to install offline callback "
                                      "[%d]: %s", ret, sss_strerror(ret));
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Periodic task [%s] was created\n", task->name);

    be_ptask_schedule(task, first_delay, BE_PTASK_SCHEDULE_FROM_NOW);

    if (_task != NULL) {
        *_task = task;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(task);
    }

    return ret;
}

void be_ptask_enable(struct be_ptask *task)
{
    if (task->enabled) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Task [%s]: already enabled\n",
                                     task->name);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Task [%s]: enabling task\n", task->name);

    task->enabled = true;
    be_ptask_schedule(task, task->enabled_delay, BE_PTASK_SCHEDULE_FROM_NOW);
}

/* Disable the task, but if a request already in progress, let it finish. */
void be_ptask_disable(struct be_ptask *task)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Task [%s]: disabling task\n", task->name);

    talloc_zfree(task->timer);
    task->enabled = false;
}

void be_ptask_destroy(struct be_ptask **task)
{
    talloc_zfree(*task);
}

time_t be_ptask_get_period(struct be_ptask *task)
{
    return task->period;
}

struct be_ptask_sync_ctx {
    be_ptask_sync_t fn;
    void *pvt;
};

struct be_ptask_sync_state {
    int dummy;
};

/* This is not an asynchronous request so there is not any _done function. */
static struct tevent_req *
be_ptask_sync_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct be_ctx *be_ctx,
                   struct be_ptask *be_ptask,
                   void *pvt)
{
    struct be_ptask_sync_ctx *ctx = NULL;
    struct be_ptask_sync_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct be_ptask_sync_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    ctx = talloc_get_type(pvt, struct be_ptask_sync_ctx);
    ret = ctx->fn(mem_ctx, ev, be_ctx, be_ptask, ctx->pvt);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t be_ptask_sync_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t be_ptask_create_sync(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             time_t period,
                             time_t first_delay,
                             time_t enabled_delay,
                             time_t timeout,
                             enum be_ptask_offline offline,
                             be_ptask_sync_t fn,
                             void *pvt,
                             const char *name,
                             struct be_ptask **_task)
{
    errno_t ret;
    struct be_ptask_sync_ctx *ctx = NULL;

    ctx = talloc_zero(mem_ctx, struct be_ptask_sync_ctx);
    if (ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ctx->fn = fn;
    ctx->pvt = pvt;

    ret = be_ptask_create(mem_ctx, be_ctx, period, first_delay,
                          enabled_delay, timeout, offline,
                          be_ptask_sync_send, be_ptask_sync_recv,
                          ctx, name, _task);
    if (ret != EOK) {
        goto done;
    }

    if (_task != NULL) {
        talloc_steal(*_task, ctx);
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }

    return ret;
}
