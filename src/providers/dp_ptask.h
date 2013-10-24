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

#ifndef _DP_PTASK_H_
#define _DP_PTASK_H_

#include <tevent.h>
#include <talloc.h>
#include <time.h>

/* solve circular dependency */
struct be_ctx;

struct be_ptask;

/**
 * Defines how should task behave when back end is offline.
 */
enum be_ptask_offline {
    /* current request will be skipped and rescheduled to 'now + period' */
    BE_PTASK_OFFLINE_SKIP,

    /* An offline and online callback is registered. The task is disabled
     * immediately when back end goes offline and then enabled again
     * when back end goes back online */
    BE_PTASK_OFFLINE_DISABLE,

    /* current request will be executed as planned */
    BE_PTASK_OFFLINE_EXECUTE
};

typedef struct tevent_req *
(*be_ptask_send_t)(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct be_ctx *be_ctx,
                   struct be_ptask *be_ptask,
                   void *pvt);

/**
 * If EOK, task will be scheduled again to 'last_execution_time + period'.
 * If other error code, task will be rescheduled to 'now + period'.
 */
typedef errno_t
(*be_ptask_recv_t)(struct tevent_req *req);

/**
 * If EOK, task will be scheduled again to 'last_execution_time + period'.
 * If other error code, task will be rescheduled to 'now + period'.
 */
typedef errno_t
(*be_ptask_sync_t)(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct be_ctx *be_ctx,
                   struct be_ptask *be_ptask,
                   void *pvt);

/**
 * The first execution is scheduled first_delay seconds after the task is
 * created.
 *
 * If request does not complete in timeout seconds, it will be
 * cancelled and rescheduled to 'now + period'.
 *
 * If the task is reenabled, it will be scheduled again to
 * 'now + enabled_delay'.
 *
 * If an internal error occurred, the task is automatically disabled.
 */
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
                        struct be_ptask **_task);

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
                             struct be_ptask **_task);

void be_ptask_enable(struct be_ptask *task);
void be_ptask_disable(struct be_ptask *task);
void be_ptask_destroy(struct be_ptask **task);

time_t be_ptask_get_period(struct be_ptask *task);

#endif /* _DP_PTASK_H_ */
