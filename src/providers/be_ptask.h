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

/* be_ptask flags */

/**
 * Do not schedule periodic task. This flag is useful for tasks that
 * should be performed only when there is offline/online change.
 */
#define BE_PTASK_NO_PERIODIC         0x0001

/**
 * Flags defining the starting point for scheduling a task
 */
/* Schedule starting from now, typically this is used when scheduling
 * relative to the finish time */
#define BE_PTASK_SCHEDULE_FROM_NOW   0x0002
/* Schedule relative to the start time of the task */
#define BE_PTASK_SCHEDULE_FROM_LAST  0x0004

/**
 * Flags defining how should task behave when back end is offline.
 */
/* current request will be skipped and rescheduled to 'now + period' */
#define BE_PTASK_OFFLINE_SKIP        0x0008
/* An offline and online callback is registered. The task is disabled */
#define BE_PTASK_OFFLINE_DISABLE     0x0010
/* current request will be executed as planned */
#define BE_PTASK_OFFLINE_EXECUTE     0x0020

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
 * Subsequent runs will be scheduled depending on the value of the
 * success_schedule_type parameter:
 *  - BE_PTASK_SCHEDULE_FROM_NOW: period seconds from the finish time
 *  - BE_PTASK_SCHEDULE_FROM_LAST: period seconds from the last start time
 *
 * If the test fails, another run is always scheduled period seconds
 * from the finish time.
 *
 * If request does not complete in timeout seconds, it will be
 * cancelled and rescheduled to 'now + period'.
 *
 * If the task is reenabled, it will be scheduled again to
 * 'now + enabled_delay'.
 *
 * The random_offset is maximum number of seconds added to the
 * expected delay. Set to 0 if no randomization is needed.
 *
 * If max_backoff is not 0 then the period is doubled
 * every time the task is scheduled. The maximum value of
 * period is max_backoff. The value of period will be reset to
 * original value when the task is disabled. With max_backoff
 * set to zero, this feature is disabled.
 *
 * If an internal error occurred, the task is automatically disabled.
 */
errno_t be_ptask_create(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        time_t period,
                        time_t first_delay,
                        time_t enabled_delay,
                        time_t random_offset,
                        time_t timeout,
                        time_t max_backoff,
                        be_ptask_send_t send_fn,
                        be_ptask_recv_t recv_fn,
                        void *pvt,
                        const char *name,
                        uint32_t flags,
                        struct be_ptask **_task);

errno_t be_ptask_create_sync(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             time_t period,
                             time_t first_delay,
                             time_t enabled_delay,
                             time_t random_offset,
                             time_t timeout,
                             time_t max_backoff,
                             be_ptask_sync_t fn,
                             void *pvt,
                             const char *name,
                             uint32_t flags,
                             struct be_ptask **_task);

void be_ptask_enable(struct be_ptask *task);
void be_ptask_disable(struct be_ptask *task);
void be_ptask_postpone(struct be_ptask *task);
void be_ptask_postpone_all(struct be_ctx *be_ctx);
void be_ptask_destroy(struct be_ptask **task);

time_t be_ptask_get_period(struct be_ptask *task);
time_t be_ptask_get_timeout(struct be_ptask *task);
bool be_ptask_running(struct be_ptask *task);

#endif /* _DP_PTASK_H_ */
