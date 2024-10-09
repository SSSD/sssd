/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#ifndef DP_PTASK_PRIVATE_H_
#define DP_PTASK_PRIVATE_H_

struct be_ptask {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    time_t orig_period;
    time_t first_delay;
    time_t enabled_delay;
    time_t random_offset;
    time_t timeout;
    time_t max_backoff;
    be_ptask_send_t send_fn;
    be_ptask_recv_t recv_fn;
    void *pvt;
    const char *name;

    time_t period;          /* computed period */
    time_t next_execution;  /* next time when the task is scheduled */
    time_t last_execution;  /* last time when send was called */
    struct tevent_req *req; /* active tevent request */
    struct tevent_timer *timer; /* active tevent timer */
    uint32_t flags;
    bool enabled;

    struct be_ptask *prev;
    struct be_ptask *next;
};

#endif /* DP_PTASK_PRIVATE_H_ */
