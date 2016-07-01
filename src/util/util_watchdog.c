/*
   SSSD

   Timer Watchdog routines

   Copyright (C) Simo Sorce             2016

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

#define WATCHDOG_DEF_INTERVAL 10

/* this is intentionally a global variable */
struct watchdog_ctx {
    timer_t timerid;
    struct timeval interval;
    struct tevent_timer *te;
    volatile int ticks;
} watchdog_ctx;

/* the watchdog is purposefully *not* handled by the tevent
 * signal handler as it is meant to check if the daemon is
 * still processing the event queue itself. A stuck process
 * may not handle the event queue at all and thus not handle
 * signals either */
static void watchdog_handler(int sig)
{
    /* if 3 ticks passed by kills itself */

    if (__sync_add_and_fetch(&watchdog_ctx.ticks, 1) > 3) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Watchdog timer overflow, killing process!\n");
        orderly_shutdown(1);
    }
}

static void watchdog_reset(void)
{
    __sync_and_and_fetch(&watchdog_ctx.ticks, 0);
}

static void watchdog_event_handler(struct tevent_context *ev,
                                   struct tevent_timer *te,
                                   struct timeval current_time,
                                   void *private_data)
{
    /* first thing reset the watchdog ticks */
    watchdog_reset();

    /* then set a new watchodg event */
    watchdog_ctx.te = tevent_add_timer(ev, ev,
        tevent_timeval_current_ofs(watchdog_ctx.interval.tv_sec, 0),
        watchdog_event_handler, NULL);
    /* if the function fails the watchdog will kill the
     * process soon enough, so we just warn */
    if (!watchdog_ctx.te) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to create a watchdog timer event!\n");
    }
}

int setup_watchdog(struct tevent_context *ev, int interval)
{
    struct sigevent sev;
    struct itimerspec its;
    int signum = SIGRTMIN;
    int ret;

    ZERO_STRUCT(sev);
    CatchSignal(signum, watchdog_handler);

    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = signum;
    sev.sigev_value.sival_ptr = &watchdog_ctx.timerid;
    errno = 0;
    ret = timer_create(CLOCK_MONOTONIC, &sev, &watchdog_ctx.timerid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to create watchdog timer (%d) [%s]\n",
              ret, strerror(ret));
        return ret;
    }

    if (interval == 0) {
        interval = WATCHDOG_DEF_INTERVAL;
    }
    watchdog_ctx.interval.tv_sec = interval;
    watchdog_ctx.interval.tv_usec = 0;

    /* Start the timer */
    /* we give 1 second head start to the watchdog event */
    its.it_value.tv_sec = interval + 1;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = interval;
    its.it_interval.tv_nsec = 0;
    errno = 0;
    ret = timer_settime(watchdog_ctx.timerid, 0, &its, NULL);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to create watchdog timer (%d) [%s]\n",
              ret, strerror(ret));
        return ret;
    }

    /* Add the watchdog event and make it fire as fast as the timer */
    watchdog_event_handler(ev, NULL, tevent_timeval_zero(), NULL);

    return EOK;
}

void teardown_watchdog(void)
{
    int ret;

    /* Disarm the timer */
    errno = 0;
    ret = timer_delete(watchdog_ctx.timerid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to destroy watchdog timer (%d) [%s]\n",
             ret, strerror(ret));
    }

    /* and kill the watchdog event */
    talloc_free(watchdog_ctx.te);
}
