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

#include <signal.h>

#include "util/util.h"

#define WATCHDOG_DEF_INTERVAL 10
#define WATCHDOG_MAX_TICKS 3
#define DEFAULT_BUFFER_SIZE 4096

/* this is intentionally a global variable */
struct watchdog_ctx {
    timer_t timerid;
    struct timeval interval;
    struct tevent_timer *te;
    volatile int ticks;

    /* To detect time shift. */
    struct tevent_context *ev;
    int input_interval;
    time_t timestamp;
    struct tevent_fd *tfd;
    int pipefd[2];
} watchdog_ctx;

static void watchdog_detect_timeshift(void)
{
    time_t prev_time;
    time_t cur_time;

    prev_time = watchdog_ctx.timestamp;
    cur_time = watchdog_ctx.timestamp = time(NULL);
    if (cur_time < prev_time) {
        /* Time shift detected. We need to restart watchdog. */
        if (write(watchdog_ctx.pipefd[1], "1", 1) != 1) {
            if (getpid() == getpgrp()) {
                kill(-getpgrp(), SIGTERM);
            }
            _exit(1);
        }
    }
}

/* the watchdog is purposefully *not* handled by the tevent
 * signal handler as it is meant to check if the daemon is
 * still processing the event queue itself. A stuck process
 * may not handle the event queue at all and thus not handle
 * signals either */
static void watchdog_handler(int sig)
{

    watchdog_detect_timeshift();

    /* if a pre-defined number of ticks passed by kills itself */
    if (__sync_add_and_fetch(&watchdog_ctx.ticks, 1) >= WATCHDOG_MAX_TICKS) {
        if (getpid() == getpgrp()) {
            kill(-getpgrp(), SIGTERM);
        }
        _exit(SSS_WATCHDOG_EXIT_CODE);
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

static errno_t watchdog_fd_recv_data(int fd)
{
    ssize_t len;
    char buffer[DEFAULT_BUFFER_SIZE];
    errno_t ret;

    errno = 0;
    len = read(fd, buffer, DEFAULT_BUFFER_SIZE);
    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return EAGAIN;
        } else {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "write failed [%d]: %s\n", ret, strerror(ret));
            return ret;
        }
    }

    return EOK;
}

static void watchdog_fd_read_handler(struct tevent_context *ev,
                                     struct tevent_fd *fde,
                                     uint16_t flags,
                                     void *data)
{
    errno_t ret;

    ret = watchdog_fd_recv_data(watchdog_ctx.pipefd[0]);
    switch(ret) {
    case EAGAIN:
        DEBUG(SSSDBG_TRACE_ALL,
              "Interrupted before any data could be read, retry later.\n");
        return;
    case EOK:
        /* all fine */
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to receive data [%d]: %s. "
              "orderly_shutdown() will be called.\n", ret, strerror(ret));
        orderly_shutdown(1);
    }

    DEBUG(SSSDBG_IMPORTANT_INFO, "Time shift detected, "
          "restarting watchdog!\n");
    teardown_watchdog();
    ret = setup_watchdog(watchdog_ctx.ev, watchdog_ctx.input_interval);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to restart watchdog "
              "[%d]: %s\n", ret, sss_strerror(ret));
        orderly_shutdown(1);
    }
    if (strncmp(debug_prg_name, "be[", sizeof("be[") - 1) == 0) {
        kill(getpid(), SIGUSR2);
        DEBUG(SSSDBG_IMPORTANT_INFO, "SIGUSR2 sent to %s\n", debug_prg_name);
    }
}

int setup_watchdog(struct tevent_context *ev, int interval)
{
    struct sigevent sev;
    struct itimerspec its;
    struct tevent_fd *tfd;
    int signum = SIGRTMIN;
    int ret;

    memset(&sev, 0, sizeof(sev));
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

    watchdog_ctx.ev = ev;
    watchdog_ctx.input_interval = interval;
    watchdog_ctx.timestamp = time(NULL);

    ret = pipe(watchdog_ctx.pipefd);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "pipe failed [%d] [%s].\n", ret, strerror(ret));
        return ret;
    }

    sss_fd_nonblocking(watchdog_ctx.pipefd[0]);
    sss_fd_nonblocking(watchdog_ctx.pipefd[1]);

    tfd = tevent_add_fd(ev, (TALLOC_CTX *)ev, watchdog_ctx.pipefd[0],
                        TEVENT_FD_READ, watchdog_fd_read_handler, NULL);
    watchdog_ctx.tfd = tfd;

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

    /* Free the tevent_fd */
    talloc_zfree(watchdog_ctx.tfd);

    /* Close the pipefds */
    PIPE_FD_CLOSE(watchdog_ctx.pipefd[0]);
    PIPE_FD_CLOSE(watchdog_ctx.pipefd[1]);

    /* and kill the watchdog event */
    talloc_free(watchdog_ctx.te);
}

int get_watchdog_ticks(void)
{
    return __sync_add_and_fetch(&watchdog_ctx.ticks, 0);
}
