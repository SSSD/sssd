/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

    SSSD's enhanced NSS API

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
#include <errno.h>
#include <stdbool.h>

#include "sss_cli.h"
#include "common_private.h"

extern struct sss_mutex sss_nss_mtx;
#ifdef HAVE_PTHREAD_EXT
bool sss_is_lockfree_mode(void);
#endif

#define SEC_FROM_MSEC(ms) ((ms) / 1000)
#define NSEC_FROM_MSEC(ms) (((ms) % 1000) * 1000 * 1000)

/* adopted from timersub() defined in /usr/include/sys/time.h */
#define TIMESPECSUB(a, b, result)                                             \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;                          \
    if ((result)->tv_nsec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_nsec += 1000000000;                                        \
    }                                                                         \
  } while (0)

#define TIMESPEC_TO_MS(ts) (  ((ts)->tv_sec * 1000) \
                            + ((ts)->tv_nsec) / (1000 * 1000) )

static int sss_mt_timedlock(struct sss_mutex *m, const struct timespec *endtime)
{
    int ret;

#ifdef HAVE_PTHREAD_EXT
    if (sss_is_lockfree_mode()) {
        return 0;
    }
#endif

    ret = pthread_mutex_timedlock(&m->mtx, endtime);
    if (ret != 0) {
        return ret;
    }
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &m->old_cancel_state);

    return 0;
}

int sss_nss_timedlock(unsigned int timeout_ms, int *time_left_ms)
{
    int ret;
    int left;
    struct timespec starttime;
    struct timespec endtime;
    struct timespec diff;

    /* make sure there is no overrun when calculating the time left */
    if (timeout_ms > INT_MAX) {
        timeout_ms = INT_MAX;
    }

    ret = clock_gettime(CLOCK_REALTIME, &starttime);
    if (ret != 0) {
        return errno;
    }
    endtime.tv_sec = starttime.tv_sec + SEC_FROM_MSEC(timeout_ms);
    endtime.tv_nsec = starttime.tv_nsec + NSEC_FROM_MSEC(timeout_ms);

    ret = sss_mt_timedlock(&sss_nss_mtx, &endtime);

    if (ret == 0) {
        ret = clock_gettime(CLOCK_REALTIME, &endtime);
        if (ret != 0) {
            ret = errno;
            sss_nss_unlock();
            return ret;
        }

        if (timeout_ms == 0) {
            *time_left_ms = 0;
        } else {
            TIMESPECSUB(&endtime, &starttime, &diff);
            left = timeout_ms - TIMESPEC_TO_MS(&diff);
            if (left <= 0) {
                sss_nss_unlock();
                return EIO;
            } else if (left > SSS_CLI_SOCKET_TIMEOUT) {
                *time_left_ms = SSS_CLI_SOCKET_TIMEOUT;
            } else {
                *time_left_ms = left;
            }
        }
    }

    return ret;
}
