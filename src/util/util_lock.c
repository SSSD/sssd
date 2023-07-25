/*
    SSSD

    util_lock.c

    Authors:
        Michal Zidek <mzidek@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "util/util.h"

errno_t sss_br_lock_file(int fd, size_t start, size_t len,
                         int num_tries, useconds_t wait)
{
    int ret = EAGAIN;
    struct flock lock;
    int retries_left;

    if (num_tries <= 0) {
        return EINVAL;
    }

    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = start;
    lock.l_len = len;
    lock.l_pid = 0;

    for (retries_left = num_tries; retries_left > 0; retries_left--) {
        ret = fcntl(fd, F_SETLK, &lock);
        if (ret == -1) {
            ret = errno;
            if (ret == EACCES || ret == EAGAIN || ret == EINTR) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Failed to lock file. Retries left: %d\n",
                       retries_left - 1);

                if ((ret == EACCES || ret == EAGAIN) && (retries_left <= 1)) {
                    /* File is locked by someone else. Return EACCESS
                     * if this is the last try. */
                    return EACCES;
                }

                if (retries_left - 1 > 0) {
                    ret = usleep(wait);
                    if (ret == -1) {
                        ret = errno;
                        DEBUG(SSSDBG_MINOR_FAILURE,
                              "usleep() failed with %d -> ignoring\n", ret);
                    }
                }
            } else {
                /* Error occurred */
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Unable to lock file.\n");
                return ret;
            }
        } else if (ret == 0) {
            /* File successfully locked */
            break;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unexpected fcntl() return code: %d\n", ret);
        }
    }
    if (retries_left == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lock file.\n");
        return ret;
    }

    return EOK;
}
