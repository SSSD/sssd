/*
   SSSD

   tools_mc_util - interface to the memcache for userspace tools

   Copyright (C) Red Hat                                        2013

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

#include <talloc.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "util/mmap_cache.h"
#include "util/sss_cli_cmd.h"
#include "sss_client/sss_cli.h"
#include "tools/common/sss_process.h"

/* This is a copy of sss_mc_set_recycled present in
 * src/responder/nss/nsssrv_mmap_cache.c. If you modify this function,
 * you should modify the original function too. */
static errno_t sss_mc_set_recycled(int fd)
{
    uint32_t w = SSS_MC_HEADER_RECYCLED;
    off_t offset;
    off_t pos;
    ssize_t written;

    offset = offsetof(struct sss_mc_header, status);

    pos = lseek(fd, offset, SEEK_SET);
    if (pos == -1) {
        /* What do we do now? */
        return errno;
    }

    errno = 0;
    written = sss_atomic_write_s(fd, (uint8_t *)&w, sizeof(w));
    if (written == -1) {
        return errno;
    }

    if (written != sizeof(w)) {
        /* Write error */
        return EIO;
    }

    return EOK;
}

static errno_t sss_memcache_invalidate(const char *mc_filename)
{
    int mc_fd = -1;
    errno_t ret;
    errno_t pret;
    useconds_t t = 50000;
    int retries = 2;

    if (!mc_filename) {
        return EINVAL;
    }

    mc_fd = open(mc_filename, O_RDWR);
    if (mc_fd == -1) {
        ret = errno;
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC,"Memory cache file %s "
                  "does not exist.\n", mc_filename);
            return EOK;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to open file %s: %s\n",
                  mc_filename, strerror(ret));
            return ret;
        }
    }

    ret = sss_br_lock_file(mc_fd, 0, 1, retries, t);
    if (ret == EACCES) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "File %s already locked by someone else.\n", mc_filename);
        goto done;
    } else if (ret != EOK) {
       DEBUG(SSSDBG_CRIT_FAILURE, "Failed to lock file %s.\n", mc_filename);
       goto done;
    }
    /* Mark the mc file as recycled. */
    ret = sss_mc_set_recycled(mc_fd);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to mark memory cache file %s "
              "as recycled.\n", mc_filename);
        goto done;
    }

    ret = EOK;
done:
    if (mc_fd != -1) {
        /* Closing the file also releases the lock */
        close(mc_fd);

        /* Only unlink the file if invalidation was successful */
        if (ret == EOK) {
            pret = unlink(mc_filename);
            if (pret == -1) {
                pret = errno;
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to unlink file %s, %d [%s]. "
                      "Will be unlinked later by sssd_nss.\n",
                      mc_filename, pret, strerror(pret));
            }
        }
    }
    return ret;
}

static int clear_memcache(bool *sssd_nss_is_off)
{
    int ret;
    ret = sss_memcache_invalidate(SSS_NSS_MCACHE_DIR"/passwd");
    if (ret != EOK) {
        if (ret == EACCES) {
            *sssd_nss_is_off = false;
            return EOK;
        } else {
            return ret;
        }
    }

    ret = sss_memcache_invalidate(SSS_NSS_MCACHE_DIR"/group");
    if (ret != EOK) {
        if (ret == EACCES) {
            *sssd_nss_is_off = false;
            return EOK;
        } else {
            return ret;
        }
    }

    ret = sss_memcache_invalidate(SSS_NSS_MCACHE_DIR"/initgroups");
    if (ret != EOK) {
        if (ret == EACCES) {
            *sssd_nss_is_off = false;
            return EOK;
        } else {
            return ret;
        }
    }

    *sssd_nss_is_off = true;
    return EOK;
}

static errno_t wait_till_nss_responder_invalidate_cache(void)
{
    struct stat stat_buf = { 0 };
    const time_t max_wait = 1000000; /* 1 second */
    const __useconds_t step_time = 5000; /* 5 milliseconds */
    const size_t steps_count = max_wait / step_time;
    int ret;

    for (size_t i = 0; i < steps_count; ++i) {
        ret = stat(SSS_NSS_MCACHE_DIR "/" CLEAR_MC_FLAG, &stat_buf);
        if (ret == -1) {
            ret = errno;
            if (ret == ENOENT) {
                /* nss responder has already invalidated memory caches */
                return EOK;
            }

            DEBUG(SSSDBG_CRIT_FAILURE,
                  "stat failed: %s (%d)\n", sss_strerror(ret), ret);
        }

        usleep(step_time);
    }

    return EAGAIN;
}

errno_t sss_memcache_clear_all(void)
{
    errno_t ret;
    bool sssd_nss_is_off = false;
    FILE *clear_mc_flag;

    ret = clear_memcache(&sssd_nss_is_off);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to clear caches.\n");
        return EIO;
    }
    if (!sssd_nss_is_off) {
        /* sssd_nss is running -> signal monitor to invalidate memcache */
        clear_mc_flag = fopen(SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG, "w");
        if (clear_mc_flag == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to create clear_mc_flag file. "
                   "Memory cache will not be cleared.\n");
            return EIO;
        }
        ret = fclose(clear_mc_flag);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to close file descriptor: %s\n",
                   strerror(ret));
            return EIO;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Sending SIGHUP to monitor.\n");
        ret = sss_signal(SIGHUP);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to send SIGHUP to monitor.\n");
            return EIO;
        }

        ret = wait_till_nss_responder_invalidate_cache();
        if (ret != EOK) {
            ERROR("The memcache was not invalidated by NSS responder.\n");
        }
    }

    return EOK;
}
