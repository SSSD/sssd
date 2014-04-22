/*
    SSSD

    Check file permissions and open file

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "util/util.h"

static errno_t perform_checks(struct stat *stat_buf,
                              uid_t uid, gid_t gid,
                              mode_t mode, mode_t mask);

errno_t check_file(const char *filename,
                   uid_t uid, uid_t gid, mode_t mode, mode_t mask,
                   struct stat *caller_stat_buf, bool follow_symlink)
{
    int ret;
    struct stat local_stat_buf;
    struct stat *stat_buf;

    if (caller_stat_buf == NULL) {
        stat_buf = &local_stat_buf;
    } else {
        stat_buf = caller_stat_buf;
    }

    if (follow_symlink) {
        ret = stat(filename, stat_buf);
    } else {
        ret = lstat(filename, stat_buf);
    }
    if (ret == -1) {
        DEBUG(SSSDBG_TRACE_FUNC, "lstat for [%s] failed: [%d][%s].\n",
                                 filename, errno, strerror(errno));
        return errno;
    }

    return perform_checks(stat_buf, uid, gid, mode, mask);
}

errno_t check_fd(int fd, uid_t uid, gid_t gid,
                 mode_t mode, mode_t mask,
                 struct stat *caller_stat_buf)
{
    int ret;
    struct stat local_stat_buf;
    struct stat *stat_buf;

    if (caller_stat_buf == NULL) {
        stat_buf = &local_stat_buf;
    } else {
        stat_buf = caller_stat_buf;
    }

    ret = fstat(fd, stat_buf);
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fstat for [%d] failed: [%d][%s].\n", fd, errno,
                                                        strerror(errno));
        return errno;
    }

    return perform_checks(stat_buf, uid, gid, mode, mask);
}

static errno_t perform_checks(struct stat *stat_buf,
                              uid_t uid, gid_t gid,
                              mode_t mode, mode_t mask)
{
    mode_t st_mode;

    if (mask) {
        st_mode = stat_buf->st_mode & mask;
    } else {
        st_mode = stat_buf->st_mode & (S_IFMT|ALLPERMS);
    }

    if ((mode & S_IFMT) != (st_mode & S_IFMT)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "File is not the right type.\n");
        return EINVAL;
    }

    if ((st_mode & ALLPERMS) != (mode & ALLPERMS)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "File has the wrong (bit masked) mode [%.7o], "
              "expected [%.7o].\n",
              (st_mode & ALLPERMS), (mode & ALLPERMS));
        return EINVAL;
    }

    if (uid != (uid_t)(-1) && stat_buf->st_uid != uid) {
        DEBUG(SSSDBG_CRIT_FAILURE, "File must be owned by uid [%d].\n", uid);
        return EINVAL;
    }

    if (gid != (gid_t)(-1) && stat_buf->st_gid != gid) {
        DEBUG(SSSDBG_CRIT_FAILURE, "File must be owned by gid [%d].\n", gid);
        return EINVAL;
    }

    return EOK;
}

errno_t check_and_open_readonly(const char *filename, int *fd,
                                uid_t uid, gid_t gid,
                                mode_t mode, mode_t mask)
{
    int ret;
    struct stat stat_buf;

    *fd = open(filename, O_RDONLY);
    if (*fd == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "open [%s] failed: [%d][%s].\n", filename, errno,
                  strerror(errno));
        return errno;
    }

    ret = check_fd(*fd, uid, gid, mode, mask, &stat_buf);
    if (ret != EOK) {
        close(*fd);
        *fd = -1;
        DEBUG(SSSDBG_CRIT_FAILURE, "check_fd failed.\n");
        return ret;
    }

    return EOK;
}

