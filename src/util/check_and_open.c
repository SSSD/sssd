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

errno_t check_and_open_readonly(const char *filename, int *fd, const uid_t uid,
                               const gid_t gid, const mode_t mode)
{
    int ret;
    struct stat stat_buf;
    struct stat fd_stat_buf;

    *fd = -1;

    ret = lstat(filename, &stat_buf);
    if (ret == -1) {
        DEBUG(1, ("lstat for [%s] failed: [%d][%s].\n", filename, errno,
                                                        strerror(errno)));
        return errno;
    }

    if (!S_ISREG(stat_buf.st_mode)) {
        DEBUG(1, ("File [%s] is not a regular file.\n", filename));
        return EINVAL;
    }

    if ((stat_buf.st_mode & ~S_IFMT) != mode) {
        DEBUG(1, ("File [%s] has the wrong mode [%.7o], expected [%.7o].\n",
                  filename, (stat_buf.st_mode & ~S_IFMT), mode));
        return EINVAL;
    }

    if (stat_buf.st_uid != uid || stat_buf.st_gid != gid) {
        DEBUG(1, ("File [%s] must be owned by uid [%d] and gid [%d].\n",
                  filename, uid, gid));
        return EINVAL;
    }

    *fd = open(filename, O_RDONLY);
    if (*fd == -1) {
        DEBUG(1, ("open [%s] failed: [%d][%s].\n", filename, errno,
                                                        strerror(errno)));
        return errno;
    }

    ret = fstat(*fd, &fd_stat_buf);
    if (ret == -1) {
        DEBUG(1, ("fstat for [%s] failed: [%d][%s].\n", filename, errno,
                                                        strerror(errno)));
        return errno;
    }

    if (stat_buf.st_dev != fd_stat_buf.st_dev ||
        stat_buf.st_ino != fd_stat_buf.st_ino) {
        DEBUG(1, ("File [%s] was modified between lstat and open.\n", filename));
        close(*fd);
        *fd = -1;
        return EIO;
    }

    return EOK;
}

