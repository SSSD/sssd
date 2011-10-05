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
                              const int uid, const int gid,
                              const int mode, enum check_file_type type);

errno_t check_file(const char *filename, const int uid, const int gid,
                   const int mode, enum check_file_type type,
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

    ret = follow_symlink ? stat(filename, stat_buf) : \
                           lstat(filename, stat_buf);
    if (ret == -1) {
        DEBUG(1, ("lstat for [%s] failed: [%d][%s].\n", filename, errno,
                                                        strerror(errno)));
        return errno;
    }

    return perform_checks(stat_buf, uid, gid, mode, type);
}

errno_t check_fd(int fd, const int uid, const int gid,
                 const int mode, enum check_file_type type,
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
        DEBUG(1, ("fstat for [%d] failed: [%d][%s].\n", fd, errno,
                                                        strerror(errno)));
        return errno;
    }

    return perform_checks(stat_buf, uid, gid, mode, type);
}

static errno_t perform_checks(struct stat *stat_buf,
                              const int uid, const int gid,
                              const int mode, enum check_file_type type)
{
    bool type_check;

    switch (type) {
        case CHECK_DONT_CHECK_FILE_TYPE:
            type_check = true;
            break;
        case CHECK_REG:
            type_check = S_ISREG(stat_buf->st_mode);
            break;
        case CHECK_DIR:
            type_check = S_ISDIR(stat_buf->st_mode);
            break;
        case CHECK_CHR:
            type_check = S_ISCHR(stat_buf->st_mode);
            break;
        case CHECK_BLK:
            type_check = S_ISBLK(stat_buf->st_mode);
            break;
        case CHECK_FIFO:
            type_check = S_ISFIFO(stat_buf->st_mode);
            break;
        case CHECK_LNK:
            type_check = S_ISLNK(stat_buf->st_mode);
            break;
        case CHECK_SOCK:
            type_check = S_ISSOCK(stat_buf->st_mode);
            break;
        default:
            DEBUG(1, ("Unsupported file type.\n"));
            return EINVAL;
    }

    if (!type_check) {
        DEBUG(1, ("File is not the right type.\n"));
        return EINVAL;
    }

    if (mode >= 0 && (stat_buf->st_mode & ~S_IFMT) != mode) {
        DEBUG(1, ("File has the wrong mode [%.7o], expected [%.7o].\n",
                  (stat_buf->st_mode & ~S_IFMT), mode));
        return EINVAL;
    }

    if (uid >= 0 && stat_buf->st_uid != uid) {
        DEBUG(1, ("File must be owned by uid [%d].\n", uid));
        return EINVAL;
    }

    if (gid >= 0 && stat_buf->st_gid != gid) {
        DEBUG(1, ("File must be owned by gid [%d].\n", gid));
        return EINVAL;
    }

    return EOK;
}

errno_t check_and_open_readonly(const char *filename, int *fd, const uid_t uid,
                               const gid_t gid, const mode_t mode,
                               enum check_file_type type)
{
    int ret;
    struct stat stat_buf;

    *fd = open(filename, O_RDONLY);
    if (*fd == -1) {
        DEBUG(1, ("open [%s] failed: [%d][%s].\n", filename, errno,
                  strerror(errno)));
        return errno;
    }

    ret = check_fd(*fd, uid, gid, mode, type, &stat_buf);
    if (ret != EOK) {
        close(*fd);
        *fd = -1;
        DEBUG(1, ("check_fd failed.\n"));
        return ret;
    }

    return EOK;
}

