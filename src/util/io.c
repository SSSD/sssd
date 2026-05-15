/*
    SSSD

    io.c

    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

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

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "shared/io.h"

/* CAUTION:
 * This file have to be minimalist and cannot include DEBUG macros
 * or header file util.h.
 */

int sss_open_cloexec(const char *pathname, int flags, int *ret)
{
    int fd;
    int oflags;

    oflags = flags;
#ifdef O_CLOEXEC
    oflags |= O_CLOEXEC;
#endif

    errno = 0;
    fd = open(pathname, oflags);
    if (fd == -1) {
        if (ret) {
            *ret = errno;
        }
        return -1;
    }

#ifndef O_CLOEXEC
    int v;

    v = fcntl(fd, F_GETFD, 0);
    /* we ignore an error, it's not fatal and there is nothing we
     * can do about it anyways */
    (void)fcntl(fd, F_SETFD, v | FD_CLOEXEC);
#endif

    return fd;
}

int sss_openat_cloexec(int dir_fd, const char *pathname, int flags, int *ret)
{
    int fd;
    int oflags;

    oflags = flags;
#ifdef O_CLOEXEC
    oflags |= O_CLOEXEC;
#endif

    errno = 0;
    fd = openat(dir_fd, pathname, oflags);
    if (fd == -1) {
        if (ret) {
            *ret = errno;
        }
        return -1;
    }

#ifndef O_CLOEXEC
    int v;

    v = fcntl(fd, F_GETFD, 0);
    /* we ignore an error, it's not fatal and there is nothing we
     * can do about it anyways */
    (void)fcntl(fd, F_SETFD, v | FD_CLOEXEC);
#endif

    return fd;
}
