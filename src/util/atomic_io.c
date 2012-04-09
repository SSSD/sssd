/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

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

#include "util/atomic_io.h"

/* based on code from libssh <http://www.libssh.org> */
ssize_t sss_atomic_io_s(int fd, void *buf, size_t n, bool do_read)
{
    char *b = buf;
    size_t pos = 0;
    ssize_t res;
    struct pollfd pfd;

    pfd.fd = fd;
    pfd.events = do_read ? POLLIN : POLLOUT;

    while (n > pos) {
        if (do_read) {
            res = read(fd, b + pos, n - pos);
        } else {
            res = write(fd, b + pos, n - pos);
        }
        switch (res) {
        case -1:
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                (void) poll(&pfd, 1, -1);
                continue;
            }
            return -1;
        case 0:
            /* read returns 0 on end-of-file */
            errno = do_read ? 0 : EPIPE;
            return pos;
        default:
            pos += (size_t) res;
        }
    }

    return pos;
}
