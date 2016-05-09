/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2016 Red Hat

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
#include "util/util.h"
#include "util/crypto/sss_crypto.h"

int generate_csprng_buffer(uint8_t *buf, size_t size)
{
    ssize_t rsize;
    ssize_t pos;
    int ret;
    int fd;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) return errno;

    rsize = 0;
    pos = 0;
    while (rsize < size) {
        rsize = read(fd, buf + pos, size - pos);
        switch (rsize) {
        case -1:
            if (errno == EINTR) continue;
            ret = EIO;
            goto done;
        case 0:
            ret = EIO;
            goto done;
        default:
            if (rsize + pos < size - pos) {
                pos += rsize;
                continue;
            }
            ret = EIO;
            goto done;
        }
    }
    if (rsize != size) {
        ret = EFAULT;
        goto done;
    }

    ret = EOK;

done:
    close(fd);
    return ret;
}
