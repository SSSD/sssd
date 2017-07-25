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

#include <sys/stat.h>
#include <fcntl.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"

int generate_csprng_buffer(uint8_t *buf, size_t size)
{
    ssize_t rsize;
    int ret;
    int fd;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) return errno;

    rsize = sss_atomic_read_s(fd, buf, size);
    if (rsize == -1) {
        ret = errno;
        goto done;
    } else if (rsize != size) {
        ret = EFAULT;
        goto done;
    }

    ret = EOK;
done:
    close(fd);
    return ret;
}
