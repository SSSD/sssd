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

#ifndef __SSSD_ATOMIC_IO_H__
#define __SSSD_ATOMIC_IO_H__

#include <unistd.h>
#include <stdbool.h>
#include <poll.h>
#include <errno.h>

/* Performs a read or write operation in an manner that is seemingly atomic
 * to the caller.
 *
 * Please note that the function does not perform any asynchronous operation
 * so the operation might potentially block
 */
ssize_t sss_atomic_io_s(int fd, void *buf, size_t n, bool do_read);

#define sss_atomic_read_s(fd, buf, n)  sss_atomic_io_s(fd, buf, n, true)
#define sss_atomic_write_s(fd, buf, n) sss_atomic_io_s(fd, buf, n, false)

/**
 * Write length of the buffer then the buffer itself.
 *
 * (uint32_t)length + buffer
 */
ssize_t sss_atomic_write_safe_s(int fd, void *buf, size_t len);

/**
 * First, read uint32_t as a message length, then read the rest of the message
 * expecting given length. The exact length is returned in _len parameter.
 */
ssize_t sss_atomic_read_safe_s(int fd, void *buf, size_t max_len, size_t *_len);

#endif /* __SSSD_ATOMIC_IO_H__ */
