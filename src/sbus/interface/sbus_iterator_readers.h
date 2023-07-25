/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef _SBUS_ITERATOR_READERS_H_
#define _SBUS_ITERATOR_READERS_H_

#include <stdint.h>
#include <stdbool.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"

errno_t sbus_iterator_read_y(DBusMessageIter *iterator,
                             uint8_t *_value);

errno_t sbus_iterator_read_b(DBusMessageIter *iterator,
                             bool *_value);

errno_t sbus_iterator_read_n(DBusMessageIter *iterator,
                             int16_t *_value);

errno_t sbus_iterator_read_q(DBusMessageIter *iterator,
                             uint16_t *_value);

errno_t sbus_iterator_read_i(DBusMessageIter *iterator,
                             int32_t *_value);

errno_t sbus_iterator_read_u(DBusMessageIter *iterator,
                             uint32_t *_value);

errno_t sbus_iterator_read_x(DBusMessageIter *iterator,
                             int64_t *_value);

errno_t sbus_iterator_read_t(DBusMessageIter *iterator,
                             uint64_t *_value);

errno_t sbus_iterator_read_d(DBusMessageIter *iterator,
                             double *_value);

errno_t sbus_iterator_read_s(TALLOC_CTX *mem_ctx,
                             DBusMessageIter *iterator,
                             const char **_value);

errno_t sbus_iterator_read_S(TALLOC_CTX *mem_ctx,
                             DBusMessageIter *iterator,
                             char **_value);

errno_t sbus_iterator_read_o(TALLOC_CTX *mem_ctx,
                             DBusMessageIter *iterator,
                             const char **_value);

errno_t sbus_iterator_read_O(TALLOC_CTX *mem_ctx,
                             DBusMessageIter *iterator,
                             char **_value);

errno_t sbus_iterator_read_ay(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              uint8_t **_value);

errno_t sbus_iterator_read_ab(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              bool **_value);

errno_t sbus_iterator_read_an(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              int16_t **_value);

errno_t sbus_iterator_read_aq(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              uint16_t **_value);

errno_t sbus_iterator_read_ai(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              int32_t **_value);

errno_t sbus_iterator_read_au(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              uint32_t **_value);

errno_t sbus_iterator_read_ax(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              int64_t **_value);

errno_t sbus_iterator_read_at(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              uint64_t **_value);

errno_t sbus_iterator_read_ad(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              double **_value);

errno_t sbus_iterator_read_as(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              const char ***_value);

errno_t sbus_iterator_read_aS(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              char ***_value);

errno_t sbus_iterator_read_ao(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              const char ***_value);

errno_t sbus_iterator_read_aO(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              char ***_value);

#endif /* _SBUS_ITERATOR_READERS_H_ */
