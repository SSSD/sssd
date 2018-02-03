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

#ifndef _SBUS_ITERATOR_WRITERS_H_
#define _SBUS_ITERATOR_WRITERS_H_

#include <stdint.h>
#include <dbus/dbus.h>

#include "util/util.h"

/* Generic writers to be used in custom type handlers. */

errno_t
_sbus_iterator_write_basic_array(DBusMessageIter *iterator,
                                 int dbus_type,
                                 int element_size,
                                 int array_length,
                                 void *value_ptr);

#define sbus_iterator_write_basic_array(iterator, dbus_type, c_type, source) \
    _sbus_iterator_write_basic_array((iterator), (dbus_type), \
                                     sizeof(c_type), -1, (void*)(source))

#define sbus_iterator_write_basic_array_len(iterator, dbus_type, c_type, source, length) \
    _sbus_iterator_write_basic_array((iterator), (dbus_type), \
                                     sizeof(c_type), (length), (void*)(source))

/* Basic types. */

errno_t sbus_iterator_write_y(DBusMessageIter *iterator,
                              uint8_t value);

errno_t sbus_iterator_write_b(DBusMessageIter *iterator,
                              bool value);

errno_t sbus_iterator_write_n(DBusMessageIter *iterator,
                              int16_t value);

errno_t sbus_iterator_write_q(DBusMessageIter *iterator,
                              uint16_t value);

errno_t sbus_iterator_write_i(DBusMessageIter *iterator,
                              int32_t value);

errno_t sbus_iterator_write_u(DBusMessageIter *iterator,
                              uint32_t value);

errno_t sbus_iterator_write_x(DBusMessageIter *iterator,
                              int64_t value);

errno_t sbus_iterator_write_t(DBusMessageIter *iterator,
                              uint64_t value);

errno_t sbus_iterator_write_d(DBusMessageIter *iterator,
                              double value);

errno_t sbus_iterator_write_s(DBusMessageIter *iterator,
                              const char *value);

errno_t sbus_iterator_write_S(DBusMessageIter *iterator,
                              char *value);

errno_t sbus_iterator_write_o(DBusMessageIter *iterator,
                              const char *value);

errno_t sbus_iterator_write_O(DBusMessageIter *iterator,
                              char *value);

errno_t sbus_iterator_write_ay(DBusMessageIter *iterator,
                               uint8_t *value);

errno_t sbus_iterator_write_ab(DBusMessageIter *iterator,
                               bool *value);

errno_t sbus_iterator_write_an(DBusMessageIter *iterator,
                               int16_t *value);

errno_t sbus_iterator_write_aq(DBusMessageIter *iterator,
                               uint16_t *value);

errno_t sbus_iterator_write_ai(DBusMessageIter *iterator,
                               int32_t *value);

errno_t sbus_iterator_write_au(DBusMessageIter *iterator,
                               uint32_t *value);

errno_t sbus_iterator_write_ax(DBusMessageIter *iterator,
                               int64_t *value);

errno_t sbus_iterator_write_at(DBusMessageIter *iterator,
                               uint64_t *value);

errno_t sbus_iterator_write_ad(DBusMessageIter *iterator,
                               double *value);

errno_t sbus_iterator_write_as(DBusMessageIter *iterator,
                               const char **value);

errno_t sbus_iterator_write_aS(DBusMessageIter *iterator,
                               char **value);

errno_t sbus_iterator_write_ao(DBusMessageIter *iterator,
                               const char **value);

errno_t sbus_iterator_write_aO(DBusMessageIter *iterator,
                               char **value);

#endif /* _SBUS_ITERATOR_WRITERS_H_ */
