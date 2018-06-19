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

#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/sss_utf8.h"
#include "sbus/interface/sbus_iterator_writers.h"

static errno_t
sbus_iterator_write_basic(DBusMessageIter *iterator,
                          int dbus_type,
                          void *value_ptr)
{
    dbus_bool_t ret;

    ret = dbus_message_iter_append_basic(iterator, dbus_type, value_ptr);

    return ret ? EOK : EIO;
}

static errno_t
sbus_iterator_write_string(DBusMessageIter *iterator,
                           int dbus_type,
                           const char *value,
                           const char *default_value)
{
    dbus_bool_t ret;
    bool is_valid;

    /* If the value is not set, we will provide a correct default value. */
    value = value == NULL ? default_value : value;

    /* D-Bus is not capable of sending NULL string. If even the default value
     * was not set, we return an error. */
    if (value == NULL) {
        return ERR_SBUS_EMPTY_STRING;
    }

    /* D-Bus can send only correct UTF-8 strings. */
    is_valid = sss_utf8_check((const uint8_t *)value, strlen(value));
    if (!is_valid) {
          DEBUG(SSSDBG_CRIT_FAILURE, "String with non-utf8 characters was "
                "given [%s]\n", value);
        return ERR_SBUS_INVALID_STRING;
    }

    ret = dbus_message_iter_append_basic(iterator, dbus_type, &value);

    return ret ? EOK : EIO;
}

static errno_t
sbus_iterator_write_string_elements(DBusMessageIter *iterator,
                                    int dbus_type,
                                    const char **values)
{
    errno_t ret;
    int i;

    if (values == NULL) {
        return EOK;
    }

    /* String arrays are NULL-terminated. */
    for (i = 0; values[i] != NULL; i++) {
        ret = sbus_iterator_write_string(iterator, dbus_type, values[i], NULL);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

static errno_t
sbus_iterator_write_fixed_elements(DBusMessageIter *iterator,
                                   int dbus_type,
                                   int element_size,
                                   int array_length,
                                   void *value_ptr)
{
    errno_t ret;
    uint8_t *element_ptr;
    int count;
    int i;

    element_ptr = value_ptr;
    if (array_length < 0) {
        count = talloc_get_size(value_ptr) / element_size;
    } else {
        count = array_length;
    }


    for (i = 0; i < count; i++) {
        ret = sbus_iterator_write_basic(iterator, dbus_type, element_ptr);
        if (ret != EOK) {
            return ret;
        }

        element_ptr += element_size;
    }

    return EOK;
}

errno_t
_sbus_iterator_write_basic_array(DBusMessageIter *iterator,
                                 int dbus_type,
                                 int element_size,
                                 int array_length,
                                 void *value_ptr)
{
    const char array_type[2] = {dbus_type, '\0'};
    DBusMessageIter arrayiter;
    dbus_bool_t dbret;
    errno_t ret;

    dbret = dbus_message_iter_open_container(iterator, DBUS_TYPE_ARRAY,
                                             array_type, &arrayiter);
    if (!dbret) {
        return EIO;
    }

    switch (dbus_type) {
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
        ret = sbus_iterator_write_string_elements(&arrayiter, dbus_type,
                                                  (const char **)value_ptr);
        if (ret != EOK) {
            goto done;
        }
        break;
    default:
        ret = sbus_iterator_write_fixed_elements(&arrayiter, dbus_type,
                                                 element_size, array_length,
                                                 value_ptr);
        if (ret != EOK) {
            goto done;
        }
        break;
    }

    dbret = dbus_message_iter_close_container(iterator, &arrayiter);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        dbus_message_iter_abandon_container(iterator, &arrayiter);
    }

    return ret;
}

errno_t sbus_iterator_write_y(DBusMessageIter *iterator,
                              uint8_t value)
{
    return sbus_iterator_write_basic(iterator, DBUS_TYPE_BYTE, &value);
}

errno_t sbus_iterator_write_b(DBusMessageIter *iterator,
                              bool value)
{
    dbus_bool_t dbus_value = value;

    return sbus_iterator_write_basic(iterator, DBUS_TYPE_BOOLEAN, &dbus_value);
}

errno_t sbus_iterator_write_n(DBusMessageIter *iterator,
                              int16_t value)
{
    dbus_int16_t dbus_value = value;

    return sbus_iterator_write_basic(iterator, DBUS_TYPE_INT16, &dbus_value);
}

errno_t sbus_iterator_write_q(DBusMessageIter *iterator,
                              uint16_t value)
{
    dbus_uint16_t dbus_value = value;

    return sbus_iterator_write_basic(iterator, DBUS_TYPE_UINT16, &dbus_value);
}

errno_t sbus_iterator_write_i(DBusMessageIter *iterator,
                              int32_t value)
{
    dbus_int32_t dbus_value = value;

    return sbus_iterator_write_basic(iterator, DBUS_TYPE_INT32, &dbus_value);
}

errno_t sbus_iterator_write_u(DBusMessageIter *iterator,
                              uint32_t value)
{
    dbus_uint32_t dbus_value = value;

    return sbus_iterator_write_basic(iterator, DBUS_TYPE_UINT32, &dbus_value);
}

errno_t sbus_iterator_write_x(DBusMessageIter *iterator,
                              int64_t value)
{
    dbus_int64_t dbus_value = value;

    return sbus_iterator_write_basic(iterator, DBUS_TYPE_INT64, &dbus_value);
}

errno_t sbus_iterator_write_t(DBusMessageIter *iterator,
                              uint64_t value)
{
    dbus_uint64_t dbus_value = value;

    return sbus_iterator_write_basic(iterator, DBUS_TYPE_UINT64, &dbus_value);
}

errno_t sbus_iterator_write_d(DBusMessageIter *iterator,
                              double value)
{
    return sbus_iterator_write_basic(iterator, DBUS_TYPE_DOUBLE, &value);
}

errno_t sbus_iterator_write_s(DBusMessageIter *iterator,
                              const char *value)
{
    return sbus_iterator_write_string(iterator, DBUS_TYPE_STRING, value, "");
}

errno_t sbus_iterator_write_S(DBusMessageIter *iterator,
                              char *value)
{
    return sbus_iterator_write_string(iterator, DBUS_TYPE_STRING, value, "");
}

errno_t sbus_iterator_write_o(DBusMessageIter *iterator,
                              const char *value)
{
    return sbus_iterator_write_string(iterator, DBUS_TYPE_OBJECT_PATH,
                                      value, "/");
}

errno_t sbus_iterator_write_O(DBusMessageIter *iterator,
                              char *value)
{
    return sbus_iterator_write_string(iterator, DBUS_TYPE_OBJECT_PATH,
                                      value, "/");
}

errno_t sbus_iterator_write_ay(DBusMessageIter *iterator,
                               uint8_t *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_BYTE,
                                           uint8_t, value);
}

errno_t sbus_iterator_write_ab(DBusMessageIter *iterator,
                               bool *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_BOOLEAN,
                                           bool, value);
}

errno_t sbus_iterator_write_an(DBusMessageIter *iterator,
                               int16_t *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_INT16,
                                           int16_t, value);
}

errno_t sbus_iterator_write_aq(DBusMessageIter *iterator,
                               uint16_t *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_UINT16,
                                           uint16_t, value);
}

errno_t sbus_iterator_write_ai(DBusMessageIter *iterator,
                               int32_t *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_INT32,
                                           int32_t, value);
}

errno_t sbus_iterator_write_au(DBusMessageIter *iterator,
                               uint32_t *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_UINT32,
                                           uint32_t, value);
}

errno_t sbus_iterator_write_ax(DBusMessageIter *iterator,
                               int64_t *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_INT64,
                                           int64_t, value);
}

errno_t sbus_iterator_write_at(DBusMessageIter *iterator,
                               uint64_t *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_UINT64,
                                           uint64_t, value);
}

errno_t sbus_iterator_write_ad(DBusMessageIter *iterator,
                               double *value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_DOUBLE,
                                           double, value);
}

errno_t sbus_iterator_write_as(DBusMessageIter *iterator,
                               const char **value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_STRING,
                                           const char *, value);
}

errno_t sbus_iterator_write_aS(DBusMessageIter *iterator,
                               char **value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_STRING,
                                           char *, value);
}

errno_t sbus_iterator_write_ao(DBusMessageIter *iterator,
                               const char **value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_OBJECT_PATH,
                                           const char *, value);
}

errno_t sbus_iterator_write_aO(DBusMessageIter *iterator,
                               char **value)
{
    return sbus_iterator_write_basic_array(iterator, DBUS_TYPE_OBJECT_PATH,
                                           char *, value);
}
