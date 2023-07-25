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
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/interface/sbus_iterator_readers.h"

static errno_t
sbus_iterator_read_basic(TALLOC_CTX *mem_ctx,
                         DBusMessageIter *iterator,
                         int dbus_type,
                         void *_value_ptr)
{
    int arg_type;
    char **strptr;
    char *str;

    arg_type = dbus_message_iter_get_arg_type(iterator);
    if (arg_type != dbus_type) {
        return ERR_SBUS_INVALID_TYPE;
    }

    dbus_message_iter_get_basic(iterator, _value_ptr);
    dbus_message_iter_next(iterator);

    switch (dbus_type) {
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
        strptr = (char**)_value_ptr;
        str = talloc_strdup(mem_ctx, *strptr);
        if (str == NULL) {
            return ENOMEM;
        }
        *strptr = str;
        break;
    default:
        break;
    }

    return EOK;
}

static errno_t
_sbus_iterator_read_basic_array(TALLOC_CTX *mem_ctx,
                                DBusMessageIter *iterator,
                                int dbus_type,
                                int element_size,
                                void **_value_ptr)
{
    DBusMessageIter subiter;
    uint8_t *arrayptr;
    void *array = NULL;
    int arg_type;
    int count;
    errno_t ret;
    int i;

    arg_type = dbus_message_iter_get_arg_type(iterator);
    if (arg_type != DBUS_TYPE_ARRAY) {
        ret = ERR_SBUS_INVALID_TYPE;
        goto done;
    }

    count = dbus_message_iter_get_element_count(iterator);
    dbus_message_iter_recurse(iterator, &subiter);

    /* NULL-terminated array for pointer types */
    switch (dbus_type) {
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
        array = talloc_zero_size(mem_ctx, (size_t)(count + 1) * element_size);
        if (array == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (count == 0) {
            array = NULL;
            ret = EOK;
            goto done;
        }
        break;
    default:
        if (count == 0) {
            array = NULL;
            ret = EOK;
            goto done;
        }

        array = talloc_zero_size(mem_ctx, (size_t)count * element_size);
        if (array == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    }

    arrayptr = array;
    for (i = 0; i < count; i++) {
        ret = sbus_iterator_read_basic(array, &subiter, dbus_type, arrayptr);
        if (ret != EOK) {
            talloc_free(array);
            goto done;
        }

        arrayptr += element_size;
    }

    ret = EOK;

done:
    /* Always step past the array. */
    dbus_message_iter_next(iterator);

    if (ret != EOK) {
        return ret;
    }

    *_value_ptr = array;

    return ret;
}

#define sbus_iterator_read_basic_array(mem_ctx, iterator, dbus_type, c_type, dest) \
    _sbus_iterator_read_basic_array((mem_ctx), (iterator), (dbus_type), \
                                    sizeof(c_type), (void**)(dest))

errno_t sbus_iterator_read_y(DBusMessageIter *iterator,
                             uint8_t *_value)
{
    return sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_BYTE, _value);
}

errno_t sbus_iterator_read_b(DBusMessageIter *iterator,
                             bool *_value)
{
    dbus_bool_t dbus_value;
    errno_t ret;

    ret = sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_BOOLEAN, &dbus_value);
    if (ret != EOK) {
        return ret;
    }

    *_value = dbus_value;

    return EOK;
}

errno_t sbus_iterator_read_n(DBusMessageIter *iterator,
                             int16_t *_value)
{
    dbus_int16_t dbus_value;
    errno_t ret;

    ret = sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_INT16, &dbus_value);
    if (ret != EOK) {
        return ret;
    }

    *_value = dbus_value;

    return EOK;
}

errno_t sbus_iterator_read_q(DBusMessageIter *iterator,
                             uint16_t *_value)
{
    dbus_uint16_t dbus_value;
    errno_t ret;

    ret = sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_UINT16, &dbus_value);
    if (ret != EOK) {
        return ret;
    }

    *_value = dbus_value;

    return EOK;
}

errno_t sbus_iterator_read_i(DBusMessageIter *iterator,
                             int32_t *_value)
{
    dbus_int32_t dbus_value;
    errno_t ret;

    ret = sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_INT32, &dbus_value);
    if (ret != EOK) {
        return ret;
    }

    *_value = dbus_value;

    return EOK;
}

errno_t sbus_iterator_read_u(DBusMessageIter *iterator,
                             uint32_t *_value)
{
    dbus_uint32_t dbus_value;
    errno_t ret;

    ret = sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_UINT32, &dbus_value);
    if (ret != EOK) {
        return ret;
    }

    *_value = dbus_value;

    return EOK;
}

errno_t sbus_iterator_read_x(DBusMessageIter *iterator,
                             int64_t *_value)
{
    dbus_int64_t dbus_value;
    errno_t ret;

    ret = sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_INT64, &dbus_value);
    if (ret != EOK) {
        return ret;
    }

    *_value = dbus_value;

    return EOK;
}

errno_t sbus_iterator_read_t(DBusMessageIter *iterator,
                             uint64_t *_value)
{
    dbus_uint64_t dbus_value;
    errno_t ret;

    ret = sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_UINT64, &dbus_value);
    if (ret != EOK) {
        return ret;
    }

    *_value = dbus_value;

    return EOK;
}

errno_t sbus_iterator_read_d(DBusMessageIter *iterator,
                             double *_value)
{
    return sbus_iterator_read_basic(NULL, iterator, DBUS_TYPE_DOUBLE, _value);
}

errno_t sbus_iterator_read_s(TALLOC_CTX *mem_ctx,
                             DBusMessageIter *iterator,
                             const char **_value)
{
    return sbus_iterator_read_basic(mem_ctx, iterator, DBUS_TYPE_STRING, _value);
}

errno_t sbus_iterator_read_S(TALLOC_CTX *mem_ctx,
                             DBusMessageIter *iterator,
                             char **_value)
{
    return sbus_iterator_read_basic(mem_ctx, iterator, DBUS_TYPE_STRING, _value);
}

errno_t sbus_iterator_read_o(TALLOC_CTX *mem_ctx,
                             DBusMessageIter *iterator,
                             const char **_value)
{
    return sbus_iterator_read_basic(mem_ctx, iterator, DBUS_TYPE_OBJECT_PATH, _value);
}

errno_t sbus_iterator_read_O(TALLOC_CTX *mem_ctx,
                             DBusMessageIter *iterator,
                             char **_value)
{
    return sbus_iterator_read_basic(mem_ctx, iterator, DBUS_TYPE_OBJECT_PATH, _value);
}

errno_t sbus_iterator_read_ay(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              uint8_t **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_BYTE,
                                          uint8_t, _value);
}

errno_t sbus_iterator_read_ab(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              bool **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_BOOLEAN,
                                          uint8_t, _value);
}

errno_t sbus_iterator_read_an(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              int16_t **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_INT16,
                                          int16_t, _value);
}

errno_t sbus_iterator_read_aq(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              uint16_t **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_UINT16,
                                          uint16_t, _value);
}

errno_t sbus_iterator_read_ai(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              int32_t **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_INT32,
                                          int32_t, _value);
}

errno_t sbus_iterator_read_au(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              uint32_t **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_UINT32,
                                          uint32_t, _value);
}

errno_t sbus_iterator_read_ax(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              int64_t **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_INT64,
                                          int64_t, _value);
}

errno_t sbus_iterator_read_at(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              uint64_t **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_UINT64,
                                          uint64_t, _value);
}

errno_t sbus_iterator_read_ad(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              double **_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_DOUBLE,
                                          double, _value);
}

errno_t sbus_iterator_read_as(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              const char ***_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_STRING,
                                          const char *, _value);
}

errno_t sbus_iterator_read_aS(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              char ***_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_STRING,
                                          char *, _value);
}

errno_t sbus_iterator_read_ao(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              const char ***_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_OBJECT_PATH,
                                          const char *, _value);
}

errno_t sbus_iterator_read_aO(TALLOC_CTX *mem_ctx,
                              DBusMessageIter *iterator,
                              char ***_value)
{
    return sbus_iterator_read_basic_array(mem_ctx, iterator,
                                          DBUS_TYPE_OBJECT_PATH,
                                          char *, _value);
}
