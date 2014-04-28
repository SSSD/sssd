/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <string.h>

#include "lib/sifp/sss_sifp.h"
#include "lib/sifp/sss_sifp_private.h"

#define GET_ATTR(attrs, name, rtype, field, out) do {                       \
    sss_sifp_attr *attr = sss_sifp_find_attr(attrs, name);                  \
                                                                            \
    if (attr == NULL) {                                                     \
        return SSS_SIFP_ATTR_MISSING;                                       \
    }                                                                       \
                                                                            \
    if (attr->type != rtype) {                                              \
        return SSS_SIFP_INCORRECT_TYPE;                                     \
    }                                                                       \
                                                                            \
    if (attr->data.field == NULL) {                                         \
        return SSS_SIFP_ATTR_NULL;                                          \
    }                                                                       \
                                                                            \
    out = attr->data.field[0];                                              \
} while (0)

#define GET_ATTR_ARRAY(attrs, name, rtype, field, out_num, out_val) do {    \
    sss_sifp_attr *attr = sss_sifp_find_attr(attrs, name);                  \
                                                                            \
    if (attr == NULL) {                                                     \
        return SSS_SIFP_ATTR_MISSING;                                       \
    }                                                                       \
                                                                            \
    if (attr->type != rtype) {                                              \
        return SSS_SIFP_INCORRECT_TYPE;                                     \
    }                                                                       \
                                                                            \
    if (attr->data.field == NULL) {                                         \
        return SSS_SIFP_ATTR_NULL;                                          \
    }                                                                       \
                                                                            \
    out_num = attr->num_values;                                             \
    out_val = attr->data.field;                                             \
} while (0)

static sss_sifp_attr *sss_sifp_find_attr(sss_sifp_attr **attrs,
                                         const char *name)
{
    int i;

    if (attrs == NULL || name == NULL) {
        return NULL;
    }

    for (i = 0; attrs[i] != NULL; i++) {
        if (strcmp(attrs[i]->name, name) == 0) {
            return attrs[i];
        }
    }

    return NULL;
}

sss_sifp_error
sss_sifp_find_attr_as_bool(sss_sifp_attr **attrs,
                           const char *name,
                           bool *_value)
{
    GET_ATTR(attrs, name, SSS_SIFP_ATTR_TYPE_BOOL, boolean, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_int16(sss_sifp_attr **attrs,
                            const char *name,
                            int16_t *_value)
{
    GET_ATTR(attrs, name, SSS_SIFP_ATTR_TYPE_INT16, int16, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_uint16(sss_sifp_attr **attrs,
                             const char *name,
                             uint16_t *_value)
{
    GET_ATTR(attrs, name, SSS_SIFP_ATTR_TYPE_UINT16, uint16, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_int32(sss_sifp_attr **attrs,
                            const char *name,
                            int32_t *_value)
{
    GET_ATTR(attrs, name, SSS_SIFP_ATTR_TYPE_INT32, int32, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_uint32(sss_sifp_attr **attrs,
                             const char *name,
                             uint32_t *_value)
{
    GET_ATTR(attrs, name, SSS_SIFP_ATTR_TYPE_UINT32, uint32, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_int64(sss_sifp_attr **attrs,
                            const char *name,
                            int64_t *_value)
{
    GET_ATTR(attrs, name, SSS_SIFP_ATTR_TYPE_INT64, int64, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_uint64(sss_sifp_attr **attrs,
                             const char *name,
                             uint64_t *_value)
{
    GET_ATTR(attrs, name, SSS_SIFP_ATTR_TYPE_UINT64, uint64, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_string(sss_sifp_attr **attrs,
                             const char *name,
                             const char **_value)
{
    const char *value = NULL;

    GET_ATTR(attrs, name, SSS_SIFP_ATTR_TYPE_STRING, str, value);

    if (value == NULL) {
        return SSS_SIFP_ATTR_NULL;
    }

    *_value = value;
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_string_dict(sss_sifp_attr **attrs,
                                  const char *name,
                                  hash_table_t **_value)
{
    sss_sifp_attr *attr = sss_sifp_find_attr(attrs, name);

    if (attr == NULL) {
        return SSS_SIFP_ATTR_MISSING;
    }

    if (attr->type != SSS_SIFP_ATTR_TYPE_STRING_DICT) {
        return SSS_SIFP_INCORRECT_TYPE;
    }

    if (attr->data.str_dict == NULL) {
        return SSS_SIFP_ATTR_NULL;
    }

    *_value = attr->data.str_dict;

    return SSS_SIFP_OK;
}

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 *
 * @return Attribute values or NULL if it is not found.
 */
sss_sifp_error
sss_sifp_find_attr_as_bool_array(sss_sifp_attr **attrs,
                                 const char *name,
                                 unsigned int *_num_values,
                                 bool **_value)
{
    GET_ATTR_ARRAY(attrs, name, SSS_SIFP_ATTR_TYPE_BOOL, boolean,
                   *_num_values, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_int16_array(sss_sifp_attr **attrs,
                                  const char *name,
                                  unsigned int *_num_values,
                                  int16_t **_value)
{
    GET_ATTR_ARRAY(attrs, name, SSS_SIFP_ATTR_TYPE_INT16, int16,
                   *_num_values, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_uint16_array(sss_sifp_attr **attrs,
                                   const char *name,
                                   unsigned int *_num_values,
                                   uint16_t **_value)
{
    GET_ATTR_ARRAY(attrs, name, SSS_SIFP_ATTR_TYPE_UINT16, uint16,
                   *_num_values, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_int32_array(sss_sifp_attr **attrs,
                                  const char *name,
                                  unsigned int *_num_values,
                                  int32_t **_value)
{
    GET_ATTR_ARRAY(attrs, name, SSS_SIFP_ATTR_TYPE_INT32, int32,
                   *_num_values, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_uint32_array(sss_sifp_attr **attrs,
                                   const char *name,
                                   unsigned int *_num_values,
                                   uint32_t **_value)
{
    GET_ATTR_ARRAY(attrs, name, SSS_SIFP_ATTR_TYPE_UINT32, uint32,
                   *_num_values, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_int64_array(sss_sifp_attr **attrs,
                                  const char *name,
                                  unsigned int *_num_values,
                                  int64_t **_value)
{
    GET_ATTR_ARRAY(attrs, name, SSS_SIFP_ATTR_TYPE_INT64, int64,
                   *_num_values, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_uint64_array(sss_sifp_attr **attrs,
                                   const char *name,
                                   unsigned int *_num_values,
                                   uint64_t **_value)
{
    GET_ATTR_ARRAY(attrs, name, SSS_SIFP_ATTR_TYPE_UINT64, uint64,
                   *_num_values, *_value);
    return SSS_SIFP_OK;
}

sss_sifp_error
sss_sifp_find_attr_as_string_array(sss_sifp_attr **attrs,
                                   const char *name,
                                   unsigned int *_num_values,
                                   const char * const **_value)
{
    char **value;

    GET_ATTR_ARRAY(attrs, name, SSS_SIFP_ATTR_TYPE_STRING, str,
                   *_num_values, value);
    *_value = (const char * const *)value;

    return SSS_SIFP_OK;
}
