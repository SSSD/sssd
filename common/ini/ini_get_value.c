/*
    INI LIBRARY

    Value interpretation functions for single values
    and corresponding memory cleanup functions.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2010

    INI Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    INI Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with INI Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "config.h"
#include "trace.h"
#include "collection.h"
#include "collection_tools.h"
#include "ini_defines.h"
#include "ini_config.h"

/* Function to get value from the configuration handle */
int get_config_item(const char *section,
                    const char *name,
                    struct collection_item *ini_config,
                    struct collection_item **item)
{
    int error = EOK;
    struct collection_item *section_handle = NULL;
    const char *to_find;
    char default_section[] = INI_DEFAULT_SECTION;

    TRACE_FLOW_STRING("get_config_item", "Entry");

    /* Do we have the accepting memory ? */
    if (item == NULL) {
        TRACE_ERROR_NUMBER("No buffer - invalid argument.", EINVAL);
        return EINVAL;
    }

    /* Is the collection of a right type */
    if ((col_is_of_class(ini_config, COL_CLASS_INI_CONFIG) == 0) &&
        (col_is_of_class(ini_config, COL_CLASS_INI_META) == 0)) {
        TRACE_ERROR_NUMBER("Wrong collection type", EINVAL);
        return EINVAL;
    }

    *item = NULL;

    if (section == NULL) to_find = default_section;
    else to_find = section;

    TRACE_INFO_STRING("Getting Name:", name);
    TRACE_INFO_STRING("In Section:", section);

    /* Get Subcollection */
    error = col_get_collection_reference(ini_config, &section_handle, to_find);
    /* Check error */
    if (error && (error != ENOENT)) {
        TRACE_ERROR_NUMBER("Failed to get section", error);
        return error;
    }

    /* Did we find a section */
    if ((error == ENOENT) || (section_handle == NULL)) {
        /* We have not found section - return success */
        TRACE_FLOW_STRING("get_value_from_config", "No such section");
        return EOK;
    }

    /* Get item */
    error = col_get_item(section_handle, name,
                         COL_TYPE_STRING, COL_TRAVERSE_ONELEVEL, item);

    /* Make sure we free the section we found */
    col_destroy_collection(section_handle);

    TRACE_FLOW_NUMBER("get_config_item returning", error);
    return error;
}

/* Get long long value from config item */
static long long get_llong_config_value(struct collection_item *item,
                                        int strict,
                                        long long def,
                                        int *error)
{
    int err;
    const char *str;
    char *endptr;
    long long val = 0;

    TRACE_FLOW_STRING("get_llong_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
       (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    /* Try to parse the value */
    str = (const char *)col_get_item_data(item);
    errno = 0;
    val = strtoll(str, &endptr, 10);
    err = errno;

    /* Check for various possible errors */
    if (err != 0) {
        TRACE_ERROR_NUMBER("Conversion failed", err);
        if (error) *error = err;
        return def;
    }

    /* Other error cases */
    if ((endptr == str) || (strict && (*endptr != '\0'))) {
        TRACE_ERROR_NUMBER("More characters or nothing processed", EIO);
        if (error) *error = EIO;
        return def;
    }

    TRACE_FLOW_NUMBER("get_llong_config_value returning", (long)val);
    return val;
}

/* Get unsigned long long value from config item */
static unsigned long long get_ullong_config_value(struct collection_item *item,
                                                  int strict,
                                                  unsigned long long def,
                                                  int *error)
{
    int err;
    const char *str;
    char *endptr;
    unsigned long long val = 0;

    TRACE_FLOW_STRING("get_ullong_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
       (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    /* Try to parse the value */
    str = (const char *)col_get_item_data(item);
    errno = 0;
    val = strtoull(str, &endptr, 10);
    err = errno;

    /* Check for various possible errors */
    if (err != 0) {
        TRACE_ERROR_NUMBER("Conversion failed", err);
        if (error) *error = err;
        return def;
    }

    /* Other error cases */
    if ((endptr == str) || (strict && (*endptr != '\0'))) {
        TRACE_ERROR_NUMBER("More characters or nothing processed", EIO);
        if (error) *error = EIO;
        return def;
    }

    TRACE_FLOW_NUMBER("get_ullong_config_value returning", val);
    return val;
}


/* Get integer value from config item */
int get_int_config_value(struct collection_item *item,
                         int strict,
                         int def,
                         int *error)
{
    long long val = 0;
    int err = 0;

    TRACE_FLOW_STRING("get_int_config_value", "Entry");

    val = get_llong_config_value(item, strict, def, &err);
    if (err == 0) {
        if ((val > INT_MAX) || (val < INT_MIN)) {
            val = def;
            err = ERANGE;
        }
    }

    if (error) *error = err;

    TRACE_FLOW_NUMBER("get_int_config_value returning", (int)val);
    return (int)val;
}

/* Get unsigned integer value from config item */
unsigned get_unsigned_config_value(struct collection_item *item,
                                   int strict,
                                   unsigned def,
                                   int *error)
{
    unsigned long long val = 0;
    int err = 0;

    TRACE_FLOW_STRING("get_unsigned_config_value", "Entry");

    val = get_ullong_config_value(item, strict, def, &err);
    if (err == 0) {
        if (val > UINT_MAX) {
            val = def;
            err = ERANGE;
        }
    }

    if (error) *error = err;

    TRACE_FLOW_NUMBER("get_unsigned_config_value returning",
                      (unsigned)val);
    return (unsigned)val;
}

/* Get long value from config item */
long get_long_config_value(struct collection_item *item,
                           int strict,
                           long def,
                           int *error)
{
    long long val = 0;
    int err = 0;

    TRACE_FLOW_STRING("get_long_config_value", "Entry");

    val = get_llong_config_value(item, strict, def, &err);
    if (err == 0) {
        if ((val > LONG_MAX) || (val < LONG_MIN)) {
            val = def;
            err = ERANGE;
        }
    }

    if (error) *error = err;

    TRACE_FLOW_NUMBER("get_long_config_value returning",
                      (long)val);
    return (long)val;
}

/* Get unsigned long value from config item */
unsigned long get_ulong_config_value(struct collection_item *item,
                                     int strict,
                                     unsigned long def,
                                     int *error)
{
    unsigned long long val = 0;
    int err = 0;

    TRACE_FLOW_STRING("get_ulong_config_value", "Entry");

    val = get_ullong_config_value(item, strict, def, &err);
    if (err == 0) {
        if (val > ULONG_MAX) {
            val = def;
            err = ERANGE;
        }
    }

    if (error) *error = err;

    TRACE_FLOW_NUMBER("get_ulong_config_value returning",
                      (unsigned long)val);
    return (unsigned long)val;
}

/* Get int32_t value from config item */
int32_t get_int32_config_value(struct collection_item *item,
                               int strict,
                               int32_t def,
                               int *error)
{
    int val = 0;

    TRACE_FLOW_STRING("get_int32_config_value", "Entry");

    val = get_int_config_value(item, strict, (int)def, error);

    TRACE_FLOW_SNUMBER("get_int32_config_value returning", (int32_t)val);
    return (int32_t)val;
}

/* Get uint32_t value from config item */
uint32_t get_uint32_config_value(struct collection_item *item,
                                 int strict,
                                 uint32_t def,
                                 int *error)
{
    unsigned val = 0;

    TRACE_FLOW_STRING("get_uint32_config_value", "Entry");

    val = get_unsigned_config_value(item, strict, (unsigned)def, error);

    TRACE_FLOW_NUMBER("get_uint32_config_value returning", (uint32_t)val);
    return (uint32_t)val;
}

/* Get int64_t value from config item */
int64_t get_int64_config_value(struct collection_item *item,
                               int strict,
                               int64_t def,
                               int *error)
{
    long long val = 0;

    TRACE_FLOW_STRING("get_int64_config_value", "Entry");

    val = get_llong_config_value(item, strict, (long long)def, error);

    TRACE_FLOW_SLNUMBER("get_int64_config_value returning", (int64_t)val);
    return (int64_t)val;
}

/* Get uint64_t value from config item */
uint64_t get_uint64_config_value(struct collection_item *item,
                                 int strict,
                                 uint64_t def,
                                 int *error)
{
    unsigned long long val = 0;

    TRACE_FLOW_STRING("get_uint64_config_value", "Entry");

    val = get_ullong_config_value(item,
                                  strict,
                                  (unsigned long long)def,
                                  error);

    TRACE_FLOW_LNUMBER("get_uint64_config_value returning", (uint64_t)val);
    return (uint64_t)val;
}

/* Get double value */
double get_double_config_value(struct collection_item *item,
                               int strict, double def, int *error)
{
    const char *str;
    char *endptr;
    double val = 0;

    TRACE_FLOW_STRING("get_double_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    /* Try to parse the value */
    str = (const char *)col_get_item_data(item);
    errno = 0;
    val = strtod(str, &endptr);

    /* Check for various possible errors */
    if ((errno == ERANGE) ||
        ((errno != 0) && (val == 0)) ||
        (endptr == str)) {
        TRACE_ERROR_NUMBER("Conversion failed", EIO);
        if (error) *error = EIO;
        return def;
    }

    if (strict && (*endptr != '\0')) {
        TRACE_ERROR_NUMBER("More characters than expected", EIO);
        if (error) *error = EIO;
        val = def;
    }

    TRACE_FLOW_DOUBLE("get_double_config_value returning", val);
    return val;
}

/* Get boolean value */
unsigned char get_bool_config_value(struct collection_item *item,
                                    unsigned char def, int *error)
{
    const char *str;
    int len;

    TRACE_FLOW_STRING("get_bool_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    str = (const char *)col_get_item_data(item);
    len = col_get_item_length(item);

    /* Try to parse the value */
    if ((strncasecmp(str, "true", len) == 0) ||
        (strncasecmp(str, "yes", len) == 0)) {
        TRACE_FLOW_STRING("Returning", "true");
        return '\1';
    }
    else if ((strncasecmp(str, "false", len) == 0) ||
             (strncasecmp(str, "no", len) == 0)) {
        TRACE_FLOW_STRING("Returning", "false");
        return '\0';
    }

    TRACE_ERROR_STRING("Returning", "error");
    if (error) *error = EIO;
    return def;
}

/* Return a string out of the value */
char *get_string_config_value(struct collection_item *item,
                              int *error)
{
    char *str = NULL;

    TRACE_FLOW_STRING("get_string_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    str = strdup((const char *)col_get_item_data(item));
    if (str == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    if (error) *error = EOK;

    TRACE_FLOW_STRING("get_string_config_value returning", str);
    return str;
}

/* Get string from item */
const char *get_const_string_config_value(struct collection_item *item, int *error)
{
    const char *str;

    TRACE_FLOW_STRING("get_const_string_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    str = (const char *)col_get_item_data(item);

    if (error) *error = EOK;

    TRACE_FLOW_STRING("get_const_string_config_value returning", str);
    return str;
}

/* A special hex format is assumed.
 * The string should be taken in single quotes
 * and consist of hex encoded value two hex digits per byte.
 * Example: '0A2BFECC'
 * Case does not matter.
 */
char *get_bin_config_value(struct collection_item *item,
                           int *length, int *error)
{
    int i;
    char *value = NULL;
    const char *buff;
    int size = 0;
    unsigned char hex;
    int len;
    const char *str;

    TRACE_FLOW_STRING("get_bin_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Check the length */
    len = col_get_item_length(item)-1;
    if ((len%2) != 0) {
        TRACE_ERROR_STRING("Invalid length for binary data", "");
        if (error) *error = EINVAL;
        return NULL;
    }

    str = (const char *)col_get_item_data(item);

    /* Is the format correct ? */
    if ((*str != '\'') ||
        (str[len -1] != '\'')) {
        TRACE_ERROR_STRING("String is not escaped","");
        if (error) *error = EIO;
        return NULL;
    }

    /* Check that all the symbols are ok */
    buff = str + 1;
    len -= 2;
    for (i = 0; i < len; i += 2) {
        if (!isxdigit(buff[i]) || !isxdigit(buff[i + 1])) {
            TRACE_ERROR_STRING("Invalid encoding for binary data", buff + i);
            if (error) *error = EIO;
            return NULL;
        }
    }

    /* The value is good so we can allocate memory for it */
    value = malloc(len / 2);
    if (value == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    /* Convert the value */
    for (i = 0; i < len; i += 2) {
        if (isdigit(buff[i])) {
            if (isdigit(buff[i+1]))
                hex = 16 * (buff[i] - '0') + (buff[i+1] - '0');
            else
                hex = 16 * (buff[i] - '0') + (tolower(buff[i+1]) - 'a' + 10);
        }
        else {
            if (isdigit(buff[i+1]))
                hex = 16 * (tolower(buff[i]) - 'a') + (buff[i+1] - '0');
            else
                hex = 16 * (tolower(buff[i]) - 'a' + 10) + (tolower(buff[i+1]) - 'a' + 10);
        }

        value[size] = (char)(hex);
        size++;
    }

    if (error) *error = EOK;
    if (length) *length = size;
    TRACE_FLOW_STRING("get_bin_config_value", "Exit");
    return value;
}

/* Function to free binary configuration value */
void free_bin_config_value(char *value)
{
    if (value) free(value);
}
