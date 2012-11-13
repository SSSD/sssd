/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "sss_client/sss_cli.h"
#include "sss_client/sudo/sss_sudo.h"
#include "sss_client/sudo/sss_sudo_private.h"

static int sss_sudo_parse_rule(const char *message,
                               size_t message_len,
                               size_t *_cursor,
                               struct sss_sudo_rule *_rule);

static int sss_sudo_parse_attr(const char *message,
                               size_t message_len,
                               size_t *_cursor,
                               struct sss_sudo_attr *_attr);

static int sss_sudo_parse_uint32(const char *message,
                                 size_t message_len,
                                 size_t *_cursor,
                                 uint32_t *_number);

static int sss_sudo_parse_string(const char *message,
                                 size_t message_len,
                                 size_t *_cursor,
                                 char **_str);

int sss_sudo_parse_response(const char *message,
                            size_t message_len,
                            char **_domainname,
                            struct sss_sudo_result **_result,
                            uint32_t *_error)
{
    struct sss_sudo_result *result = NULL;
    char *domainname = NULL;
    size_t cursor = 0;
    int ret = EOK;
    int i = 0;

    /* error code */
    ret = sss_sudo_parse_uint32(message, message_len, &cursor, _error);
    if (ret != EOK || *_error != SSS_SUDO_ERROR_OK) {
        return ret;
    }

    /* domain name - deprecated
     * it won't be used, but we will read it anyway to ease parsing
     * TODO: when possible change the protocol */
    ret = sss_sudo_parse_string(message, message_len, &cursor, &domainname);
    if (ret != EOK) {
        return ret;
    }

    free(domainname);
    if (_domainname != NULL) {
        *_domainname = NULL;
    }

    /* result */
    result = malloc(sizeof(struct sss_sudo_result));
    if (result == NULL) {
        return ENOMEM;
    }

    memset(result, 0, sizeof(struct sss_sudo_result));

    /* rules_num */
    ret = sss_sudo_parse_uint32(message, message_len,
                                &cursor, &result->num_rules);
    if (ret != EOK) {
        goto fail;
    }

    /* rules */
    result->rules = calloc(result->num_rules, sizeof(struct sss_sudo_rule));
    if (result->rules == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    for (i = 0; i < result->num_rules; i++) {
        ret = sss_sudo_parse_rule(message, message_len,
                                  &cursor, &result->rules[i]);
        if (ret != EOK) {
            goto fail;
        }
    }

    *_result = result;

    return EOK;

fail:
    sss_sudo_free_result(result);
    return ret;
}

int sss_sudo_parse_rule(const char *message,
                        size_t message_len,
                        size_t *_cursor,
                        struct sss_sudo_rule *_rule)
{
    int ret = EOK;
    int i = 0;

    /* attrs_num */
    ret = sss_sudo_parse_uint32(message, message_len,
                                _cursor, &_rule->num_attrs);
    if (ret != EOK) {
       return ret;
    }

    /* attrs */
    _rule->attrs = calloc(_rule->num_attrs, sizeof(struct sss_sudo_attr));
    if (_rule->attrs == NULL) {
        return ENOMEM;
    }

    for (i = 0; i < _rule->num_attrs; i++) {
        ret = sss_sudo_parse_attr(message, message_len,
                                  _cursor, &_rule->attrs[i]);
        if (ret != EOK) {
           return ret;
        }
    }

    return EOK;
}

int sss_sudo_parse_attr(const char *message,
                        size_t message_len,
                        size_t *_cursor,
                        struct sss_sudo_attr *_attr)
{
    char *str = NULL;
    int ret = EOK;
    int i = 0;

    /* name */
    ret = sss_sudo_parse_string(message, message_len, _cursor, &str);
    if (ret != EOK) {
        return ret;
    }
    _attr->name = str;

    /* values_num */
    ret = sss_sudo_parse_uint32(message, message_len,
                                _cursor, &_attr->num_values);
    if (ret != EOK) {
        return ret;
    }

    /* values */
    _attr->values = calloc(_attr->num_values, sizeof(const char*));
    if (_attr->values == NULL) {
        return ENOMEM;
    }

    for (i = 0; i < _attr->num_values; i++) {
        ret = sss_sudo_parse_string(message, message_len, _cursor, &str);
        if (ret != EOK) {
            return ret;
        }
        _attr->values[i] = str;
    }

    return EOK;
}

int sss_sudo_parse_uint32(const char *message,
                          size_t message_len,
                          size_t *_cursor,
                          uint32_t *_number)
{
   size_t start_pos = 0;

    if (_cursor == NULL) {
       return EINVAL;
    }

    start_pos = *_cursor;

    if (start_pos + sizeof(uint32_t) > message_len) {
        return EINVAL;
    }

    /* expanded SAFEALIGN_COPY_UINT32 macro from util.h */
    memcpy(_number, message + start_pos, sizeof(uint32_t));
    *_cursor = start_pos + sizeof(uint32_t);

    return EOK;
}

int sss_sudo_parse_string(const char *message,
                          size_t message_len,
                          size_t *_cursor,
                          char **_str)
{
    const char *current = NULL;
    char *str = NULL;
    size_t start_pos = 0;
    size_t len = 0;
    size_t maxlen = 0;

    if (_cursor == NULL) {
       return EINVAL;
    }

    start_pos = *_cursor;
    maxlen = message_len - start_pos;

    if (start_pos >= message_len ) {
        return EINVAL;
    }

    current = message + start_pos;
    len = strnlen(current, maxlen);
    if (len == maxlen) {
        /* the string exceeds message length */
        return EINVAL;
    }

    str = strndup(current, len);
    if (str == NULL) {
        return ENOMEM;
    }

    /* go after \0 */
    *_cursor = start_pos + len + 1;
    *_str = str;

    return EOK;
}
