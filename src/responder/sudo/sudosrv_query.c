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

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <talloc.h>
#include <tevent.h>

#include "util/util.h"
#include "responder/sudo/sudosrv_private.h"

static int sudosrv_response_append_string(TALLOC_CTX *mem_ctx,
                                          const char *str,
                                          size_t str_len,
                                          uint8_t **_response_body,
                                          size_t *_response_len)
{
    size_t response_len = *_response_len;
    uint8_t *response_body = *_response_body;

    response_body = talloc_realloc(mem_ctx, response_body, uint8_t,
                                   response_len + (str_len * sizeof(char)));
    if (response_body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_realloc() failed\n");
        return ENOMEM;
    }
    memcpy(response_body + response_len, str, str_len);
    response_len += str_len;

    *_response_body = response_body;
    *_response_len = response_len;

    return EOK;
}

static int sudosrv_response_append_uint32(TALLOC_CTX *mem_ctx,
                                          uint32_t number,
                                          uint8_t **_response_body,
                                          size_t *_response_len)
{
    size_t response_len = *_response_len;
    uint8_t *response_body = *_response_body;

    response_body = talloc_realloc(mem_ctx, response_body, uint8_t,
                                   response_len + sizeof(uint32_t));
    if (response_body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_realloc() failed\n");
        return ENOMEM;
    }
    SAFEALIGN_SET_UINT32(response_body + response_len, number, &response_len);

    *_response_body = response_body;
    *_response_len = response_len;

    return EOK;
}

static int sudosrv_response_append_attr(TALLOC_CTX *mem_ctx,
                                        const char *name,
                                        unsigned int values_num,
                                        struct ldb_val *values,
                                        uint8_t **_response_body,
                                        size_t *_response_len)
{
    uint8_t *response_body = *_response_body;
    size_t response_len = *_response_len;
    TALLOC_CTX *tmp_ctx = NULL;
    unsigned int i = 0;
    int ret = EOK;
    const char *strval;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* attr name */
    ret = sudosrv_response_append_string(tmp_ctx, name, strlen(name) + 1,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto done;
    }

    /* values count */
    ret = sudosrv_response_append_uint32(tmp_ctx, values_num,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto done;
    }

    /* values */
    for (i = 0; i < values_num; i++) {
        strval = (const char *) values[i].data;

        if (strlen((strval)) != values[i].length) {
            DEBUG(SSSDBG_CRIT_FAILURE, "value is not a string\n");
            ret = EINVAL;
            goto done;
        }

        ret = sudosrv_response_append_string(tmp_ctx,
                                             strval,
                                             values[i].length + 1,
                                             &response_body, &response_len);
        DEBUG(SSSDBG_TRACE_INTERNAL, "%s:%s\n", name, strval);
        if (ret != EOK) {
            goto done;
        }
    }

    *_response_body = talloc_steal(mem_ctx, response_body);
    *_response_len = response_len;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int sudosrv_response_append_rule(TALLOC_CTX *mem_ctx,
                                        int attrs_num,
                                        struct ldb_message_element *attrs,
                                        uint8_t **_response_body,
                                        size_t *_response_len)
{
    uint8_t *response_body = *_response_body;
    size_t response_len = *_response_len;
    TALLOC_CTX *tmp_ctx = NULL;
    int i = 0;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* attrs count */
    ret = sudosrv_response_append_uint32(tmp_ctx, attrs_num,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto done;
    }

    /* attrs */
    for (i = 0; i < attrs_num; i++) {
        ret = sudosrv_response_append_attr(tmp_ctx, attrs[i].name,
                                           attrs[i].num_values, attrs[i].values,
                                           &response_body, &response_len);
        if (ret != EOK) {
            goto done;
        }
    }

    *_response_body = talloc_steal(mem_ctx, response_body);
    *_response_len = response_len;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * Response format:
 * <error_code(uint32_t)><domain(char*)>\0<num_entries(uint32_t)><rule1><rule2>...
 * <ruleN> = <num_attrs(uint32_t)><attr1><attr2>...
 * <attrN>  = <name(char*)>\0<num_values(uint32_t)><value1(char*)>\0<value2(char*)>\0...
 *
 * if <error_code> is not SSS_SUDO_ERROR_OK, the rest of the data is skipped.
 */
errno_t sudosrv_build_response(TALLOC_CTX *mem_ctx,
                               uint32_t error,
                               uint32_t rules_num,
                               struct sysdb_attrs **rules,
                               uint8_t **_response_body,
                               size_t *_response_len)
{
    uint8_t *response_body = NULL;
    size_t response_len = 0;
    TALLOC_CTX *tmp_ctx = NULL;
    uint32_t i = 0;
    errno_t ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* error code */
    ret = sudosrv_response_append_uint32(tmp_ctx, error,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "error: [%"PRIu32"]\n", error);

    if (error != SSS_SUDO_ERROR_OK) {
        goto done;
    }

    /* domain name - deprecated
     * TODO: when possible change the protocol */
    ret = sudosrv_response_append_string(tmp_ctx, "\0", 1,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto fail;
    }

    /* rules count */
    ret = sudosrv_response_append_uint32(tmp_ctx, rules_num,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "rules_num: [%"PRIu32"]\n", rules_num);

    /* rules */
    for (i = 0; i < rules_num; i++) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "rule [%"PRIu32"]/[%"PRIu32"]\n", i+1, rules_num);
        ret = sudosrv_response_append_rule(tmp_ctx, rules[i]->num, rules[i]->a,
                                           &response_body, &response_len);
        if (ret != EOK) {
            goto fail;
        }
    }

done:
    *_response_body = talloc_steal(mem_ctx, response_body);
    *_response_len = response_len;

    ret = EOK;

fail:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sudosrv_parse_query(TALLOC_CTX *mem_ctx,
                            uint8_t *query_body,
                            size_t query_len,
                            char **_rawname,
                            uid_t *_uid)
{
    size_t offset = 0;
    size_t rawname_len;
    char *rawname;
    uid_t uid;

    /* uid */
    if (query_len < sizeof(uid_t)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Query is too small\n");
        return EINVAL;
    }
    safealign_memcpy(&uid, query_body, sizeof(uid_t), &offset);

    /* username[@domain] */
    rawname = (char*)(query_body + offset);
    rawname_len = query_len - offset; /* strlen + zero */

    if (rawname[rawname_len - 1] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Username is not zero terminated\n");
        return EINVAL;
    }

    if (rawname_len < 2) { /* at least one character and zero */
        DEBUG(SSSDBG_CRIT_FAILURE, "Query does not contain username\n");
        return EINVAL;
    }

    if (!sss_utf8_check((uint8_t*)rawname, rawname_len - 1)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Supplied data is not valid UTF-8 string\n");
        return EINVAL;
    }

    rawname = talloc_strdup(mem_ctx, rawname);
    if (rawname == NULL) {
        return ENOMEM;
    }

    *_uid = uid;
    *_rawname = rawname;

    return EOK;
}
