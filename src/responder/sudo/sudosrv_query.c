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

#include "util/util.h"
#include "responder/sudo/sudosrv_private.h"

int sudosrv_response_append_string(TALLOC_CTX *mem_ctx,
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
        return ENOMEM;
    }
    memcpy(response_body + response_len, str, str_len);
    response_len += str_len;

    *_response_body = response_body;
    *_response_len = response_len;

    return EOK;
}

int sudosrv_response_append_uint32(TALLOC_CTX *mem_ctx,
                                   uint32_t number,
                                   uint8_t **_response_body,
                                   size_t *_response_len)
{
    size_t response_len = *_response_len;
    uint8_t *response_body = *_response_body;

    response_body = talloc_realloc(mem_ctx, response_body, uint8_t,
                                   response_len + sizeof(int));
    if (response_body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
        return ENOMEM;
    }
    SAFEALIGN_SET_UINT32(response_body + response_len, number, &response_len);

    *_response_body = response_body;
    *_response_len = response_len;

    return EOK;
}

int sudosrv_response_append_rule(TALLOC_CTX *mem_ctx,
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
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

int sudosrv_response_append_attr(TALLOC_CTX *mem_ctx,
                                 const char *name,
                                 unsigned int values_num,
                                 struct ldb_val *values,
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
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
        if (strlen((char*)(values[i].data)) != values[i].length) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("value is not a string"));
            ret = EINVAL;
            goto done;
        }

        ret = sudosrv_response_append_string(tmp_ctx,
                                             (const char*)values[i].data,
                                             values[i].length + 1,
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
