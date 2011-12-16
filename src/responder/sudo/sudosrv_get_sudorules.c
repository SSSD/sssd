/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <stdint.h>
#include <string.h>
#include <talloc.h>

#include "util/util.h"
#include "db/sysdb_sudo.h"
#include "responder/sudo/sudosrv_private.h"

errno_t sudosrv_get_sudorules(struct sudo_dom_ctx *dctx)
{
    dctx->res = NULL;
    dctx->res_count = 0;

    return EOK;
}

char * sudosrv_get_sudorules_parse_query(TALLOC_CTX *mem_ctx,
                                         const char *query_body,
                                         int query_len)
{
    if (query_len < 2 || ((query_len - 1) != strlen(query_body))) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query.\n"));
        return NULL;
    }

    return talloc_strdup(mem_ctx, query_body);
}

/*
 * Response format:
 * <error_code(uint32_t)><num_entries(uint32_t)><rule1><rule2>...
 * <ruleN> = <num_attrs(uint32_t)><attr1><attr2>...
 * <attrN>  = <name(char*)>\0<num_values(uint32_t)><value1(char*)>\0<value2(char*)>\0...
 *
 * if <error_code> is not SSS_SUDO_ERROR_OK, the rest of the data is skipped.
 */
int sudosrv_get_sudorules_build_response(TALLOC_CTX *mem_ctx,
                                         uint32_t error,
                                         int rules_num,
                                         struct sysdb_attrs **rules,
                                         uint8_t **_response_body,
                                         size_t *_response_len)
{
    uint8_t *response_body = NULL;
    size_t response_len = 0;
    TALLOC_CTX *tmp_ctx = NULL;
    int i = 0;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    /* error code */
    ret = sudosrv_response_append_uint32(tmp_ctx, error,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto fail;
    }

    if (error != SSS_SUDO_ERROR_OK) {
        goto done;
    }

    /* rules count */
    ret = sudosrv_response_append_uint32(tmp_ctx, (uint32_t)rules_num,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto fail;
    }

    /* rules */
    for (i = 0; i < rules_num; i++) {
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
