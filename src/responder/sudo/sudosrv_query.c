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
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
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
                               int rules_num,
                               struct sysdb_attrs **rules,
                               uint8_t **_response_body,
                               size_t *_response_len)
{
    uint8_t *response_body = NULL;
    size_t response_len = 0;
    TALLOC_CTX *tmp_ctx = NULL;
    int i = 0;
    errno_t ret = EOK;

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

    /* domain name - deprecated
     * TODO: when possible change the protocol */
    ret = sudosrv_response_append_string(tmp_ctx, "\0", 1,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto fail;
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

struct sudosrv_parse_query_state {
    struct resp_ctx *rctx;
    uid_t uid;
    char *rawname;
};

static void sudosrv_parse_query_done(struct tevent_req *subreq);

struct tevent_req *sudosrv_parse_query_send(TALLOC_CTX *mem_ctx,
                                            struct resp_ctx *rctx,
                                            uint8_t *query_body,
                                            size_t query_len)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sudosrv_parse_query_state *state = NULL;
    size_t offset = 0;
    size_t rawname_len = 0;
    char *rawname = NULL;
    char *domainname = NULL;
    errno_t ret;

    /* create request */
    req = tevent_req_create(mem_ctx, &state,
                            struct sudosrv_parse_query_state);
    if (req == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->rctx = rctx;

    /* uid */

    if (query_len < sizeof(uid_t)) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Query is too small\n"));
        ret = EINVAL;
        goto done;
    }
    safealign_memcpy(&state->uid, query_body, sizeof(uid_t), &offset);

    /* username[@domain] */

    rawname = (char*)(query_body + offset);
    rawname_len = query_len - offset; /* strlen + zero */

    if (rawname[rawname_len - 1] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Username is not zero terminated\n"));
        ret = EINVAL;
        goto done;
    }

    if (rawname_len < 2) { /* at least one character and zero */
        DEBUG(SSSDBG_CRIT_FAILURE, ("Query does not contain username\n"));
        ret = EINVAL;
        goto done;
    }

    if (!sss_utf8_check((uint8_t*)rawname, rawname_len - 1)) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Supplied data is not valid UTF-8 string\n"));
        ret = EINVAL;
        goto done;
    }

    /* parse username */

    state->rawname = rawname;
    ret = sss_parse_name_for_domains(state, rctx->domains,
                                     rctx->default_domain, state->rawname,
                                     &domainname, NULL);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Domain [%s] not found, "
              "sending subdomain request\n", domainname));

        subreq = sss_dp_get_domains_send(state, rctx, true, domainname);
        if (subreq == NULL) {
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(subreq, sudosrv_parse_query_done, req);
            ret = EAGAIN;
        }
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid name received [%s]\n", rawname));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EAGAIN) {
        if (ret == EOK) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
        tevent_req_post(req, rctx->ev);
    }

    return req;
}

static void sudosrv_parse_query_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sss_dp_get_domains_recv(subreq);
    talloc_free(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }

    tevent_req_done(req);
}

errno_t sudosrv_parse_query_recv(TALLOC_CTX *mem_ctx,
                                 struct tevent_req *req,
                                 uid_t *_uid,
                                 char **_username,
                                 struct sss_domain_info **_domain)
{
    struct sudosrv_parse_query_state *state = NULL;
    struct sss_domain_info *domain = NULL;
    char *username = NULL;
    char *domainname = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct sudosrv_parse_query_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->rawname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No query specified?!\n"));
        return EINVAL;
    }

    /* Try to parse username@domain again because if the first call
     * returned EAGAIN, then username is unset. If we get EAGAIN again,
     * we will not search for it again.
     */
    ret = sss_parse_name_for_domains(state, state->rctx->domains,
                                     state->rctx->default_domain,
                                     state->rawname,
                                     &domainname, &username);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Unable to parse domain [%d]: %s\n",
                                  ret, strerror(ret)));
        return ret;
    }

    if (username == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No username specified!\n"));
        return EINVAL;
    }

    if (domainname != NULL) {
        /* mem_ctx because it duplicates only subdomains not domains
         * so I cannot easily steal it */
        domain = responder_get_domain(mem_ctx, state->rctx, domainname);
        if (domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Corresponding domain [%s] has not been "
                                      "found\n", domainname));
            return ENOENT;
        }
    }

    *_uid = state->uid;
    *_username = talloc_steal(mem_ctx, username);
    *_domain = domain; /* do not steal on mem_ctx */

    return EOK;
}
