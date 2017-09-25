/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <ldb.h>
#include <talloc.h>
#include <errno.h>

#include "util/util.h"
#include "responder/common/cache_req/cache_req_private.h"

errno_t
cache_req_add_result(TALLOC_CTX *mem_ctx,
                     struct cache_req_result *new_result,
                     struct cache_req_result ***_results,
                     size_t *_num_results)
{
    struct cache_req_result **results = *_results;
    size_t idx;
    size_t count;

    /* Make space for new results. */
    idx = *_num_results;
    count = *_num_results + 1;

    results = talloc_realloc(mem_ctx, results, struct cache_req_result *,
                             count + 1);
    if (results == NULL) {
        return ENOMEM;
    }

    results[idx] = talloc_steal(results, new_result);
    results[idx + 1] = NULL;

    *_results = results;
    *_num_results = count;

    return EOK;
}

struct cache_req_result *
cache_req_create_result(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        struct ldb_result *ldb_result,
                        const char *lookup_name,
                        const char *well_known_domain)
{
    struct cache_req_result *result;

    result = talloc_zero(mem_ctx, struct cache_req_result);
    if (result == NULL) {
        return NULL;
    }

    result->domain = domain;
    result->ldb_result = talloc_steal(result, ldb_result);
    result->count = ldb_result != NULL ? ldb_result->count : 0;
    result->msgs = ldb_result != NULL ? ldb_result->msgs : NULL;

    if (lookup_name != NULL) {
        result->lookup_name = talloc_strdup(result, lookup_name);
        if (result->lookup_name == NULL) {
            talloc_free(result);
            return NULL;
        }
    }

    if (well_known_domain != NULL) {
        result->well_known_domain = talloc_strdup(result, well_known_domain);
        if (result->well_known_domain == NULL) {
            talloc_free(result);
            return NULL;
        }
    }

    return result;
}

errno_t
cache_req_create_and_add_result(TALLOC_CTX *mem_ctx,
                                struct cache_req *cr,
                                struct sss_domain_info *domain,
                                struct ldb_result *ldb_result,
                                const char *name,
                                struct cache_req_result ***_results,
                                size_t *_num_results)
{
    struct cache_req_result *item;
    errno_t ret;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                    "Found %u entries in domain %s\n",
                    ldb_result->count, domain->name);

    item = cache_req_create_result(mem_ctx, domain, ldb_result, name, NULL);
    if (item == NULL) {
        return ENOMEM;
    }

    ret = cache_req_add_result(mem_ctx, item, _results, _num_results);
    if (ret != EOK) {
        talloc_free(item);
    }

    return ret;
}

struct ldb_result *
cache_req_create_ldb_result_from_msg_list(TALLOC_CTX *mem_ctx,
                                          struct ldb_message **ldb_msgs,
                                          size_t ldb_msg_count)
{
    struct ldb_result *ldb_result;

    if (ldb_msgs == NULL || ldb_msgs[0] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No message set!\n");
        return NULL;
    }

    ldb_result = talloc_zero(NULL, struct ldb_result);
    if (ldb_result == NULL) {
        return NULL;
    }

    ldb_result->extended = NULL;
    ldb_result->controls = NULL;
    ldb_result->refs = NULL;
    ldb_result->count = ldb_msg_count;
    ldb_result->msgs = talloc_zero_array(ldb_result, struct ldb_message *,
                                         ldb_msg_count + 1);
    if (ldb_result->msgs == NULL) {
        talloc_free(ldb_result);
        return NULL;
    }

    for (size_t i = 0; i < ldb_msg_count; i++) {
        ldb_result->msgs[i] = talloc_steal(ldb_result->msgs, ldb_msgs[i]);
    }

    return ldb_result;
}

struct ldb_result *
cache_req_create_ldb_result_from_msg(TALLOC_CTX *mem_ctx,
                                     struct ldb_message *ldb_msg)
{
    struct ldb_result *ldb_result;

    if (ldb_msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No message set!\n");
        return NULL;
    }

    ldb_result = talloc_zero(NULL, struct ldb_result);
    if (ldb_result == NULL) {
        return NULL;
    }

    ldb_result->extended = NULL;
    ldb_result->controls = NULL;
    ldb_result->refs = NULL;
    ldb_result->count = 1;
    ldb_result->msgs = talloc_zero_array(ldb_result, struct ldb_message *, 2);
    if (ldb_result->msgs == NULL) {
        talloc_free(ldb_result);
        return NULL;
    }

    ldb_result->msgs[0] = talloc_steal(ldb_result->msgs, ldb_msg);

    return ldb_result;
}

struct cache_req_result *
cache_req_create_result_from_msg(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 struct ldb_message *ldb_msg,
                                 const char *lookup_name,
                                 const char *well_known_domain)
{
    struct cache_req_result *result;
    struct ldb_result *ldb_result;

    if (ldb_msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No message set!\n");
        return NULL;
    }

    ldb_result = cache_req_create_ldb_result_from_msg(mem_ctx, ldb_msg);
    if (ldb_result == NULL) {
        return NULL;
    }

    result = cache_req_create_result(mem_ctx, domain, ldb_result,
                                     lookup_name, well_known_domain);
    if (result == NULL) {
        talloc_free(ldb_result);
        return NULL;
    }

    return result;
}

struct cache_req_result *
cache_req_copy_limited_result(TALLOC_CTX *mem_ctx,
                              struct cache_req_result *result,
                              uint32_t start,
                              uint32_t limit)
{
    struct cache_req_result *out = NULL;
    struct ldb_result *ldb_result;
    unsigned int left;
    errno_t ret;

    if (start >= result->count) {
        ret = ERANGE;
        goto done;
    }

    out = talloc_zero(mem_ctx, struct cache_req_result);
    if (out == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ldb_result = talloc_zero(out, struct ldb_result);
    if (ldb_result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    left = result->count - start;

    ldb_result->extended = result->ldb_result->extended;
    ldb_result->controls = result->ldb_result->controls;
    ldb_result->refs = result->ldb_result->refs;
    ldb_result->msgs = &(result->ldb_result->msgs[start]);
    ldb_result->count = left < limit ? left : limit;

    out->domain = result->domain;
    out->ldb_result = ldb_result;
    out->lookup_name = result->lookup_name;
    out->count = ldb_result->count;
    out->msgs = ldb_result->msgs;

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create cache request result "
              "[%d]: %s\n", ret, sss_strerror(ret));

        talloc_free(out);
        return NULL;
    }

    return out;
}
