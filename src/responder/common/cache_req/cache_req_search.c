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
#include <tevent.h>

#include "util/util.h"
#include "responder/common/cache_req/cache_req_private.h"
#include "responder/common/cache_req/cache_req_plugin.h"
#include "db/sysdb.h"

static errno_t cache_req_search_ncache(struct cache_req *cr)
{
    errno_t ret;

    if (cr->plugin->ncache_check_fn == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_INTERNAL, cr,
                        "This request type does not support negative cache\n");
        return EOK;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                    "Checking negative cache for [%s]\n",
                    cr->debugobj);

    ret = cr->plugin->ncache_check_fn(cr->ncache, cr->domain, cr->data);
    if (ret == EEXIST) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                        "[%s] does not exist (negative cache)\n",
                        cr->debugobj);
        return ENOENT;
    } else if (ret != EOK && ret != ENOENT) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Unable to check negative cache [%d]: %s\n",
                        ret, sss_strerror(ret));
        return ret;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                    "[%s] is not present in negative cache\n",
                    cr->debugobj);

    return EOK;
}

void cache_req_search_ncache_add_to_domain(struct cache_req *cr,
                                           struct sss_domain_info *domain)
{
    errno_t ret;

    if (cr->plugin->ncache_add_fn == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_INTERNAL, cr,
                        "This request type does not support negative cache\n");
        return;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Adding [%s] to negative cache\n",
                    cr->debugobj);

    ret = cr->plugin->ncache_add_fn(cr->ncache, domain, cr->data);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_MINOR_FAILURE, cr,
                        "Cannot set negative cache for [%s] [%d]: %s\n",
                        cr->debugobj, ret, sss_strerror(ret));
        /* not fatal */
    }

    return;
}

static void cache_req_search_ncache_add(struct cache_req *cr)
{
    return cache_req_search_ncache_add_to_domain(cr, cr->domain);
}

static errno_t cache_req_search_ncache_filter(TALLOC_CTX *mem_ctx,
                                              struct cache_req *cr,
                                              struct ldb_result **_result)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *filtered_result;
    struct ldb_message **msgs;
    size_t msg_count;
    const char *name;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (cr->plugin->ncache_filter_fn == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                        "This request type does not support filtering "
                        "result by negative cache\n");

        ret = EOK;
        goto done;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                    "Filtering out results by negative cache\n");

    msgs = talloc_zero_array(tmp_ctx, struct ldb_message *, (*_result)->count);
    msg_count = 0;

    for (size_t i = 0; i < (*_result)->count; i++) {
        name = sss_get_name_from_msg(cr->domain, (*_result)->msgs[i]);
        if (name == NULL) {
            CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                  "sss_get_name_from_msg() returned NULL, which should never "
                  "happen in this scenario!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        ret = cr->plugin->ncache_filter_fn(cr->ncache, cr->domain, name);
        if (ret == EEXIST) {
            CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                            "[%s] filtered out! (negative cache)\n",
                            name);
            continue;
        } else if (ret != EOK && ret != ENOENT) {
            CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                            "Unable to check negative cache [%d]: %s\n",
                            ret, sss_strerror(ret));
            goto done;
        }

        msgs[msg_count] = talloc_steal(msgs, (*_result)->msgs[i]);
        msg_count++;
    }

    if (msg_count == 0) {
        ret = ENOENT;
        goto done;
    }

    filtered_result = cache_req_create_ldb_result_from_msg_list(tmp_ctx, msgs,
                                                                msg_count);
    if (filtered_result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_zfree(*_result);
    *_result = talloc_steal(mem_ctx, filtered_result);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int
cache_req_should_be_in_cache(struct cache_req *cr,
                             struct ldb_result *result)
{
    id_t id = 0;

    if (result == NULL || result->count != 1) {
        /* can't decide so keep it */
        return EOK;
    }

    id = ldb_msg_find_attr_as_uint(result->msgs[0], SYSDB_UIDNUM, 0);
    if (id && OUT_OF_ID_RANGE(id, cr->domain->id_min, cr->domain->id_max)) {
        return ERR_ID_OUTSIDE_RANGE;
    }

    id = ldb_msg_find_attr_as_uint(result->msgs[0], SYSDB_GIDNUM, 0);
    if (id && OUT_OF_ID_RANGE(id, cr->domain->id_min, cr->domain->id_max)) {
        return ERR_ID_OUTSIDE_RANGE;
    }

    return EOK;
}

static errno_t cache_req_search_cache(TALLOC_CTX *mem_ctx,
                                      struct cache_req *cr,
                                      struct ldb_result **_result)
{
    struct ldb_result *result = NULL;
    errno_t ret;

    if (cr->plugin->lookup_fn == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Bug: No cache lookup function specified\n");
        return ERR_INTERNAL;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                    "Looking up [%s] in cache\n",
                    cr->debugobj);

    ret = cr->plugin->lookup_fn(mem_ctx, cr, cr->data, cr->domain, &result);
    if (ret == EOK && (result == NULL || result->count == 0)) {
        ret = ENOENT;
    }

    if (ret == EOK) {
        ret = cache_req_should_be_in_cache(cr, result);
    }

    switch (ret) {
    case EOK:
        if (cr->plugin->only_one_result && result->count > 1) {
            CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                            "Multiple objects were found when "
                            "only one was expected!\n");
            ret = ERR_MULTIPLE_ENTRIES;
            goto done;
        }

        *_result = result;
        break;
    case ERR_ID_OUTSIDE_RANGE:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                        "ID [%s] was filtered out\n",
                        cr->debugobj);
        break;
    case ENOENT:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                        "Object [%s] was not found in cache\n",
                        cr->debugobj);
        break;
    default:
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Unable to lookup [%s] in cache [%d]: %s\n",
                        cr->debugobj, ret, sss_strerror(ret));
        break;
    }

done:
    if (ret != EOK) {
        talloc_free(result);
    }

    return ret;
}

static enum cache_object_status
cache_req_expiration_status(struct cache_req *cr,
                            struct ldb_result *result)
{
    time_t expire;
    errno_t ret;

    if (result == NULL || result->count == 0 || cr->plugin->bypass_cache) {
        return CACHE_OBJECT_MISSING;
    }

    expire = ldb_msg_find_attr_as_uint64(result->msgs[0],
                                         cr->plugin->attr_expiration, 0);

    ret = sss_cmd_check_cache(result->msgs[0], cr->midpoint, expire);
    if (ret == EOK) {
        return CACHE_OBJECT_VALID;
    } else if (ret == EAGAIN) {
        return CACHE_OBJECT_MIDPOINT;
    }

    return CACHE_OBJECT_EXPIRED;
}

struct cache_req_search_state {
    /* input data */
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct cache_req *cr;

    /* output data */
    struct ldb_result *result;
    bool dp_success;
};

static errno_t cache_req_search_dp(struct tevent_req *req,
                                   enum cache_object_status status);
static void cache_req_search_oob_done(struct tevent_req *subreq);
static void cache_req_search_done(struct tevent_req *subreq);

struct tevent_req *
cache_req_search_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct cache_req *cr,
                      bool first_iteration,
                      bool cache_only_override)
{
    struct cache_req_search_state *state;
    enum cache_object_status status;
    struct tevent_req *req;
    bool bypass_cache = false;
    bool bypass_dp = false;
    bool skip_refresh = false;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_search_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Looking up %s\n", cr->debugobj);

    state->ev = ev;
    state->cr = cr;

    ret = cache_req_search_ncache(cr);
    if (ret != EOK) {
        goto done;
    }

    if (cache_only_override) {
        bypass_dp = true;
    } else {
        switch (cr->cache_behavior) {
        case CACHE_REQ_CACHE_FIRST:
            bypass_cache = first_iteration ? false : true;
            bypass_dp = first_iteration ? true : false;
            break;
        case CACHE_REQ_BYPASS_CACHE:
            bypass_cache = true;
            break;
        case CACHE_REQ_BYPASS_PROVIDER:
            bypass_dp = true;
            skip_refresh = true;
            break;
        default:
            break;
        }
    }

    /* If bypass_cache is enabled we always contact data provider before
     * searching the cache. Thus we set expiration status to missing,
     * which will trigger data provider request later.
     *
     * If disabled, we want to search the cache here to see if the
     * object is already cached and valid or if data provider needs
     * to be contacted.
     */
    state->result = NULL;
    status = CACHE_OBJECT_MISSING;
    if (!bypass_cache) {
        ret = cache_req_search_cache(state, cr, &state->result);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }

        status = cache_req_expiration_status(cr, state->result);
        if (status == CACHE_OBJECT_VALID) {
            CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                            "Returning [%s] from cache\n", cr->debugobj);
            ret = EOK;
            goto done;
        }

        /* For the CACHE_REQ_CACHE_FIRST case, if bypass_dp is true but we
         * found the object in this domain, we will contact the data provider
         * anyway to refresh it so we can return it without searching the rest
         * of the domains.
         */
        if (status != CACHE_OBJECT_MISSING && !skip_refresh) {
            CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                            "Object found, but needs to be refreshed.\n");
            bypass_dp = false;
        } else {
            ret = ENOENT;
        }
    }

    if (!bypass_dp) {
        ret = cache_req_search_dp(req, status);
    }

    if (ret != EAGAIN) {
        goto done;
    }

    return req;

done:
    if (ret == EOK) {
        ret = cache_req_search_ncache_filter(state, cr, &state->result);
    }

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t cache_req_search_dp(struct tevent_req *req,
                                   enum cache_object_status status)
{
    struct cache_req_search_state *state;
    struct tevent_req *subreq;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_search_state);

    switch (status) {
    case CACHE_OBJECT_MIDPOINT:
        /* Out of band update. The calling function will return the cached
         * entry immediately. We need to use rctx so the request is not
         * removed when state is freed. */

        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Performing midpoint cache update of [%s]\n",
                        state->cr->debugobj);

        subreq = state->cr->plugin->dp_send_fn(state->rctx, state->cr,
                                               state->cr->data,
                                               state->cr->domain,
                                               state->result);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory sending out-of-band "
                                       "data provider request\n");
            /* This is non-fatal, so we'll continue here */
        } else {
            tevent_req_set_callback(subreq, cache_req_search_oob_done, req);
        }

        ret = EOK;
        break;
    case CACHE_OBJECT_EXPIRED:
    case CACHE_OBJECT_MISSING:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Looking up [%s] in data provider\n",
                        state->cr->debugobj);

        subreq = state->cr->plugin->dp_send_fn(state->cr, state->cr,
                                               state->cr->data,
                                               state->cr->domain,
                                               state->result);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
            ret = ENOMEM;
            break;
        }

        tevent_req_set_callback(subreq, cache_req_search_done, req);
        ret = EAGAIN;
        break;
    default:
        /* error */
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                        "Unexpected status [%d]\n", status);
        ret = ERR_INTERNAL;
        break;
    }

    return ret;
}

static void cache_req_search_oob_done(struct tevent_req *subreq)
{
    DEBUG(SSSDBG_TRACE_INTERNAL, "Out of band request finished\n");
    talloc_zfree(subreq);

    return;
}

static void cache_req_search_done(struct tevent_req *subreq)
{
    struct cache_req_search_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_search_state);

    state->dp_success = state->cr->plugin->dp_recv_fn(subreq, state->cr);
    talloc_zfree(subreq);

    /* Get result from cache again. */
    ret = cache_req_search_cache(state, state->cr, &state->result);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* Only store entry in negative cache if DP request succeeded
             * because only then we know that the entry does not exist. */
            if (state->dp_success) {
                cache_req_search_ncache_add(state->cr);
            }
        }
        goto done;
    }

    /* ret == EOK */
    ret = cache_req_search_ncache_filter(state, state->cr, &state->result);
    if (ret != EOK) {
        goto done;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                    "Returning updated object [%s]\n", state->cr->debugobj);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t cache_req_search_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              struct ldb_result **_result,
                              bool *_dp_success)
{
    struct cache_req_search_state *state = NULL;
    state = tevent_req_data(req, struct cache_req_search_state);

    *_dp_success = state->dp_success;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_result = talloc_steal(mem_ctx, state->result);

    return EOK;
}

struct cache_req_locate_domain_state {
    struct cache_req *cr;

    char *found_domain;
};

static void cache_req_locate_domain_done(struct tevent_req *subreq);

struct tevent_req *cache_req_locate_domain_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct cache_req *cr)
{
    struct cache_req_locate_domain_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;
    bool should_run;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_locate_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }
    state->cr = cr;

    should_run = cr->plugin->dp_get_domain_check_fn(cr->rctx,
                                                    get_domains_head(cr->domain),
                                                    cr->data);
    if (should_run == false) {
        /* The request was tried too recently, don't issue a new one
         * as its results are still valid
         */
        ret = ERR_GET_ACCT_DOM_CACHED;
        goto immediate;
    }

    subreq = cr->plugin->dp_get_domain_send_fn(state,
                                               cr->rctx,
                                               get_domains_head(cr->domain),
                                               cr->data);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, cache_req_locate_domain_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void cache_req_locate_domain_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct cache_req_locate_domain_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_locate_domain_state);

    ret = state->cr->plugin->dp_get_domain_recv_fn(state,
                                                   subreq,
                                                   state->cr,
                                                   &state->found_domain);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t cache_req_locate_domain_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     char **_found_domain)
{
    struct cache_req_locate_domain_state *state = NULL;

    state = tevent_req_data(req, struct cache_req_locate_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_found_domain = talloc_steal(mem_ctx, state->found_domain);
    return EOK;
}
