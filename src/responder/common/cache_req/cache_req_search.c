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

static void cache_req_search_ncache_add(struct cache_req *cr)
{
    errno_t ret;

    if (cr->plugin->ncache_add_fn == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_INTERNAL, cr,
                        "This request type does not support negative cache\n");
        return;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Adding [%s] to negative cache\n",
                    cr->debugobj);

    ret = cr->plugin->ncache_add_fn(cr->ncache, cr->domain, cr->data);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_MINOR_FAILURE, cr,
                        "Cannot set negative cache for [%s] [%d]: %s\n",
                        cr->debugobj, ret, sss_strerror(ret));
        /* not fatal */
    }

    return;
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

    switch (ret) {
    case EOK:
        if (cr->plugin->only_one_result && result->count > 1) {
            CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                            "Multiple objects were found when "
                            "only one was expected!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        *_result = result;
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

static errno_t cache_req_dpreq_params(TALLOC_CTX *mem_ctx,
                                      struct cache_req *cr,
                                      struct ldb_result *result,
                                      const char **_string,
                                      uint32_t *_id,
                                      const char **_flag)
{
    errno_t ret;

    if (cr->plugin->dpreq_params_fn == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Bug: No dpreq params function specified\n");
        return ERR_INTERNAL;
    }


    CACHE_REQ_DEBUG(SSSDBG_TRACE_INTERNAL, cr,
                    "Creating DP request parameters\n");

    ret = cr->plugin->dpreq_params_fn(mem_ctx, cr, result, _string, _id, _flag);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Unable to create DP request parameters [%d]: %s\n",
                        ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static void cache_req_search_process_dp(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *subreq,
                                        struct cache_req *cr)
{
    char *err_msg;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    errno_t ret;

    ret = sss_dp_get_account_recv(mem_ctx, subreq, &err_maj, &err_min, &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_OP_FAILURE, cr,
                        "Could not get account info [%d]: %s\n",
                        ret, sss_strerror(ret));
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                        "Due to an error we will return cached data\n");
    }

    if (err_maj) {
        CACHE_REQ_DEBUG(SSSDBG_OP_FAILURE, cr,
                        "Data Provider Error: %u, %u, %s\n",
                        (unsigned int)err_maj, (unsigned int)err_min, err_msg);
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                        "Due to an error we will return cached data\n");
    }

    return;
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
};

static errno_t cache_req_search_dp(struct tevent_req *req,
                                   enum cache_object_status status);
static void cache_req_search_oob_done(struct tevent_req *subreq);
static void cache_req_search_done(struct tevent_req *subreq);

struct tevent_req *
cache_req_search_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct cache_req *cr)
{
    struct cache_req_search_state *state;
    enum cache_object_status status;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_search_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->cr = cr;

    ret = cache_req_search_ncache(cr);
    if (ret != EOK) {
        goto done;
    }

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

    ret = cache_req_search_dp(req, status);
    if (ret != EAGAIN) {
        goto done;
    }

    return req;

done:
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
    const char *extra_flag;
    const char *search_str;
    uint32_t search_id;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_search_state);

    ret = cache_req_dpreq_params(state, state->cr, state->result,
                                 &search_str, &search_id, &extra_flag);
    if (ret != EOK) {
        return ret;
    }

    switch (status) {
    case CACHE_OBJECT_MIDPOINT:
        /* Out of band update. The calling function will return the cached
         * entry immediately. We need to use rctx so the request is not
         * removed when state is freed. */

        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Performing midpoint cache update of [%s]\n",
                        state->cr->debugobj);

        subreq = sss_dp_get_account_send(state->cr->rctx, state->cr->rctx,
                                         state->cr->domain, true,
                                         state->cr->dp_type,
                                         search_str, search_id, extra_flag);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory sending out-of-band "
                                       "data provider request\n");
            /* This is non-fatal, so we'll continue here */
        } else {
            tevent_req_set_callback(subreq, cache_req_search_oob_done, req);
        }

        return EOK;
    case CACHE_OBJECT_EXPIRED:
    case CACHE_OBJECT_MISSING:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Looking up [%s] in data provider\n",
                        state->cr->debugobj);

        subreq = sss_dp_get_account_send(state, state->cr->rctx,
                                         state->cr->domain, true,
                                         state->cr->dp_type,
                                         search_str, search_id, extra_flag);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
            return ENOMEM;
        }

        tevent_req_set_callback(subreq, cache_req_search_done, req);
        return EAGAIN;
    default:
        /* error */
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                        "Unexpected status [%d]\n", status);
        return ret;
    }
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

    cache_req_search_process_dp(state, subreq, state->cr);

    /* Get result from cache again. */
    ret = cache_req_search_cache(state, state->cr, &state->result);
    if (ret == ENOENT) {
        cache_req_search_ncache_add(state->cr);
        tevent_req_error(req, ENOENT);
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                    "Returning updated object [%s]\n", state->cr->debugobj);

    tevent_req_done(req);
    return;
}

errno_t cache_req_search_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              struct ldb_result **_result)
{
    struct cache_req_search_state *state = NULL;
    state = tevent_req_data(req, struct cache_req_search_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_result = talloc_steal(mem_ctx, state->result);

    return EOK;
}
