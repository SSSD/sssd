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

#include <dbus/dbus.h>
#include <ldb.h>
#include <talloc.h>
#include <tevent.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "responder/common/responder_cache_req.h"

static errno_t cache_req_check_ncache(enum sss_dp_acct_type dp_type,
                                      struct sss_nc_ctx *ncache,
                                      int neg_timeout,
                                      struct sss_domain_info *domain,
                                      const char *name)
{
    errno_t ret;

    switch (dp_type) {
    case SSS_DP_USER:
    case SSS_DP_INITGROUPS:
        ret = sss_ncache_check_user(ncache, neg_timeout, domain, name);
        break;
    default:
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported DP request type\n");
        break;
    }

    if (ret == EEXIST) {
        DEBUG(SSSDBG_TRACE_FUNC, "[%s] does not exist in [%s]! "
              "(negative cache)\n", name, domain->name);
    }

    return ret;
}

static void cache_req_add_to_ncache(enum sss_dp_acct_type dp_type,
                                    struct sss_nc_ctx *ncache,
                                    struct sss_domain_info *domain,
                                    const char *name)
{
    errno_t ret;

    switch (dp_type) {
    case SSS_DP_USER:
    case SSS_DP_INITGROUPS:
        ret = sss_ncache_set_user(ncache, false, domain, name);
        break;
    default:
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported DP request type\n");
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set negcache for %s@%s [%d]: %s\n",
              name, domain->name, ret, sss_strerror(ret));

        /* not fatal */
    }

    return;
}

static errno_t cache_req_get_object(TALLOC_CTX *mem_ctx,
                                    enum sss_dp_acct_type dp_type,
                                    struct sss_domain_info *domain,
                                    const char *name,
                                    struct ldb_result **_result)
{
    struct ldb_result *result = NULL;
    bool one_item_only;
    errno_t ret;

    DEBUG(SSSDBG_FUNC_DATA, "Requesting info for [%s@%s]\n",
          name, domain->name);

    switch (dp_type) {
    case SSS_DP_USER:
        one_item_only = true;
        ret = sysdb_getpwnam(mem_ctx, domain, name, &result);
        break;
    case SSS_DP_INITGROUPS:
        one_item_only = false;
        ret = sysdb_initgroups(mem_ctx, domain, name, &result);
        break;
    default:
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported DP request type\n");
        break;
    }

    if (ret != EOK) {
        goto done;
    } else if (result->count == 0) {
        ret = ENOENT;
        goto done;
    } else if (one_item_only && result->count > 1) {
        ret = ENOENT;
        DEBUG(SSSDBG_CRIT_FAILURE, "Multiple objects were found when"
              "sysdb search expected only one!\n");
        goto done;
    }

    *_result = result;

done:
    return ret;
}

struct cache_req_cache_state {
    /* input data */
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int neg_timeout;
    int cache_refresh_percent;
    enum sss_dp_acct_type dp_type;
    struct sss_domain_info *domain;
    const char *name;

    /* output data */
    struct ldb_result *result;
};

static errno_t cache_req_cache_search(struct tevent_req *req);
static errno_t cache_req_cache_check(struct tevent_req *req);
static void cache_req_cache_done(struct tevent_req *subreq);

static struct tevent_req *cache_req_cache_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct resp_ctx *rctx,
                                               struct sss_nc_ctx *ncache,
                                               int neg_timeout,
                                               int cache_refresh_percent,
                                               enum sss_dp_acct_type dp_type,
                                               struct sss_domain_info *domain,
                                               const char *name)
{
    struct cache_req_cache_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_cache_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->ev = ev;
    state->rctx = rctx;
    state->ncache = ncache;
    state->neg_timeout = neg_timeout;
    state->cache_refresh_percent = cache_refresh_percent;
    state->dp_type = dp_type;
    state->domain = domain;

    /* Sanitize input name. */
    state->name = sss_get_cased_name(state, name, domain->case_sensitive);
    if (state->name == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->name = sss_reverse_replace_space(state, state->name,
                                            state->rctx->override_space);
    if (state->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_reverse_replace_space failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    /* Check negative cache first. */
    ret = cache_req_check_ncache(state->dp_type, state->ncache,
                                 state->neg_timeout, state->domain,
                                 state->name);
    if (ret == EEXIST) {
        ret = ENOENT;
        goto immediately;
    }

    /* We will first search the cache. If we get cache miss or the entry
     * is expired we will contact data provider and then search again. */
    ret = cache_req_cache_search(req);
    if (ret != EAGAIN) {
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t cache_req_cache_search(struct tevent_req *req)
{
    struct cache_req_cache_state *state = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_cache_state);

    ret = cache_req_get_object(state, state->dp_type, state->domain,
                               state->name, &state->result);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to make request to our cache "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    /* Verify that the cache is up to date. */
    ret = cache_req_cache_check(req);
    if (req != EOK) {
        return ret;
    }

    /* One result found */
    DEBUG(SSSDBG_TRACE_FUNC,
          "Returning info for [%s@%s]\n", state->name, state->domain->name);
    return EOK;
}

static errno_t cache_req_cache_check(struct tevent_req *req)
{
    struct cache_req_cache_state *state = NULL;
    struct tevent_req *subreq = NULL;
    uint64_t cache_expire = 0;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_cache_state);

    if (state->result == NULL || state->result->count == 0) {
        ret = ENOENT;
    } else {
        if (state->dp_type == SSS_DP_INITGROUPS) {
            cache_expire = ldb_msg_find_attr_as_uint64(state->result->msgs[0],
                                                       SYSDB_INITGR_EXPIRE, 0);
        } else {
            cache_expire = ldb_msg_find_attr_as_uint64(state->result->msgs[0],
                                                       SYSDB_CACHE_EXPIRE, 0);
        }

        ret = sss_cmd_check_cache(state->result->msgs[0],
                                  state->cache_refresh_percent, cache_expire);
    }

    switch (ret) {
    case EOK:
        DEBUG(SSSDBG_TRACE_FUNC, "Cached entry is valid, returning...\n");
        return EOK;
    case EAGAIN:
        /* Out of band update. The calling function will return the cached
         * entry immediately. No callback is required. */

        DEBUG(SSSDBG_TRACE_FUNC, "Performing midpoint cache update\n");

        subreq = sss_dp_get_account_send(state, state->rctx, state->domain,
                                         true, state->dp_type, state->name,
                                         0, NULL);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory sending out-of-band "
                                       "data provider request\n");
            /* This is non-fatal, so we'll continue here */
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Updating cache out-of-band\n");
        }

        return EOK;
    case ENOENT:
        /* Cache miss or the cache is expired. We need to get the updated
         * information before returning it. */

        subreq = sss_dp_get_account_send(state, state->rctx, state->domain,
                                         true, state->dp_type, state->name,
                                         0, NULL);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
            return ENOMEM;
        }

        tevent_req_set_callback(subreq, cache_req_cache_done, req);
        return EAGAIN;
    default:
        /* error */
        DEBUG(SSSDBG_CRIT_FAILURE, "Error checking cache [%d]: %s\n",
                                   ret, sss_strerror(ret));
        return ret;
    }
}

static void cache_req_cache_done(struct tevent_req *subreq)
{
    struct cache_req_cache_state *state = NULL;
    struct tevent_req *req = NULL;
    char *err_msg = NULL;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_cache_state);

    ret = sss_dp_get_account_recv(state, subreq, &err_maj, &err_min, &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not get account info [%d]: %s\n",
                                 ret, sss_strerror(ret));
    }

    if (err_maj) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Unable to get information from Data Provider\n"
              "Error: %u, %u, %s\n"
              "Will try to return what we have in cache\n",
              (unsigned int)err_maj, (unsigned int)err_min, err_msg);
    }

    /* Get result from cache again. */
    ret = cache_req_get_object(state, state->dp_type, state->domain,
                               state->name, &state->result);
    if (ret == ENOENT) {
        cache_req_add_to_ncache(state->dp_type, state->ncache,
                                state->domain, state->name);
        ret = ENOENT;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to make request to our cache "
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* One result found */
    DEBUG(SSSDBG_TRACE_FUNC,
          "Returning info for [%s@%s]\n", state->name, state->domain->name);

    tevent_req_done(req);
}

static errno_t cache_req_cache_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct ldb_result **_result)
{
    struct cache_req_cache_state *state = NULL;
    state = tevent_req_data(req, struct cache_req_cache_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_result = talloc_steal(mem_ctx, state->result);

    return EOK;
}


struct cache_req_state {
    /* input data */
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int neg_timeout;
    int cache_refresh_percent;
    const char *name;
    enum sss_dp_acct_type dp_type;

    /* work data */
    struct ldb_result *result;
    struct sss_domain_info *domain;
    struct sss_domain_info *selected_domain;
    bool check_next;
};

static errno_t cache_req_next_domain(struct tevent_req *req);
static void cache_req_done(struct tevent_req *subreq);

struct tevent_req *cache_req_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int neg_timeout,
                                  int cache_refresh_percent,
                                  enum sss_dp_acct_type dp_type,
                                  const char *domain,
                                  const char *name)
{
    struct cache_req_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->ev = ev;
    state->rctx = rctx;
    state->ncache = ncache;
    state->neg_timeout = neg_timeout;
    state->cache_refresh_percent = cache_refresh_percent;
    state->dp_type = dp_type;
    state->name = talloc_strdup(state, name);
    if (state->name == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (domain != NULL) {
        /* single-domain search */
        state->domain = responder_get_domain(state->rctx, domain);
        if (state->domain == NULL) {
            ret = EINVAL;
            goto immediately;
        }

        state->check_next = false;
    } else {
        /* multi-domain search */
        state->domain = state->rctx->domains;
        state->check_next = true;
    }

    ret = cache_req_next_domain(req);
    if (ret != EAGAIN) {
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t cache_req_next_domain(struct tevent_req *req)
{
    struct cache_req_state *state = NULL;
    struct tevent_req *subreq = NULL;

    state = tevent_req_data(req, struct cache_req_state);

    while (state->domain != NULL) {
       /* If it is a domainless search, skip domains that require fully
        * qualified names instead. */
        while (state->domain != NULL && state->check_next
                && state->domain->fqnames) {
            state->domain = get_next_domain(state->domain, false);
        }

        state->selected_domain = state->domain;

        if (state->domain == NULL) {
            break;
        }

        subreq = cache_req_cache_send(state, state->ev, state->rctx,
                                      state->ncache, state->neg_timeout,
                                      state->cache_refresh_percent,
                                      state->dp_type, state->domain,
                                      state->name);
        if (subreq == NULL) {
            return ENOMEM;
        }

        tevent_req_set_callback(subreq, cache_req_done, req);

        /* we will continue with the following domain the next time */
        if (state->check_next) {
            state->domain = get_next_domain(state->domain, false);
        }

        return EAGAIN;
    }

    return ENOENT;
}

static void cache_req_done(struct tevent_req *subreq)
{
    struct cache_req_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = cache_req_cache_recv(state, subreq, &state->result);
    talloc_zfree(subreq);
    if (ret == EOK) {
        tevent_req_done(req);
        return;
    }

    if (state->check_next == false) {
        tevent_req_error(req, ret);
        return;
    }

    ret = cache_req_next_domain(req);
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

errno_t cache_req_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ldb_result **_result,
                       struct sss_domain_info **_domain)
{
    struct cache_req_state *state = NULL;
    state = tevent_req_data(req, struct cache_req_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_result != NULL) {
        *_result = talloc_steal(mem_ctx, state->result);
    }

    if (_domain != NULL) {
        *_domain = state->selected_domain;
    }

    return EOK;
}
