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
#include "providers/data_provider.h"

static errno_t updated_users_by_filter(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *domain,
                                       const char *name_filter,
                                       time_t since,
                                       struct ldb_result **_res)
{
    int ret;
    char *recent_filter;

    recent_filter = talloc_asprintf(mem_ctx, "(%s>=%lu)",
                                    SYSDB_LAST_UPDATE, since);
    ret = sysdb_enumpwent_filter_with_views(mem_ctx, domain,
                                            name_filter, recent_filter,
                                            _res);
    talloc_free(recent_filter);

    return ret;
}

static errno_t updated_groups_by_filter(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domain,
                                        const char *name_filter,
                                        time_t since,
                                        struct ldb_result **_res)
{
    int ret;
    char *recent_filter;

    recent_filter = talloc_asprintf(mem_ctx, "(%s>=%lu)",
                                    SYSDB_LAST_UPDATE, since);
    ret = sysdb_enumgrent_filter_with_views(mem_ctx, domain,
                                            name_filter, recent_filter,
                                            _res);
    talloc_free(recent_filter);

    return ret;
}

struct cache_req_input {
    enum cache_req_type type;

    /* Provided input. */
    const char *orig_name;
    uint32_t id;
    const char *cert;

    /* Parsed name or UPN. */
    const char *name;

    /* Data Provider request type resolved from @type.
     * FIXME: This is currently needed for data provider calls. We should
     * refactor responder_dp.c to get rid of this member. */
    enum sss_dp_acct_type dp_type;

    /* Domain related informations. */
    struct sss_domain_info *domain;

    /* Name sanitized according to domain rules such as case sensitivity and
     * replacement of space character. This needs to be set up for each
     * domain separately. */
    const char *dom_objname;

    /* Fully qualified object name used in debug messages. */
    const char *debug_fqn;
    /* Time when the request started. Useful for by-filter lookups */
    time_t req_start;
};

struct cache_req_input *
cache_req_input_create(TALLOC_CTX *mem_ctx,
                       enum cache_req_type type,
                       const char *name,
                       uint32_t id,
                       const char *cert)
{
    struct cache_req_input *input;

    input = talloc_zero(mem_ctx, struct cache_req_input);
    if (input == NULL) {
        return NULL;
    }

    input->type = type;
    input->req_start = time(NULL);

    /* Check that input parameters match selected type. */
    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        if (name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name cannot be NULL!\n");
            goto fail;
        }

        input->orig_name = talloc_strdup(input, name);
        if (input->orig_name == NULL) {
            goto fail;
        }
        break;
    case CACHE_REQ_USER_BY_CERT:
        if (cert == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: certificate cannot be NULL!\n");
            goto fail;
        }

        input->cert = talloc_strdup(input, cert);
        if (input->cert == NULL) {
            goto fail;
        }
        break;
    case CACHE_REQ_USER_BY_ID:
    case CACHE_REQ_GROUP_BY_ID:
        if (id == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: id cannot be 0!\n");
            goto fail;
        }

        input->id = id;
        break;
    }

    /* Resolve Data Provider request type. */
    switch (type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_USER_BY_ID:
        input->dp_type = SSS_DP_USER;
        break;

    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_GROUP_BY_ID:
        input->dp_type = SSS_DP_GROUP;
        break;

    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        input->dp_type = SSS_DP_INITGROUPS;
        break;

    case CACHE_REQ_USER_BY_CERT:
        input->dp_type = SSS_DP_CERT;
        break;

    case CACHE_REQ_USER_BY_FILTER:
        input->dp_type = SSS_DP_WILDCARD_USER;
        break;

    case CACHE_REQ_GROUP_BY_FILTER:
        input->dp_type = SSS_DP_WILDCARD_GROUP;
        break;
    }

    return input;

fail:
    talloc_free(input);
    return NULL;
}

static errno_t
cache_req_input_set_name(struct cache_req_input *input,
                         const char *name)
{
    const char *dup_name;

    dup_name = talloc_strdup(input, name);
    if (dup_name == NULL) {
        return ENOMEM;
    }

    talloc_zfree(input->name);
    input->name = dup_name;

    return EOK;
}

static errno_t
cache_req_input_set_domain(struct cache_req_input *input,
                           struct sss_domain_info *domain,
                           struct resp_ctx *rctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *name = NULL;
    const char *debug_fqn = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    talloc_zfree(input->dom_objname);
    talloc_zfree(input->debug_fqn);

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        if (input->name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: input->name is NULL?\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        name = sss_get_cased_name(tmp_ctx, input->name, domain->case_sensitive);
        if (name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        name = sss_reverse_replace_space(tmp_ctx, name, rctx->override_space);
        if (name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        debug_fqn = talloc_asprintf(tmp_ctx, "%s@%s", name, domain->name);
        if (debug_fqn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        break;

    case CACHE_REQ_USER_BY_ID:
        debug_fqn = talloc_asprintf(tmp_ctx, "UID:%d@%s", input->id, domain->name);
        if (debug_fqn == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;

    case CACHE_REQ_GROUP_BY_ID:
        debug_fqn = talloc_asprintf(tmp_ctx, "GID:%d@%s", input->id, domain->name);
        if (debug_fqn == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    case CACHE_REQ_USER_BY_CERT:
        /* certificates might be quite long, only use the last 10 charcters
         * for logging */
        debug_fqn = talloc_asprintf(tmp_ctx, "CERT:%s@%s",
                                    get_last_x_chars(input->cert, 10),
                                    domain->name);
        if (debug_fqn == NULL) {
            ret = ENOMEM;
            goto done;
        }
        break;
    }

    input->domain = domain;
    input->dom_objname = talloc_steal(input, name);
    input->debug_fqn = talloc_steal(input, debug_fqn);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static bool
cache_req_input_is_upn(struct cache_req_input *input)
{
    switch (input->type) {
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        return true;
    default:
        return false;
    }
}

static bool
cache_req_input_assume_upn(struct cache_req_input *input)
{
    errno_t ret;
    bool bret;

    if (input->orig_name == NULL || strchr(input->orig_name, '@') == NULL) {
        return false;
    }

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
        input->type = CACHE_REQ_USER_BY_UPN;
        bret = true;
        break;
    case CACHE_REQ_INITGROUPS:
        input->type = CACHE_REQ_INITGROUPS_BY_UPN;
        bret = true;
        break;
    default:
        bret = false;
        break;
    }

    if (bret == true) {
        ret = cache_req_input_set_name(input, input->orig_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "cache_req_input_set_orig_name() failed\n");
            return false;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Assuming UPN %s\n", input->orig_name);
    }

    return bret;
}

static errno_t cache_req_check_ncache(struct cache_req_input *input,
                                      struct sss_nc_ctx *ncache,
                                      int neg_timeout)
{
    errno_t ret = ERR_INTERNAL;

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        ret = sss_ncache_check_user(ncache, neg_timeout,
                                    input->domain, input->dom_objname);
        break;
    case CACHE_REQ_GROUP_BY_NAME:
        ret = sss_ncache_check_group(ncache, neg_timeout,
                                     input->domain, input->dom_objname);
        break;
    case CACHE_REQ_USER_BY_ID:
        ret = sss_ncache_check_uid(ncache, neg_timeout, NULL, input->id);
        break;
    case CACHE_REQ_GROUP_BY_ID:
        ret = sss_ncache_check_gid(ncache, neg_timeout, NULL, input->id);
        break;
    case CACHE_REQ_USER_BY_CERT:
        ret = sss_ncache_check_cert(ncache, neg_timeout, input->cert);
        break;
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
        ret = EOK;
        break;
    }

    if (ret == EEXIST) {
        DEBUG(SSSDBG_TRACE_FUNC, "[%s] does not exist (negative cache)\n",
              input->debug_fqn);
    }

    return ret;
}

static void cache_req_add_to_ncache(struct cache_req_input *input,
                                    struct sss_nc_ctx *ncache)
{
    errno_t ret = ERR_INTERNAL;

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        ret = sss_ncache_set_user(ncache, false, input->domain,
                                  input->dom_objname);
        break;
    case CACHE_REQ_GROUP_BY_NAME:
        ret = sss_ncache_set_group(ncache, false, input->domain,
                                   input->dom_objname);
        break;
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
        /* Nothing to do, adding a wildcard request to ncache doesn't
         * make sense */
    case CACHE_REQ_USER_BY_ID:
    case CACHE_REQ_GROUP_BY_ID:
    case CACHE_REQ_USER_BY_CERT:
        /* Nothing to do. Those types must be unique among all domains so
         * the don't contain domain part. Therefore they must be set only
         * if all domains are search and the entry is not found. */
        ret = EOK;
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set negcache for [%s] [%d]: %s\n",
              input->debug_fqn, ret, sss_strerror(ret));

        /* not fatal */
    }

    return;
}

static void cache_req_add_to_ncache_global(struct cache_req_input *input,
                                           struct sss_nc_ctx *ncache)
{
    errno_t ret = ERR_INTERNAL;

    switch (input->type) {
    case CACHE_REQ_USER_BY_FILTER:
    case CACHE_REQ_GROUP_BY_FILTER:
        /* Nothing to do, adding a wildcard request to ncache doesn't
         * make sense */
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_UPN:
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        /* Nothing to do. Those types are already in ncache for selected
         * domains. */
        ret = EOK;
        break;
    case CACHE_REQ_USER_BY_ID:
        ret = sss_ncache_set_uid(ncache, false, NULL, input->id);
        break;
    case CACHE_REQ_GROUP_BY_ID:
        ret = sss_ncache_set_gid(ncache, false, NULL, input->id);
        break;
    case CACHE_REQ_USER_BY_CERT:
        ret = sss_ncache_set_cert(ncache, false, input->cert);
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set negcache for [%s] [%d]: %s\n",
              input->debug_fqn, ret, sss_strerror(ret));

        /* not fatal */
    }

    return;
}

static errno_t cache_req_get_object(TALLOC_CTX *mem_ctx,
                                    struct cache_req_input *input,
                                    struct ldb_result **_result)
{
    struct ldb_result *result = NULL;
    bool one_item_only = false;
    errno_t ret = ERR_INTERNAL;

    DEBUG(SSSDBG_FUNC_DATA, "Requesting info for [%s]\n", input->debug_fqn);

    switch (input->type) {
    case CACHE_REQ_USER_BY_NAME:
        one_item_only = true;
        ret = sysdb_getpwnam_with_views(mem_ctx, input->domain,
                                        input->dom_objname, &result);
        break;
    case CACHE_REQ_USER_BY_UPN:
        one_item_only = true;
        ret = sysdb_getpwupn(mem_ctx, input->domain,
                             input->dom_objname, &result);
        break;
    case CACHE_REQ_USER_BY_ID:
        one_item_only = true;
        ret = sysdb_getpwuid_with_views(mem_ctx, input->domain,
                                        input->id, &result);
        break;
    case CACHE_REQ_GROUP_BY_NAME:
        one_item_only = true;
        ret = sysdb_getgrnam_with_views(mem_ctx, input->domain,
                                        input->dom_objname, &result);
        break;
    case CACHE_REQ_GROUP_BY_ID:
        one_item_only = true;
        ret = sysdb_getgrgid_with_views(mem_ctx, input->domain,
                                        input->id, &result);
        break;
    case CACHE_REQ_INITGROUPS:
        one_item_only = false;
        ret = sysdb_initgroups_with_views(mem_ctx, input->domain,
                                          input->dom_objname, &result);
        break;
    case CACHE_REQ_INITGROUPS_BY_UPN:
        one_item_only = false;
        ret = sysdb_initgroups_by_upn(mem_ctx, input->domain,
                                      input->dom_objname, &result);
        break;
    case CACHE_REQ_USER_BY_CERT:
        one_item_only = true;
        ret = sysdb_search_user_by_cert(mem_ctx, input->domain,
                                        input->cert, &result);
        break;
    case CACHE_REQ_USER_BY_FILTER:
        one_item_only = false;
        ret = updated_users_by_filter(mem_ctx, input->domain,
                                      input->dom_objname, input->req_start,
                                      &result);
        break;
    case CACHE_REQ_GROUP_BY_FILTER:
        one_item_only = false;
        ret = updated_groups_by_filter(mem_ctx, input->domain,
                                       input->dom_objname, input->req_start,
                                       &result);
        break;
    }

    if (ret != EOK) {
        goto done;
    } else if (result->count == 0) {
        ret = ENOENT;
        goto done;
    } else if (one_item_only && result->count > 1) {
        ret = ERR_INTERNAL;
        DEBUG(SSSDBG_CRIT_FAILURE, "Multiple objects were found when"
              "sysdb search expected only one!\n");
        goto done;
    }

    *_result = result;

done:
    return ret;
}

/* Return true if the request bypasses cache or false if the cache_req
 * code can leverage sysdb for this request.
 */
static bool cache_req_bypass_cache(struct cache_req_input *input)
{
    if (input->type == CACHE_REQ_USER_BY_FILTER ||
            input->type == CACHE_REQ_GROUP_BY_FILTER) {
        return true;
    }

    return false;
}

struct cache_req_cache_state {
    /* input data */
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int neg_timeout;
    int cache_refresh_percent;
    struct cache_req_input *input;

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
                                               struct cache_req_input *input)
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
    state->input = input;

    /* Check negative cache first. */
    ret = cache_req_check_ncache(state->input, state->ncache,
                                 state->neg_timeout);
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

    ret = cache_req_get_object(state, state->input, &state->result);
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
    DEBUG(SSSDBG_TRACE_FUNC, "Returning info for [%s]\n",
          state->input->debug_fqn);
    return EOK;
}

static errno_t cache_req_cache_check(struct tevent_req *req)
{
    struct cache_req_cache_state *state = NULL;
    struct tevent_req *subreq = NULL;
    const char *extra_flag = NULL;
    uint64_t cache_expire = 0;
    errno_t ret;
    const char *search_str;

    state = tevent_req_data(req, struct cache_req_cache_state);

    if (state->result == NULL || state->result->count == 0 ||
            cache_req_bypass_cache(state->input) == true) {
        ret = ENOENT;
    } else {
        if (state->input->type == CACHE_REQ_INITGROUPS) {
            cache_expire = ldb_msg_find_attr_as_uint64(state->result->msgs[0],
                                                       SYSDB_INITGR_EXPIRE, 0);
        } else {
            cache_expire = ldb_msg_find_attr_as_uint64(state->result->msgs[0],
                                                       SYSDB_CACHE_EXPIRE, 0);
        }

        ret = sss_cmd_check_cache(state->result->msgs[0],
                                  state->cache_refresh_percent, cache_expire);
    }

    search_str = state->input->dom_objname;
    if (state->input->type == CACHE_REQ_USER_BY_CERT) {
        search_str = state->input->cert;
    }

    if (DOM_HAS_VIEWS(state->input->domain)) {
        extra_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
    } else if (cache_req_input_is_upn(state->input)) {
        extra_flag = EXTRA_NAME_IS_UPN;
    }

    switch (ret) {
    case EOK:
        DEBUG(SSSDBG_TRACE_FUNC, "Cached entry is valid, returning...\n");
        return EOK;
    case EAGAIN:
        /* Out of band update. The calling function will return the cached
         * entry immediately. No callback is required. */

        DEBUG(SSSDBG_TRACE_FUNC, "Performing midpoint cache update\n");

        subreq = sss_dp_get_account_send(state, state->rctx,
                                         state->input->domain, true,
                                         state->input->dp_type,
                                         search_str,
                                         state->input->id, extra_flag);
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

        subreq = sss_dp_get_account_send(state, state->rctx,
                                         state->input->domain, true,
                                         state->input->dp_type,
                                         search_str,
                                         state->input->id, extra_flag);
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
    ret = cache_req_get_object(state, state->input, &state->result);
    if (ret == ENOENT) {
        cache_req_add_to_ncache(state->input, state->ncache);
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
    DEBUG(SSSDBG_TRACE_FUNC, "Returning info for [%s]\n",
          state->input->debug_fqn);

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
    struct cache_req_input *input;

    /* work data */
    struct ldb_result *result;
    struct sss_domain_info *domain;
    struct sss_domain_info *selected_domain;
    bool check_next;
};

static void cache_req_input_parsed(struct tevent_req *subreq);

static errno_t cache_req_select_domains(struct tevent_req *req,
                                        const char *domain);

static errno_t cache_req_next_domain(struct tevent_req *req);

static void cache_req_done(struct tevent_req *subreq);

struct tevent_req *cache_req_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int neg_timeout,
                                  int cache_refresh_percent,
                                  const char *domain,
                                  struct cache_req_input *input)
{
    struct cache_req_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
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
    state->input = input;

    if (state->input->orig_name != NULL && domain == NULL) {
        /* Parse input name first, since it may contain domain name. */
        subreq = sss_parse_inp_send(state, rctx, input->orig_name);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto immediately;
        }

        tevent_req_set_callback(subreq, cache_req_input_parsed, req);
    } else {
        if (input->orig_name != NULL) {
            ret = cache_req_input_set_name(input, input->orig_name);
            if (ret != EOK) {
                goto immediately;
            }
        }

        ret = cache_req_select_domains(req, domain);
        if (ret != EAGAIN) {
            goto immediately;
        }
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

static void cache_req_input_parsed(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct cache_req_state *state;
    char *name;
    char *domain;
    errno_t ret;
    bool maybe_upn;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = sss_parse_inp_recv(subreq, state, &name, &domain);
    switch (ret) {
    case EOK:
        ret = cache_req_input_set_name(state->input, name);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        break;
    case ERR_DOMAIN_NOT_FOUND:
        maybe_upn = cache_req_input_assume_upn(state->input);
        if (!maybe_upn) {
            tevent_req_error(req, ret);
            return;
        }

        domain = NULL;
        break;
    default:
        tevent_req_error(req, ret);
        return;
    }

    ret = cache_req_select_domains(req, domain);
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }
}

static errno_t cache_req_select_domains(struct tevent_req *req,
                                        const char *domain)
{
    struct cache_req_state *state = NULL;

    state = tevent_req_data(req, struct cache_req_state);

    if (domain != NULL) {
        /* single-domain search */
        state->domain = responder_get_domain(state->rctx, domain);
        if (state->domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }

        state->check_next = false;
    } else {
        /* multi-domain search */
        state->domain = state->rctx->domains;
        state->check_next = true;
    }

    return cache_req_next_domain(req);
}

static errno_t cache_req_next_domain(struct tevent_req *req)
{
    struct cache_req_state *state = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_state);

    while (state->domain != NULL) {
       /* If it is a domainless search, skip domains that require fully
        * qualified names instead. */
        while (state->domain != NULL && state->check_next
                && state->domain->fqnames
                && state->input->type != CACHE_REQ_USER_BY_CERT
                && !cache_req_input_is_upn(state->input)) {
            state->domain = get_next_domain(state->domain, 0);
        }

        state->selected_domain = state->domain;

        if (state->domain == NULL) {
            break;
        }

        ret = cache_req_input_set_domain(state->input, state->domain,
                                         state->rctx);
        if (ret != EOK) {
            return ret;
        }

        subreq = cache_req_cache_send(state, state->ev, state->rctx,
                                      state->ncache, state->neg_timeout,
                                      state->cache_refresh_percent,
                                      state->input);
        if (subreq == NULL) {
            return ENOMEM;
        }

        tevent_req_set_callback(subreq, cache_req_done, req);

        /* we will continue with the following domain the next time */
        if (state->check_next) {
            if (cache_req_input_is_upn(state->input)
                    || state->input->type == CACHE_REQ_USER_BY_CERT ) {
                state->domain = get_next_domain(state->domain, SSS_GND_DESCEND);
            } else {
                state->domain = get_next_domain(state->domain, 0);
            }
        }

        return EAGAIN;
    }

    /* If the object searched has to be unique among all maintained domains,
     * we have to add it into negative cache here when all domains have
     * been searched. */

    cache_req_add_to_ncache_global(state->input, state->ncache);

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
        if (ret == ENOENT && cache_req_input_assume_upn(state->input)) {
            /* search by upn now */
            cache_req_select_domains(req, NULL);
            return;
        }

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
                       struct sss_domain_info **_domain,
                       char **_name)
{
    struct cache_req_state *state = NULL;
    char *name;

    state = tevent_req_data(req, struct cache_req_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_name != NULL) {
        if (state->input->dom_objname == NULL) {
            *_name = NULL;
        } else {
            name = talloc_strdup(mem_ctx, state->input->name);
            if (name == NULL) {
                return ENOMEM;
            }

            *_name = name;
        }
    }

    if (_result != NULL) {
        *_result = talloc_steal(mem_ctx, state->result);
    }

    if (_domain != NULL) {
        *_domain = state->selected_domain;
    }

    return EOK;
}

static struct tevent_req *
cache_req_steal_input_and_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct resp_ctx *rctx,
                               struct sss_nc_ctx *ncache,
                               int neg_timeout,
                               int cache_refresh_percent,
                               const char *domain,
                               struct cache_req_input *input)
{
    struct tevent_req *req;

    req = cache_req_send(mem_ctx, ev, rctx, ncache, neg_timeout,
                         cache_refresh_percent, domain, input);
    if (req == NULL) {
        talloc_zfree(input);
    }

    talloc_steal(req, input);

    return req;
}

struct tevent_req *
cache_req_user_by_name_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int neg_timeout,
                            int cache_refresh_percent,
                            const char *domain,
                            const char *name)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, CACHE_REQ_USER_BY_NAME, name, 0,
                                   NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_user_by_id_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct resp_ctx *rctx,
                          struct sss_nc_ctx *ncache,
                          int neg_timeout,
                          int cache_refresh_percent,
                          const char *domain,
                          uid_t uid)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, CACHE_REQ_USER_BY_ID, NULL, uid,
                                   NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_user_by_cert_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int neg_timeout,
                            int cache_refresh_percent,
                            const char *domain,
                            const char *pem_cert)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, CACHE_REQ_USER_BY_CERT,
                                   NULL, 0, pem_cert);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_group_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct resp_ctx *rctx,
                             struct sss_nc_ctx *ncache,
                             int neg_timeout,
                             int cache_refresh_percent,
                             const char *domain,
                             const char *name)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, CACHE_REQ_GROUP_BY_NAME, name, 0,
                                   NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_group_by_id_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int neg_timeout,
                           int cache_refresh_percent,
                           const char *domain,
                           gid_t gid)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, CACHE_REQ_GROUP_BY_ID, NULL, gid,
                                   NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_initgr_by_name_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int neg_timeout,
                              int cache_refresh_percent,
                              const char *domain,
                              const char *name)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, CACHE_REQ_INITGROUPS, name, 0,
                                   NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, ncache,
                                          neg_timeout, cache_refresh_percent,
                                          domain, input);
}

struct tevent_req *
cache_req_user_by_filter_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              const char *domain,
                              const char *filter)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, CACHE_REQ_USER_BY_FILTER,
                                   filter, 0, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, NULL,
                                          0, 0, domain, input);
}

struct tevent_req *
cache_req_group_by_filter_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct resp_ctx *rctx,
                               const char *domain,
                               const char *filter)
{
    struct cache_req_input *input;

    input = cache_req_input_create(mem_ctx, CACHE_REQ_GROUP_BY_FILTER,
                                   filter, 0, NULL);
    if (input == NULL) {
        return NULL;
    }

    return cache_req_steal_input_and_send(mem_ctx, ev, rctx, NULL,
                                          0, 0, domain, input);
}
