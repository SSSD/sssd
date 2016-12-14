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
#include <errno.h>

#include "util/util.h"
#include "responder/common/cache_req/cache_req_private.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static const struct cache_req_plugin *
cache_req_get_plugin(enum cache_req_type type)
{
    static const struct cache_req_plugin *plugins[CACHE_REQ_SENTINEL] = {
        &cache_req_user_by_name,
        &cache_req_user_by_upn,
        &cache_req_user_by_id,
        &cache_req_user_by_cert,
        &cache_req_user_by_filter,

        &cache_req_group_by_name,
        &cache_req_group_by_id,
        &cache_req_group_by_filter,

        &cache_req_initgroups_by_name,
        &cache_req_initgroups_by_upn,

        &cache_req_object_by_sid,
        &cache_req_object_by_name,
        &cache_req_object_by_id,

        &cache_req_enum_users,
        &cache_req_enum_groups,
        &cache_req_enum_svc,

        &cache_req_svc_by_name,
        &cache_req_svc_by_port,

        &cache_req_netgroup_by_name,
    };

    if (type >= CACHE_REQ_SENTINEL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Bug: invalid plugin type!");
        return NULL;
    }

    return plugins[type];
}

static errno_t cache_req_set_plugin(struct cache_req *cr,
                                    enum cache_req_type type)
{
    const struct cache_req_plugin *plugin;

    plugin = cache_req_get_plugin(type);
    if (plugin == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Bug: unset plugin!");
        return EINVAL;
    }

    cr->reqname = plugin->name;
    cr->dp_type = plugin->dp_type;
    cr->plugin = plugin;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_INTERNAL, cr, "Setting \"%s\" plugin\n",
                    plugin->name);

    return EOK;
}

static struct cache_req *
cache_req_create(TALLOC_CTX *mem_ctx,
                 struct resp_ctx *rctx,
                 struct cache_req_data *data,
                 struct sss_nc_ctx *ncache,
                 int midpoint)
{
    struct cache_req *cr;
    errno_t ret;

    cr = talloc_zero(mem_ctx, struct cache_req);
    if (cr == NULL) {
        return NULL;
    }

    cr->rctx = rctx;
    cr->data = data;
    cr->ncache = ncache;
    cr->midpoint = midpoint;
    cr->req_start = time(NULL);

    /* It is perfectly fine to just overflow here. */
    cr->reqid = rctx->cache_req_num++;

    ret = cache_req_set_plugin(cr, data->type);
    if (ret != EOK) {
        talloc_free(cr);
        return NULL;
    }

    return cr;
}

static errno_t
cache_req_set_name(struct cache_req *cr, const char *name)
{
    const char *dup_name;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Setting name [%s]\n", name);

    dup_name = talloc_strdup(cr->data, name);
    if (dup_name == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr, "Unable to set name!\n");
        return ENOMEM;
    }

    talloc_zfree(cr->data->name.name);
    cr->data->name.name = dup_name;

    return EOK;
}

static bool
cache_req_validate_domain(struct cache_req *cr,
                          struct sss_domain_info *domain)
{
    if (!cr->plugin->require_enumeration) {
        return true;
    }

    if (domain->enumerate == false) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Domain %s does not support "
                        "enumeration, skipping...\n", domain->name);
        return false;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Domain %s supports enumeration\n",
                    domain->name);

    return true;
}

static errno_t
cache_req_is_well_known_object(TALLOC_CTX *mem_ctx,
                               struct cache_req *cr,
                               struct cache_req_result **_result)
{
    errno_t ret;

    if (cr->plugin->is_well_known_fn == NULL) {
        return ENOENT;
    }

    ret = cr->plugin->is_well_known_fn(mem_ctx, cr, cr->data, _result);
    if (ret == EOK) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Object is well known!\n");
        (*_result)->well_known_object = true;
    } else if (ret != ENOENT) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Unable to prepare data [%d]: %s\n",
                        ret, sss_strerror(ret));
    }

    return ret;
}

static errno_t
cache_req_prepare_domain_data(struct cache_req *cr,
                              struct sss_domain_info *domain)
{
    errno_t ret;

    if (cr->plugin->prepare_domain_data_fn == NULL) {
        return EOK;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                    "Preparing input data for domain [%s] rules\n",
                    domain->name);

    ret = cr->plugin->prepare_domain_data_fn(cr, cr->data, domain);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Unable to prepare data [%d]: %s\n",
                        ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static errno_t
cache_req_create_debug_name(struct cache_req *cr,
                            struct sss_domain_info *domain)
{
    if (cr->plugin->create_debug_name_fn == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Bug: no create debug name function specified!\n");
        return ERR_INTERNAL;
    }

    talloc_zfree(cr->debugobj);

    cr->debugobj = cr->plugin->create_debug_name_fn(cr, cr->data, domain);
    if (cr->debugobj == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Unable to create debug name!\n");
        return ENOMEM;
    }

    return EOK;
}

static errno_t
cache_req_set_domain(struct cache_req *cr,
                     struct sss_domain_info *domain)
{
    errno_t ret;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Using domain [%s]\n", domain->name);

    ret = cache_req_prepare_domain_data(cr, domain);
    if (ret != EOK) {
        return ret;
    }

    ret = cache_req_create_debug_name(cr, domain);
    if (ret != EOK) {
        return ret;
    }

    cr->domain = domain;

    return EOK;
}

static void cache_req_global_ncache_add(struct cache_req *cr)
{
    errno_t ret;

    if (cr->plugin->global_ncache_add_fn == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_INTERNAL, cr,
                        "This request type does not support "
                        "global negative cache\n");
        return;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Adding [%s] to global "
                    "negative cache\n", cr->debugobj);

    ret = cr->plugin->global_ncache_add_fn(cr->ncache, cr->data);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_MINOR_FAILURE, cr,
                        "Cannot set negative cache for [%s] [%d]: %s\n",
                        cr->debugobj, ret, sss_strerror(ret));
        /* not fatal */
    }

    return;
}

static bool
cache_req_assume_upn(struct cache_req *cr)
{
    errno_t ret;

    if (cr->plugin->allow_switch_to_upn == false
            || cr->data->name.input == NULL
            || strchr(cr->data->name.input, '@') == NULL) {
        return false;
    }

    ret = cache_req_set_plugin(cr, cr->plugin->upn_equivalent);
    if (ret != EOK) {
        return false;
    }

    ret = cache_req_set_name(cr, cr->data->name.input);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_set_name() failed\n");
        return false;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Assuming UPN [%s]\n",
                    cr->data->name.input);

    return true;
}

struct cache_req_state {
    /* input data */
    struct tevent_context *ev;
    struct cache_req *cr;

    /* work data */
    struct sss_domain_info *domain;
    struct sss_domain_info *selected_domain;
    struct cache_req_result **results;
    size_t num_results;
    bool check_next;
    bool dp_success;
};

static errno_t cache_req_add_result(struct cache_req_state *state,
                                    struct cache_req_result *new);

static errno_t cache_req_process_input(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       struct cache_req *cr,
                                       const char *domain);

static void cache_req_input_parsed(struct tevent_req *subreq);

static errno_t cache_req_select_domains(struct tevent_req *req,
                                        const char *domain);

static errno_t cache_req_next_domain(struct tevent_req *req);

static void cache_req_done(struct tevent_req *subreq);

struct tevent_req *cache_req_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int midpoint,
                                  const char *domain,
                                  struct cache_req_data *data)
{
    struct cache_req_state *state;
    struct cache_req_result *result;
    struct cache_req *cr;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->dp_success = true;
    state->cr = cr = cache_req_create(state, rctx, data, ncache, midpoint);
    if (state->cr == NULL) {
        ret = ENOMEM;
        goto done;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "New request '%s'\n", cr->reqname);

    ret = cache_req_is_well_known_object(state, cr, &result);
    if (ret == EOK) {
        ret = cache_req_add_result(state, result);
        goto done;
    } else if (ret != ENOENT) {
        goto done;
    }

    ret = cache_req_process_input(state, req, cr, domain);
    if (ret != EOK) {
        goto done;
    }

    ret = cache_req_select_domains(req, domain);

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t cache_req_process_input(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       struct cache_req *cr,
                                       const char *domain)
{
    struct tevent_req *subreq;

    if (cr->data->name.input == NULL) {
        /* Input was not name, there is no need to process it further. */
        return EOK;
    }

    if (cr->plugin->parse_name == false || domain != NULL) {
        /* We do not want to parse the name. */
        return cache_req_set_name(cr, cr->data->name.input);
    }

    /* Parse name since it may contain a domain name. */
    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                    "Parsing input name [%s]\n", cr->data->name.input);

    subreq = sss_parse_inp_send(mem_ctx, cr->rctx, cr->data->name.input);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, cache_req_input_parsed, req);

    return EAGAIN;
}

static void cache_req_input_parsed(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct cache_req_state *state;
    char *name;
    char *domain;
    bool maybe_upn;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = sss_parse_inp_recv(subreq, state, &name, &domain);
    switch (ret) {
    case EOK:
        ret = cache_req_set_name(state->cr, name);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        break;
    case ERR_DOMAIN_NOT_FOUND:
        maybe_upn = cache_req_assume_upn(state->cr);
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
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Performing a single domain search\n");

        state->domain = responder_get_domain(state->cr->rctx, domain);
        if (state->domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }

        state->check_next = false;
    } else {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Performing a multi-domain search\n");

        state->domain = state->cr->rctx->domains;
        state->check_next = true;
    }

    return cache_req_next_domain(req);
}

static errno_t cache_req_next_domain(struct tevent_req *req)
{
    struct cache_req_state *state;
    struct tevent_req *subreq;
    struct cache_req *cr;
    uint32_t next_domain_flag;
    bool is_domain_valid;
    bool allow_no_fqn;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_state);
    cr = state->cr;

    next_domain_flag = cr->plugin->get_next_domain_flags;
    allow_no_fqn = cr->plugin->allow_missing_fqn;

    while (state->domain != NULL) {
        /* Check if this domain is valid for this request. */
        is_domain_valid = cache_req_validate_domain(cr, state->domain);
        if (!is_domain_valid) {
            state->domain = get_next_domain(state->domain, next_domain_flag);
            continue;
        }

        /* If not specified otherwise, we skip domains that require fully
         * qualified names on domain less search. We do not descend into
         * subdomains here since those are implicitly qualified.
         */
        if (state->check_next && !allow_no_fqn && state->domain->fqnames) {
            state->domain = get_next_domain(state->domain, 0);
            continue;
        }

        state->selected_domain = state->domain;

        if (state->domain == NULL) {
            break;
        }

        ret = cache_req_set_domain(cr, state->domain);
        if (ret != EOK) {
            return ret;
        }

        subreq = cache_req_search_send(state, state->ev, cr);
        if (subreq == NULL) {
            return ENOMEM;
        }

        tevent_req_set_callback(subreq, cache_req_done, req);

        /* we will continue with the following domain the next time */
        if (state->check_next) {
            state->domain = get_next_domain(state->domain,
                                            cr->plugin->get_next_domain_flags);
        }

        return EAGAIN;
    }

    /* If we've got some result from previous searches we want to return
     * EOK here so the whole cache request is successfully finished. */
    if (state->num_results > 0) {
        return EOK;
    }

    /* We have searched all available domains and no result was found.
     *
     * If the plug-in uses a negative cache which is shared among all domains
     * (e.g. unique identifiers such as user or group id or sid), we add it
     * here and return object not found error.
     *
     * However, we can only set the negative cache if all data provider
     * requests succeeded because only then we can be sure that it does
     * not exist-
     */
    if (state->dp_success) {
        cache_req_global_ncache_add(cr);
    }

    return ENOENT;
}

static errno_t
cache_req_add_result(struct cache_req_state *state,
                     struct cache_req_result *new)
{
    struct cache_req_result **results = state->results;
    size_t index;
    size_t count;

    /* Make space for new results. */
    index = state->num_results;
    count = state->num_results + 1;

    results = talloc_realloc(state, results, struct cache_req_result *, count + 1);
    if (results == NULL) {
        return ENOMEM;
    }

    results[index] = talloc_steal(results, new);
    results[index + 1] = NULL;
    state->results = results;
    state->num_results = count;

    return EOK;
}

static errno_t
cache_req_create_and_add_result(struct cache_req_state *state,
                                struct sss_domain_info *domain,
                                struct ldb_result *ldb_result,
                                const char *name)
{
    struct cache_req_result *item;
    errno_t ret;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                    "Found %u entries in domain %s\n",
                    ldb_result->count, domain->name);

    item = cache_req_create_result(state, domain, ldb_result, name, NULL);
    if (item == NULL) {
        return ENOMEM;
    }

    ret = cache_req_add_result(state, item);
    if (ret != EOK) {
        talloc_free(item);
    }

    return ret;
}

static void cache_req_done(struct tevent_req *subreq)
{
    struct cache_req_state *state;
    struct ldb_result *result;
    struct tevent_req *req;
    bool dp_success;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = cache_req_search_recv(state, subreq, &result, &dp_success);
    talloc_zfree(subreq);

    /* Remember if any DP request fails. */
    state->dp_success = !dp_success ? false : state->dp_success;

    switch (ret) {
    case EOK:
        /* We got some data from this search. Save it. */
        ret = cache_req_create_and_add_result(state, state->selected_domain,
                                              result,
                                              state->cr->data->name.lookup);
        if (ret != EOK) {
            /* We were unable to save data. */
            goto done;
        }

        if (!state->check_next || !state->cr->plugin->search_all_domains) {
            /* We are not interested in more results. */
            ret = EOK;
            goto done;
        }

        break;
    case ENOENT:
        if (state->check_next == false) {
            /* Lookup domain was specified as input.
             * We don't want to try the next domain,
             * but we may want to try UPN search. */

            if (cache_req_assume_upn(state->cr)) {
                /* Try UPN now. */
                ret = cache_req_select_domains(req, NULL);
                goto done;
            }

            /* Not found. */
            ret = ENOENT;
            goto done;
        }

        break;
    default:
        /* Some serious error has happened. Finish. */
        goto done;
    }

    /* This is a domain less search, continue with the next domain. */
    ret = cache_req_next_domain(req);

done:
    if (ret == ENOENT && state->results != NULL) {
        /* We have at least one result. */
        ret = EOK;
    }

    switch (ret) {
    case EOK:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr, "Finished: Success\n");
        tevent_req_done(req);
        break;
    case EAGAIN:
        break;
    case ENOENT:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr, "Finished: Not found\n");
        tevent_req_error(req, ret);
        break;
    default:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Finished: Error %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        break;
    }

    return;
}

errno_t cache_req_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct cache_req_result ***_results)
{
    struct cache_req_state *state;

    state = tevent_req_data(req, struct cache_req_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_results != NULL) {
        *_results = talloc_steal(mem_ctx, state->results);
    }

    return EOK;
}

errno_t cache_req_single_domain_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     struct cache_req_result **_result)
{
    struct cache_req_state *state;

    state = tevent_req_data(req, struct cache_req_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_result != NULL) {
        *_result = talloc_steal(mem_ctx, state->results[0]);
    }

    return EOK;
}

struct tevent_req *
cache_req_steal_data_and_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int cache_refresh_percent,
                              const char *domain,
                              struct cache_req_data *data)
{
    struct tevent_req *req;

    req = cache_req_send(mem_ctx, ev, rctx, ncache,
                         cache_refresh_percent, domain, data);
    if (req == NULL) {
        talloc_zfree(data);
        return NULL;
    }

    talloc_steal(req, data);

    return req;
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

struct cache_req_result *
cache_req_create_result_from_msg(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 struct ldb_message *ldb_msg,
                                 const char *lookup_name,
                                 const char *well_known_domain)
{
    struct cache_req_result *result;
    struct ldb_result *ldb_result;
    errno_t ret;

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
        ret = ENOMEM;
        goto done;
    }

    ldb_result->msgs[0] = talloc_steal(ldb_result->msgs, ldb_msg);

    result = cache_req_create_result(mem_ctx, domain, ldb_result,
                                     lookup_name, well_known_domain);
    if (result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
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
