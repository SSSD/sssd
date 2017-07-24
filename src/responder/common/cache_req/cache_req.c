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
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req_private.h"
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

        &cache_req_host_by_name,
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
    cr->plugin = plugin;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_INTERNAL, cr, "Setting \"%s\" plugin\n",
                    plugin->name);

    return EOK;
}

static const char *
cache_req_dom_type_as_str(struct cache_req *cr)
{
    if (cr == NULL) {
        return "BUG: Invalid cache_req pointer\n";
    }
    switch (cr->req_dom_type) {
    case CACHE_REQ_POSIX_DOM:
        return "POSIX-only";
    case CACHE_REQ_APPLICATION_DOM:
        return "Application-only";
    case CACHE_REQ_ANY_DOM:
        return "Any";
    }

    return "Unknown";
}

static struct cache_req *
cache_req_create(TALLOC_CTX *mem_ctx,
                 struct resp_ctx *rctx,
                 struct cache_req_data *data,
                 struct sss_nc_ctx *ncache,
                 int midpoint,
                 enum cache_req_dom_type req_dom_type)
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
    cr->req_dom_type = req_dom_type;
    cr->req_start = time(NULL);

    /* It is perfectly fine to just overflow here. */
    cr->reqid = rctx->cache_req_num++;

    ret = cache_req_set_plugin(cr, data->type);
    if (ret != EOK) {
        talloc_free(cr);
        return NULL;
    }

    cr->cache_first = rctx->cache_first;
    cr->bypass_cache = cr->plugin->bypass_cache || cr->data->bypass_cache;

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
cache_req_validate_domain_enumeration(struct cache_req *cr,
                                      struct sss_domain_info *domain)
{
    if (!cr->plugin->require_enumeration) {
        return true;
    }

    if (domain->enumerate == false) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Domain %s does not support "
                        "enumeration, skipping...\n", domain->name);
        if (cr->rctx->enumeration_warn_logged == false) {
            sss_log(SSS_LOG_NOTICE, "Enumeration requested but not enabled\n");
            CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                            "Enumeration requested but not enabled\n");
            cr->rctx->enumeration_warn_logged = true;
        }
        return false;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "Domain %s supports enumeration\n",
                    domain->name);

    return true;
}

static bool
cache_req_validate_domain_type(struct cache_req *cr,
                               struct sss_domain_info *domain)
{
    bool valid = false;

    switch (cr->req_dom_type) {
    case CACHE_REQ_POSIX_DOM:
        valid = domain->type == DOM_TYPE_POSIX ? true : false;
        break;
    case CACHE_REQ_APPLICATION_DOM:
        valid = domain->type == DOM_TYPE_APPLICATION ? true : false;
        break;
    case CACHE_REQ_ANY_DOM:
        valid = true;
        break;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Request type %s for domain %s type %s is %svalid\n",
          cache_req_dom_type_as_str(cr),
          domain->name,
          sss_domain_type_str(domain),
          valid ? "" : "not ");
    return valid;
}

static bool
cache_req_validate_domain(struct cache_req *cr,
                          struct sss_domain_info *domain)
{
    bool ok;

    ok = cache_req_validate_domain_enumeration(cr, domain);
    if (ok == false) {
        return false;
    }

    ok = cache_req_validate_domain_type(cr, domain);
    if (ok == false) {
        return false;
    }

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

struct cache_req_search_domains_state {
    /* input data */
    struct tevent_context *ev;
    struct cache_req *cr;

    /* work data */
    struct cache_req_domain *cr_domain;
    struct sss_domain_info *selected_domain;
    struct cache_req_result **results;
    size_t num_results;
    bool check_next;
    bool dp_success;
    bool bypass_cache;
    bool bypass_dp;
};

static errno_t cache_req_search_domains_next(struct tevent_req *req);

static void cache_req_search_domains_done(struct tevent_req *subreq);

struct tevent_req *
cache_req_search_domains_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct cache_req *cr,
                              struct cache_req_domain *cr_domain,
                              bool check_next,
                              bool bypass_cache,
                              bool bypass_dp)
{
    struct tevent_req *req;
    struct cache_req_search_domains_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct cache_req_search_domains_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->cr = cr;

    state->cr_domain = cr_domain;
    state->check_next = check_next;
    state->dp_success = true;
    state->bypass_cache = bypass_cache;
    state->bypass_dp = bypass_dp;

    ret = cache_req_search_domains_next(req);
    if (ret == EAGAIN) {
        return req;
    }

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, ev);
    return req;
}

static errno_t cache_req_search_domains_next(struct tevent_req *req)
{
    struct cache_req_search_domains_state *state;
    struct tevent_req *subreq;
    struct cache_req *cr;
    struct sss_domain_info *domain;
    uint32_t next_domain_flag;
    bool is_domain_valid;
    bool allow_no_fqn;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_search_domains_state);
    cr = state->cr;

    next_domain_flag = cr->plugin->get_next_domain_flags;
    allow_no_fqn = cr->plugin->allow_missing_fqn;

    while (state->cr_domain != NULL) {
        domain = state->cr_domain->domain;
        /* As the cr_domain list is a flatten version of the domains
         * list, we have to ensure to only go through the subdomains in
         * case it's specified in the plugin to do so.
         */
        if (next_domain_flag == 0 && IS_SUBDOMAIN(domain)) {
            state->cr_domain = state->cr_domain->next;
            continue;
        }

        /* Check if this domain is valid for this request. */
        is_domain_valid = cache_req_validate_domain(cr, domain);
        if (!is_domain_valid) {
            state->cr_domain = state->cr_domain->next;
            continue;
        }

        /* If not specified otherwise, we skip domains that require fully
         * qualified names on domain less search. We do not descend into
         * subdomains here since those are implicitly qualified.
         */
        if (state->check_next && !allow_no_fqn && state->cr_domain->fqnames) {
            state->cr_domain = state->cr_domain->next;
            continue;
        }

        state->selected_domain = domain;

        if (domain == NULL) {
            break;
        }

        ret = cache_req_set_domain(cr, domain);
        if (ret != EOK) {
            return ret;
        }

        subreq = cache_req_search_send(state, state->ev, cr,
                                       state->bypass_cache, state->bypass_dp);
        if (subreq == NULL) {
            return ENOMEM;
        }

        tevent_req_set_callback(subreq, cache_req_search_domains_done, req);

        /* we will continue with the following domain the next time */
        if (state->check_next) {
            state->cr_domain = state->cr_domain->next;
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

static void cache_req_search_domains_done(struct tevent_req *subreq)
{
    struct cache_req_search_domains_state *state;
    struct ldb_result *result;
    struct tevent_req *req;
    bool dp_success;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_search_domains_state);

    ret = cache_req_search_recv(state, subreq, &result, &dp_success);
    talloc_zfree(subreq);

    /* Remember if any DP request fails. */
    state->dp_success = !dp_success ? false : state->dp_success;

    switch (ret) {
    case EOK:
        /* We got some data from this search. Save it. */
        ret = cache_req_create_and_add_result(state,
                                              state->cr,
                                              state->selected_domain,
                                              result,
                                              state->cr->data->name.lookup,
                                              &state->results,
                                              &state->num_results);
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
            /* Not found. */
            ret = ENOENT;
            goto done;
        }

        /* Continue with next domain. */
        break;
    default:
        /* Some serious error has happened. Finish. */
        goto done;
    }

    /* This is a domain less search, continue with the next domain. */
    ret = cache_req_search_domains_next(req);

done:
    if (ret == ENOENT && state->results != NULL) {
        /* We have at least one result. */
        ret = EOK;
    }

    switch (ret) {
    case EOK:
        tevent_req_done(req);
        break;
    case EAGAIN:
        break;
    default:
        tevent_req_error(req, ret);
        break;
    }

    return;
}

static errno_t
cache_req_search_domains_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              struct cache_req_result ***_results,
                              size_t *_num_results)
{
    struct cache_req_search_domains_state *state;

    state = tevent_req_data(req, struct cache_req_search_domains_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_results != NULL) {
        *_results = talloc_steal(mem_ctx, state->results);
    }
    if (_num_results != NULL) {
        *_num_results = state->num_results;
    }

    return EOK;
}

/**
 * Return true if we should issue another search.
 */
static bool cache_req_search_schema(struct cache_req *cr,
                                    const char *input_domain,
                                    bool first_iteration,
                                    bool *_bypass_cache,
                                    bool *_bypass_dp)
{
    bool bypass_cache;
    bool bypass_dp;

    if (cr->bypass_cache) {
        /* The caller wants to contact Data Provider first
         * or it is inferred by cache_req plug-in. */
        bypass_cache = true;
        bypass_dp = false;

        if (!first_iteration) {
            return false;
        }
    } else if (input_domain != NULL) {
        /* We will search only one domain. */
        bypass_cache = false;
        bypass_dp = false;

        if (!first_iteration) {
            return false;
        }
     } else if (!cr->cache_first) {
        /* We will search cache and on cache-miss
         * contact domain provider sequentially. */
        bypass_cache = false;
        bypass_dp = false;

        if (!first_iteration) {
            return false;
        }
    } else {
        /* We will first search the cache in all domains. If we don't get
         * any match we will then contact Data Provider starting with the
         * first domain again. */
        bypass_cache = first_iteration ? false : true;
        bypass_dp = first_iteration ? true : false;
    }

    *_bypass_cache = bypass_cache;
    *_bypass_dp = bypass_dp;

    return true;
}

struct cache_req_state {
    /* input data */
    struct tevent_context *ev;
    struct cache_req *cr;
    const char *domain_name;

    /* work data */
    struct cache_req_result **results;
    size_t num_results;
    bool first_iteration;
};

static errno_t cache_req_process_input(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       struct cache_req *cr,
                                       const char *domain);

static errno_t cache_req_update_domains(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        struct cache_req *cr,
                                        const char *domain);

static void cache_req_domains_updated(struct tevent_req *subreq);

static void cache_req_input_parsed(struct tevent_req *subreq);

static errno_t cache_req_select_domains(struct tevent_req *req,
                                        const char *domain_name);

static errno_t
cache_req_search_domains(struct tevent_req *req,
                         struct cache_req_domain *oredered_domain,
                         bool check_next,
                         bool bypass_cache,
                         bool bypass_dp);

static void cache_req_process_result(struct tevent_req *subreq);

static void cache_req_done(struct tevent_req *subreq);

struct tevent_req *cache_req_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int midpoint,
                                  enum cache_req_dom_type req_dom_type,
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
    state->cr = cr = cache_req_create(state, rctx, data,
                                      ncache, midpoint, req_dom_type);
    if (state->cr == NULL) {
        ret = ENOMEM;
        goto done;
    }
    state->first_iteration = true;

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "New request '%s'\n", cr->reqname);

    ret = cache_req_is_well_known_object(state, cr, &result);
    if (ret == EOK) {
        ret = cache_req_add_result(state, result, &state->results,
                                   &state->num_results);
        goto done;
    } else if (ret != ENOENT) {
        goto done;
    }

    state->domain_name = domain;
    ret = cache_req_process_input(state, req, cr, domain);
    if (ret != EOK) {
        goto done;
    }

    ret = cache_req_select_domains(req, state->domain_name);

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
    const char *default_domain;
    errno_t ret;

    if (cr->data->name.input == NULL) {
        /* Call cache_req_update_domains() in order to get a up to date list
         * of domains and subdomains, if needed. Otherwise just return EOK as
         * the input was not a name, thus there's no need to process it
         * further. */
        return cache_req_update_domains(mem_ctx, req, cr, domain);
    }

    if (cr->plugin->parse_name == false || domain != NULL) {
        /* Call cache_req_update_domains() in order to get a up to date list
         * of domains and subdomains, if needed. Otherwise, just use the input
         * name as it is. */
        ret = cache_req_update_domains(mem_ctx, req, cr, domain);
        if (ret != EOK) {
            return ret;
        }

        return cache_req_set_name(cr, cr->data->name.input);
    }

    default_domain = NULL;
    if (!cr->plugin->ignore_default_domain) {
        default_domain = cr->rctx->default_domain;
    }

    /* Parse name since it may contain a domain name. */
    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                    "Parsing input name [%s]\n", cr->data->name.input);

    subreq = sss_parse_inp_send(mem_ctx, cr->rctx, default_domain,
                                cr->data->name.input);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, cache_req_input_parsed, req);

    return EAGAIN;
}

static errno_t cache_req_update_domains(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        struct cache_req *cr,
                                        const char *domain)
{
    struct tevent_req *subreq;

    if (cr->rctx->get_domains_last_call.tv_sec != 0) {
        return EOK;
    }

    subreq = sss_dp_get_domains_send(mem_ctx, cr->rctx, false, domain);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, cache_req_domains_updated, req);
    return EAGAIN;
}

static void cache_req_domains_updated(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct cache_req_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = sss_dp_get_domains_recv(subreq);
    talloc_free(subreq);
    if (ret != EOK) {
        goto done;
    }

    if (state->cr->data->name.input == NULL) {
        /* Input was not name, there is no need to process it further. */
        goto immediately;
    }

    if (state->cr->plugin->parse_name == false || state->domain_name != NULL) {
        /* We do not want to parse the name. */
        ret = cache_req_set_name(state->cr, state->cr->data->name.input);
        if (ret != EOK) {
            goto done;
        }
    }

immediately:
    ret = cache_req_select_domains(req, state->domain_name);

done:
    if (ret != EOK && ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }
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

    state->domain_name = domain;
    ret = cache_req_select_domains(req, domain);
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }
}

static errno_t cache_req_select_domains(struct tevent_req *req,
                                        const char *domain_name)
{
    struct cache_req_state *state = NULL;
    struct cache_req_domain *cr_domain;
    bool check_next;
    bool bypass_cache;
    bool bypass_dp;
    bool search;

    state = tevent_req_data(req, struct cache_req_state);

    search = cache_req_search_schema(state->cr, domain_name,
                                     state->first_iteration,
                                     &bypass_cache, &bypass_dp);
    if (!search) {
        /* We're done here. */
        return EOK;
    }

    if (domain_name != NULL) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Performing a single domain search\n");

        cr_domain = cache_req_domain_get_domain_by_name(
                                    state->cr->rctx->cr_domains, domain_name);
        if (cr_domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }
        check_next = false;
    } else {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Performing a multi-domain search\n");

        cr_domain = state->cr->rctx->cr_domains;
        check_next = true;
    }

    return cache_req_search_domains(req, cr_domain, check_next,
                                    bypass_cache, bypass_dp);
}

static errno_t
cache_req_search_domains(struct tevent_req *req,
                         struct cache_req_domain *cr_domain,
                         bool check_next,
                         bool bypass_cache,
                         bool bypass_dp)
{
    struct tevent_req *subreq;
    struct cache_req_state *state = NULL;

    state = tevent_req_data(req, struct cache_req_state);

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                    "Search will %s the cache and %s the data provider\n",
                    bypass_cache ? "bypass" : "check",
                    bypass_dp ? "bypass" : "check");

    subreq = cache_req_search_domains_send(state, state->ev, state->cr,
                                           cr_domain, check_next,
                                           bypass_cache, bypass_dp);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, cache_req_process_result, req);
    return EAGAIN;
}

static void cache_req_process_result(struct tevent_req *subreq)
{
    struct cache_req_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = cache_req_search_domains_recv(state, subreq,
                                        &state->results, &state->num_results);
    talloc_zfree(subreq);

    if (ret == ENOENT && state->first_iteration) {
        /* Try again different search schema. */
        state->first_iteration = false;
        ret = cache_req_select_domains(req, state->domain_name);
        if (ret == EOK) {
            /* We're done searching and we have found nothing. */
            ret = ENOENT;

            if (state->domain_name != NULL) {
                /* Lookup domain was specified as input. Since we haven't
                 * found anything yet we may want to try UPN search with
                 * some plug-ins. */

                if (cache_req_assume_upn(state->cr)) {
                    /* Try UPN now. */
                    state->first_iteration = true;
                    ret = cache_req_select_domains(req, NULL);
                }
            }
        }
    }

    /* Overlay each result with session recording flag */
    if (ret == EOK) {
        subreq = cache_req_sr_overlay_send(state, state->ev, state->cr,
                                           state->results,
                                           state->num_results);
        if (subreq == NULL) {
            CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                            "Failed creating a session recording "
                            "overlay request\n");
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(subreq, cache_req_done, req);
            ret = EAGAIN;
        }
    }

    switch (ret) {
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

static void cache_req_done(struct tevent_req *subreq)
{
    struct cache_req_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);
    ret = cache_req_sr_overlay_recv(subreq);
    talloc_zfree(subreq);

    switch (ret) {
    case EOK:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr, "Finished: Success\n");
        tevent_req_done(req);
        break;
    default:
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Finished: Error %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        break;
    }
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
                              enum cache_req_dom_type req_dom_type,
                              const char *domain,
                              struct cache_req_data *data)
{
    struct tevent_req *req;

    req = cache_req_send(mem_ctx, ev, rctx, ncache,
                         cache_refresh_percent,
                         req_dom_type, domain, data);
    if (req == NULL) {
        talloc_zfree(data);
        return NULL;
    }

    talloc_steal(req, data);

    return req;
}
