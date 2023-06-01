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
#include "util/sss_chain_id.h"
#include "responder/common/responder.h"
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

#ifdef BUILD_SUBID
        &cache_req_subid_ranges_by_name,
#endif

        &cache_req_object_by_sid,
        &cache_req_object_by_name,
        &cache_req_object_by_id,

        &cache_req_enum_users,
        &cache_req_enum_groups,
        &cache_req_enum_svc,
        &cache_req_enum_ip_hosts,
        &cache_req_enum_ip_networks,

        &cache_req_svc_by_name,
        &cache_req_svc_by_port,

        &cache_req_netgroup_by_name,

        &cache_req_ssh_host_id_by_name,

        &cache_req_autofs_map_entries,
        &cache_req_autofs_map_by_name,
        &cache_req_autofs_entry_by_name,

        &cache_req_ip_host_by_name,
        &cache_req_ip_host_by_addr,
        &cache_req_ip_network_by_name,
        &cache_req_ip_network_by_addr,
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
    bool bypass_cache;
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

    bypass_cache = cr->plugin->bypass_cache || cr->data->bypass_cache;
    if (bypass_cache && cr->data->bypass_dp) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Cannot bypass cache and dp at the same time!");
        talloc_free(cr);
        return NULL;
    }
    if (rctx->cache_first) {
        cr->cache_behavior = CACHE_REQ_CACHE_FIRST;
    }
    /* it is ok to override cache_first here */
    if (bypass_cache) {
        cr->cache_behavior = CACHE_REQ_BYPASS_CACHE;
    } else if (cr->data->bypass_dp) {
        cr->cache_behavior = CACHE_REQ_BYPASS_PROVIDER;
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

    ok = !cr->data->hybrid_lookup || domain->mpg_mode == MPG_HYBRID;
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

static bool cache_req_check_acct_domain_lookup_type(struct cache_req *cr,
                                                    struct sss_domain_info *dom)
{
    struct sss_domain_info *head;
    int nret;

    head = get_domains_head(dom);
    if (head == NULL) {
        return false;
    }

    nret = sss_ncache_check_domain_locate_type(cr->rctx->ncache,
                                               head,
                                               cr->plugin->name);
    if (nret == ENOENT) {
        return true;
    }
    return false;
}

static errno_t cache_req_set_acct_domain_lookup_type(struct cache_req *cr,
                                                     struct sss_domain_info *dom)
{
    struct sss_domain_info *head;

    head = get_domains_head(dom);
    if (head == NULL) {
        return EINVAL;
    }

    return sss_ncache_set_domain_locate_type(cr->rctx->ncache,
                                             head,
                                             cr->plugin->name);
}

static void cache_req_domain_set_locate_flag(struct cache_req_domain *domains,
                                             struct cache_req *cr)
{
    struct cache_req_domain *crd_iter;

    DLIST_FOR_EACH(crd_iter, domains) {
        if (cache_req_check_acct_domain_lookup_type(cr, crd_iter->domain)) {
            crd_iter->locate_domain = true;
        }
    }
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

struct cache_req_locate_dom_state {
    /* input data */
    struct tevent_context *ev;
    struct cache_req *cr;
    struct cache_req_domain *req_domains;

    /* Return values in case the first cache lookup succeeds */
    struct ldb_result *result;
    bool dp_success;
};

static void cache_req_locate_dom_cache_done(struct tevent_req *subreq);
static void cache_req_locate_dom_done(struct tevent_req *subreq);
static void cache_req_locate_dom_mark_neg_all(
                                struct cache_req_locate_dom_state *state);
static void cache_req_locate_dom_mark_neg_domains(
                                struct cache_req_locate_dom_state *state,
                                const char *found_domain_name);

static struct tevent_req *cache_req_locate_dom_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct cache_req *cr,
                                                    struct cache_req_domain *req_domains)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct cache_req_locate_dom_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct cache_req_locate_dom_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }
    state->ev = ev;
    state->cr = cr;
    state->req_domains = req_domains;

    /* It is wasteful to run the domain locator request if the results are
     * present in the cache, because the domain locator always contacts
     * the DP. Therefore, first run a cache-only search and only if the
     * requested data is not available, run the locator
     *
     * FIXME - this could be optimized further if we are running the
     * second iteration with cache_first, then we don't need to search
     * again
     */
    subreq = cache_req_search_send(state,
                                   state->ev,
                                   state->cr,
                                   false,
                                   true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, cache_req_locate_dom_cache_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void cache_req_locate_dom_cache_done(struct tevent_req *subreq)
{
    struct cache_req_locate_dom_state *state = NULL;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_locate_dom_state);

    ret = cache_req_search_recv(state, subreq, &state->result, &state->dp_success);
    talloc_zfree(subreq);

    switch (ret) {
    case EOK:
        /* Just finish the request and let the caller handle the result */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Result found in the cache\n");
        tevent_req_done(req);
        return;
    case ERR_ID_OUTSIDE_RANGE:
    case ENOENT:
        /* Not cached and locator was requested, run the locator
         * DP request plugin
         */
        subreq = cache_req_locate_domain_send(state,
                                              state->ev,
                                              state->cr);
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, cache_req_locate_dom_done, req);
        return;
    default:
        DEBUG(SSSDBG_OP_FAILURE,
              "cache_req_search_recv returned [%d]: %s\n", ret, sss_strerror(ret));
        break;
    }

    tevent_req_error(req, ret);
    return;
}

static void cache_req_locate_dom_done(struct tevent_req *subreq)
{
    struct cache_req_locate_dom_state *state;
    struct tevent_req *req;
    errno_t ret;
    char *found_domain_name;
    int nret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_locate_dom_state);

    ret = cache_req_locate_domain_recv(state, subreq, &found_domain_name);
    talloc_zfree(subreq);
    switch (ret) {
    case ERR_GET_ACCT_DOM_NOT_SUPPORTED:
        nret = cache_req_set_acct_domain_lookup_type(state->cr,
                                                     state->cr->domain);
        if (nret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to disable domain locating functionality for %s\n",
                  state->cr->plugin->name);
        }
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Disabled domain locating functionality for %s\n",
              state->cr->plugin->name);
        break;
    case ERR_NOT_FOUND:
        cache_req_locate_dom_mark_neg_all(state);
        break;
    case EOK:
        cache_req_locate_dom_mark_neg_domains(state, found_domain_name);
        break;
    default:
        /* We explicitly ignore errors here */
        break;
    }

    tevent_req_done(req);
    return;
}

static void cache_req_locate_dom_mark_neg_all(
                                struct cache_req_locate_dom_state *state)
{
    struct cache_req_domain *iter;

    DLIST_FOR_EACH(iter, state->req_domains) {
        if (get_domains_head(state->cr->domain) != get_domains_head(iter->domain)) {
            /* Only add to negative cache for domains from the same "main"
             * domain" */
            continue;
        }
        cache_req_search_ncache_add_to_domain(state->cr, iter->domain);
    }
}

static void cache_req_locate_dom_mark_neg_domains(
                                struct cache_req_locate_dom_state *state,
                                const char *found_domain_name)
{
    struct sss_domain_info *found_domain;
    struct cache_req_domain *iter;

    found_domain = find_domain_by_name(get_domains_head(state->cr->domain),
                                       found_domain_name,
                                       true);
    if (found_domain == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "Cannot find domain %s\n", found_domain_name);
        return;
    }

    /* Set negcache in all subdomains of the one being examined
     * except the found one */
    DLIST_FOR_EACH(iter, state->req_domains) {
        if (strcasecmp(found_domain_name,
                       iter->domain->name) == 0) {
            continue;
        }

        if (get_domains_head(found_domain) != get_domains_head(iter->domain)) {
            /* Don't set negative cache for domains outside the main
             * domain/subdomain tree b/c the locator request is not
             * authoritative for them
             */
            continue;
        }
        cache_req_search_ncache_add_to_domain(state->cr, iter->domain);
    }
}

static errno_t cache_req_locate_dom_cache_recv(TALLOC_CTX *mem_ctx,
                                               struct tevent_req *req,
                                               struct ldb_result **_result,
                                               bool *_dp_success)
{
    struct cache_req_locate_dom_state *state;

    state = tevent_req_data(req, struct cache_req_locate_dom_state);

    if (_dp_success != NULL) {
        *_dp_success = state->dp_success;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_result != NULL) {
        *_result = talloc_steal(mem_ctx, state->result);
    }

    return EOK;
}

struct cache_req_search_domains_state {
    /* input data */
    struct tevent_context *ev;
    struct cache_req *cr;

    /* work data */
    struct cache_req_domain *cr_domain;
    struct cache_req_domain *req_domains;
    struct sss_domain_info *selected_domain;
    struct cache_req_result **results;
    size_t num_results;
    bool check_next;
    bool dp_success;
    bool first_iteration;
};

static errno_t cache_req_search_domains_next(struct tevent_req *req);
static errno_t cache_req_handle_result(struct tevent_req *req,
                                       struct ldb_result *result);

static void cache_req_search_domains_locate_done(struct tevent_req *subreq);

static void cache_req_search_domains_done(struct tevent_req *subreq);

static bool
cache_req_dp_contacted(struct cache_req_search_domains_state *state)
{
    switch (state->cr->cache_behavior) {
        case CACHE_REQ_CACHE_FIRST:
            if (state->first_iteration) {
                /* This is the first iteration so provider was bypassed. */
                return false;
            }

            /* This is the second iteration so the provider was contacted. */
            return true;
        case CACHE_REQ_BYPASS_PROVIDER:
            return false;
        default:
            /* Other schemas talks to provider immediately. */
            return true;
    }
}

struct tevent_req *
cache_req_search_domains_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct cache_req *cr,
                              struct cache_req_domain *cr_domain,
                              bool check_next,
                              bool first_iteration)
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
    state->req_domains = cr_domain;
    state->check_next = check_next;
    state->dp_success = true;
    state->first_iteration = first_iteration;

    if (cr->plugin->dp_get_domain_send_fn != NULL
            && ((state->check_next && cr_domain->next != NULL)
                || ((state->cr->cache_behavior == CACHE_REQ_CACHE_FIRST)
                    && !first_iteration))) {
        /* If the request is not qualified with a domain name AND
         * there are multiple domains to search OR if this is the second
         * pass during the "check-cache-first" schema, it makes sense
         * to try to run the domain-locator plugin
         */
        cache_req_domain_set_locate_flag(cr_domain, cr);
    }

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

        if (domain == NULL) {
            break;
        }

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

        ret = cache_req_set_domain(cr, domain);
        if (ret != EOK) {
            return ret;
        }

        if (state->cr_domain->locate_domain) {
            subreq = cache_req_locate_dom_send(state,
                                               state->ev,
                                               cr,
                                               state->req_domains);
            if (subreq == NULL) {
                return ENOMEM;
            }
            tevent_req_set_callback(subreq, cache_req_search_domains_locate_done, req);
            return EAGAIN;
        }

        subreq = cache_req_search_send(state, state->ev, cr,
                                       state->first_iteration,
                                       false);
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
    if (cache_req_dp_contacted(state) && state->dp_success) {
        cache_req_global_ncache_add(cr);
    }

    return ENOENT;
}

static void cache_req_search_domains_locate_done(struct tevent_req *subreq)
{
    struct cache_req_search_domains_state *state;
    struct ldb_result *result = NULL;
    struct tevent_req *req;
    bool dp_success;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_search_domains_state);

    ret = cache_req_locate_dom_cache_recv(state, subreq, &result, &dp_success);
    talloc_zfree(subreq);

    /* Remember if any DP request fails, but here it shouldn't matter
     * as the only DP request that should realistically happen is midpoint
     * refresh */
    state->dp_success = !dp_success ? false : state->dp_success;

    /* Don't locate the domain again */
    state->cr_domain->locate_domain = false;

    switch (ret) {
    case EOK:
        if (result != NULL) {
            /* Handle result as normally */
            ret = cache_req_handle_result(req, result);
            if (ret != EAGAIN) {
                goto done;
            }
        }
        break;
    default:
        /* Some serious error has happened. Finish. */
        goto done;
    }

    /* This is a domain less search, continue with the next domain. */
    ret = cache_req_search_domains_next(req);

done:
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

static errno_t cache_req_handle_result(struct tevent_req *req,
                                       struct ldb_result *result)
{
    struct cache_req_search_domains_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_search_domains_state);

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
        return ret;
    }

    if (!state->check_next || !state->cr->plugin->search_all_domains) {
        /* We are not interested in more results. */
        return EOK;
    }

    return EAGAIN;
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

    /* Remember if any DP request fails, if DP was contacted. */
    if (cache_req_dp_contacted(state)) {
        state->dp_success = !dp_success ? false : state->dp_success;
    }

    switch (ret) {
    case EOK:
        ret = cache_req_handle_result(req, result);
        if (ret != EAGAIN) {
            goto done;
        }
        break;
    case ERR_ID_OUTSIDE_RANGE:
    case ENOENT:
        if (state->check_next == false) {
             if (cache_req_dp_contacted(state)
                 && !state->dp_success
                 && state->cr->data->propogate_offline_status) {
                /* Not found and data provider request failed so we were
                 * unable to fetch the data. */
                ret = ERR_OFFLINE;
                goto done;
            }

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
        if (cache_req_dp_contacted(state)
            && ret == ENOENT
            && !state->dp_success
            && state->cr->data->propogate_offline_status) {
            /* Not found and data provider request failed so we were
             * unable to fetch the data. */
            ret = ERR_OFFLINE;
        }
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

struct cache_req_state {
    /* input data */
    struct tevent_context *ev;
    struct cache_req *cr;
    const char *domain_name;

    /* work data */
    struct cache_req_domain *cr_domains;
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
                                        const char *domain_name,
                                        char **requested_domains);

static errno_t
cache_req_search_domains(struct tevent_req *req,
                         struct cache_req_domain *oredered_domain,
                         bool check_next);

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

    SSS_REQ_TRACE_CID_CR(SSSDBG_TRACE_FUNC, cr, "New request [CID #%lu] '%s'\n",
                         sss_chain_id_get(), cr->reqname);

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

    ret = cache_req_select_domains(req, state->domain_name,
                                   cr->data->requested_domains);

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

    if (cr->plugin->parse_name == false) {
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
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_parse_inp_send() failed\n");
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
    ret = cache_req_select_domains(req, state->domain_name,
                                   state->cr->data->requested_domains);

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
    char *domain = NULL;
    bool maybe_upn;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = sss_parse_inp_recv(subreq, state, &name, &domain);

    if (state->domain_name != NULL && domain != NULL
        && strcmp(state->domain_name, domain) != 0){
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Mismatch between input domain name [%s] and parsed domain name [%s]\n",
              state->domain_name, domain);
        tevent_req_error(req, ERR_INPUT_PARSE);
        return;
    }

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

    if (state->domain_name == NULL) {
        state->domain_name = domain;
    }
    ret = cache_req_select_domains(req, state->domain_name,
                                   state->cr->data->requested_domains);
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }
}

static errno_t cache_req_select_domains(struct tevent_req *req,
                                        const char *domain_name,
                                        char **requested_domains)
{
    struct cache_req_state *state = NULL;
    struct cache_req_domain *cr_domain;
    bool check_next;
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_state);

    if (state->cr->cache_behavior != CACHE_REQ_CACHE_FIRST) {

        if (!state->first_iteration) {
            /* We're done here. */
            return EOK;
        }
    }

    ret = cache_req_domain_copy_cr_domains(state,
                                           state->cr->rctx->cr_domains,
                                           requested_domains,
                                           &state->cr_domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_copy_cr_domains() failed\n");
        return EINVAL;
    }

    if (domain_name != NULL) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Performing a single domain search\n");

        cr_domain = cache_req_domain_get_domain_by_name(
                                    state->cr_domains, domain_name);
        if (cr_domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }
        check_next = false;
    } else {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Performing a multi-domain search\n");

        cr_domain = state->cr_domains;
        check_next = true;
    }

    return cache_req_search_domains(req, cr_domain, check_next);
}

static errno_t
cache_req_search_domains(struct tevent_req *req,
                         struct cache_req_domain *cr_domain,
                         bool check_next)
{
    struct tevent_req *subreq;
    struct cache_req_state *state = NULL;
    const char *cache_action;
    const char *provider_action;

    state = tevent_req_data(req, struct cache_req_state);

    switch (state->cr->cache_behavior) {
    case CACHE_REQ_CACHE_FIRST:
        cache_action = (state->first_iteration) ? "check" : "bypass";
        provider_action = (state->first_iteration) ? "bypass" : "check";
        break;
    case CACHE_REQ_BYPASS_CACHE:
        cache_action = "bypass";
        provider_action = "check";
        break;
    case CACHE_REQ_BYPASS_PROVIDER:
        cache_action = "check";
        provider_action = "bypass";
        break;
    default:
        cache_action = "check";
        provider_action = "check";
        break;
    }
    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                    "Search will %s the cache and %s the data provider\n",
                    cache_action, provider_action);

    subreq = cache_req_search_domains_send(state, state->ev, state->cr,
                                           cr_domain, check_next,
                                           state->first_iteration);
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
        ret = cache_req_select_domains(req, state->domain_name,
                                       state->cr->data->requested_domains);
        if (ret == EOK) {
            /* We're done searching and we have found nothing. */
            ret = ENOENT;
        }
    }

    /* Have have tried all domains and found nothing. Let's try UPN search. */
    if (ret == ENOENT) {
        if (state->domain_name != NULL) {
            /* Lookup domain was specified as input. Since we haven't
             * found anything yet we may want to try UPN search with
             * some plug-ins. */

            if (cache_req_assume_upn(state->cr)) {
                /* Try UPN now. */
                state->first_iteration = true;
                ret = cache_req_select_domains(req, NULL,
                                        state->cr->data->requested_domains);
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

uint32_t cache_req_get_reqid(struct tevent_req *req)
{
    const struct cache_req_state *state;

    state = tevent_req_data(req, struct cache_req_state);

    if (state && state->cr) {
        return state->cr->reqid;
    }

    return 0;
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
