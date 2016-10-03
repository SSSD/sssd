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

static struct cache_req_plugin *
cache_req_get_plugin(enum cache_req_type type)
{
    static struct cache_req_plugin *plugins[CACHE_REQ_SENTINEL] = {

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
    struct cache_req_plugin *plugin;

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
    struct ldb_result *result;
    struct sss_domain_info *domain;
    struct sss_domain_info *selected_domain;
    bool check_next;
};

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
    struct cache_req *cr;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct cache_req_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->cr = cr = cache_req_create(state, rctx, data, ncache, midpoint);
    if (state->cr == NULL) {
        ret = ENOMEM;
        goto done;
    }

    CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr, "New request\n");

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
    errno_t ret;

    state = tevent_req_data(req, struct cache_req_state);
    cr = state->cr;

    while (state->domain != NULL) {
       /* If it is a domainless search, skip domains that require fully
        * qualified names instead. */
        while (state->domain != NULL && state->check_next
                && state->domain->fqnames
                && !cr->plugin->allow_missing_fqn) {
            state->domain = get_next_domain(state->domain, 0);
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

    /* If the object searched has to be unique among all maintained domains,
     * we have to add it into negative cache here when all domains have
     * been searched. */
    cache_req_global_ncache_add(cr);

    return ENOENT;
}

static void cache_req_done(struct tevent_req *subreq)
{
    struct cache_req_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_state);

    ret = cache_req_search_recv(state, subreq, &state->result);
    talloc_zfree(subreq);
    if (ret == EOK) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr, "Finished: Success\n");
        tevent_req_done(req);
        return;
    }

    if (state->check_next == false) {
        if (ret == ENOENT && cache_req_assume_upn(state->cr)) {
            /* search by upn now */
            cache_req_select_domains(req, NULL);
            return;
        }

        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr, "Finished: Not found\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = cache_req_next_domain(req);
    if (ret != EAGAIN) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, state->cr,
                        "Finished: Error %d: %s\n", ret, sss_strerror(ret));
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
        if (state->cr->data->name.lookup == NULL) {
            *_name = NULL;
        } else {
            name = talloc_strdup(mem_ctx, state->cr->data->name.lookup);
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
