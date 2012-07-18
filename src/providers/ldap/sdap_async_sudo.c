/*
    SSSD

    Async LDAP Helper routines for sudo

    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <errno.h>
#include <talloc.h>
#include <tevent.h>

#include "providers/dp_backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"
#include "db/sysdb_sudo.h"

struct sdap_sudo_refresh_state {
    struct be_ctx *be_ctx;
    struct sdap_options *opts;
    struct sdap_id_op *sdap_op;
    struct sdap_id_conn_cache *sdap_conn_cache;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *ldap_filter;    /* search */
    const char *sysdb_filter;   /* delete */

    int dp_error;
    int error;
    char *highest_usn;
    size_t num_rules;
};

struct sdap_sudo_load_sudoers_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sysdb_attrs **ldap_rules; /* search result will be stored here */
    size_t ldap_rules_count;         /* search result will be stored here */

    const char **attrs;
    const char *filter;
    size_t base_iter;
    struct sdap_search_base **search_bases;
    int timeout;
};

static int sdap_sudo_refresh_retry(struct tevent_req *req);

static void sdap_sudo_refresh_connect_done(struct tevent_req *subreq);

static struct tevent_req * sdap_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                       struct tevent_context *ev,
                                                       struct sdap_options *opts,
                                                       struct sdap_handle *sh,
                                                       const char *ldap_filter);

static errno_t sdap_sudo_load_sudoers_next_base(struct tevent_req *req);

static void sdap_sudo_load_sudoers_process(struct tevent_req *subreq);

static int sdap_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *rules_count,
                                       struct sysdb_attrs ***rules);

static void sdap_sudo_load_sudoers_done(struct tevent_req *subreq);

static int sdap_sudo_purge_sudoers(struct sysdb_ctx *sysdb_ctx,
                                   const char *filter,
                                   struct sdap_attr_map *map,
                                   size_t rules_count,
                                   struct sysdb_attrs **rules);

static int sdap_sudo_store_sudoers(TALLOC_CTX *mem_ctx,
                                   struct sysdb_ctx *sysdb_ctx,
                                   struct sdap_options *opts,
                                   size_t rules_count,
                                   struct sysdb_attrs **rules,
                                   int cache_timeout,
                                   time_t now,
                                   char **_usn);

struct tevent_req *sdap_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct be_ctx *be_ctx,
                                          struct sdap_options *opts,
                                          struct sdap_id_conn_cache *conn_cache,
                                          const char *ldap_filter,
                                          const char *sysdb_filter)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_refresh_state *state = NULL;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_refresh_state);
    if (!req) {
        return NULL;
    }

    /* if we don't have a search filter, this request is meaningless */
    if (ldap_filter == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->be_ctx = be_ctx;
    state->opts = opts;
    state->sdap_op = NULL;
    state->sdap_conn_cache = conn_cache;
    state->sysdb = be_ctx->sysdb;
    state->domain = be_ctx->domain;
    state->ldap_filter = talloc_strdup(state, ldap_filter);
    state->sysdb_filter = talloc_strdup(state, sysdb_filter);
    state->dp_error = DP_ERR_OK;
    state->error = EOK;
    state->highest_usn = NULL;

    if (state->ldap_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (sysdb_filter != NULL && state->sysdb_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = sdap_sudo_refresh_retry(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, be_ctx->ev);

    return req;
}

int sdap_sudo_refresh_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           int *dp_error,
                           int *error,
                           char **usn,
                           size_t *num_rules)
{
    struct sdap_sudo_refresh_state *state = NULL;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *error = state->error;

    if (usn != NULL && state->highest_usn != NULL) {
        *usn = talloc_steal(mem_ctx, state->highest_usn);
    }

    if (num_rules != NULL) {
        *num_rules = state->num_rules;
    }

    return EOK;
}

static int sdap_sudo_refresh_retry(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct sdap_sudo_refresh_state *state = NULL;
    int ret;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    if (be_is_offline(state->be_ctx)) {
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        return EOK;
    }

    if (state->sdap_op == NULL) {
        state->sdap_op = sdap_id_op_create(state, state->sdap_conn_cache);
        if (state->sdap_op == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("sdap_id_op_create() failed\n"));
            state->dp_error = DP_ERR_FATAL;
            state->error = EIO;
            return EIO;
        }
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sdap_id_op_connect_send() failed: %d(%s)\n", ret, strerror(ret)));
        talloc_zfree(state->sdap_op);
        state->dp_error = DP_ERR_FATAL;
        state->error = ret;
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_sudo_refresh_connect_done, req);

    return EAGAIN;
}

static void sdap_sudo_refresh_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL; /* req from sdap_sudo_refresh_send() */
    struct sdap_sudo_refresh_state *state = NULL;
    int dp_error;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(state->sdap_op);
        state->dp_error = DP_ERR_OFFLINE;
        state->error = EAGAIN;
        tevent_req_done(req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("SUDO LDAP connection failed - %s\n", strerror(ret)));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("SUDO LDAP connection successful\n"));

    subreq = sdap_sudo_load_sudoers_send(state, state->be_ctx->ev,
                                         state->opts,
                                         sdap_id_op_handle(state->sdap_op),
                                         state->ldap_filter);
    if (subreq == NULL) {
        ret = EFAULT;
        goto fail;
    }

    tevent_req_set_callback(subreq, sdap_sudo_load_sudoers_done, req);

    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    state->error = ret;
    tevent_req_error(req, ret);
}

static struct tevent_req * sdap_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                       struct tevent_context *ev,
                                                       struct sdap_options *opts,
                                                       struct sdap_handle *sh,
                                                       const char *ldap_filter)



{
    struct tevent_req *req = NULL;
    struct sdap_sudo_load_sudoers_state *state = NULL;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_load_sudoers_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->base_iter = 0;
    state->search_bases = opts->sudo_search_bases;
    state->filter = ldap_filter;
    state->timeout = dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT);
    state->ldap_rules = NULL;
    state->ldap_rules_count = 0;

    if (!state->search_bases) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("SUDOERS lookup request without a search base\n"));
        ret = EINVAL;
        goto done;
    }

    /* create attrs from map */
    ret = build_attrs_from_map(state, opts->sudorule_map, SDAP_OPTS_SUDO,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) {
        goto fail;
    }

    /* begin search */
    ret = sdap_sudo_load_sudoers_next_base(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static errno_t sdap_sudo_load_sudoers_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct sdap_sudo_load_sudoers_state *state = NULL;
    struct sdap_search_base *search_base = NULL;
    char *filter = NULL;

    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);
    search_base = state->search_bases[state->base_iter];
    if (search_base == NULL) {
        /* should not happen */
        DEBUG(SSSDBG_CRIT_FAILURE, ("search_base is null\n"));
        return EFAULT;
    }

    /* create filter */
    filter = sdap_get_id_specific_filter(state, state->filter,
                                         search_base->filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    /* send request */
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Searching for sudo rules with base [%s]\n",
           search_base->basedn));

    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->opts,
                                   state->sh,
                                   search_base->basedn,
                                   search_base->scope,
                                   filter,
                                   state->attrs,
                                   state->opts->sudorule_map,
                                   SDAP_OPTS_SUDO,
                                   state->timeout,
                                   true);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_sudo_load_sudoers_process, req);

    return EOK;
}

static void sdap_sudo_load_sudoers_process(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_load_sudoers_state *state = NULL;
    struct sdap_search_base *search_base = NULL;
    struct sysdb_attrs **attrs = NULL;
    size_t count;
    int ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);
    search_base = state->search_bases[state->base_iter];

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Receiving sudo rules with base [%s]\n",
           search_base->basedn));

    ret = sdap_get_generic_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* add rules to result */
    if (count > 0) {
        state->ldap_rules = talloc_realloc(state, state->ldap_rules,
                                           struct sysdb_attrs *,
                                           state->ldap_rules_count + count);
        if (state->ldap_rules == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i = 0; i < count; i++) {
            state->ldap_rules[state->ldap_rules_count + i] = talloc_steal(
                                                   state->ldap_rules, attrs[i]);
        }

        state->ldap_rules_count += count;
    }

    /* go to next base */
    state->base_iter++;
    if (state->search_bases[state->base_iter]) {
        ret = sdap_sudo_load_sudoers_next_base(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }

        return;
    }

    /* we are done */
    tevent_req_done(req);
}

static int sdap_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *rules_count,
                                       struct sysdb_attrs ***rules)
{
    struct sdap_sudo_load_sudoers_state *state = NULL;

    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *rules_count = state->ldap_rules_count;
    *rules = talloc_steal(mem_ctx, state->ldap_rules);

    return EOK;
}

static void sdap_sudo_load_sudoers_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL; /* req from sdap_sudo_refresh_send() */
    struct sdap_sudo_refresh_state *state = NULL;
    struct sysdb_attrs **rules = NULL;
    size_t rules_count = 0;
    int ret;
    errno_t sret;
    bool in_transaction = false;
    time_t now;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    ret = sdap_sudo_load_sudoers_recv(subreq, state, &rules_count, &rules);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Received %d rules\n", rules_count));

    /* start transaction */
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    /* purge cache */
    ret = sdap_sudo_purge_sudoers(state->sysdb, state->sysdb_filter,
                                  state->opts->sudorule_map, rules_count, rules);
    if (ret != EOK) {
        goto done;
    }

    /* store rules */
    now = time(NULL);
    ret = sdap_sudo_store_sudoers(state, state->sysdb, state->opts, rules_count,
                                  rules, state->domain->sudo_timeout, now,
                                  &state->highest_usn);
    if (ret != EOK) {
        goto done;
    }

    /* commit transaction */
    ret = sysdb_transaction_commit(state->sysdb);
    if (ret == EOK) {
        in_transaction = false;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Sudoers is successfuly stored in cache\n"));

    ret = EOK;
    state->num_rules = rules_count;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    state->error = ret;
    if (ret == EOK) {
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
    } else {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
    }
}

static int sdap_sudo_purge_sudoers(struct sysdb_ctx *sysdb_ctx,
                                   const char *filter,
                                   struct sdap_attr_map *map,
                                   size_t rules_count,
                                   struct sysdb_attrs **rules)
{
    const char *name;
    int i;
    errno_t ret;

    if (filter == NULL) {
        /* removes downloaded rules from the cache */
        if (rules_count == 0 || rules == NULL) {
            return EOK;
        }

        for (i = 0; i < rules_count; i++) {
            ret = sysdb_attrs_get_string(rules[i],
                                         map[SDAP_AT_SUDO_NAME].sys_name,
                                         &name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Failed to retrieve rule name: [%s]\n", strerror(ret)));
                continue;
            }

            ret = sysdb_sudo_purge_byname(sysdb_ctx, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Failed to delete rule %s: [%s]\n",
                       name, strerror(ret)));
                continue;
            }
        }
    } else {
        /* purge cache by provided filter */
        ret = sysdb_sudo_purge_byfilter(sysdb_ctx, filter);
        if (ret != EOK) {
            goto done;
        }
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("failed to purge sudo rules [%d]: %s\n",
                                  ret, strerror(ret)));
    }

    return ret;
}

static int sdap_sudo_store_sudoers(TALLOC_CTX *mem_ctx,
                                   struct sysdb_ctx *sysdb_ctx,
                                   struct sdap_options *opts,
                                   size_t rules_count,
                                   struct sysdb_attrs **rules,
                                   int cache_timeout,
                                   time_t now,
                                   char **_usn)
{
    errno_t ret;

    /* Empty sudoers? Done. */
    if (rules_count == 0 || rules == NULL) {
        return EOK;
    }

    ret = sdap_save_native_sudorule_list(mem_ctx, sysdb_ctx, opts->sudorule_map,
                                         rules, rules_count, cache_timeout, now,
                                         _usn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("failed to save sudo rules [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    return EOK;
}
