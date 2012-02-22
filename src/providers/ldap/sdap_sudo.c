/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include <string.h>
#include <tevent.h>

#include "providers/dp_backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"
#include "providers/ldap/sdap_sudo_timer.h"
#include "db/sysdb_sudo.h"

static void
sdap_sudo_shutdown(struct be_req *req)
{
    sdap_handler_done(req, DP_ERR_OK, EOK, NULL);
}

struct bet_ops sdap_sudo_ops = {
    .handler = sdap_sudo_handler,
    .finalize = sdap_sudo_shutdown
};

int sdap_sudo_setup_tasks(struct sdap_id_ctx *id_ctx);

int sdap_sudo_init(struct be_ctx *be_ctx,
                   struct sdap_id_ctx *id_ctx,
                   struct bet_ops **ops,
                   void **pvt_data)
{
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Initializing sudo LDAP back end\n"));

    *ops = &sdap_sudo_ops;
    *pvt_data = id_ctx;

    ret = ldap_get_sudo_options(id_ctx, be_ctx->cdb,
                                be_ctx->conf_path, id_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot get SUDO options [%d]: %s\n",
                                  ret, strerror(ret)));
        return ret;
    }

    ret = sdap_sudo_setup_tasks(id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("SUDO setup failed [%d]: %s\n",
                                  ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

int sdap_sudo_setup_tasks(struct sdap_id_ctx *id_ctx)
{
    struct sdap_sudo_refresh_ctx *refresh_ctx = NULL;
    struct timeval tv;
    int ret = EOK;
    bool refreshed = false;
    bool refresh_enabled = dp_opt_get_bool(id_ctx->opts->basic,
                                           SDAP_SUDO_REFRESH_ENABLED);

    /* set up periodical update of sudo rules */
    if (refresh_enabled) {
        refresh_ctx = sdap_sudo_refresh_ctx_init(id_ctx, id_ctx->be, id_ctx,
                                                 id_ctx->opts,
                                                 tevent_timeval_zero());
        if (refresh_ctx == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("sdap_sudo_refresh_ctx_init() failed!\n"));
            return ENOMEM;
        }

        /* If this is the first startup, we need to kick off
         * an refresh immediately, to close a window where
         * clients requesting sudo information won't get an
         * immediate reply with no entries
         */
        ret = sysdb_sudo_get_refreshed(id_ctx->be->sysdb, &refreshed);
        if (ret != EOK) {
            return ret;
        }
        if (refreshed) {
            /* At least one update has previously run,
             * so clients will get cached data. We will delay
             * starting to enumerate by 10s so we don't slow
             * down the startup process if this is happening
             * during system boot.
             */
            tv = tevent_timeval_current_ofs(10, 0);
            DEBUG(SSSDBG_FUNC_DATA, ("Delaying first refresh of SUDO rules "
                  "for 10 seconds\n"));
        } else {
            /* This is our first startup. Schedule the
             * update to start immediately once we
             * enter the mainloop.
             */
            tv = tevent_timeval_current();
        }

        ret = sdap_sudo_refresh_set_timer(refresh_ctx, tv);
        if (ret != EOK) {
            talloc_free(refresh_ctx);
            return ret;
        }
    }

    return EOK;
}

struct sdap_sudo_load_sudoers_state {
    struct tevent_context *ev;
    struct sdap_sudo_ctx *sudo_ctx;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sysdb_attrs **ldap_rules; /* search result will be stored here */
    size_t ldap_rules_count; /* search result will be stored here */

    const char **attrs;
    const char *filter;
    size_t base_iter;
    struct sdap_search_base **search_bases;
    int timeout;
};

struct sdap_sudo_refresh_state {
    struct be_ctx *be_ctx;
    struct be_sudo_req *sudo_req;
    struct sdap_options *opts;
    struct sdap_id_op *sdap_op;
    struct sdap_id_conn_cache *sdap_conn_cache;

    int dp_error;
    int error;
};

static int sdap_sudo_connect(struct tevent_req *req);

static void sdap_sudo_connect_done(struct tevent_req *subreq);

static struct tevent_req * sdap_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                       struct tevent_context *ev,
                                                       struct be_sudo_req *sudo_req,
                                                       struct sdap_options *opts,
                                                       struct sdap_handle *sh);

static errno_t sdap_sudo_load_sudoers_next_base(struct tevent_req *req);

static void sdap_sudo_load_sudoers_process(struct tevent_req *subreq);

static int sdap_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *rules_count,
                                       struct sysdb_attrs ***rules);

static void sdap_sudo_load_sudoers_done(struct tevent_req *req);

static int sdap_sudo_purge_sudoers(struct sysdb_ctx *sysdb_ctx,
                                   struct sss_domain_info *domain,
                                   struct be_sudo_req *sudo_req);

static int sdap_sudo_store_sudoers(struct sysdb_ctx *sysdb_ctx,
                                   struct sdap_options *opts,
                                   size_t rules_count,
                                   struct sysdb_attrs **rules);

static const char *sdap_sudo_build_filter(TALLOC_CTX *mem_ctx,
                                          struct sdap_attr_map *map,
                                          struct be_sudo_req *sudo_req);

static const char *sdap_sudo_build_user_filter(TALLOC_CTX *mem_ctx,
                                               struct sdap_attr_map *map,
                                               const char *username,
                                               uid_t uid,
                                               char **groups);

static void sdap_sudo_reply(struct tevent_req *req)
{
    struct be_req *be_req = NULL;
    int dp_error;
    int error;
    int ret;

    be_req = tevent_req_callback_data(req, struct be_req);
    ret = sdap_sudo_refresh_recv(req, &dp_error, &error);
    talloc_zfree(req);
    if (ret != EOK) {
        sdap_handler_done(be_req, DP_ERR_FATAL, ret, strerror(ret));
        return;
    }

    sdap_handler_done(be_req, dp_error, error, strerror(error));
}

void sdap_sudo_handler(struct be_req *be_req)
{
    struct tevent_req *req = NULL;
    struct be_sudo_req *sudo_req = NULL;
    struct sdap_id_ctx *id_ctx = NULL;
    int ret = EOK;

    id_ctx = talloc_get_type(be_req->be_ctx->bet_info[BET_SUDO].pvt_bet_data,
                             struct sdap_id_ctx);

    sudo_req = talloc_get_type(be_req->req_data, struct be_sudo_req);

    /* get user info */
    if (sudo_req->username != NULL) {
        ret = sysdb_get_sudo_user_info(sudo_req, sudo_req->username,
                                       id_ctx->be->sysdb,
                                       &sudo_req->uid, &sudo_req->groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to get uid and groups of %s\n",
                  sudo_req->username));
            goto fail;
        }
    } else {
        sudo_req->uid = 0;
        sudo_req->groups = NULL;
    }

    req = sdap_sudo_refresh_send(be_req, id_ctx->be, sudo_req, id_ctx->opts,
                                 id_ctx->conn_cache);
    if (req == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(req, sdap_sudo_reply, be_req);

    return;

fail:
    sdap_handler_done(be_req, DP_ERR_FATAL, ret, NULL);
}

struct tevent_req *sdap_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct be_ctx *be_ctx,
                                          struct be_sudo_req *sudo_req,
                                          struct sdap_options *opts,
                                          struct sdap_id_conn_cache *conn_cache)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_refresh_state *state = NULL;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_refresh_state);
    if (!req) {
        return NULL;
    }

    state->be_ctx = be_ctx;
    state->sudo_req = sudo_req;
    state->opts = opts;
    state->sdap_op = NULL;
    state->sdap_conn_cache = conn_cache;
    state->dp_error = DP_ERR_OK;
    state->error = EOK;

    switch (sudo_req->type) {
    case BE_REQ_SUDO_ALL:
        DEBUG(SSSDBG_TRACE_FUNC, ("Requested refresh for: <ALL>\n"));
        break;
    case BE_REQ_SUDO_DEFAULTS:
        DEBUG(SSSDBG_TRACE_FUNC, ("Requested refresh of cn=defaults\n"));
        break;
    case BE_REQ_SUDO_USER:
        DEBUG(SSSDBG_TRACE_FUNC, ("Requested refresh for: %s\n",
                                  sudo_req->username));
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid request type %d\n", sudo_req->type));
        ret = EINVAL;
        goto immediately;
    }

    ret = sdap_sudo_connect(req);
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

int sdap_sudo_refresh_recv(struct tevent_req *req,
                           int *dp_error,
                           int *error)
{
    struct sdap_sudo_refresh_state *state = NULL;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *error = state->error;

    return EOK;
}

int sdap_sudo_connect(struct tevent_req *req)
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

    tevent_req_set_callback(subreq, sdap_sudo_connect_done, req);

    return EAGAIN;
}

void sdap_sudo_connect_done(struct tevent_req *subreq)
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
                                         state->sudo_req, state->opts,
                                         sdap_id_op_handle(state->sdap_op));
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

struct tevent_req * sdap_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct be_sudo_req *sudo_req,
                                                struct sdap_options *opts,
                                                struct sdap_handle *sh)



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
    state->timeout = dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT);
    state->ldap_rules = NULL;
    state->ldap_rules_count = 0;

    if (!state->search_bases) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("SUDOERS lookup request without a search base\n"));
        ret = EINVAL;
        goto done;
    }

    /* create filter */
    state->filter = sdap_sudo_build_filter(state, opts->sudorule_map, sudo_req);
    if (state->filter == NULL) {
        goto fail;
    }

    /* create attrs from map */
    ret = build_attrs_from_map(state, opts->sudorule_map, SDAP_OPTS_SUDO,
                               &state->attrs);
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

int sdap_sudo_load_sudoers_recv(struct tevent_req *req,
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

void sdap_sudo_load_sudoers_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL; /* req from sdap_sudo_refresh_send() */
    struct sdap_sudo_refresh_state *state = NULL;
    struct sysdb_attrs **rules = NULL;
    size_t rules_count;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    ret = sdap_sudo_load_sudoers_recv(subreq, state, &rules_count, &rules);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Received %d rules\n", rules_count));

    /* purge cache */
    ret = sdap_sudo_purge_sudoers(state->be_ctx->sysdb, state->be_ctx->domain,
                                  state->sudo_req);
    if (ret != EOK) {
        goto done;
    }

    /* store rules */
    ret = sdap_sudo_store_sudoers(state->be_ctx->sysdb, state->opts,
                                  rules_count, rules);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Sudoers is successfuly stored in cache\n"));

    ret = EOK;

done:
    state->error = ret;
    if (ret == EOK) {
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
    } else {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
    }
}

int sdap_sudo_purge_sudoers(struct sysdb_ctx *sysdb_ctx,
                            struct sss_domain_info *domain,
                            struct be_sudo_req *sudo_req)
{
    TALLOC_CTX *tmp_ctx;
    char *filter = NULL;
    char **sudouser = NULL;
    int ret = EOK;
    errno_t sret;
    bool in_transaction = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb_ctx);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    switch (sudo_req->type) {
    case BE_REQ_SUDO_ALL:
        DEBUG(SSSDBG_TRACE_FUNC, ("Purging SUDOers cache of all rules\n"));
        ret = sysdb_sudo_purge_all(sysdb_ctx);
        break;
    case BE_REQ_SUDO_DEFAULTS:
        DEBUG(SSSDBG_TRACE_FUNC, ("Purging SUDOers cache of default options\n"));
        ret = sysdb_sudo_purge_byname(sysdb_ctx, SDAP_SUDO_DEFAULTS);
        break;
    case BE_REQ_SUDO_USER:
        DEBUG(SSSDBG_TRACE_FUNC, ("Purging SUDOers cache of user's [%s] rules\n",
              sudo_req->username));

        /* netgroups */
        ret = sysdb_get_sudo_filter(tmp_ctx, NULL, 0, NULL,
                                    SYSDB_SUDO_FILTER_NGRS, &filter);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to create filter to purge "
                  "SUDOers cache [%d]: %s\n", ret, strerror(ret)));
            goto done;
        }

        ret = sysdb_sudo_purge_byfilter(sysdb_ctx, filter);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to purge SUDOers cache "
                  "(netgroups) [%d]: %s\n", ret, strerror(ret)));
            goto done;
        }

        /* user, uid, groups */
        sudouser = sysdb_sudo_build_sudouser(tmp_ctx, sudo_req->username,
                                             sudo_req->uid, sudo_req->groups,
                                             true);
        if (sudouser == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to create sudoUser to purge "
                  "SUDOers cache [%d]: %s\n", ret, strerror(ret)));
            goto done;
        }

        ret = sysdb_sudo_purge_bysudouser(sysdb_ctx, sudouser);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid request type %d\n", sudo_req->type));
        return EINVAL;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to purge SUDOers cache [%d]: %s\n",
                                    ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb_ctx);
    if (ret == EOK) {
        in_transaction = false;
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb_ctx);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sdap_sudo_store_sudoers(struct sysdb_ctx *sysdb_ctx,
                            struct sdap_options *opts,
                            size_t rules_count,
                            struct sysdb_attrs **rules)
{
    errno_t ret;

    /* Empty sudoers? Done. */
    if (rules_count == 0 || rules == NULL) {
        return EOK;
    }

    ret = sdap_save_native_sudorule_list(sysdb_ctx, opts->sudorule_map,
                                         rules, rules_count);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("failed to save sudo rules [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

const char *sdap_sudo_build_filter(TALLOC_CTX *mem_ctx,
                                   struct sdap_attr_map *map,
                                   struct be_sudo_req *sudo_req)
{
    switch (sudo_req->type) {
    case BE_REQ_SUDO_ALL:
        return talloc_asprintf(mem_ctx, SDAP_SUDO_FILTER_ALL,
                               map[SDAP_OC_SUDORULE].name);
        break;
    case BE_REQ_SUDO_DEFAULTS:
        return talloc_asprintf(mem_ctx, SDAP_SUDO_FILTER_DEFAULTS,
                               map[SDAP_OC_SUDORULE].name,
                               map[SDAP_AT_SUDO_NAME].name,
                               SDAP_SUDO_DEFAULTS); /* FIXME: add option for this */
        break;
    case BE_REQ_SUDO_USER:
        return sdap_sudo_build_user_filter(mem_ctx, map, sudo_req->username,
                                           sudo_req->uid, sudo_req->groups);

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid request type %d\n", sudo_req->type));
        return NULL;
    }
}

/* alway update cn=defaults and sudoUser=ALL */
const char *sdap_sudo_build_user_filter(TALLOC_CTX *mem_ctx,
                                        struct sdap_attr_map *map,
                                        const char *username,
                                        uid_t uid,
                                        char **groups)
{
    char *filter = NULL;
    char *output = NULL;
    char *sanitized = NULL;
    char **group = NULL;
    int ret;

    /* user name */
    ret = sss_filter_sanitize(filter, username, &sanitized);
    if (ret != EOK) {
        goto fail;
    }
    filter = talloc_asprintf_append(filter, SDAP_SUDO_FILTER_USERNAME,
                                    map[SDAP_AT_SUDO_USER].name,
                                    sanitized);
    if (filter == NULL) {
        goto fail;
    }

    /* user uid */
    filter = talloc_asprintf_append(filter, SDAP_SUDO_FILTER_UID,
                                    map[SDAP_AT_SUDO_USER].name,
                                    uid);
    if (filter == NULL) {
        goto fail;
    }

    /* groups */
    if (groups != NULL) {
        for (group = groups; *group != NULL; group++) {
            ret = sss_filter_sanitize(filter, *group, &sanitized);
            if (ret != EOK) {
                goto fail;
            }
            filter = talloc_asprintf_append(filter, SDAP_SUDO_FILTER_GROUP,
                                            map[SDAP_AT_SUDO_USER].name,
                                            sanitized);
            if (filter == NULL) {
                goto fail;
            }
        }
    }

    /* netgroups */
    /*
     * FIXME: load only netgroups user is member of
     * FIXME: add option to disable this filter
     */
    filter = talloc_asprintf_append(filter, SDAP_SUDO_FILTER_NETGROUP,
                                    map[SDAP_AT_SUDO_USER].name,
                                    "*");
    if (filter == NULL) {
        goto fail;
    }


    output = talloc_asprintf(mem_ctx, SDAP_SUDO_FILTER_USER,
                             map[SDAP_OC_SUDORULE].name,
                             map[SDAP_AT_SUDO_NAME].name,
                             SDAP_SUDO_DEFAULTS, /* FIXME: add option for this */
                             map[SDAP_AT_SUDO_USER].name,
                             filter);

    talloc_free(filter);
    return output;

fail:
    talloc_free(filter);
    return NULL;
}
