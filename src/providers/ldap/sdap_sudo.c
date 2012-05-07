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
#include "db/sysdb_sudo.h"

struct sdap_sudo_full_refresh_state {
    struct sysdb_ctx *sysdb;
    int dp_error;
    int error;
};

static struct tevent_req *sdap_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                                                      struct sdap_id_ctx *id_ctx);

static void sdap_sudo_full_refresh_done(struct tevent_req *subreq);

static int sdap_sudo_full_refresh_recv(struct tevent_req *req,
                                       int *dp_error,
                                       int *error);

static struct tevent_req *sdap_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                                                       struct be_ctx *be_ctx,
                                                       struct sdap_options *opts,
                                                       struct sdap_id_conn_cache *conn_cache,
                                                       char **rules);

static int sdap_sudo_rules_refresh_recv(struct tevent_req *req,
                                        int *dp_error,
                                        int *error);

static void sdap_sudo_periodical_full_refresh_done(struct tevent_req *req);

static void
sdap_sudo_shutdown(struct be_req *req)
{
    sdap_handler_done(req, DP_ERR_OK, EOK, NULL);
}

struct bet_ops sdap_sudo_ops = {
    .handler = sdap_sudo_handler,
    .finalize = sdap_sudo_shutdown
};

int sdap_sudo_setup_periodical_full_refresh(struct sdap_id_ctx *id_ctx);

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

    ret = sdap_sudo_setup_periodical_full_refresh(id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Unable to setup periodical full refresh"
                                  "of sudo rules [%d]: %s\n", ret, strerror(ret)));
    }

    return EOK;
}

int sdap_sudo_setup_periodical_full_refresh(struct sdap_id_ctx *id_ctx)
{
    struct tevent_req *req;
    time_t full_interval;
    time_t last_full;
    time_t now;
    struct timeval tv;
    int ret;

    /* setup periodical full refresh */
    full_interval = dp_opt_get_int(id_ctx->opts->basic,
                                   SDAP_SUDO_FULL_REFRESH_INTERVAL);
    if (full_interval != 0) {
        ret = sysdb_sudo_get_last_full_refresh(id_ctx->be->sysdb, &last_full);
        if (ret != EOK) {
            return ret;
        }

        if (last_full == 0) {
            /* If this is the first startup, we need to kick off
             * an refresh immediately, to close a window where
             * clients requesting sudo information won't get an
             * immediate reply with no entries
             */
            tv = tevent_timeval_current();
        } else {
            /* At least one update has previously run,
             * so clients will get cached data.
             * We will delay the refresh so we don't slow
             * down the startup process if this is happening
             * during system boot.
             */

            now = time(NULL);
            if (last_full + full_interval < now) {
                /* delay at least by 10s */
                tv = tevent_timeval_current_ofs(10, 0);
            } else {
                tv = tevent_timeval_set(last_full + full_interval, 0);
            }
        }

        req = sdap_sudo_timer_send(id_ctx, id_ctx->be->ev, id_ctx,
                                   tv, full_interval,
                                   sdap_sudo_full_refresh_send);
        if (req == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Unable to schedule full refresh of sudo "
                  "rules! Full periodical refresh will not work.\n"));
            return ENOMEM;
        }

        tevent_req_set_callback(req, sdap_sudo_periodical_full_refresh_done,
                                id_ctx);

        DEBUG(SSSDBG_TRACE_FUNC, ("Full refresh scheduled at: %lld\n",
                                      (long long)tv.tv_sec));
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, ("Periodical full refresh of sudo rules "
                                     "is disabled\n"));
    }

    return EOK;
}

static void sdap_sudo_reply(struct tevent_req *req)
{
    struct be_req *be_req = NULL;
    struct be_sudo_req *sudo_req = NULL;
    int dp_error;
    int error;
    int ret;

    be_req = tevent_req_callback_data(req, struct be_req);
    sudo_req = talloc_get_type(be_req->req_data, struct be_sudo_req);

    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        ret = sdap_sudo_full_refresh_recv(req, &dp_error, &error);
        break;
    case BE_REQ_SUDO_RULES:
        ret = sdap_sudo_rules_refresh_recv(req, &dp_error, &error);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid request type: %d\n",
                                    sudo_req->type));
        ret = EINVAL;
    }

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

    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        DEBUG(SSSDBG_TRACE_FUNC, ("Issuing a full refresh of sudo rules\n"));
        req = sdap_sudo_full_refresh_send(be_req, id_ctx);
        break;
    case BE_REQ_SUDO_RULES:
        DEBUG(SSSDBG_TRACE_FUNC, ("Issuing a refresh of specific sudo rules\n"));
        req = sdap_sudo_rules_refresh_send(be_req, id_ctx->be, id_ctx->opts,
                                           id_ctx->conn_cache, sudo_req->rules);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid request type: %d\n",
                                    sudo_req->type));
        ret = EINVAL;
        goto fail;
    }

    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to send request: %d\n",
                                    sudo_req->type));
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(req, sdap_sudo_reply, be_req);

    return;

fail:
    sdap_handler_done(be_req, DP_ERR_FATAL, ret, NULL);
}

/* issue full refresh of sudo rules */
static struct tevent_req *sdap_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                                                      struct sdap_id_ctx *id_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_sudo_full_refresh_state *state = NULL;
    char *ldap_filter = NULL;
    char *sysdb_filter = NULL;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_full_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->sysdb = id_ctx->be->sysdb;

    /* Download all rules from LDAP */
    ldap_filter = talloc_asprintf(state, SDAP_SUDO_FILTER_CLASS,
                                  id_ctx->opts->sudorule_map[SDAP_OC_SUDORULE].name);
    if (ldap_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* Remove all rules from cache */
    sysdb_filter = talloc_asprintf(state, "(%s=%s)",
                                   SYSDB_OBJECTCLASS, SYSDB_SUDO_CACHE_AT_OC);
    if (sysdb_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Issuing a full refresh of sudo rules\n"));

    subreq = sdap_sudo_refresh_send(state, id_ctx->be, id_ctx->opts,
                                    id_ctx->conn_cache,
                                    ldap_filter, sysdb_filter);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_sudo_full_refresh_done, req);

    /* free filters */
    talloc_free(ldap_filter);
    talloc_free(sysdb_filter);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, id_ctx->be->ev);

    return req;
}

static int sdap_sudo_full_refresh_recv(struct tevent_req *req,
                                       int *dp_error,
                                       int *error)
{
    struct sdap_sudo_full_refresh_state *state = NULL;
    state = tevent_req_data(req, struct sdap_sudo_full_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *error = state->error;

    return EOK;
}

static void sdap_sudo_full_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_full_refresh_state *state = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_full_refresh_state);

    ret = sdap_sudo_refresh_recv(subreq, &state->dp_error, &state->error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* save the time in the sysdb */
    ret = sysdb_sudo_set_last_full_refresh(state->sysdb, time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Unable to save time of "
                                     "a successful full refresh\n"));
        /* this is only a minor error that does not affect the functionality,
         * therefore there is no need to report it with tevent_req_error()
         * which would cause problems in the consumers */
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Successful full refresh of sudo rules\n"));

    tevent_req_done(req);
}

/* issue refresh of specific sudo rules */
static struct tevent_req *sdap_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                                                       struct be_ctx *be_ctx,
                                                       struct sdap_options *opts,
                                                       struct sdap_id_conn_cache *conn_cache,
                                                       char **rules)
{
    struct tevent_req *req = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    char *ldap_filter = NULL;
    char *sysdb_filter = NULL;
    char *safe_rule = NULL;
    int ret;
    int i;

    if (rules == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return NULL;
    }

    ldap_filter = talloc_zero(tmp_ctx, char); /* assign to tmp_ctx */
    sysdb_filter = talloc_zero(tmp_ctx, char); /* assign to tmp_ctx */

    /* Download only selected rules from LDAP */
    /* Remove all selected rules from cache */
    for (i = 0; rules[i] != NULL; i++) {
        ret = sss_filter_sanitize(tmp_ctx, rules[i], &safe_rule);
        if (ret != EOK) {
            goto done;
        }

        ldap_filter = talloc_asprintf_append_buffer(ldap_filter, "(%s=%s)",
                                     opts->sudorule_map[SDAP_AT_SUDO_NAME].name,
                                     safe_rule);
        if (ldap_filter == NULL) {
            goto done;
        }

        sysdb_filter = talloc_asprintf_append_buffer(sysdb_filter, "(%s=%s)",
                                                     SYSDB_SUDO_CACHE_AT_CN,
                                                     safe_rule);
        if (sysdb_filter == NULL) {
            goto done;
        }
    }

    ldap_filter = talloc_asprintf(tmp_ctx, "(&"SDAP_SUDO_FILTER_CLASS"(|%s))",
                                  opts->sudorule_map[SDAP_OC_SUDORULE].name,
                                  ldap_filter);
    if (ldap_filter == NULL) {
        goto done;
    }

    sysdb_filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(|%s))",
                                   SYSDB_OBJECTCLASS, SYSDB_SUDO_CACHE_AT_OC,
                                   sysdb_filter);
    if (sysdb_filter == NULL) {
        goto done;
    }

    req = sdap_sudo_refresh_send(mem_ctx, be_ctx, opts, conn_cache,
                                 ldap_filter, sysdb_filter);
    if (req == NULL) {
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return req;
}

static int sdap_sudo_rules_refresh_recv(struct tevent_req *req,
                                        int *dp_error,
                                        int *error)
{
    return sdap_sudo_refresh_recv(req, dp_error, error);
}

static void sdap_sudo_periodical_full_refresh_done(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL; /* req from sdap_sudo_full_refresh_send() */
    struct tevent_req *newreq = NULL;
    struct sdap_id_ctx *id_ctx = NULL;
    struct timeval tv;
    time_t delay;
    int dp_error;
    int error;
    int ret;

    ret = sdap_sudo_timer_recv(req, req, &subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Sudo timer failed [%d]: %s\n", ret, strerror(ret)));
        goto schedule;
    }

    ret = sdap_sudo_full_refresh_recv(subreq, &dp_error, &error);
    if (dp_error != DP_ERR_OK || error != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Periodical full refresh of sudo rules "
              "failed [dp_error: %d] ([%d]: %s)",
              dp_error, error, strerror(error)));
        goto schedule;
    }

schedule:
    id_ctx = tevent_req_callback_data(req, struct sdap_id_ctx);
    talloc_zfree(req);

    delay = dp_opt_get_int(id_ctx->opts->basic, SDAP_SUDO_FULL_REFRESH_INTERVAL);
    if (delay == 0) {
        /* runtime configuration change? */
        DEBUG(SSSDBG_TRACE_FUNC, ("Periodical full refresh of sudo rules "
                                  "is disabled\n"));
        return;
    }

    /* schedule new refresh */
    tv = tevent_timeval_current_ofs(delay, 0);
    newreq = sdap_sudo_timer_send(id_ctx, id_ctx->be->ev, id_ctx,
                                  tv, delay, sdap_sudo_full_refresh_send);
    if (newreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Unable to schedule full refresh of sudo "
              "rules! Full periodical refresh will not work.\n"));
        return;
    }

    tevent_req_set_callback(newreq, sdap_sudo_periodical_full_refresh_done,
                            id_ctx);

    DEBUG(SSSDBG_TRACE_FUNC, ("Full refresh scheduled at: %lld\n",
                              (long long)tv.tv_sec));
}
