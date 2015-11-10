/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include "util/util.h"
#include "providers/dp_ptask.h"
#include "providers/ldap/sdap_sudo.h"
#include "db/sysdb_sudo.h"

struct sdap_sudo_full_refresh_state {
    struct sdap_sudo_ctx *sudo_ctx;
    struct sdap_id_ctx *id_ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    int dp_error;
};

static void sdap_sudo_full_refresh_done(struct tevent_req *subreq);

struct tevent_req *sdap_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                                               struct sdap_sudo_ctx *sudo_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_id_ctx *id_ctx = sudo_ctx->id_ctx;
    struct sdap_sudo_full_refresh_state *state = NULL;
    char *search_filter = NULL;
    char *delete_filter = NULL;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_full_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    sudo_ctx->full_refresh_in_progress = true;

    state->sudo_ctx = sudo_ctx;
    state->id_ctx = id_ctx;
    state->sysdb = id_ctx->be->domain->sysdb;
    state->domain = id_ctx->be->domain;

    /* Download all rules from LDAP */
    search_filter = talloc_asprintf(state, SDAP_SUDO_FILTER_CLASS,
                            id_ctx->opts->sudorule_map[SDAP_OC_SUDORULE].name);
    if (search_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* Remove all rules from cache */
    delete_filter = talloc_asprintf(state, "(%s=%s)",
                                    SYSDB_OBJECTCLASS, SYSDB_SUDO_CACHE_OC);
    if (delete_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing a full refresh of sudo rules\n");

    subreq = sdap_sudo_refresh_send(state, sudo_ctx, search_filter,
                                    delete_filter);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_sudo_full_refresh_done, req);

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

static void sdap_sudo_full_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_full_refresh_state *state = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_full_refresh_state);

    ret = sdap_sudo_refresh_recv(state, subreq, &state->dp_error, NULL);
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK) {
        goto done;
    }

    state->sudo_ctx->full_refresh_done = true;

    /* save the time in the sysdb */
    ret = sysdb_sudo_set_last_full_refresh(state->domain, time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to save time of "
                                    "a successful full refresh\n");
        /* this is only a minor error that does not affect the functionality,
         * therefore there is no need to report it with tevent_req_error()
         * which would cause problems in the consumers */
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Successful full refresh of sudo rules\n");

done:
    state->sudo_ctx->full_refresh_in_progress = false;

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_sudo_full_refresh_recv(struct tevent_req *req,
                                int *dp_error)
{
    struct sdap_sudo_full_refresh_state *state = NULL;
    state = tevent_req_data(req, struct sdap_sudo_full_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    return EOK;
}

struct sdap_sudo_smart_refresh_state {
    struct sdap_id_ctx *id_ctx;
    struct sysdb_ctx *sysdb;
    int dp_error;
};

static void sdap_sudo_smart_refresh_done(struct tevent_req *subreq);

struct tevent_req *sdap_sudo_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_sudo_ctx *sudo_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_id_ctx *id_ctx = sudo_ctx->id_ctx;
    struct sdap_attr_map *map = id_ctx->opts->sudorule_map;
    struct sdap_server_opts *srv_opts = id_ctx->srv_opts;
    struct sdap_sudo_smart_refresh_state *state = NULL;
    char *search_filter = NULL;
    const char *usn;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_smart_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (!sudo_ctx->full_refresh_done
            || srv_opts == NULL || srv_opts->max_sudo_value == NULL) {
        /* Perform full refresh first */
        DEBUG(SSSDBG_TRACE_FUNC, "USN value is unknown, "
                                 "waiting for full refresh!\n");
        ret = EINVAL;
        goto immediately;
    }

    state->id_ctx = id_ctx;
    state->sysdb = id_ctx->be->domain->sysdb;

    /* Download all rules from LDAP that are newer than usn */
    usn = srv_opts->max_sudo_value;
    search_filter = talloc_asprintf(state,
                                    "(&(objectclass=%s)(%s>=%s)(!(%s=%s)))",
                                    map[SDAP_OC_SUDORULE].name,
                                    map[SDAP_AT_SUDO_USN].name, usn,
                                    map[SDAP_AT_SUDO_USN].name, usn);
    if (search_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* Do not remove any rules that are already in the sysdb
     * sysdb_filter = NULL; */

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing a smart refresh of sudo rules "
                             "(USN > %s)\n", usn);

    subreq = sdap_sudo_refresh_send(state, sudo_ctx, search_filter, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_sudo_smart_refresh_done, req);

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

static void sdap_sudo_smart_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_smart_refresh_state *state = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_smart_refresh_state);

    ret = sdap_sudo_refresh_recv(state, subreq, &state->dp_error, NULL);
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Successful smart refresh of sudo rules\n");

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_sudo_smart_refresh_recv(struct tevent_req *req,
                                 int *dp_error)
{
    struct sdap_sudo_smart_refresh_state *state = NULL;
    state = tevent_req_data(req, struct sdap_sudo_smart_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    return EOK;
}

struct sdap_sudo_rules_refresh_state {
    struct sdap_id_ctx *id_ctx;
    size_t num_rules;
    int dp_error;
    bool deleted;
};

static void sdap_sudo_rules_refresh_done(struct tevent_req *subreq);

struct tevent_req *sdap_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_sudo_ctx *sudo_ctx,
                                                char **rules)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_sudo_rules_refresh_state *state = NULL;
    struct sdap_id_ctx *id_ctx = sudo_ctx->id_ctx;
    struct sdap_options *opts = id_ctx->opts;
    TALLOC_CTX *tmp_ctx = NULL;
    char *search_filter = NULL;
    char *delete_filter = NULL;
    char *safe_rule = NULL;
    int ret;
    int i;

    if (rules == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_rules_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    search_filter = talloc_zero(tmp_ctx, char); /* assign to tmp_ctx */
    delete_filter = talloc_zero(tmp_ctx, char); /* assign to tmp_ctx */

    /* Download only selected rules from LDAP */
    /* Remove all selected rules from cache */
    for (i = 0; rules[i] != NULL; i++) {
        ret = sss_filter_sanitize(tmp_ctx, rules[i], &safe_rule);
        if (ret != EOK) {
            ret = ENOMEM;
            goto immediately;
        }

        search_filter = talloc_asprintf_append_buffer(search_filter, "(%s=%s)",
                                     opts->sudorule_map[SDAP_AT_SUDO_NAME].name,
                                     safe_rule);
        if (search_filter == NULL) {
            ret = ENOMEM;
            goto immediately;
        }

        delete_filter = talloc_asprintf_append_buffer(delete_filter, "(%s=%s)",
                                                      SYSDB_SUDO_CACHE_AT_CN,
                                                      safe_rule);
        if (delete_filter == NULL) {
            ret = ENOMEM;
            goto immediately;
        }
    }

    state->id_ctx = sudo_ctx->id_ctx;
    state->num_rules = i;

    search_filter = talloc_asprintf(tmp_ctx, "(&"SDAP_SUDO_FILTER_CLASS"(|%s))",
                                    opts->sudorule_map[SDAP_OC_SUDORULE].name,
                                    search_filter);
    if (search_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    delete_filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(|%s))",
                                    SYSDB_OBJECTCLASS, SYSDB_SUDO_CACHE_OC,
                                    delete_filter);
    if (delete_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_sudo_refresh_send(req, sudo_ctx, search_filter,
                                    delete_filter);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_sudo_rules_refresh_done, req);

    ret = EOK;
immediately:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, id_ctx->be->ev);
    }

    return req;
}

static void sdap_sudo_rules_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_rules_refresh_state *state = NULL;
    size_t downloaded_rules_num;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_rules_refresh_state);

    ret = sdap_sudo_refresh_recv(state, subreq, &state->dp_error,
                                 &downloaded_rules_num);
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK) {
        goto done;
    }

    state->deleted = downloaded_rules_num != state->num_rules ? true : false;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_sudo_rules_refresh_recv(struct tevent_req *req,
                                 int *dp_error,
                                 bool *deleted)
{
    struct sdap_sudo_rules_refresh_state *state = NULL;
    state = tevent_req_data(req, struct sdap_sudo_rules_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *deleted = state->deleted;

    return EOK;
}

static struct tevent_req *
sdap_sudo_ptask_full_refresh_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct be_ptask *be_ptask,
                                  void *pvt)
{
    struct sdap_sudo_ctx *sudo_ctx;
    sudo_ctx = talloc_get_type(pvt, struct sdap_sudo_ctx);

    return sdap_sudo_full_refresh_send(mem_ctx, sudo_ctx);
}

static errno_t
sdap_sudo_ptask_full_refresh_recv(struct tevent_req *req)
{
    int dp_error;

    return sdap_sudo_full_refresh_recv(req, &dp_error);
}

static struct tevent_req *
sdap_sudo_ptask_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *be_ctx,
                                   struct be_ptask *be_ptask,
                                   void *pvt)
{
    struct sdap_sudo_ctx *sudo_ctx;
    sudo_ctx = talloc_get_type(pvt, struct sdap_sudo_ctx);

    return sdap_sudo_smart_refresh_send(mem_ctx, sudo_ctx);
}

static errno_t
sdap_sudo_ptask_smart_refresh_recv(struct tevent_req *req)
{
    int dp_error;

    return sdap_sudo_smart_refresh_recv(req, &dp_error);
}

errno_t
sdap_sudo_ptask_setup(struct be_ctx *be_ctx, struct sdap_sudo_ctx *sudo_ctx)
{
    struct dp_option *opts = sudo_ctx->id_ctx->opts->basic;
    time_t smart;
    time_t full;
    time_t delay;
    time_t last_refresh;
    errno_t ret;

    smart = dp_opt_get_int(opts, SDAP_SUDO_SMART_REFRESH_INTERVAL);
    full = dp_opt_get_int(opts, SDAP_SUDO_FULL_REFRESH_INTERVAL);

    if (smart == 0 && full == 0) {
        /* We don't allow both types to be disabled. At least smart refresh
         * needs to be enabled. In this case smart refresh will catch up new
         * and modified rules and deleted rules are caught when expired. */
        smart = opts[SDAP_SUDO_SMART_REFRESH_INTERVAL].def_val.number;

        DEBUG(SSSDBG_CONF_SETTINGS, "At least smart refresh needs to be "
              "enabled. Setting smart refresh interval to default value "
              "(%ld) seconds.\n", smart);
    } else if (full <= smart) {
        /* In this case it does not make any sense to run smart refresh. */
        smart = 0;

        DEBUG(SSSDBG_CONF_SETTINGS, "Smart refresh interval has to be lower "
              "than full refresh interval. Periodical smart refresh will be "
              "disabled.\n");
    }

    ret = sysdb_sudo_get_last_full_refresh(be_ctx->domain, &last_refresh);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to obtain time of last full "
              "refresh. Assuming none was performed so far.\n");
        last_refresh = 0;
    }

    if (last_refresh == 0) {
        /* If this is the first startup, we need to kick off an refresh
         * immediately, to close a window where clients requesting sudo
         * information won't get an immediate reply with no entries */
        delay = 0;
    } else {
        /* At least one update has previously run, so clients will get cached
         * data. We will delay the refresh so we don't slow down the startup
         * process if this is happening during system boot. */
        delay = 10;
    }

    /* Full refresh.
     *
     * Disable when offline and run immediately when SSSD goes back online.
     * Since we have periodical online check we don't have to run this task
     * when offline. */
    ret = be_ptask_create(be_ctx, be_ctx, full, delay, 0, 0, full,
                          BE_PTASK_OFFLINE_DISABLE, 0,
                          sdap_sudo_ptask_full_refresh_send,
                          sdap_sudo_ptask_full_refresh_recv,
                          sudo_ctx, "SUDO Full Refresh", NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup full refresh ptask "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    /* Smart refresh.
     *
     * Disable when offline and reschedule normally when SSSD goes back online.
     * Since we have periodical online check we don't have to run this task
     * when offline. */
    ret = be_ptask_create(be_ctx, be_ctx, smart, delay + smart, smart, 0, smart,
                          BE_PTASK_OFFLINE_DISABLE, 0,
                          sdap_sudo_ptask_smart_refresh_send,
                          sdap_sudo_ptask_smart_refresh_recv,
                          sudo_ctx, "SUDO Smart Refresh", NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup smart refresh ptask "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}
