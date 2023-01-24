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
#include "providers/be_ptask.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_sudo_shared.h"
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

    state->sudo_ctx = sudo_ctx;
    state->id_ctx = id_ctx;
    state->sysdb = id_ctx->be->domain->sysdb;
    state->domain = id_ctx->be->domain;

    /* Download all rules from LDAP */
    search_filter = talloc_asprintf(state, SDAP_SUDO_FILTER_CLASS,
                            id_ctx->opts->sudorule_map[SDAP_AT_SUDO_OC].name,
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
                                    delete_filter, true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_sudo_full_refresh_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
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
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* We just finished full request, we can postpone smart refresh. */
    be_ptask_postpone(state->sudo_ctx->smart_refresh);

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

    if (be_ptask_running(sudo_ctx->full_refresh)) {
        DEBUG(SSSDBG_TRACE_FUNC, "Skipping smart refresh because "
              "there is ongoing full refresh.\n");
        state->dp_error = DP_ERR_OK;
        ret = EOK;
        goto immediately;
    }

    state->id_ctx = id_ctx;
    state->sysdb = id_ctx->be->domain->sysdb;

    /* Download all rules from LDAP that are newer than usn */
    if (srv_opts == NULL || srv_opts->max_sudo_value == NULL
         || strcmp(srv_opts->max_sudo_value, "0") == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "USN value is unknown, assuming zero and "
              "omitting it from the filter.\n");
        usn = "0";
        search_filter = talloc_asprintf(state, "(%s=%s)",
                                        map[SDAP_AT_SUDO_OC].name,
                                        map[SDAP_OC_SUDORULE].name);
    } else {
        usn = srv_opts->max_sudo_value;
        search_filter = talloc_asprintf(state, "(&(%s=%s)(%s>=%s))",
                                        map[SDAP_AT_SUDO_OC].name,
                                        map[SDAP_OC_SUDORULE].name,
                                        map[SDAP_AT_SUDO_USN].name, usn);
    }
    if (search_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* Do not remove any rules that are already in the sysdb
     * sysdb_filter = NULL; */

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing a smart refresh of sudo rules "
                             "(USN >= %s)\n", usn);

    subreq = sdap_sudo_refresh_send(state, sudo_ctx, search_filter, NULL, true);
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
                                                const char **rules)
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
                                    opts->sudorule_map[SDAP_AT_SUDO_OC].name,
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
                                    delete_filter, false);
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
    return sdap_sudo_ptask_setup_generic(be_ctx, sudo_ctx->id_ctx->opts->basic,
                                         sdap_sudo_ptask_full_refresh_send,
                                         sdap_sudo_ptask_full_refresh_recv,
                                         sdap_sudo_ptask_smart_refresh_send,
                                         sdap_sudo_ptask_smart_refresh_recv,
                                         sudo_ctx,
                                         &sudo_ctx->full_refresh,
                                         &sudo_ctx->smart_refresh);
}
