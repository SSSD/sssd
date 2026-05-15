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
#include "providers/ipa/ipa_sudo.h"
#include "providers/ldap/sdap_sudo_shared.h"
#include "db/sysdb_sudo.h"

struct ipa_sudo_full_refresh_state {
    struct ipa_sudo_ctx *sudo_ctx;
    struct sss_domain_info *domain;
    int dp_error;
};

static void ipa_sudo_full_refresh_done(struct tevent_req *subreq);

struct tevent_req *
ipa_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ipa_sudo_ctx *sudo_ctx)
{
    struct ipa_sudo_full_refresh_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    char *delete_filter;
    int ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_sudo_full_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->domain = sudo_ctx->id_ctx->be->domain;
    state->sudo_ctx = sudo_ctx;

    /* Remove all rules from cache */
    delete_filter = talloc_asprintf(state, "(%s=%s)", SYSDB_OBJECTCLASS,
                                    SYSDB_SUDO_CACHE_OC);
    if (delete_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing a full refresh of sudo rules\n");

    subreq = ipa_sudo_refresh_send(state, ev, sudo_ctx,
                                   NULL, NULL, delete_filter, true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_sudo_full_refresh_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void
ipa_sudo_full_refresh_done(struct tevent_req *subreq)
{
    struct ipa_sudo_full_refresh_state *state;
    struct tevent_req *req;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_full_refresh_state);

    ret = ipa_sudo_refresh_recv(subreq, &state->dp_error, NULL);
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK) {
        goto done;
    }

    ret = sysdb_sudo_set_last_full_refresh(state->domain, time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to save time of "
                                    "a successful full refresh\n");
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

int
ipa_sudo_full_refresh_recv(struct tevent_req *req,
                           int *dp_error)
{
    struct ipa_sudo_full_refresh_state *state;
    state = tevent_req_data(req, struct ipa_sudo_full_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    return EOK;
}

struct ipa_sudo_smart_refresh_state {
    int dp_error;
};

static void ipa_sudo_smart_refresh_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_sudo_smart_refresh_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct ipa_sudo_ctx *sudo_ctx)
{
    struct sdap_server_opts *srv_opts = sudo_ctx->id_ctx->srv_opts;
    struct ipa_sudo_smart_refresh_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    char *cmdgroups_filter;
    char *search_filter;
    const char *usn;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_sudo_smart_refresh_state);
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

    /* Download all rules from LDAP that are newer than usn */
    if (srv_opts == NULL || srv_opts->max_sudo_value == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "USN value is unknown, assuming zero.\n");
        usn = "0";
        search_filter = NULL;
    } else {
        usn = srv_opts->max_sudo_value;
        search_filter = talloc_asprintf(state, "(%s>=%s)",
                sudo_ctx->sudorule_map[IPA_AT_SUDORULE_ENTRYUSN].name, usn);
        if (search_filter == NULL) {
            ret = ENOMEM;
            goto immediately;
        }
    }

    cmdgroups_filter = talloc_asprintf(state, "(%s>=%s)",
            sudo_ctx->sudocmdgroup_map[IPA_AT_SUDOCMDGROUP_ENTRYUSN].name, usn);
    if (cmdgroups_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* Do not remove any rules that are already in the sysdb. */

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing a smart refresh of sudo rules "
                             "(USN >= %s)\n", usn);

    subreq = ipa_sudo_refresh_send(state, ev, sudo_ctx, cmdgroups_filter,
                                   search_filter, NULL, true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_sudo_smart_refresh_done, req);

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

static void ipa_sudo_smart_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct ipa_sudo_smart_refresh_state *state = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_smart_refresh_state);

    ret = ipa_sudo_refresh_recv(subreq, &state->dp_error, NULL);
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

int ipa_sudo_smart_refresh_recv(struct tevent_req *req,
                                int *dp_error)
{
    struct ipa_sudo_smart_refresh_state *state = NULL;
    state = tevent_req_data(req, struct ipa_sudo_smart_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    return EOK;
}

struct ipa_sudo_rules_refresh_state {
    size_t num_rules;
    int dp_error;
    bool deleted;
};

static void ipa_sudo_rules_refresh_done(struct tevent_req *subreq);

struct tevent_req *
ipa_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct ipa_sudo_ctx *sudo_ctx,
                            const char **rules)
{
    TALLOC_CTX *tmp_ctx;
    struct ipa_sudo_rules_refresh_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    char *search_filter;
    char *delete_filter;
    char *safe_rule;
    errno_t ret;
    int i;

    req = tevent_req_create(mem_ctx, &state, struct ipa_sudo_rules_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    if (rules == NULL || rules[0] == NULL) {
        state->dp_error = DP_ERR_OK;
        state->num_rules = 0;
        state->deleted = false;
        ret = EOK;
        goto immediately;
    }

    search_filter = talloc_zero(tmp_ctx, char); /* assign to tmp_ctx */
    delete_filter = talloc_zero(tmp_ctx, char); /* assign to tmp_ctx */

    /* Download only selected rules from LDAP. */
    /* Remove all selected rules from cache. */
    for (i = 0; rules[i] != NULL; i++) {
        ret = sss_filter_sanitize(tmp_ctx, rules[i], &safe_rule);
        if (ret != EOK) {
            ret = ENOMEM;
            goto immediately;
        }

        search_filter = talloc_asprintf_append_buffer(search_filter, "(%s=%s)",
                             sudo_ctx->sudorule_map[IPA_AT_SUDORULE_NAME].name,
                             safe_rule);
        if (search_filter == NULL) {
            ret = ENOMEM;
            goto immediately;
        }

        delete_filter = talloc_asprintf_append_buffer(delete_filter, "(%s=%s)",
                                                      SYSDB_NAME, safe_rule);
        if (delete_filter == NULL) {
            ret = ENOMEM;
            goto immediately;
        }
    }

    state->num_rules = i;

    search_filter = talloc_asprintf(tmp_ctx, "(|%s)", search_filter);
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

    subreq = ipa_sudo_refresh_send(req, ev, sudo_ctx, NULL, search_filter,
                                   delete_filter, false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_sudo_rules_refresh_done, req);

    ret = EOK;

immediately:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
ipa_sudo_rules_refresh_done(struct tevent_req *subreq)
{
    struct ipa_sudo_rules_refresh_state *state;
    struct tevent_req *req = NULL;
    size_t downloaded_rules_num;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_rules_refresh_state);

    ret = ipa_sudo_refresh_recv(subreq, &state->dp_error, &downloaded_rules_num);
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

int
ipa_sudo_rules_refresh_recv(struct tevent_req *req,
                            int *dp_error,
                            bool *deleted)
{
    struct ipa_sudo_rules_refresh_state *state;
    state = tevent_req_data(req, struct ipa_sudo_rules_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;
    *deleted = state->deleted;

    return EOK;
}

static struct tevent_req *
ipa_sudo_ptask_full_refresh_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct be_ctx *be_ctx,
                                 struct be_ptask *be_ptask,
                                 void *pvt)
{
    struct ipa_sudo_ctx *sudo_ctx;
    sudo_ctx = talloc_get_type(pvt, struct ipa_sudo_ctx);

    return ipa_sudo_full_refresh_send(mem_ctx, be_ctx->ev, sudo_ctx);
}

static errno_t
ipa_sudo_ptask_full_refresh_recv(struct tevent_req *req)
{
    int dp_error;

    return ipa_sudo_full_refresh_recv(req, &dp_error);
}

static struct tevent_req *
ipa_sudo_ptask_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct be_ptask *be_ptask,
                                  void *pvt)
{
    struct ipa_sudo_ctx *sudo_ctx;
    sudo_ctx = talloc_get_type(pvt, struct ipa_sudo_ctx);

    return ipa_sudo_smart_refresh_send(mem_ctx, be_ctx->ev, sudo_ctx);
}

static errno_t
ipa_sudo_ptask_smart_refresh_recv(struct tevent_req *req)
{
    int dp_error;

    return ipa_sudo_smart_refresh_recv(req, &dp_error);
}

errno_t
ipa_sudo_ptask_setup(struct be_ctx *be_ctx, struct ipa_sudo_ctx *sudo_ctx)
{
    return sdap_sudo_ptask_setup_generic(be_ctx, sudo_ctx->id_ctx->opts->basic,
                                         ipa_sudo_ptask_full_refresh_send,
                                         ipa_sudo_ptask_full_refresh_recv,
                                         ipa_sudo_ptask_smart_refresh_send,
                                         ipa_sudo_ptask_smart_refresh_recv,
                                         sudo_ctx,
                                         &sudo_ctx->full_refresh,
                                         &sudo_ctx->smart_refresh);
}
