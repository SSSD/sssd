/*
    SSSD

    IPA Backend Module -- Access control

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ipa/ipa_hbac_rules.h"
#include "providers/ipa/ipa_rules_common.h"

/* External logging function for HBAC. */
void hbac_debug_messages(const char *file, int line,
                         const char *function,
                         enum hbac_debug_level level,
                         const char *fmt, ...)
{
    int loglevel;
    va_list ap;

    switch(level) {
    case HBAC_DBG_FATAL:
        loglevel = SSSDBG_FATAL_FAILURE;
        break;
    case HBAC_DBG_ERROR:
        loglevel = SSSDBG_OP_FAILURE;
        break;
    case HBAC_DBG_WARNING:
        loglevel = SSSDBG_MINOR_FAILURE;
        break;
    case HBAC_DBG_INFO:
        loglevel = SSSDBG_CONF_SETTINGS;
        break;
    case HBAC_DBG_TRACE:
        loglevel = SSSDBG_TRACE_INTERNAL;
        break;
    default:
        loglevel = SSSDBG_UNRESOLVED;
        break;
    }

    va_start(ap, fmt);
    sss_vdebug_fn(file, line, function, loglevel, 0, fmt, ap);
    va_end(ap);
}

enum hbac_result {
    HBAC_ALLOW = 1,
    HBAC_DENY,
    HBAC_NOT_APPLICABLE
};

enum check_result {
    RULE_APPLICABLE = 0,
    RULE_NOT_APPLICABLE,
    RULE_ERROR
};

struct ipa_fetch_hbac_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct sdap_id_ctx *sdap_ctx;
    struct ipa_access_ctx *access_ctx;
    struct sdap_id_op *sdap_op;
    struct dp_option *ipa_options;

    struct sdap_search_base **search_bases;

    /* Hosts */
    struct ipa_common_entries *hosts;
    struct sysdb_attrs *ipa_host;

    /* Rules */
    struct ipa_common_entries *rules;

    /* Services */
    struct ipa_common_entries *services;
};

static errno_t ipa_fetch_hbac_retry(struct tevent_req *req);
static void ipa_fetch_hbac_connect_done(struct tevent_req *subreq);
static errno_t ipa_fetch_hbac_hostinfo(struct tevent_req *req);
static void ipa_fetch_hbac_hostinfo_done(struct tevent_req *subreq);
static void ipa_fetch_hbac_services_done(struct tevent_req *subreq);
static void ipa_fetch_hbac_rules_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_fetch_hbac_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct be_ctx *be_ctx,
                    struct ipa_access_ctx *access_ctx)
{
    struct ipa_fetch_hbac_state *state;
    struct tevent_req *req;
    time_t now, refresh_interval;
    bool offline;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_fetch_hbac_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->access_ctx = access_ctx;
    state->sdap_ctx = access_ctx->sdap_ctx;
    state->ipa_options = access_ctx->ipa_options;
    state->search_bases = access_ctx->hbac_search_bases;
    state->hosts = talloc_zero(state, struct ipa_common_entries);
    if (state->hosts == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    state->services = talloc_zero(state, struct ipa_common_entries);
    if (state->hosts == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    state->rules = talloc_zero(state, struct ipa_common_entries);
    if (state->rules == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (state->search_bases == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No HBAC search base found.\n");
        ret = EINVAL;
        goto immediately;
    }

    state->sdap_op = sdap_id_op_create(state, state->sdap_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    offline = be_is_offline(be_ctx);
    DEBUG(SSSDBG_TRACE_ALL, "Connection status is [%s].\n",
          offline ? "offline" : "online");

    refresh_interval = dp_opt_get_int(state->ipa_options, IPA_HBAC_REFRESH);
    now = time(NULL);

    if (offline || now < access_ctx->last_update + refresh_interval) {
        DEBUG(SSSDBG_TRACE_FUNC, "Performing cached HBAC evaluation\n");
        ret = EOK;
        goto immediately;
    }

    ret = ipa_fetch_hbac_retry(req);
    if (ret != EAGAIN) {
        goto immediately;
    }

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

static errno_t ipa_fetch_hbac_retry(struct tevent_req *req)
{
    struct ipa_fetch_hbac_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct ipa_fetch_hbac_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed: "
                                   "%d(%s)\n", ret, strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, ipa_fetch_hbac_connect_done, req);

    return EAGAIN;
}

static void ipa_fetch_hbac_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    if (dp_error == DP_ERR_OFFLINE) {
        ret = EOK;
        goto done;
    }

    ret = ipa_fetch_hbac_hostinfo(req);
    if (ret == EAGAIN) {
        return;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ipa_fetch_hbac_hostinfo(struct tevent_req *req)
{
    struct ipa_fetch_hbac_state *state;
    struct tevent_req *subreq;
    const char *hostname;
    bool srchost;

    state = tevent_req_data(req, struct ipa_fetch_hbac_state);

    srchost = dp_opt_get_bool(state->ipa_options, IPA_HBAC_SUPPORT_SRCHOST);
    if (srchost) {
        /* Support srchost
         * -> we don't want any particular host,
         *    we want all hosts
         */
        hostname = NULL;

        /* THIS FEATURE IS DEPRECATED */
        DEBUG(SSSDBG_MINOR_FAILURE, "WARNING: Using deprecated option "
                    "ipa_hbac_support_srchost.\n");
        sss_log(SSS_LOG_NOTICE, "WARNING: Using deprecated option "
                    "ipa_hbac_support_srchost.\n");
    } else {
        hostname = dp_opt_get_string(state->ipa_options, IPA_HOSTNAME);
    }

    subreq = ipa_host_info_send(state, state->ev,
                                sdap_id_op_handle(state->sdap_op),
                                state->sdap_ctx->opts, hostname,
                                state->access_ctx->host_map,
                                state->access_ctx->hostgroup_map,
                                state->access_ctx->host_search_bases);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_fetch_hbac_hostinfo_done, req);

    return EAGAIN;
}

static void ipa_fetch_hbac_hostinfo_done(struct tevent_req *subreq)
{
    struct ipa_fetch_hbac_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;
    int dp_error;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_fetch_hbac_state);

    ret = ipa_host_info_recv(subreq, state,
                             &state->hosts->entry_count,
                             &state->hosts->entries,
                             &state->hosts->group_count,
                             &state->hosts->groups);
    state->hosts->entry_subdir = HBAC_HOSTS_SUBDIR;
    state->hosts->group_subdir = HBAC_HOSTGROUPS_SUBDIR;
    talloc_zfree(subreq);

    if (ret != EOK) {
        /* Only call sdap_id_op_done in case of an error to trigger a
         * failover. In general changing the tevent_req layout would be better
         * so that all searches are in another sub-request so that we can
         * error out at any step and the parent request can call
         * sdap_id_op_done just once. */
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
        if (dp_error == DP_ERR_OK && ret != EOK) {
            /* retry */
            ret = ipa_fetch_hbac_retry(req);
            if (ret != EAGAIN) {
                goto done;
            }
            return;
        }
        goto done;
    }

    subreq = ipa_hbac_service_info_send(state, state->ev,
                                        sdap_id_op_handle(state->sdap_op),
                                        state->sdap_ctx->opts,
                                        state->search_bases);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_fetch_hbac_services_done, req);

    return;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void ipa_fetch_hbac_services_done(struct tevent_req *subreq)
{
    struct ipa_fetch_hbac_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_fetch_hbac_state);

    ret = ipa_hbac_service_info_recv(subreq, state,
                                     &state->services->entry_count,
                                     &state->services->entries,
                                     &state->services->group_count,
                                     &state->services->groups);
    state->services->entry_subdir = HBAC_SERVICES_SUBDIR;
    state->services->group_subdir = HBAC_SERVICEGROUPS_SUBDIR;
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    /* Get the ipa_host attrs */
    ret = ipa_get_host_attrs(state->ipa_options,
                             state->hosts->entry_count,
                             state->hosts->entries,
                             &state->ipa_host);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not locate IPA host.\n");
        goto done;
    }

    subreq = ipa_hbac_rule_info_send(state, state->ev,
                                     sdap_id_op_handle(state->sdap_op),
                                     state->sdap_ctx->opts,
                                     state->search_bases,
                                     state->ipa_host);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_fetch_hbac_rules_done, req);

    return;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void ipa_fetch_hbac_rules_done(struct tevent_req *subreq)
{
    struct ipa_fetch_hbac_state *state = NULL;
    struct tevent_req *req = NULL;
    int dp_error;
    errno_t ret;
    bool found;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_fetch_hbac_state);

    ret = ipa_hbac_rule_info_recv(subreq, state,
                                  &state->rules->entry_count,
                                  &state->rules->entries);
    state->rules->entry_subdir = HBAC_RULES_SUBDIR;
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        /* Set ret to EOK so we can safely call sdap_id_op_done. */
        found = false;
        ret = EOK;
    } else if (ret == EOK) {
        found = true;
    } else {
        goto done;
    }

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ipa_fetch_hbac_retry(req);
        if (ret != EAGAIN) {
            tevent_req_error(req, ret);
        }
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (found == false) {
        /* No rules were found that apply to this host. */
        ret = ipa_common_purge_rules(state->be_ctx->domain,
                                     HBAC_RULES_SUBDIR);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to remove HBAC rules\n");
            goto done;
        }

        ret = ENOENT;
        goto done;
    }

    ret = ipa_common_save_rules(state->be_ctx->domain,
                                state->hosts, state->services, state->rules,
                                &state->access_ctx->last_update);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to save HBAC rules\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ipa_fetch_hbac_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t ipa_hbac_evaluate_rules(struct be_ctx *be_ctx,
                                struct dp_option *ipa_options,
                                struct pam_data *pd)
{
    TALLOC_CTX *tmp_ctx;
    struct hbac_ctx hbac_ctx;
    struct hbac_rule **hbac_rules;
    struct hbac_eval_req *eval_req;
    enum hbac_eval_result result;
    struct hbac_info *info = NULL;
    const char **attrs_get_cached_rules;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    hbac_ctx.be_ctx = be_ctx;
    hbac_ctx.ipa_options = ipa_options;
    hbac_ctx.pd = pd;

    /* Get HBAC rules from the sysdb */
    attrs_get_cached_rules = hbac_get_attrs_to_get_cached_rules(tmp_ctx);
    if (attrs_get_cached_rules == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "hbac_get_attrs_to_get_cached_rules() failed\n");
        ret = ENOMEM;
        goto done;
    }
    ret = ipa_common_get_cached_rules(tmp_ctx, be_ctx->domain,
                                      IPA_HBAC_RULE, HBAC_RULES_SUBDIR,
                                      attrs_get_cached_rules,
                                      &hbac_ctx.rule_count, &hbac_ctx.rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not retrieve rules from the cache\n");
        goto done;
    }

    ret = hbac_ctx_to_rules(tmp_ctx, &hbac_ctx, &hbac_rules, &eval_req);
    if (ret == EPERM) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "DENY rules detected. Denying access to all users\n");
        ret = ERR_ACCESS_DENIED;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not construct HBAC rules\n");
        goto done;
    }

    hbac_enable_debug(hbac_debug_messages);

    result = hbac_evaluate(hbac_rules, eval_req, &info);
    if (result == HBAC_EVAL_ALLOW) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Access granted by HBAC rule [%s]\n",
              info->rule_name);
        ret = EOK;
        goto done;
    } else if (result == HBAC_EVAL_ERROR) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error [%s] occurred in rule [%s]\n",
              hbac_error_string(info->code), info->rule_name);
        ret = EIO;
        goto done;
    } else if (result == HBAC_EVAL_OOM) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Insufficient memory\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "Access denied by HBAC rules\n");
    ret = ERR_ACCESS_DENIED;

done:
    hbac_free_info(info);
    talloc_free(tmp_ctx);
    return ret;
}

struct ipa_pam_access_handler_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ipa_access_ctx *access_ctx;
    struct pam_data *pd;
};

static void ipa_pam_access_handler_sdap_done(struct tevent_req *subreq);
static void ipa_pam_access_handler_done(struct tevent_req *subreq);

struct tevent_req *
ipa_pam_access_handler_send(TALLOC_CTX *mem_ctx,
                           struct ipa_access_ctx *access_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params)
{
    struct ipa_pam_access_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_pam_access_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->ev = params->ev;
    state->be_ctx = params->be_ctx;
    state->access_ctx = access_ctx;

    subreq = sdap_access_send(state, params->ev, params->be_ctx,
                              params->domain, access_ctx->sdap_access_ctx,
                              access_ctx->sdap_ctx->conn, pd);
    if (subreq == NULL) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_pam_access_handler_sdap_done, req);

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void ipa_pam_access_handler_sdap_done(struct tevent_req *subreq)
{
    struct ipa_pam_access_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_access_handler_state);

    ret = sdap_access_recv(subreq);
    talloc_free(subreq);
    switch (ret) {
    case EOK:
    case ERR_PASSWORD_EXPIRED_WARN:
        /* Account wasn't locked. Continue below to HBAC processing. */
        state->pd->pam_status = PAM_SUCCESS;
        break;
    case ERR_PASSWORD_EXPIRED_RENEW:
        state->pd->pam_status = PAM_NEW_AUTHTOK_REQD;
        break;
    case ERR_ACCESS_DENIED:
    case ERR_PASSWORD_EXPIRED_REJECT:
        /* Account was locked or password expired. */
        state->pd->pam_status = PAM_PERM_DENIED;
        goto done;
    case ERR_ACCOUNT_EXPIRED:
        state->pd->pam_status = PAM_ACCT_EXPIRED;
        goto done;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Error retrieving access check result "
              "[%d]: %s.\n", ret, sss_strerror(ret));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        break;
    }

    subreq = ipa_fetch_hbac_send(state, state->ev, state->be_ctx,
                                 state->access_ctx);
    if (subreq == NULL) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    /* The callback function will not overwrite pam_status in case of
     * success. Because of that, pam_status must be set to the desired
     * value in advance. */
    tevent_req_set_callback(subreq, ipa_pam_access_handler_done, req);

    return;

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

static void ipa_pam_access_handler_done(struct tevent_req *subreq)
{
    struct ipa_pam_access_handler_state *state;
    struct tevent_req *req;
    int preset_pam_status;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_access_handler_state);

    ret = ipa_fetch_hbac_recv(subreq);
    talloc_free(subreq);

    if (ret == ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No HBAC rules found, denying access\n");
        state->pd->pam_status = PAM_PERM_DENIED;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to fetch HBAC rules [%d]: %s\n",
              ret, sss_strerror(ret));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    /* ipa_hbac_evaluate_rules() could overwrite state->pd->pam_status but
       we don't want that. Save the previous value and set it back in case
       of succcess. */
    preset_pam_status = state->pd->pam_status;
    ret = ipa_hbac_evaluate_rules(state->be_ctx,
                                  state->access_ctx->ipa_options, state->pd);
    if (ret == EOK) {
        state->pd->pam_status = preset_pam_status;
    } else if (ret == ERR_ACCESS_DENIED) {
        state->pd->pam_status = PAM_PERM_DENIED;
    } else {
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }
done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
ipa_pam_access_handler_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            struct pam_data **_data)
{
    struct ipa_pam_access_handler_state *state = NULL;

    state = tevent_req_data(req, struct ipa_pam_access_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}

struct ipa_refresh_access_rules_state {
    int dummy;
};

static void ipa_refresh_access_rules_done(struct tevent_req *subreq);

struct tevent_req *
ipa_refresh_access_rules_send(TALLOC_CTX *mem_ctx,
                              struct ipa_access_ctx *access_ctx,
                              void *no_input_data,
                              struct dp_req_params *params)
{
    struct ipa_refresh_access_rules_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    DEBUG(SSSDBG_TRACE_FUNC, "Refreshing HBAC rules\n");

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_refresh_access_rules_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    subreq = ipa_fetch_hbac_send(state, params->ev, params->be_ctx, access_ctx);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, params->ev);
        return req;
    }

    tevent_req_set_callback(subreq, ipa_refresh_access_rules_done, req);

    return req;
}

static void ipa_refresh_access_rules_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = ipa_fetch_hbac_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t ipa_refresh_access_rules_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      void **_no_output_data)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
