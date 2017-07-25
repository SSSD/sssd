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

/* External logging function for HBAC. */
void hbac_debug_messages(const char *file, int line,
                         const char *function,
                         enum hbac_debug_level level,
                         const char *fmt, ...)
{
    int loglevel;

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

    if (DEBUG_IS_SET(loglevel)) {
        va_list ap;

        va_start(ap, fmt);
        sss_vdebug_fn(file, line, function, loglevel, 0, fmt, ap);
        va_end(ap);
    }
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
    struct time_rules_ctx *tr_ctx;

    struct sdap_search_base **search_bases;

    /* Hosts */
    size_t host_count;
    struct sysdb_attrs **hosts;
    size_t hostgroup_count;
    struct sysdb_attrs **hostgroups;
    struct sysdb_attrs *ipa_host;

    /* Rules */
    size_t rule_count;
    struct sysdb_attrs **rules;

    /* Services */
    size_t service_count;
    struct sysdb_attrs **services;
    size_t servicegroup_count;
    struct sysdb_attrs **servicegroups;
};

static errno_t ipa_fetch_hbac_retry(struct tevent_req *req);
static void ipa_fetch_hbac_connect_done(struct tevent_req *subreq);
static errno_t ipa_fetch_hbac_hostinfo(struct tevent_req *req);
static void ipa_fetch_hbac_hostinfo_done(struct tevent_req *subreq);
static void ipa_fetch_hbac_services_done(struct tevent_req *subreq);
static void ipa_fetch_hbac_rules_done(struct tevent_req *subreq);
static errno_t ipa_purge_hbac(struct sss_domain_info *domain);
static errno_t ipa_save_hbac(struct sss_domain_info *domain,
                             struct ipa_fetch_hbac_state *state);

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
    state->tr_ctx = access_ctx->tr_ctx;
    state->search_bases = access_ctx->hbac_search_bases;

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

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_fetch_hbac_state);

    ret = ipa_host_info_recv(subreq, state,
                             &state->host_count, &state->hosts,
                             &state->hostgroup_count, &state->hostgroups);
    talloc_zfree(subreq);
    if (ret != EOK) {
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
    const char *ipa_hostname;
    const char *hostname;
    errno_t ret;
    size_t i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_fetch_hbac_state);

    ret = ipa_hbac_service_info_recv(subreq, state,
                             &state->service_count, &state->services,
                             &state->servicegroup_count, &state->servicegroups);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    /* Get the ipa_host attrs */
    state->ipa_host = NULL;
    ipa_hostname = dp_opt_get_cstring(state->ipa_options, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing ipa_hostname, this should never happen.\n");
        ret = EINVAL;
        goto done;
    }

    for (i = 0; i < state->host_count; i++) {
        ret = sysdb_attrs_get_string(state->hosts[i], SYSDB_FQDN, &hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not locate IPA host\n");
            goto done;
        }

        if (strcasecmp(hostname, ipa_hostname) == 0) {
            state->ipa_host = state->hosts[i];
            break;
        }
    }

    if (state->ipa_host == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not locate IPA host\n");
        ret = EINVAL;
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
                                  &state->rule_count, &state->rules);
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
        ret = ipa_purge_hbac(state->be_ctx->domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to remove HBAC rules\n");
            goto done;
        }

        ret = ENOENT;
        goto done;
    }

    ret = ipa_save_hbac(state->be_ctx->domain, state);
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

static errno_t ipa_purge_hbac(struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Delete any rules in the sysdb so offline logins are also denied. */
    base_dn = sysdb_custom_subtree_dn(tmp_ctx, domain, HBAC_RULES_SUBDIR);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_delete_recursive(domain->sysdb, base_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_delete_recursive failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t ipa_save_hbac(struct sss_domain_info *domain,
                             struct ipa_fetch_hbac_state *state)
{
    bool in_transaction = false;
    errno_t ret;
    errno_t sret;

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not start transaction\n");
        goto done;
    }
    in_transaction = true;

    /* Save the hosts */
    ret = ipa_hbac_sysdb_save(domain, HBAC_HOSTS_SUBDIR, SYSDB_FQDN,
                              state->host_count, state->hosts,
                              HBAC_HOSTGROUPS_SUBDIR, SYSDB_NAME,
                              state->hostgroup_count, state->hostgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error saving hosts [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Save the services */
    ret = ipa_hbac_sysdb_save(domain, HBAC_SERVICES_SUBDIR, IPA_CN,
                              state->service_count, state->services,
                              HBAC_SERVICEGROUPS_SUBDIR, IPA_CN,
                              state->servicegroup_count,
                              state->servicegroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error saving services [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }
    /* Save the rules */
    ret = ipa_hbac_sysdb_save(domain, HBAC_RULES_SUBDIR, IPA_UNIQUE_ID,
                              state->rule_count, state->rules,
                              NULL, NULL, 0, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error saving rules [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    state->access_ctx->last_update = time(NULL);

    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }

    return ret;
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
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    hbac_ctx.be_ctx = be_ctx;
    hbac_ctx.ipa_options = ipa_options;
    hbac_ctx.pd = pd;

    /* Get HBAC rules from the sysdb */
    ret = hbac_get_cached_rules(tmp_ctx, be_ctx->domain,
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

errno_t hbac_get_cached_rules(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              size_t *_rule_count,
                              struct sysdb_attrs ***_rules)
{
    errno_t ret;
    struct ldb_message **msgs;
    struct sysdb_attrs **rules;
    size_t rule_count;
    TALLOC_CTX *tmp_ctx;
    char *filter;
    const char *attrs[] = { OBJECTCLASS,
                            IPA_CN,
                            SYSDB_ORIG_DN,
                            IPA_UNIQUE_ID,
                            IPA_ENABLED_FLAG,
                            IPA_ACCESS_RULE_TYPE,
                            IPA_MEMBER_USER,
                            IPA_USER_CATEGORY,
                            IPA_MEMBER_SERVICE,
                            IPA_SERVICE_CATEGORY,
                            IPA_SOURCE_HOST,
                            IPA_SOURCE_HOST_CATEGORY,
                            IPA_EXTERNAL_HOST,
                            IPA_MEMBER_HOST,
                            IPA_HOST_CATEGORY,
                            NULL };

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    filter = talloc_asprintf(tmp_ctx, "(objectClass=%s)", IPA_HBAC_RULE);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              HBAC_RULES_SUBDIR, attrs,
                              &rule_count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up HBAC rules\n");
        goto done;
    } if (ret == ENOENT) {
       rule_count = 0;
    }

    ret = sysdb_msg2attrs(tmp_ctx, rule_count, msgs, &rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not convert ldb message to sysdb_attrs\n");
        goto done;
    }

    if (_rules) *_rules = talloc_steal(mem_ctx, rules);
    if (_rule_count) *_rule_count = rule_count;

    ret = EOK;
done:
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
        /* Account wasn't locked. Continue below to HBAC processing. */
        break;
    case ERR_ACCESS_DENIED:
        /* Account was locked. Return permission denied here. */
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
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_access_handler_state);

    ret = ipa_fetch_hbac_recv(subreq);
    talloc_free(subreq);

    if (ret == ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No HBAC rules find, denying access\n");
        state->pd->pam_status = PAM_PERM_DENIED;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to fetch HBAC rules [%d]: %s\n",
              ret, sss_strerror(ret));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    ret = ipa_hbac_evaluate_rules(state->be_ctx,
                                  state->access_ctx->ipa_options, state->pd);
    if (ret == EOK) {
        state->pd->pam_status = PAM_SUCCESS;
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
