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

#include <sys/param.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_hbac.h"
#include "providers/ipa/ipa_hbac_private.h"

static char *get_hbac_search_base(TALLOC_CTX *mem_ctx,
                                  struct dp_option *ipa_options)
{
    char *base;
    int ret;

    base = dp_opt_get_string(ipa_options, IPA_HBAC_SEARCH_BASE);
    if (base != NULL) {
        return talloc_strdup(mem_ctx, base);
    }

    DEBUG(9, ("ipa_hbac_search_base not available, trying base DN.\n"));

    ret = domain_to_basedn(mem_ctx,
                           dp_opt_get_string(ipa_options, IPA_KRB5_REALM),
                           &base);
    if (ret != EOK) {
        DEBUG(1, ("domain_to_basedn failed.\n"));
        return NULL;
    }

    return base;
}

static void ipa_access_reply(struct hbac_ctx *hbac_ctx, int pam_status)
{
    struct be_req *be_req = hbac_ctx->be_req;
    struct pam_data *pd;
    pd = talloc_get_type(be_req->req_data, struct pam_data);
    pd->pam_status = pam_status;

    /* destroy HBAC context now to release all used resources and LDAP connection */
    talloc_zfree(hbac_ctx);

    if (pam_status == PAM_SUCCESS || pam_status == PAM_PERM_DENIED) {
        be_req->fn(be_req, DP_ERR_OK, pam_status, NULL);
    } else {
        be_req->fn(be_req, DP_ERR_FATAL, pam_status, NULL);
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

static int hbac_retry(struct hbac_ctx *hbac_ctx);
static void hbac_connect_done(struct tevent_req *subreq);
static bool hbac_check_step_result(struct hbac_ctx *hbac_ctx, int ret);

static int hbac_get_host_info_step(struct hbac_ctx *hbac_ctx);

static void ipa_hbac_evaluate_rules(struct hbac_ctx *hbac_ctx);

void ipa_access_handler(struct be_req *be_req)
{
    struct pam_data *pd;
    struct hbac_ctx *hbac_ctx;
    const char *deny_method;
    int pam_status = PAM_SYSTEM_ERR;
    struct ipa_access_ctx *ipa_access_ctx;
    int ret;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    hbac_ctx = talloc_zero(be_req, struct hbac_ctx);
    if (hbac_ctx == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        goto fail;
    }

    hbac_ctx->be_req = be_req;
    hbac_ctx->pd = pd;
    ipa_access_ctx = talloc_get_type(
                              be_req->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                              struct ipa_access_ctx);
    hbac_ctx->access_ctx = ipa_access_ctx;
    hbac_ctx->sdap_ctx = ipa_access_ctx->sdap_ctx;
    hbac_ctx->ipa_options = ipa_access_ctx->ipa_options;
    hbac_ctx->tr_ctx = ipa_access_ctx->tr_ctx;
    hbac_ctx->hbac_search_base = get_hbac_search_base(hbac_ctx,
                                                      hbac_ctx->ipa_options);
    if (hbac_ctx->hbac_search_base == NULL) {
        DEBUG(1, ("No HBAC search base found.\n"));
        goto fail;
    }

    deny_method = dp_opt_get_string(hbac_ctx->ipa_options,
                                    IPA_HBAC_DENY_METHOD);
    if (strcasecmp(deny_method, "IGNORE") == 0) {
        hbac_ctx->get_deny_rules = false;
    } else {
        hbac_ctx->get_deny_rules = true;
    }

    ret = hbac_retry(hbac_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    if (hbac_ctx) {
        /* Return an proper error */
        ipa_access_reply(hbac_ctx, pam_status);
    } else {
        be_req->fn(be_req, DP_ERR_FATAL, pam_status, NULL);
    }
}

static int hbac_retry(struct hbac_ctx *hbac_ctx)
{
    struct tevent_req *subreq;
    int ret;
    bool offline;
    time_t now, refresh_interval;
    struct ipa_access_ctx *access_ctx = hbac_ctx->access_ctx;

    offline = be_is_offline(hbac_ctx->be_req->be_ctx);
    DEBUG(9, ("Connection status is [%s].\n", offline ? "offline" : "online"));

    refresh_interval = dp_opt_get_int(hbac_ctx->ipa_options,
                                      IPA_HBAC_REFRESH);

    now = time(NULL);
    if (now < access_ctx->last_update + refresh_interval) {
        /* Simulate offline mode and just go to the cache */
        DEBUG(6, ("Performing cached HBAC evaluation\n"));
        offline = true;
    }

    if (!offline) {
        if (hbac_ctx->sdap_op == NULL) {
            hbac_ctx->sdap_op = sdap_id_op_create(hbac_ctx,
                                        hbac_ctx_sdap_id_ctx(hbac_ctx)->conn_cache);
            if (hbac_ctx->sdap_op == NULL) {
                DEBUG(1, ("sdap_id_op_create failed.\n"));
                return EIO;
            }
        }

        subreq = sdap_id_op_connect_send(hbac_ctx_sdap_id_op(hbac_ctx), hbac_ctx, &ret);
        if (!subreq) {
            DEBUG(1, ("sdap_id_op_connect_send failed: %d(%s).\n", ret, strerror(ret)));
            talloc_zfree(hbac_ctx->sdap_op);
            return ret;
        }

        tevent_req_set_callback(subreq, hbac_connect_done, hbac_ctx);
    } else {
        /* Evaluate the rules based on what we have in the
         * sysdb
         */
        ipa_hbac_evaluate_rules(hbac_ctx);
        return EOK;
    }
    return EOK;
}

static void hbac_connect_done(struct tevent_req *subreq)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(subreq, struct hbac_ctx);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        /* switching to offline mode */
        talloc_zfree(hbac_ctx->sdap_op);

        ipa_hbac_evaluate_rules(hbac_ctx);
        return;
    } else if (ret != EOK) {
        goto fail;
    }

    ret = hbac_get_host_info_step(hbac_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

static void hbac_clear_rule_data(struct hbac_ctx *hbac_ctx)
{
    hbac_ctx->host_count = 0;
    talloc_zfree(hbac_ctx->hosts);

    hbac_ctx->hostgroup_count = 0;
    talloc_zfree(hbac_ctx->hostgroups);

    hbac_ctx->service_count = 0;
    talloc_zfree(hbac_ctx->services);

    hbac_ctx->servicegroup_count = 0;
    talloc_zfree(hbac_ctx->servicegroups);

    hbac_ctx->rule_count = 0;
    talloc_zfree(hbac_ctx->rules);
}

/* Check the step result code and continue, retry, get offline result or abort accordingly */
static bool hbac_check_step_result(struct hbac_ctx *hbac_ctx, int ret)
{
    int dp_error;

    if (ret == EOK) {
        return true;
    }

    if (hbac_ctx_is_offline(hbac_ctx)) {
        /* already offline => the error is fatal */
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return false;
    }

    ret = sdap_id_op_done(hbac_ctx_sdap_id_op(hbac_ctx), ret, &dp_error);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            /* switching to offline mode */
            talloc_zfree(hbac_ctx->sdap_op);

            /* Free any of the results we've gotten */
            hbac_clear_rule_data(hbac_ctx);

            dp_error = DP_ERR_OK;
        }

        if (dp_error == DP_ERR_OK) {
            /* retry */
            ret = hbac_retry(hbac_ctx);
            if (ret == EOK) {
                return false;
            }
        }
    }

    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
    return false;
}

static void hbac_get_service_info_step(struct tevent_req *req);
static void hbac_get_rule_info_step(struct tevent_req *req);
static void hbac_sysdb_save (struct tevent_req *req);

static int hbac_get_host_info_step(struct hbac_ctx *hbac_ctx)
{
    struct tevent_req *req =
            ipa_hbac_host_info_send(hbac_ctx,
                                    hbac_ctx_ev(hbac_ctx),
                                    hbac_ctx_sysdb(hbac_ctx),
                                    hbac_ctx_be(hbac_ctx)->domain,
                                    sdap_id_op_handle(hbac_ctx->sdap_op),
                                    hbac_ctx_sdap_id_ctx(hbac_ctx)->opts,
                                    hbac_ctx->hbac_search_base);
    if (req == NULL) {
        DEBUG(1, ("Could not get host info\n"));
        return ENOMEM;
    }
    tevent_req_set_callback(req, hbac_get_service_info_step, hbac_ctx);

    return EOK;
}

static void hbac_get_service_info_step(struct tevent_req *req)
{
    errno_t ret;
    struct hbac_ctx *hbac_ctx =
            tevent_req_callback_data(req, struct hbac_ctx);

    ret = ipa_hbac_host_info_recv(req, hbac_ctx,
                                  &hbac_ctx->host_count,
                                  &hbac_ctx->hosts,
                                  &hbac_ctx->hostgroup_count,
                                  &hbac_ctx->hostgroups);
    talloc_zfree(req);
    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    /* Get services and service groups */
    req = ipa_hbac_service_info_send(hbac_ctx,
                                    hbac_ctx_ev(hbac_ctx),
                                    hbac_ctx_sysdb(hbac_ctx),
                                    hbac_ctx_be(hbac_ctx)->domain,
                                    sdap_id_op_handle(hbac_ctx->sdap_op),
                                    hbac_ctx_sdap_id_ctx(hbac_ctx)->opts,
                                    hbac_ctx->hbac_search_base);
    if (req == NULL) {
        DEBUG(1,("Could not get service info\n"));
        goto fail;
    }
    tevent_req_set_callback(req, hbac_get_rule_info_step, hbac_ctx);
    return;

fail:
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

static void hbac_get_rule_info_step(struct tevent_req *req)
{
    errno_t ret;
    size_t i;
    const char *ipa_hostname;
    const char *hostname;
    struct hbac_ctx *hbac_ctx =
            tevent_req_callback_data(req, struct hbac_ctx);

    ret = ipa_hbac_service_info_recv(req, hbac_ctx,
                                     &hbac_ctx->service_count,
                                     &hbac_ctx->services,
                                     &hbac_ctx->servicegroup_count,
                                     &hbac_ctx->servicegroups);
    talloc_zfree(req);
    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    /* Get the ipa_host attrs */
    hbac_ctx->ipa_host = NULL;
    ipa_hostname = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        DEBUG(1, ("Missing ipa_hostname, this should never happen.\n"));
        goto fail;
    }

    for (i = 0; i < hbac_ctx->host_count; i++) {
        ret = sysdb_attrs_get_string(hbac_ctx->hosts[i],
                                     IPA_HOST_FQDN,
                                     &hostname);
        if (ret != EOK) {
            DEBUG(1, ("Could not locate IPA host\n"));
            goto fail;
        }

        if (strcasecmp(hostname, ipa_hostname) == 0) {
            hbac_ctx->ipa_host = hbac_ctx->hosts[i];
            break;
        }
    }
    if (hbac_ctx->ipa_host == NULL) {
        DEBUG(1, ("Could not locate IPA host\n"));
        goto fail;
    }


    /* Get the list of applicable rules */
    req = ipa_hbac_rule_info_send(hbac_ctx,
                                  hbac_ctx->get_deny_rules,
                                  hbac_ctx_ev(hbac_ctx),
                                  hbac_ctx_sysdb(hbac_ctx),
                                  hbac_ctx_be(hbac_ctx)->domain,
                                  sdap_id_op_handle(hbac_ctx->sdap_op),
                                  hbac_ctx_sdap_id_ctx(hbac_ctx)->opts,
                                  hbac_ctx->hbac_search_base,
                                  hbac_ctx->ipa_host);
    if (req == NULL) {
        DEBUG(1, ("Could not get rules\n"));
        goto fail;
    }

    tevent_req_set_callback(req, hbac_sysdb_save, hbac_ctx);
    return;

fail:
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

static void hbac_sysdb_save(struct tevent_req *req)
{
    errno_t ret;
    bool in_transaction = false;
    struct hbac_ctx *hbac_ctx =
            tevent_req_callback_data(req, struct hbac_ctx);
    struct sss_domain_info *domain = hbac_ctx_be(hbac_ctx)->domain;
    struct sysdb_ctx *sysdb = hbac_ctx_sysdb(hbac_ctx);
    struct ldb_dn *base_dn;
    struct be_ctx *be_ctx = hbac_ctx_be(hbac_ctx);
    struct ipa_access_ctx *access_ctx =
            talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                            struct ipa_access_ctx);
    TALLOC_CTX *tmp_ctx;

    ret = ipa_hbac_rule_info_recv(req, hbac_ctx,
                                  &hbac_ctx->rule_count,
                                  &hbac_ctx->rules);
    talloc_zfree(req);
    if (ret == ENOENT) {
        /* No rules were found that apply to this
         * host.
         */

        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
            return;
        }
        /* Delete any rules in the sysdb so offline logins
         * are also denied.
         */
        base_dn = sysdb_custom_subtree_dn(sysdb, tmp_ctx,
                                          domain->name,
                                          HBAC_RULES_SUBDIR);
        if (base_dn == NULL) {
            talloc_free(tmp_ctx);
            ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
            return;
        }

        ret = sysdb_delete_recursive(tmp_ctx, sysdb, base_dn, true);
        talloc_free(tmp_ctx);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_delete_recursive failed.\n"));
            ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
            return;
        }

        /* If no rules are found, we default to DENY */
        ipa_access_reply(hbac_ctx, PAM_PERM_DENIED);
        return;
    }

    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Could not start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    /* Save the hosts */
    ret = ipa_hbac_sysdb_save(sysdb, domain,
                              HBAC_HOSTS_SUBDIR, IPA_HOST_FQDN,
                              hbac_ctx->host_count, hbac_ctx->hosts,
                              HBAC_HOSTGROUPS_SUBDIR, IPA_CN,
                              hbac_ctx->hostgroup_count,
                              hbac_ctx->hostgroups);
    if (ret != EOK) {
        DEBUG(1, ("Error saving hosts: [%d][%s]\n",
                  ret, strerror(ret)));
        goto fail;
    }

    /* Save the services */
    ret = ipa_hbac_sysdb_save(sysdb, domain,
                              HBAC_SERVICES_SUBDIR, IPA_CN,
                              hbac_ctx->service_count, hbac_ctx->services,
                              HBAC_SERVICEGROUPS_SUBDIR, IPA_CN,
                              hbac_ctx->servicegroup_count,
                              hbac_ctx->servicegroups);
    if (ret != EOK) {
        DEBUG(1, ("Error saving services:  [%d][%s]\n",
                  ret, strerror(ret)));
        goto fail;
    }
    /* Save the rules */
    ret = ipa_hbac_sysdb_save(sysdb, domain,
                              HBAC_RULES_SUBDIR, IPA_UNIQUE_ID,
                              hbac_ctx->rule_count,
                              hbac_ctx->rules,
                              NULL, NULL, 0, NULL);
    if (ret != EOK) {
        DEBUG(1, ("Error saving rules:  [%d][%s]\n",
                  ret, strerror(ret)));
        goto fail;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Failed to commit transaction\n"));
        goto fail;
    }

    /* We don't need the rule data any longer,
     * the rest of the processing relies on
     * sysdb lookups.
     */
    hbac_clear_rule_data(hbac_ctx);


    access_ctx->last_update = time(NULL);

    /* Now evaluate the request against the rules */
    ipa_hbac_evaluate_rules(hbac_ctx);

    return;

fail:
    if (in_transaction) {
        ret = sysdb_transaction_cancel(sysdb);
        if (ret != EOK) {
            DEBUG(0, ("Could not cancel transaction\n"));
        }
    }
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

static errno_t hbac_get_cached_rules(TALLOC_CTX *mem_ctx,
                                     struct hbac_ctx *hbac_ctx);

void ipa_hbac_evaluate_rules(struct hbac_ctx *hbac_ctx)
{
    errno_t ret;
    struct hbac_rule **hbac_rules;
    struct hbac_eval_req *eval_req;
    enum hbac_eval_result result;
    struct hbac_info *info;

    /* Get HBAC rules from the sysdb */
    ret = hbac_get_cached_rules(hbac_ctx, hbac_ctx);
    if (ret != EOK) {
        DEBUG(1, ("Could not retrieve rules from the cache\n"));
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
    }

    ret = hbac_ctx_to_rules(hbac_ctx, hbac_ctx,
                            &hbac_rules, &eval_req);
    if (ret == EPERM) {
        DEBUG(1, ("DENY rules detected. Denying access to all users\n"));
        ipa_access_reply(hbac_ctx, PAM_PERM_DENIED);
        return;
    } else if (ret != EOK) {
        DEBUG(1, ("Could not construct HBAC rules\n"));
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return;
    }

    result = hbac_evaluate(hbac_rules, eval_req, &info);
    if (result == HBAC_EVAL_ALLOW) {
        DEBUG(3, ("Access granted by HBAC rule [%s]\n",
                  info->rule_name));
        hbac_free_info(info);
        ipa_access_reply(hbac_ctx, PAM_SUCCESS);
        return;
    } else if (result == HBAC_EVAL_ERROR) {
        DEBUG(1, ("Error [%s] occurred in rule [%s]\n",
                  hbac_error_string(info->code),
                  info->rule_name));
        hbac_free_info(info);
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return;
    } else if (result == HBAC_EVAL_OOM) {
        DEBUG(1, ("Insufficient memory\n"));
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return;
    }

    DEBUG(3, ("Access denied by HBAC rules\n"));
    hbac_free_info(info);
    ipa_access_reply(hbac_ctx, PAM_PERM_DENIED);
}

static errno_t hbac_get_cached_rules(TALLOC_CTX *mem_ctx,
                                     struct hbac_ctx *hbac_ctx)
{
    errno_t ret;
    struct sysdb_ctx *sysdb = hbac_ctx_sysdb(hbac_ctx);
    struct sss_domain_info *domain = hbac_ctx_be(hbac_ctx)->domain;
    size_t count;
    struct ldb_message **msgs;
    TALLOC_CTX *tmp_ctx;
    char *filter;
    const char *attrs[] = { OBJECTCLASS,
                            IPA_CN,
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

    tmp_ctx = talloc_new(hbac_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    filter = talloc_asprintf(tmp_ctx, "(objectClass=%s)", IPA_HBAC_RULE);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(mem_ctx, sysdb, domain, filter,
                              HBAC_RULES_SUBDIR, attrs,
                              &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(1, ("Error looking up HBAC rules"));
        goto done;
    } if (ret == ENOENT) {
       count = 0;
    }

    ret = msgs2attrs_array(mem_ctx, count, msgs, &hbac_ctx->rules);
    if (ret != EOK) {
        DEBUG(1, ("Could not convert ldb message to sysdb_attrs\n"));
        goto done;
    }
    hbac_ctx->rule_count = count;

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}
