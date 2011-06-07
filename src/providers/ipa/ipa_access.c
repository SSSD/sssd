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

    return EOK;

not_applicable:
    if (ret == RULE_NOT_APPLICABLE) {
        *result = HBAC_NOT_APPLICABLE;
    } else {
        *result = HBAC_DENY;
    }
    return EOK;
}


    return EOK;
}

static int hbac_retry(struct hbac_ctx *hbac_ctx);
static void hbac_connect_done(struct tevent_req *subreq);
static bool hbac_check_step_result(struct hbac_ctx *hbac_ctx, int ret);

static int hbac_get_host_info_step(struct hbac_ctx *hbac_ctx);

void ipa_access_handler(struct be_req *be_req)
{
    struct pam_data *pd;
    struct hbac_ctx *hbac_ctx;
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
    hbac_ctx->sdap_ctx = ipa_access_ctx->sdap_ctx;
    hbac_ctx->ipa_options = ipa_access_ctx->ipa_options;
    hbac_ctx->tr_ctx = ipa_access_ctx->tr_ctx;
    hbac_ctx->hbac_search_base = get_hbac_search_base(hbac_ctx,
                                                      hbac_ctx->ipa_options);
    if (hbac_ctx->hbac_search_base == NULL) {
        DEBUG(1, ("No HBAC search base found.\n"));
        goto fail;
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

    if (hbac_ctx_is_offline(hbac_ctx)) {
        return hbac_get_host_info_step(hbac_ctx);
    }

    subreq = sdap_id_op_connect_send(hbac_ctx_sdap_id_op(hbac_ctx), hbac_ctx, &ret);
    if (!subreq) {
        DEBUG(1, ("sdap_id_op_connect_send failed: %d(%s).\n", ret, strerror(ret)));
        return ret;
    }

    tevent_req_set_callback(subreq, hbac_connect_done, hbac_ctx);
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

static int hbac_get_host_info_step(struct hbac_ctx *hbac_ctx)
{
    struct pam_data *pd = hbac_ctx->pd;
    const char *hostlist[3];
    struct tevent_req *subreq;

    hostlist[0] = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (hostlist[0] == NULL) {
        DEBUG(1, ("ipa_hostname not available.\n"));
        return EINVAL;
    }
    if (pd->rhost != NULL && *pd->rhost != '\0') {
        hostlist[1] = pd->rhost;
        hostlist[2] = NULL;
    } else {
        hostlist[1] = NULL;
        pd->rhost = discard_const_p(char, hostlist[0]);
    }

    subreq = hbac_get_host_info_send(hbac_ctx, hbac_ctx, hostlist);
    if (!subreq) {
        DEBUG(1, ("hbac_get_host_info_send failed.\n"));
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, hbac_get_host_info_done, hbac_ctx);
    return EOK;
}

static void hbac_get_host_info_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    const char *ipa_hostname;
    struct hbac_host_info *local_hhi = NULL;

    ret = hbac_get_host_info_recv(req, hbac_ctx, &hbac_ctx->hbac_hosts_count,
                                  &hbac_ctx->hbac_hosts_list);
    talloc_zfree(req);

    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    ipa_hostname = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        DEBUG(1, ("Missing ipa_hostname, this should never happen.\n"));
        goto fail;
    }

    ret = set_local_and_remote_host_info(hbac_ctx, hbac_ctx->hbac_hosts_count,
                                         hbac_ctx->hbac_hosts_list, ipa_hostname,
                                         hbac_ctx->pd->rhost, &local_hhi,
                                         &hbac_ctx->remote_hhi);
    if (ret != EOK) {
        DEBUG(1, ("set_local_and_remote_host_info failed.\n"));
        goto fail;
     }

    if (local_hhi == NULL) {
        DEBUG(1, ("Missing host info for [%s].\n", ipa_hostname));
        pam_status = PAM_PERM_DENIED;
        goto fail;
    }
    req = hbac_get_rules_send(hbac_ctx, hbac_ctx, local_hhi->dn,
                              local_hhi->memberof);
    if (req == NULL) {
        DEBUG(1, ("hbac_get_rules_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(req, hbac_get_rules_done, hbac_ctx);
    return;

fail:
    ipa_access_reply(hbac_ctx, pam_status);
}

static void hbac_get_rules_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;

    hbac_ctx->hbac_rule_count = 0;
    talloc_zfree(hbac_ctx->hbac_rule_list);

    ret = hbac_get_rules_recv(req, hbac_ctx, &hbac_ctx->hbac_rule_count,
                              &hbac_ctx->hbac_rule_list);
    talloc_zfree(req);

    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    req = hbac_get_service_data_send(hbac_ctx, hbac_ctx);
    if (req == NULL) {
        DEBUG(1, ("hbac_get_service_data_send failed.\n"));
        goto failed;
    }

    tevent_req_set_callback(req, hbac_get_service_data_done, hbac_ctx);
    return;

failed:
    ipa_access_reply(hbac_ctx, pam_status);
}

static void hbac_get_service_data_done(struct tevent_req *req)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(req, struct hbac_ctx);
    struct pam_data *pd = hbac_ctx->pd;
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    bool access_allowed = false;

    hbac_ctx->hbac_services_count = 0;
    talloc_zfree(hbac_ctx->hbac_services_list);

    ret = hbac_get_service_data_recv(req, hbac_ctx,
                                     &hbac_ctx->hbac_services_count,
                                     &hbac_ctx->hbac_services_list);
    talloc_zfree(req);

    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    if (hbac_ctx->user_dn) {
        talloc_free(discard_const_p(TALLOC_CTX, hbac_ctx->user_dn));
        hbac_ctx->user_dn = 0;
    }

    if (!hbac_ctx_is_offline(hbac_ctx)) {
        ret = hbac_save_data_to_sysdb(hbac_ctx);
        if (ret != EOK) {
            DEBUG(1, ("Failed to save data, "
                      "offline authentication might not work.\n"));
            /* This is not a fatal error. */
        }
    }

    hbac_ctx->groups_count = 0;
    talloc_zfree(hbac_ctx->groups);

    ret = hbac_get_user_info(hbac_ctx, hbac_ctx_be(hbac_ctx),
                             pd->user, &hbac_ctx->user_dn,
                             &hbac_ctx->groups_count, &hbac_ctx->groups);
    if (ret != EOK) {
        goto failed;
    }

    ret = evaluate_ipa_hbac_rules(hbac_ctx, &access_allowed);
    if (ret != EOK) {
        DEBUG(1, ("evaluate_ipa_hbac_rules failed.\n"));
        goto failed;
    }

    if (access_allowed) {
        pam_status = PAM_SUCCESS;
        DEBUG(5, ("Access allowed.\n"));
    } else {
        pam_status = PAM_PERM_DENIED;
        DEBUG(3, ("Access denied.\n"));
    }

failed:
    ipa_access_reply(hbac_ctx, pam_status);
}
