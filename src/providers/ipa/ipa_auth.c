/*
    SSSD

    IPA Backend Module -- Authentication

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
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/ipa/ipa_common.h"

#define IPA_CONFIG_MIRATION_ENABLED "ipaMigrationEnabled"
#define IPA_CONFIG_SEARCH_BASE_TEMPLATE "cn=etc,%s"
#define IPA_CONFIG_FILTER "(&(cn=ipaConfig)(objectClass=ipaGuiConfig))"

static void ipa_auth_reply(struct be_req *be_req, int dp_err, int result)
{
    be_req->fn(be_req, dp_err, result, NULL);
}

struct get_password_migration_flag_state {
    struct tevent_context *ev;
    struct sdap_auth_ctx *sdap_auth_ctx;
    struct sdap_handle *sh;
    enum sdap_result result;
    struct fo_server *srv;
    char *ipa_domain;
    bool password_migration;
};

static void get_password_migration_flag_auth_done(struct tevent_req *subreq);
static void get_password_migration_flag_done(struct tevent_req *subreq);

static struct tevent_req *get_password_migration_flag_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct sdap_auth_ctx *sdap_auth_ctx,
                                            char *ipa_domain)
{
    int ret;
    struct tevent_req *req, *subreq;
    struct get_password_migration_flag_state *state;

    if (sdap_auth_ctx == NULL || ipa_domain == NULL) {
        DEBUG(1, ("Missing parameter.\n"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state,
                            struct get_password_migration_flag_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->sdap_auth_ctx = sdap_auth_ctx;
    state->sh = NULL;
    state->result = SDAP_ERROR;
    state->srv = NULL;
    state->password_migration = false;
    state->ipa_domain = ipa_domain;

    /* We request to use StartTLS here, because if password migration is
     * enabled we will use this connection for authentication, too. */
    ret = dp_opt_set_bool(sdap_auth_ctx->opts->basic, SDAP_ID_TLS, true);
    if (ret != EOK) {
        DEBUG(1, ("Failed to set SDAP_ID_TLS to true.\n"));
        goto fail;
    }

    subreq = sdap_cli_connect_send(state, ev, sdap_auth_ctx->opts,
                                   sdap_auth_ctx->be, sdap_auth_ctx->service,
                                   NULL);
    if (subreq == NULL) {
        DEBUG(1, ("sdap_cli_connect_send failed.\n"));
        goto fail;
    }
    tevent_req_set_callback(subreq, get_password_migration_flag_auth_done,
                            req);

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void get_password_migration_flag_auth_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_password_migration_flag_state *state = tevent_req_data(req,
                                      struct get_password_migration_flag_state);
    int ret;
    char *ldap_basedn;
    char *search_base;
    const char **attrs;

    ret = sdap_cli_connect_recv(subreq, state, &state->sh, NULL);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(1, ("sdap_auth request failed.\n"));
        tevent_req_error(req, ret);
        return;
    }

    ret = domain_to_basedn(state, state->ipa_domain, &ldap_basedn);
    if (ret != EOK) {
        DEBUG(1, ("domain_to_basedn failed.\n"));
        tevent_req_error(req, ret);
        return;
    }

    search_base = talloc_asprintf(state, IPA_CONFIG_SEARCH_BASE_TEMPLATE,
                                  ldap_basedn);
    if (search_base == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    attrs = talloc_array(state, const char*, 2);
    if (attrs == NULL) {
        DEBUG(1, ("talloc_array failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    attrs[0] = IPA_CONFIG_MIRATION_ENABLED;
    attrs[1] = NULL;

    subreq = sdap_get_generic_send(state, state->ev, state->sdap_auth_ctx->opts,
                                   state->sh, search_base, LDAP_SCOPE_SUBTREE,
                                   IPA_CONFIG_FILTER, attrs, NULL, 0);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, get_password_migration_flag_done, req);
}

static void get_password_migration_flag_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_password_migration_flag_state *state = tevent_req_data(req,
                                      struct get_password_migration_flag_state);
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    const char *value = NULL;

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (reply_count != 1) {
        DEBUG(1, ("Unexpected number of results, expected 1, got %d.\n",
                  reply_count));
        tevent_req_error(req, EINVAL);
        return;
    }

    ret = sysdb_attrs_get_string(reply[0], IPA_CONFIG_MIRATION_ENABLED, &value);
    if (strcasecmp(value, "true") == 0) {
        state->password_migration = true;
    }

    tevent_req_done(req);
}

static int get_password_migration_flag_recv(struct tevent_req *req,
                                            TALLOC_CTX *mem_ctx,
                                            bool *password_migration,
                                            struct sdap_handle **sh)
{
    struct get_password_migration_flag_state *state = tevent_req_data(req,
                                      struct get_password_migration_flag_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *password_migration = state->password_migration;
    if (sh != NULL) {
        *sh = talloc_steal(mem_ctx, state->sh);
    }

    return EOK;
}


struct ipa_auth_state {
    struct be_req *be_req;
    struct tevent_context *ev;
    struct ipa_auth_ctx *ipa_auth_ctx;
    struct pam_data *pd;
    bool password_migration;
    struct sdap_handle *sh;
};

static void ipa_auth_handler_done(struct tevent_req *req);
static void ipa_get_migration_flag_done(struct tevent_req *req);
static void ipa_auth_ldap_done(struct tevent_req *req);
static void ipa_auth_handler_retry_done(struct tevent_req *req);

void ipa_auth(struct be_req *be_req)
{
    struct tevent_req *req;
    struct ipa_auth_state *state;
    struct pam_data *pd = talloc_get_type(be_req->req_data, struct pam_data);

    state = talloc_zero(be_req, struct ipa_auth_state);
    if (state == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        goto fail;
    }

    state->password_migration = false;
    state->sh = NULL;

    state->be_req = be_req;
    state->ev = be_req->be_ctx->ev;

    state->pd = pd;

    switch (state->pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            state->ipa_auth_ctx = talloc_get_type(
                                be_req->be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                                struct ipa_auth_ctx);
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            state->ipa_auth_ctx = talloc_get_type(
                              be_req->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                              struct ipa_auth_ctx);
            break;
        default:
            DEBUG(1, ("Unsupported PAM task.\n"));
            goto fail;
    }

    req = krb5_auth_send(state, state->ev, be_req->be_ctx, state->pd,
                         state->ipa_auth_ctx->krb5_auth_ctx);
    if (req == NULL) {
        DEBUG(1, ("krb5_auth_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(req, ipa_auth_handler_done, state);
    return;

fail:
    talloc_free(state);
    pd->pam_status = PAM_SYSTEM_ERR;
    ipa_auth_reply(be_req, DP_ERR_FATAL, pd->pam_status);
}

static void ipa_auth_handler_done(struct tevent_req *req)
{
    struct ipa_auth_state *state = tevent_req_callback_data(req,
                                                         struct ipa_auth_state);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err;

    ret = krb5_auth_recv(req, &pam_status, &dp_err);
    talloc_zfree(req);
    state->pd->pam_status = pam_status;
    if (ret != EOK && pam_status != PAM_CRED_ERR) {
        DEBUG(1, ("krb5_auth_recv request failed.\n"));
        dp_err = DP_ERR_OK;
        goto done;
    }

    if (dp_err != DP_ERR_OK) {
        goto done;
    }

    if (state->pd->cmd == SSS_PAM_AUTHENTICATE &&
        state->pd->pam_status == PAM_CRED_ERR) {

        req = get_password_migration_flag_send(state, state->ev,
                                             state->ipa_auth_ctx->sdap_auth_ctx,
                                             dp_opt_get_string(
                                               state->ipa_auth_ctx->ipa_options,
                                               IPA_DOMAIN));
        if (req == NULL) {
            DEBUG(1, ("get_password_migration_flag failed.\n"));
            goto done;
        }

        tevent_req_set_callback(req, ipa_get_migration_flag_done, state);
        return;
    }

done:
    ipa_auth_reply(state->be_req, dp_err, state->pd->pam_status);
}

static void ipa_get_migration_flag_done(struct tevent_req *req)
{
    struct ipa_auth_state *state = tevent_req_callback_data(req,
                                                         struct ipa_auth_state);
    int ret;
    int dp_err = DP_ERR_FATAL;
    const char **attrs;
    struct ldb_message *user_msg;
    const char *dn;
    struct dp_opt_blob password;

    ret = get_password_migration_flag_recv(req, state,
                                           &state->password_migration,
                                           &state->sh);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("get_password_migration_flag request failed.\n"));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        dp_err = DP_ERR_OK;
        goto done;
    }

    if (state->password_migration) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        DEBUG(1, ("Assuming Kerberos password is missing, "
                  "starting password migration.\n"));

        attrs = talloc_array(state, const char *, 2);
        if (attrs == NULL) {
            DEBUG(1, ("talloc_array failed.\n"));
            state->pd->pam_status = PAM_SYSTEM_ERR;
            dp_err = DP_ERR_OK;
            goto done;
        }
        attrs[0] = SYSDB_ORIG_DN;
        attrs[1] = NULL;

        ret = sysdb_search_user_by_name(state, state->be_req->be_ctx->sysdb,
                                        state->be_req->be_ctx->domain,
                                        state->pd->user, attrs, &user_msg);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_search_user_by_name failed.\n"));
            goto done;
        }

        dn = ldb_msg_find_attr_as_string(user_msg, SYSDB_ORIG_DN, NULL);
        if (dn == NULL) {
            DEBUG(1, ("Missing original DN for user [%s].\n", state->pd->user));
            state->pd->pam_status = PAM_SYSTEM_ERR;
            dp_err = DP_ERR_OK;
            goto done;
        }

        password.data = state->pd->authtok;
        password.length = state->pd->authtok_size;

        req = sdap_auth_send(state, state->ev, state->sh, NULL, NULL, dn,
                             "password", password);
        if (req == NULL) {
            DEBUG(1, ("sdap_auth_send failed.\n"));
            goto done;
        }

        tevent_req_set_callback(req, ipa_auth_ldap_done, state);
        return;

    } else {
        DEBUG(5, ("Password migration is not enabled.\n"));
    }

    dp_err = DP_ERR_OK;

done:
    ipa_auth_reply(state->be_req, dp_err, state->pd->pam_status);
}

static void ipa_auth_ldap_done(struct tevent_req *req)
{
    struct ipa_auth_state *state = tevent_req_callback_data(req,
                                                         struct ipa_auth_state);
    int ret;
    int dp_err = DP_ERR_FATAL;
    enum sdap_result result;

    ret = sdap_auth_recv(req, state, &result, NULL);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("auth_send request failed.\n"));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        dp_err = DP_ERR_OK;
        goto done;
    }

/* TODO: do we need to handle expired passwords? */
    if (result != SDAP_AUTH_SUCCESS) {
        DEBUG(1, ("LDAP authentication failed, "
                  "Password migration not possible.\n"));
        state->pd->pam_status = PAM_CRED_INSUFFICIENT;
        dp_err = DP_ERR_OK;
        goto done;
    }

    DEBUG(1, ("LDAP authentication succeded, "
              "trying Kerberos authentication again.\n"));

    req = krb5_auth_send(state, state->ev,
                         state->be_req->be_ctx, state->pd,
                         state->ipa_auth_ctx->krb5_auth_ctx);
    if (req == NULL) {
        DEBUG(1, ("krb5_auth_send failed.\n"));
        goto done;
    }

    tevent_req_set_callback(req, ipa_auth_handler_retry_done, state);
    return;

done:
    ipa_auth_reply(state->be_req, dp_err, state->pd->pam_status);
}

static void ipa_auth_handler_retry_done(struct tevent_req *req)
{
    struct ipa_auth_state *state = tevent_req_callback_data(req,
                                                         struct ipa_auth_state);
    int ret;
    int pam_status;
    int dp_err;

    ret = krb5_auth_recv(req, &pam_status, &dp_err);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("krb5_auth_recv request failed.\n"));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        dp_err = DP_ERR_OK;
        goto done;
    }

    state->pd->pam_status = pam_status;

done:
    ipa_auth_reply(state->be_req, dp_err, state->pd->pam_status);
}
