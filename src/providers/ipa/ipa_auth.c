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

#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/ipa/ipa_auth.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_config.h"

struct get_password_migration_flag_state {
    struct tevent_context *ev;
    struct sdap_id_op *sdap_op;
    struct sdap_id_ctx *sdap_id_ctx;
    struct fo_server *srv;
    char *ipa_realm;
    bool password_migration;
};

static void get_password_migration_flag_auth_done(struct tevent_req *subreq);
static void get_password_migration_flag_done(struct tevent_req *subreq);

static struct tevent_req *get_password_migration_flag_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct sdap_id_ctx *sdap_id_ctx,
                                            char *ipa_realm)
{
    int ret;
    struct tevent_req *req, *subreq;
    struct get_password_migration_flag_state *state;

    if (sdap_id_ctx == NULL || ipa_realm == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing parameter.\n");
        return NULL;
    }

    req = tevent_req_create(memctx, &state,
                            struct get_password_migration_flag_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->sdap_id_ctx = sdap_id_ctx;
    state->srv = NULL;
    state->password_migration = false;
    state->ipa_realm = ipa_realm;

    state->sdap_op = sdap_id_op_create(state,
                                       state->sdap_id_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        goto fail;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (!subreq) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
        goto fail;
    }

    tevent_req_set_callback(subreq, get_password_migration_flag_auth_done, req);

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
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No IPA server is available, cannot get the "
                   "migration flag while offline\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to IPA server: [%d](%s)\n",
                   ret, strerror(ret));
        }

        tevent_req_error(req, ret);
        return;
    }

    subreq = ipa_get_config_send(state, state->ev,
                                 sdap_id_op_handle(state->sdap_op),
                                 state->sdap_id_ctx->opts, state->ipa_realm,
                                 NULL, NULL, NULL);

    tevent_req_set_callback(subreq, get_password_migration_flag_done, req);
}

static void get_password_migration_flag_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_password_migration_flag_state *state = tevent_req_data(req,
                                      struct get_password_migration_flag_state);
    int ret;
    struct sysdb_attrs *reply = NULL;
    const char *value = NULL;

    ret = ipa_get_config_recv(subreq, state, &reply);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(SSSDBG_IMPORTANT_INFO, "Unable to retrieve migration flag "
                                     "from IPA server");
        goto done;
    }

    ret = sysdb_attrs_get_string(reply, IPA_CONFIG_MIGRATION_ENABLED, &value);
    if (ret == EOK && strcasecmp(value, "true") == 0) {
        state->password_migration = true;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

static int get_password_migration_flag_recv(struct tevent_req *req,
                                            bool *password_migration)
{
    struct get_password_migration_flag_state *state = tevent_req_data(req,
                                      struct get_password_migration_flag_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *password_migration = state->password_migration;
    return EOK;
}

struct ipa_pam_auth_handler_state {
    struct tevent_context *ev;
    struct ipa_auth_ctx *auth_ctx;
    struct be_ctx *be_ctx;
    struct pam_data *pd;
    struct sss_domain_info *dom;
};

static void ipa_pam_auth_handler_krb5_done(struct tevent_req *subreq);
static void ipa_pam_auth_handler_flag_done(struct tevent_req *subreq);
static void ipa_pam_auth_handler_connect_done(struct tevent_req *subreq);
static void ipa_pam_auth_handler_auth_done(struct tevent_req *subreq);
static void ipa_pam_auth_handler_retry_done(struct tevent_req *subreq);

struct tevent_req *
ipa_pam_auth_handler_send(TALLOC_CTX *mem_ctx,
                          struct ipa_auth_ctx *auth_ctx,
                          struct pam_data *pd,
                          struct dp_req_params *params)
{
    struct ipa_pam_auth_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_pam_auth_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->ev = params->ev;
    state->auth_ctx = auth_ctx;
    state->be_ctx = params->be_ctx;
    state->dom = find_domain_by_name(state->be_ctx->domain,
                                     state->pd->domain,
                                     true);
    if (state->dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown domain %s\n", state->pd->domain);
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    pd->pam_status = PAM_SYSTEM_ERR;

    subreq = krb5_auth_queue_send(state, params->ev, params->be_ctx,
                                  pd, auth_ctx->krb5_auth_ctx);
    if (subreq == NULL) {
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_pam_auth_handler_krb5_done, req);

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void ipa_pam_auth_handler_krb5_done(struct tevent_req *subreq)
{
    struct ipa_pam_auth_handler_state *state;
    struct tevent_req *req;
    int dp_err;
    char *realm;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_auth_handler_state);

    state->pd->pam_status = PAM_SYSTEM_ERR;
    ret = krb5_auth_queue_recv(subreq, &state->pd->pam_status, &dp_err);
    talloc_free(subreq);
    if (ret != EOK && state->pd->pam_status != PAM_CRED_ERR) {
        DEBUG(SSSDBG_OP_FAILURE, "KRB5 auth failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (dp_err != DP_ERR_OK) {
        goto done;
    }
    if (state->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM
        && state->pd->pam_status == PAM_TRY_AGAIN) {
        /* Reset this to fork a new krb5_child in handle_child_send() */
        state->pd->child_pid = 0;
        subreq = krb5_auth_queue_send(state, state->ev, state->be_ctx, state->pd,
                                      state->auth_ctx->krb5_auth_ctx);
        if (subreq == NULL) {
            goto done;
        }

        tevent_req_set_callback(subreq, ipa_pam_auth_handler_retry_done, req);
        return;
    }

    if (state->pd->cmd == SSS_PAM_AUTHENTICATE
            && state->pd->pam_status == PAM_CRED_ERR
            && !IS_SUBDOMAIN(state->dom)) {
        realm = dp_opt_get_string(state->auth_ctx->ipa_options, IPA_KRB5_REALM);
        subreq = get_password_migration_flag_send(state, state->ev,
                                                  state->auth_ctx->sdap_id_ctx,
                                                  realm);
        if (subreq == NULL) {
            goto done;
        }

        tevent_req_set_callback(subreq, ipa_pam_auth_handler_flag_done, req);
        return;
    }

    /* PAM_CRED_ERR is used to indicate to the IPA provider that trying
     * password migration would make sense. From this point on it isn't
     * necessary to keep this status, so it can be translated to PAM_AUTH_ERR.
     */
    if (state->pd->pam_status == PAM_CRED_ERR) {
        state->pd->pam_status = PAM_AUTH_ERR;
    }

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

static void ipa_pam_auth_handler_flag_done(struct tevent_req *subreq)
{
    struct ipa_pam_auth_handler_state *state;
    struct sdap_auth_ctx *sdap_auth_ctx;
    bool password_migration = false;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_auth_handler_state);

    ret = get_password_migration_flag_recv(subreq, &password_migration);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get password migration flag "
              "[%d]: %s\n", ret, sss_strerror(ret));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    if (password_migration) {
        sdap_auth_ctx = state->auth_ctx->sdap_auth_ctx;
        subreq = sdap_cli_connect_send(state, state->ev,
                                       sdap_auth_ctx->opts,
                                       sdap_auth_ctx->be,
                                       sdap_auth_ctx->service,
                                       true, CON_TLS_ON, true);
        if (subreq == NULL) {
            state->pd->pam_status = PAM_SYSTEM_ERR;
            goto done;
        }

        tevent_req_set_callback(subreq, ipa_pam_auth_handler_connect_done, req);
        return;
    }

    /* PAM_CRED_ERR is used to indicate to the IPA provider that trying
     * password migration would make sense. From this point on it isn't
     * necessary to keep this status, so it can be translated to PAM_AUTH_ERR.
     */
    if (state->pd->pam_status == PAM_CRED_ERR) {
        state->pd->pam_status = PAM_AUTH_ERR;
    }

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

static void ipa_pam_auth_handler_connect_done(struct tevent_req *subreq)
{
    struct ipa_pam_auth_handler_state *state;
    struct tevent_req *req;
    struct sdap_handle *sh = NULL;
    const char *attrs[] = {SYSDB_ORIG_DN, NULL};
    struct ldb_message *msg;
    const char *dn;
    int timeout;
    bool use_ppolicy;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_auth_handler_state);

    state->pd->pam_status = PAM_SYSTEM_ERR;

    ret = sdap_cli_connect_recv(subreq, state, NULL, &sh, NULL);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot connect to LDAP server to perform "
              "migration [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Assuming Kerberos password is missing, "
          "starting password migration.\n");

    ret = sysdb_search_user_by_name(state, state->be_ctx->domain,
                                    state->pd->user, attrs, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_name failed.\n");
        goto done;
    }

    dn = ldb_msg_find_attr_as_string(msg, SYSDB_ORIG_DN, NULL);
    if (dn == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Missing original DN for user [%s].\n",
              state->pd->user);
        goto done;
    }

    timeout = dp_opt_get_int(state->auth_ctx->sdap_auth_ctx->opts->basic,
                             SDAP_OPT_TIMEOUT);
    use_ppolicy = dp_opt_get_bool(state->auth_ctx->sdap_auth_ctx->opts->basic,
                                  SDAP_USE_PPOLICY);

    subreq = sdap_auth_send(state, state->ev, sh, NULL, NULL, dn,
                            state->pd->authtok, timeout, use_ppolicy);
    if (subreq == NULL) {
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_pam_auth_handler_auth_done, req);
    return;

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

static void ipa_pam_auth_handler_auth_done(struct tevent_req *subreq)
{
    struct ipa_pam_auth_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_auth_handler_state);

    ret = sdap_auth_recv(subreq, state, NULL);

    talloc_free(subreq);
    switch (ret) {
    case EOK:
        break;
    case ERR_AUTH_DENIED:
    case ERR_AUTH_FAILED:
    case ERR_PASSWORD_EXPIRED:
    /* TODO: do we need to handle expired passwords? */
        DEBUG(SSSDBG_MINOR_FAILURE, "LDAP authentication failed, "
              "password migration not possible.\n");
        state->pd->pam_status = PAM_CRED_INSUFFICIENT;
        goto done;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "auth_send request failed.\n");
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "LDAP authentication succeeded, "
          "trying Kerberos authentication again.\n");

    subreq = krb5_auth_queue_send(state, state->ev, state->be_ctx, state->pd,
                                  state->auth_ctx->krb5_auth_ctx);
    if (subreq == NULL) {
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_pam_auth_handler_retry_done, req);
    return;

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

static void ipa_pam_auth_handler_retry_done(struct tevent_req *subreq)
{
    struct ipa_pam_auth_handler_state *state;
    struct tevent_req *req;
    int dp_err;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_auth_handler_state);

    ret = krb5_auth_queue_recv(subreq, &state->pd->pam_status, &dp_err);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_auth_recv request failed.\n");
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
ipa_pam_auth_handler_recv(TALLOC_CTX *mem_ctx,
                          struct tevent_req *req,
                          struct pam_data **_data)
{
    struct ipa_pam_auth_handler_state *state = NULL;

    state = tevent_req_data(req, struct ipa_pam_auth_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
