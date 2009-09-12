/*
    SSSD

    LDAP Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2008 Red Hat

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

#ifdef WITH_MOZLDAP
#define LDAP_OPT_SUCCESS LDAP_SUCCESS
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID  ((ber_tag_t) 0x80U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_OLD ((ber_tag_t) 0x81U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW ((ber_tag_t) 0x82U)
#endif

#include <errno.h>
#include <sys/time.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/dp_backend.h"
#include "providers/ldap/sdap_async.h"

struct sdap_auth_ctx {
    struct be_ctx *be;
    struct sdap_options *opts;
};

/* ==Get-User-DN========================================================== */

struct get_user_dn_state {
    struct tevent_context *ev;
    struct sdap_auth_ctx *ctx;
    struct sdap_handle *sh;

    const char **attrs;
    const char *name;

    char *dn;
};

static void get_user_dn_done(void *pvt, int err, struct ldb_result *res);

struct tevent_req *get_user_dn_send(TALLOC_CTX *memctx,
                                    struct tevent_context *ev,
                                    struct sdap_auth_ctx *ctx,
                                    struct sdap_handle *sh,
                                    const char *username)
{
    struct tevent_req *req;
    struct get_user_dn_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct get_user_dn_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sh = sh;
    state->name = username;

    state->attrs = talloc_array(state, const char *, 2);
    if (!state->attrs) {
        talloc_zfree(req);
        return NULL;
    }
    state->attrs[0] = SYSDB_ORIG_DN;
    state->attrs[1] = NULL;

    /* this sysdb call uses a sysdn operation, which means it will be
     * schedule only after we return, no timer hack needed */
    ret = sysdb_get_user_attr(state, state->ctx->be->sysdb,
                              state->ctx->be->domain, state->name,
                              state->attrs, get_user_dn_done, req);
    if (ret) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void get_user_dn_done(void *pvt, int err, struct ldb_result *res)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct get_user_dn_state *state = tevent_req_data(req,
                                           struct get_user_dn_state);
    const char *dn;

    if (err != LDB_SUCCESS) {
        tevent_req_error(req, EIO);
        return;
    }

    switch (res->count) {
    case 0:
        /* FIXME: not in cache, needs a true search */
        tevent_req_error(req, ENOENT);
        break;

    case 1:
        dn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_ORIG_DN, NULL);
        if (!dn) {
            /* TODO: try to search ldap server ? */

            /* FIXME: remove once we store originalDN on every call
             * NOTE: this is wrong, works only with some DITs */
            dn = talloc_asprintf(state, "%s=%s,%s",
                        state->ctx->opts->user_map[SDAP_AT_USER_NAME].name,
                        state->name,
                        state->ctx->opts->basic[SDAP_USER_SEARCH_BASE].value);
            if (!dn) {
                tevent_req_error(req, ENOMEM);
                break;
            }
        }
        state->dn = talloc_strdup(state, dn);
        if (!state->dn) {
            tevent_req_error(req, ENOMEM);
            break;
        }

        tevent_req_done(req);
        break;

    default:
        DEBUG(1, ("A user search by name (%s) returned > 1 results!\n",
                  state->name));
        tevent_req_error(req, EFAULT);
        break;
    }
}

static int get_user_dn_recv(struct tevent_req *req,
                            TALLOC_CTX *memctx, char **dn)
{
    struct get_user_dn_state *state = tevent_req_data(req,
                                           struct get_user_dn_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    *dn = talloc_steal(memctx, state->dn);
    if (!*dn) return ENOMEM;

    return EOK;
}

/* ==Authenticate-User==================================================== */

struct auth_state {
    struct tevent_context *ev;
    struct sdap_auth_ctx *ctx;
    const char *username;
    const char *password;

    struct sdap_handle *sh;

    enum sdap_result result;
    char *dn;
};

static void auth_connect_done(struct tevent_req *subreq);
static void auth_get_user_dn_done(struct tevent_req *subreq);
static void auth_bind_user_done(struct tevent_req *subreq);

struct tevent_req *auth_send(TALLOC_CTX *memctx,
                             struct tevent_context *ev,
                             struct sdap_auth_ctx *ctx,
                             const char *username,
                             const char *password)
{
    struct tevent_req *req, *subreq;
    struct auth_state *state;

    req = tevent_req_create(memctx, &state, struct auth_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->username = username;
    state->password = password;

    subreq = sdap_connect_send(state, ev, ctx->opts, true);
    if (!subreq) goto fail;

    tevent_req_set_callback(subreq, auth_connect_done, req);

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void auth_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;

    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = get_user_dn_send(state, state->ev,
                              state->ctx, state->sh,
                              state->username);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, auth_get_user_dn_done, req);
}

static void auth_get_user_dn_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;

    ret = get_user_dn_recv(subreq, state, &state->dn);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_auth_send(state, state->ev, state->sh,
                            state->dn, "password", state->password);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, auth_bind_user_done, req);
}

static void auth_bind_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;

    ret = sdap_auth_recv(subreq, &state->result);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int auth_recv(struct tevent_req *req, enum sdap_result *result,
                     TALLOC_CTX *memctx, struct sdap_handle **sh, char **dn)
{
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err == ETIMEDOUT) *result = SDAP_UNAVAIL;
        else *result = SDAP_ERROR;
        return EOK;
    }

    if (sh != NULL) {
        *sh = talloc_steal(memctx, state->sh);
        if (*sh == NULL) return ENOMEM;
    }

    if (dn != NULL) {
        *dn = talloc_steal(memctx, state->dn);
        if (*dn == NULL) return ENOMEM;
    }

    *result = state->result;
    return EOK;
}

/* ==Perform-Password-Change===================== */

struct sdap_pam_chpass_state {
    struct be_req *breq;
    struct pam_data *pd;
    const char *username;
    char *dn;
    char *password;
    char *new_password;
    struct sdap_handle *sh;
};

static void sdap_auth4chpass_done(struct tevent_req *req);
static void sdap_pam_chpass_done(struct tevent_req *req);
static void sdap_pam_auth_reply(struct be_req *breq, int result);

static void sdap_pam_chpass_send(struct be_req *breq)
{
    struct sdap_pam_chpass_state *state;
    struct sdap_auth_ctx *ctx;
    struct tevent_req *subreq;
    struct pam_data *pd;

    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                          struct sdap_auth_ctx);
    pd = talloc_get_type(breq->req_data, struct pam_data);

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }

    DEBUG(2, ("starting password change request for user [%s].\n", pd->user));

    pd->pam_status = PAM_SYSTEM_ERR;

    if (pd->cmd != SSS_PAM_CHAUTHTOK) {
        DEBUG(2, ("chpass target was called by wrong pam command.\n"));
        goto done;
    }

    state = talloc_zero(breq, struct sdap_pam_chpass_state);
    if (!state) goto done;

    state->breq = breq;
    state->pd = pd;
    state->username = pd->user;
    state->password = talloc_strndup(state,
                                     (char *)pd->authtok, pd->authtok_size);
    if (!state->password) goto done;
    talloc_set_destructor((TALLOC_CTX *)state->password,
                          password_destructor);
    state->new_password = talloc_strndup(state,
                                         (char *)pd->newauthtok,
                                         pd->newauthtok_size);
    if (!state->new_password) goto done;
    talloc_set_destructor((TALLOC_CTX *)state->new_password,
                          password_destructor);

    subreq = auth_send(breq, breq->be_ctx->ev,
                       ctx, state->username, state->password);
    if (!subreq) goto done;

    tevent_req_set_callback(subreq, sdap_auth4chpass_done, state);
    return;
done:
    sdap_pam_auth_reply(breq, pd->pam_status);
}

static void sdap_auth4chpass_done(struct tevent_req *req)
{
    struct sdap_pam_chpass_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_chpass_state);
    struct tevent_req *subreq;
    enum sdap_result result;
    int ret;

    ret = auth_recv(req, &result, state, &state->sh, &state->dn);
    talloc_zfree(req);
    if (ret) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }


    switch (result) {
    case SDAP_AUTH_SUCCESS:
        DEBUG(7, ("user [%s] successfully authenticated.\n", state->dn));
        subreq = sdap_exop_modify_passwd_send(state,
                                              state->breq->be_ctx->ev,
                                              state->sh,
                                              state->dn,
                                              state->password,
                                              state->new_password);

        if (!subreq) {
            DEBUG(2, ("Failed to change password for %s\n", state->username));
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_pam_chpass_done, state);
        return;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }

done:
    sdap_pam_auth_reply(state->breq, state->pd->pam_status);
}

static void sdap_pam_chpass_done(struct tevent_req *req)
{
    struct sdap_pam_chpass_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_chpass_state);
    enum sdap_result result;
    int ret;

    ret = sdap_exop_modify_passwd_recv(req, &result);
    talloc_zfree(req);
    if (ret) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    switch (result) {
    case SDAP_SUCCESS:
        state->pd->pam_status = PAM_SUCCESS;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }

done:
    sdap_pam_auth_reply(state->breq, state->pd->pam_status);
}
/* ==Perform-User-Authentication-and-Password-Caching===================== */

struct sdap_pam_auth_state {
    struct be_req *breq;
    struct pam_data *pd;
    const char *username;
    char *password;
};

static void sdap_pam_auth_done(struct tevent_req *req);
static void sdap_password_cache_done(struct tevent_req *req);
static void sdap_pam_auth_reply(struct be_req *breq, int result);

/* FIXME: convert caller to tevent_req too ?*/
static void sdap_pam_auth_send(struct be_req *breq)
{
    struct sdap_pam_auth_state *state;
    struct sdap_auth_ctx *ctx;
    struct tevent_req *subreq;
    struct pam_data *pd;

    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_AUTH].pvt_bet_data, struct sdap_auth_ctx);
    pd = talloc_get_type(breq->req_data, struct pam_data);

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }

    pd->pam_status = PAM_SYSTEM_ERR;

    switch (pd->cmd) {
    case SSS_PAM_AUTHENTICATE:

        state = talloc_zero(breq, struct sdap_pam_auth_state);
        if (!state) goto done;

        state->breq = breq;
        state->pd = pd;
        state->username = pd->user;
        state->password = talloc_strndup(state,
                                         (char *)pd->authtok, pd->authtok_size);
        if (!state->password) goto done;
        talloc_set_destructor((TALLOC_CTX *)state->password,
                              password_destructor);

        subreq = auth_send(breq, breq->be_ctx->ev,
                                ctx, state->username, state->password);
        if (!subreq) goto done;

        tevent_req_set_callback(subreq, sdap_pam_auth_done, state);
        return;

/* FIXME: handle other cases */
    case SSS_PAM_CHAUTHTOK:
        break;

    default:
        pd->pam_status = PAM_SUCCESS;
    }

done:
    sdap_pam_auth_reply(breq, pd->pam_status);
}

static void sdap_pam_auth_done(struct tevent_req *req)
{
    struct sdap_pam_auth_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_auth_state);
    struct tevent_req *subreq;
    enum sdap_result result;
    int ret;

    ret = auth_recv(req, &result, NULL, NULL, NULL);
    talloc_zfree(req);
    if (ret) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    switch (result) {
    case SDAP_AUTH_SUCCESS:
        state->pd->pam_status = PAM_SUCCESS;
        break;
    case SDAP_AUTH_FAILED:
        state->pd->pam_status = PAM_CRED_INSUFFICIENT;
        break;
    case SDAP_UNAVAIL:
        state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }

    if (result == SDAP_UNAVAIL) {
        be_mark_offline(state->breq->be_ctx);
        goto done;
    }

    if (result == SDAP_AUTH_SUCCESS &&
        state->breq->be_ctx->domain->cache_credentials) {

        subreq = sysdb_cache_password_send(state,
                                           state->breq->be_ctx->ev,
                                           state->breq->be_ctx->sysdb,
                                           NULL,
                                           state->breq->be_ctx->domain,
                                           state->username, state->password);

        /* password caching failures are not fatal errors */
        if (!subreq) {
            DEBUG(2, ("Failed to cache password for %s\n", state->username));
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_password_cache_done, state);
        return;
    }

done:
    sdap_pam_auth_reply(state->breq, state->pd->pam_status);
}

static void sdap_password_cache_done(struct tevent_req *subreq)
{
    struct sdap_pam_auth_state *state = tevent_req_callback_data(subreq,
                                                struct sdap_pam_auth_state);
    int ret;

    ret = sysdb_cache_password_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        /* password caching failures are not fatal errors */
        DEBUG(2, ("Failed to cache password for %s\n", state->username));
    } else {
        DEBUG(4, ("Password successfully cached for %s\n", state->username));
    }

    sdap_pam_auth_reply(state->breq, state->pd->pam_status);
}

static void sdap_pam_auth_reply(struct be_req *req, int result)
{
    const char *errstr = NULL;
    if (result) errstr = "Operation failed";
    req->fn(req, result, errstr);
}

/* ==Module-Initialization-and-Dispose==================================== */

static void sdap_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    req->fn(req, EOK, NULL);
}

struct bet_ops sdap_auth_ops = {
    .handler = sdap_pam_auth_send,
    .finalize = sdap_shutdown
};

struct bet_ops sdap_chpass_ops = {
    .handler = sdap_pam_chpass_send,
    .finalize = sdap_shutdown
};

int sssm_ldap_auth_init(struct be_ctx *bectx,
                        struct bet_ops **ops,
                        void **pvt_data)
{
    int ldap_opt_x_tls_require_cert;
    struct sdap_auth_ctx *ctx;
    char *tls_reqcert;
    int ret;

    ctx = talloc(bectx, struct sdap_auth_ctx);
    if (!ctx) return ENOMEM;

    ctx->be = bectx;

    ret = sdap_get_options(ctx, bectx->cdb, bectx->conf_path,
                              &ctx->opts);
    if (ret != EOK) goto done;

    tls_reqcert = ctx->opts->basic[SDAP_TLS_REQCERT].value;
    if (tls_reqcert) {
        if (strcasecmp(tls_reqcert, "never") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_NEVER;
        }
        else if (strcasecmp(tls_reqcert, "allow") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_ALLOW;
        }
        else if (strcasecmp(tls_reqcert, "try") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_TRY;
        }
        else if (strcasecmp(tls_reqcert, "demand") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_DEMAND;
        }
        else if (strcasecmp(tls_reqcert, "hard") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_HARD;
        }
        else {
            DEBUG(1, ("Unknown value for tls_reqcert.\n"));
            ret = EINVAL;
            goto done;
        }
        /* LDAP_OPT_X_TLS_REQUIRE_CERT has to be set as a global option,
         * because the SSL/TLS context is initialized from this value. */
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
                              &ldap_opt_x_tls_require_cert);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", ldap_err2string(ret)));
            ret = EIO;
            goto done;
        }
    }

    *ops = &sdap_auth_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_ldap_chpass_init(struct be_ctx *bectx,
                          struct bet_ops **ops,
                          void **pvt_data)
{
    int ret;
    ret = sssm_ldap_auth_init(bectx, ops, pvt_data);
    *ops = &sdap_chpass_ops;
    return ret;
}
