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

struct ipa_auth_ctx {
    struct sdap_auth_ctx *sdap_auth_ctx;
    struct krb5_ctx *krb5_ctx;
    struct be_req *be_req;
    be_async_callback_t callback;
    void *pvt;
    bool password_migration;

    int dp_err_type;
    int errnum;
    char *errstr;
};

static void ipa_auth_reply(struct ipa_auth_ctx *ipa_auth_ctx)
{
    struct pam_data *pd;
    struct be_req *be_req = ipa_auth_ctx->be_req;
    be_req->fn = ipa_auth_ctx->callback;
    be_req->pvt = ipa_auth_ctx->pvt;
    be_req->be_ctx->bet_info[BET_AUTH].pvt_bet_data = ipa_auth_ctx->krb5_ctx;
    pd = talloc_get_type(be_req->req_data, struct pam_data);
    int dp_err_type = ipa_auth_ctx->dp_err_type;
    char *errstr = ipa_auth_ctx->errstr;

    talloc_zfree(ipa_auth_ctx);
    DEBUG(9, ("sending [%d] [%d] [%s].\n", dp_err_type, pd->pam_status,
                                           errstr));

    be_req->fn(be_req, dp_err_type, pd->pam_status, errstr);
}

struct ipa_auth_handler_state {
    struct tevent_context *ev;

    int dp_err_type;
    int errnum;
    char *errstr;
};

static void ipa_auth_handler_callback(struct be_req *be_req,
                                   int dp_err_type,
                                   int errnum,
                                   const char *errstr);

static struct tevent_req *ipa_auth_handler_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct be_req *be_req,
                                            be_req_fn_t auth_handler)
{
    struct ipa_auth_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(memctx, &state, struct ipa_auth_handler_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;

    be_req->fn = ipa_auth_handler_callback;
    be_req->pvt = req;

    auth_handler(be_req);

    return req;
}

static void ipa_auth_handler_callback(struct be_req *be_req,
                                   int dp_err_type,
                                   int errnum,
                                   const char *errstr)
{
    struct tevent_req *req = talloc_get_type(be_req->pvt, struct tevent_req);
    struct ipa_auth_handler_state *state = tevent_req_data(req,
                                                 struct ipa_auth_handler_state);

    DEBUG(9, ("received from handler [%d] [%d] [%s].\n", dp_err_type, errnum,
                                                         errstr));
    state->dp_err_type = dp_err_type;
    state->errnum = errnum;
    state->errstr = talloc_strdup(state, errstr);

    tevent_req_post(req, state->ev);
    tevent_req_done(req);
    return;
}

static int ipa_auth_handler_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                              int *dp_err_type, int *errnum,
                              char **errstr)
{
    struct ipa_auth_handler_state *state = tevent_req_data(req,
                                                 struct ipa_auth_handler_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    *dp_err_type = state->dp_err_type;
    *errnum = state->errnum;
    *errstr = talloc_steal(memctx, state->errstr);

    return EOK;
}


static void ipa_auth_handler_done(struct tevent_req *req);
static void ipa_auth_ldap_done(struct tevent_req *req);
static void ipa_auth_handler_retry_done(struct tevent_req *req);

void ipa_auth(struct be_req *be_req)
{
    struct tevent_req *req;
    struct ipa_auth_ctx *ipa_auth_ctx;
    struct sdap_id_ctx *sdap_id_ctx;

    ipa_auth_ctx = talloc_zero(be_req, struct ipa_auth_ctx);
    if (ipa_auth_ctx == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        be_req->fn(be_req, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
    }

    ipa_auth_ctx->callback = be_req->fn;
    ipa_auth_ctx->pvt = be_req->pvt;

    ipa_auth_ctx->be_req = be_req;

    ipa_auth_ctx->sdap_auth_ctx = talloc_zero(ipa_auth_ctx,
                                              struct sdap_auth_ctx);
    if (ipa_auth_ctx->sdap_auth_ctx == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        goto fail;
    }

    sdap_id_ctx = talloc_get_type(
                              be_req->be_ctx->bet_info[BET_ID].pvt_bet_data,
                              struct sdap_id_ctx);
    ipa_auth_ctx->sdap_auth_ctx->be = sdap_id_ctx->be;
    ipa_auth_ctx->sdap_auth_ctx->opts = sdap_id_ctx->opts;

    ipa_auth_ctx->krb5_ctx = talloc_get_type(
                              be_req->be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                              struct krb5_ctx);

/* TODO: test and activate when server side support is available */
    ipa_auth_ctx->password_migration = false;

    ipa_auth_ctx->dp_err_type = DP_ERR_FATAL;
    ipa_auth_ctx->errnum = EIO;
    ipa_auth_ctx->errstr = NULL;

    req = ipa_auth_handler_send(ipa_auth_ctx, be_req->be_ctx->ev, be_req,
                                krb5_pam_handler);
    if (req == NULL) {
        DEBUG(1, ("ipa_auth_handler_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(req, ipa_auth_handler_done, ipa_auth_ctx);
    return;

fail:
    ipa_auth_reply(ipa_auth_ctx);
}

static void ipa_auth_handler_done(struct tevent_req *req)
{
    struct ipa_auth_ctx *ipa_auth_ctx = tevent_req_callback_data(req,
                                                           struct ipa_auth_ctx);
    struct pam_data *pd;
    struct be_req *be_req;
    int ret;

    be_req = ipa_auth_ctx->be_req;
    pd = talloc_get_type(be_req->req_data, struct pam_data);

    ret = ipa_auth_handler_recv(req, ipa_auth_ctx, &ipa_auth_ctx->dp_err_type,
                                &ipa_auth_ctx->errnum, &ipa_auth_ctx->errstr);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("ipa_auth_handler request failed.\n"));
        pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    if (ipa_auth_ctx->dp_err_type != DP_ERR_OK) {
        pd->pam_status = ipa_auth_ctx->errnum;
        goto done;
    }

    if (ipa_auth_ctx->password_migration && pd->pam_status == PAM_CRED_ERR) {
        DEBUG(1, ("Assuming Kerberos password is missing, "
                  "starting password migration.\n"));
        be_req->be_ctx->bet_info[BET_AUTH].pvt_bet_data =
                                                    ipa_auth_ctx->sdap_auth_ctx;
        req = ipa_auth_handler_send(ipa_auth_ctx, be_req->be_ctx->ev, be_req,
                                    sdap_pam_auth_handler);
        if (req == NULL) {
            DEBUG(1, ("ipa_auth_ldap_send failed.\n"));
            goto done;
        }

        tevent_req_set_callback(req, ipa_auth_ldap_done, ipa_auth_ctx);
        return;
    }

done:
    ipa_auth_reply(ipa_auth_ctx);
}

static void ipa_auth_ldap_done(struct tevent_req *req)
{
    struct ipa_auth_ctx *ipa_auth_ctx = tevent_req_callback_data(req,
                                                           struct ipa_auth_ctx);
    struct pam_data *pd;
    struct be_req *be_req;
    int ret;

    be_req = ipa_auth_ctx->be_req;
    pd = talloc_get_type(be_req->req_data, struct pam_data);

    ret = ipa_auth_handler_recv(req, ipa_auth_ctx, &ipa_auth_ctx->dp_err_type,
                                &ipa_auth_ctx->errnum, &ipa_auth_ctx->errstr);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("ipa_auth_handler request failed.\n"));
        pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    if (ipa_auth_ctx->dp_err_type != DP_ERR_OK) {
        pd->pam_status = ipa_auth_ctx->errnum;
        goto done;
    }

    if (pd->pam_status == PAM_SUCCESS) {
        DEBUG(1, ("LDAP authentication succeded, "
                  "trying Kerberos authentication again.\n"));
        be_req->be_ctx->bet_info[BET_AUTH].pvt_bet_data = ipa_auth_ctx->krb5_ctx;
        req = ipa_auth_handler_send(ipa_auth_ctx, be_req->be_ctx->ev, be_req,
                                    krb5_pam_handler);
        if (req == NULL) {
            DEBUG(1, ("ipa_auth_ldap_send failed.\n"));
            goto done;
        }

        tevent_req_set_callback(req, ipa_auth_handler_retry_done, ipa_auth_ctx);
        return;
    }

done:
    ipa_auth_reply(ipa_auth_ctx);
}

static void ipa_auth_handler_retry_done(struct tevent_req *req)
{
    struct ipa_auth_ctx *ipa_auth_ctx = tevent_req_callback_data(req,
                                                           struct ipa_auth_ctx);
    struct pam_data *pd;
    struct be_req *be_req;
    int ret;

    be_req = ipa_auth_ctx->be_req;
    pd = talloc_get_type(be_req->req_data, struct pam_data);

    ret = ipa_auth_handler_recv(req, ipa_auth_ctx, &ipa_auth_ctx->dp_err_type,
                                &ipa_auth_ctx->errnum, &ipa_auth_ctx->errstr);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("ipa_auth_handler request failed.\n"));
        pd->pam_status = PAM_SYSTEM_ERR;
    }
    if (ipa_auth_ctx->dp_err_type != DP_ERR_OK) {
        pd->pam_status = ipa_auth_ctx->errnum;
    }

    ipa_auth_reply(ipa_auth_ctx);
}
