/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com> - 2009
    Copyright (C) 2010, rhafer@suse.de, Novell Inc.

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

#include <sasl/sasl.h>
#include "util/util.h"
#include "util/sss_krb5.h"
#include "providers/ldap/sdap_async_private.h"

#define LDAP_X_SSSD_PASSWORD_EXPIRED 0x555D

/* ==Connect-to-LDAP-Server=============================================== */

struct sdap_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sdap_op *op;

    struct sdap_msg *reply;
    int result;
};

static void sdap_connect_done(struct sdap_op *op,
                              struct sdap_msg *reply,
                              int error, void *pvt);

struct tevent_req *sdap_connect_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sdap_options *opts,
                                     const char *uri,
                                     bool use_start_tls)
{
    struct tevent_req *req;
    struct sdap_connect_state *state;
    struct timeval tv;
    int ver;
    int lret;
    int optret;
    int ret = EOK;
    int msgid;
    char *errmsg = NULL;
    bool ldap_referrals;

    req = tevent_req_create(memctx, &state, struct sdap_connect_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sdap_handle_create(state);
    if (!state->sh) {
        talloc_zfree(req);
        return NULL;
    }
    /* Initialize LDAP handler */
    lret = ldap_initialize(&state->sh->ldap, uri);
    if (lret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_initialize failed: %s\n", ldap_err2string(lret)));
        goto fail;
    }

    /* Force ldap version to 3 */
    ver = LDAP_VERSION3;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set ldap version to 3\n"));
        goto fail;
    }

    /* TODO: maybe this can be remove when we go async, currently we need it
     * to handle EINTR during poll(). */
    ret = ldap_set_option(state->sh->ldap, LDAP_OPT_RESTART, LDAP_OPT_ON);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set restart option.\n"));
    }

    /* Set Network Timeout */
    tv.tv_sec = dp_opt_get_int(opts->basic, SDAP_NETWORK_TIMEOUT);
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set network timeout to %d\n",
                  dp_opt_get_int(opts->basic, SDAP_NETWORK_TIMEOUT)));
        goto fail;
    }

    /* Set Default Timeout */
    tv.tv_sec = dp_opt_get_int(opts->basic, SDAP_OPT_TIMEOUT);
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set default timeout to %d\n",
                  dp_opt_get_int(opts->basic, SDAP_OPT_TIMEOUT)));
        goto fail;
    }

    /* Set Referral chasing */
    ldap_referrals = dp_opt_get_bool(opts->basic, SDAP_REFERRALS);
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_REFERRALS,
                           (ldap_referrals ? LDAP_OPT_ON : LDAP_OPT_OFF));
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set referral chasing to %s\n",
                  (ldap_referrals ? "LDAP_OPT_ON" : "LDAP_OPT_OFF")));
        goto fail;
    }

    ret = setup_ldap_connection_callbacks(state->sh, state->ev);
    if (ret != EOK) {
        DEBUG(1, ("setup_ldap_connection_callbacks failed.\n"));
        goto fail;
    }

    /* if we do not use start_tls the connection is not really connected yet
     * just fake an async procedure and leave connection to the bind call */
    if (!use_start_tls) {
        tevent_req_post(req, ev);
        return req;
    }

    DEBUG(4, ("Executing START TLS\n"));

    lret = ldap_start_tls(state->sh->ldap, NULL, NULL, &msgid);
    if (lret != LDAP_SUCCESS) {
        optret = ldap_get_option(state->sh->ldap,
                                 LDAP_OPT_DIAGNOSTIC_MESSAGE,
                                 (void*)&errmsg);
        if (optret == LDAP_SUCCESS) {
            DEBUG(3, ("ldap_start_tls failed: [%s] [%s]\n",
                      ldap_err2string(lret),
                      errmsg));
            ldap_memfree(errmsg);
        }
        else {
            DEBUG(3, ("ldap_start_tls failed: [%s]\n",
                      ldap_err2string(lret)));
        }
        goto fail;
    }

    ret = sdap_set_connected(state->sh, state->ev);
    if (ret) goto fail;

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, state->sh, msgid,
                      sdap_connect_done, req, 5, &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    if (ret) {
        tevent_req_error(req, ret);
    } else {
        if (lret == LDAP_SERVER_DOWN) {
            tevent_req_error(req, ETIMEDOUT);
        } else {
            tevent_req_error(req, EIO);
        }
    }
    tevent_req_post(req, ev);
    return req;
}

static void sdap_connect_done(struct sdap_op *op,
                              struct sdap_msg *reply,
                              int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_connect_state *state = tevent_req_data(req,
                                          struct sdap_connect_state);
    char *errmsg;
    char *tlserr;
    int ret;
    int optret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    ret = ldap_parse_result(state->sh->ldap, state->reply->msg,
                            &state->result, NULL, &errmsg, NULL, NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(3, ("START TLS result: %s(%d), %s\n",
              ldap_err2string(state->result), state->result, errmsg));

    if (ldap_tls_inplace(state->sh->ldap)) {
        DEBUG(9, ("SSL/TLS handler already in place.\n"));
        tevent_req_done(req);
        return;
    }

/* FIXME: take care that ldap_install_tls might block */
    ret = ldap_install_tls(state->sh->ldap);
    if (ret != LDAP_SUCCESS) {

        optret = ldap_get_option(state->sh->ldap,
                                 LDAP_OPT_DIAGNOSTIC_MESSAGE,
                                 (void*)&tlserr);
        if (optret == LDAP_SUCCESS) {
            DEBUG(3, ("ldap_install_tls failed: [%s] [%s]\n",
                      ldap_err2string(ret),
                      tlserr));
            ldap_memfree(tlserr);
        }
        else {
            DEBUG(3, ("ldap_install_tls failed: [%s]\n",
                      ldap_err2string(ret)));
        }

        state->result = ret;
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

int sdap_connect_recv(struct tevent_req *req,
                      TALLOC_CTX *memctx,
                      struct sdap_handle **sh)
{
    struct sdap_connect_state *state = tevent_req_data(req,
                                                  struct sdap_connect_state);
    enum tevent_req_state tstate;
    uint64_t err = EIO;

    if (tevent_req_is_error(req, &tstate, &err)) {
        /* if tstate shows in progress, it is because
         * we did not ask to perform tls, just pretend all is fine */
        if (tstate != TEVENT_REQ_IN_PROGRESS) {
            return err;
        }
    }

    *sh = talloc_steal(memctx, state->sh);
    if (!*sh) {
        return ENOMEM;
    }
    return EOK;
}

/* ==Simple-Bind========================================================== */

struct simple_bind_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    const char *user_dn;
    struct berval *pw;

    struct sdap_op *op;

    struct sdap_msg *reply;
    struct sdap_ppolicy_data *ppolicy;
    int result;
};

static void simple_bind_done(struct sdap_op *op,
                             struct sdap_msg *reply,
                             int error, void *pvt);

static struct tevent_req *simple_bind_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           const char *user_dn,
                                           struct berval *pw)
{
    struct tevent_req *req;
    struct simple_bind_state *state;
    int ret = EOK;
    int msgid;
    int ldap_err;
    LDAPControl *request_controls[2];

    req = tevent_req_create(memctx, &state, struct simple_bind_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

    state->ev = ev;
    state->sh = sh;
    state->user_dn = user_dn;
    state->pw = pw;

    ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                  0, NULL, 0, &request_controls[0]);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("sss_ldap_control_create failed.\n"));
        goto fail;
    }
    request_controls[1] = NULL;

    DEBUG(4, ("Executing simple bind as: %s\n", state->user_dn));

    ret = ldap_sasl_bind(state->sh->ldap, state->user_dn, LDAP_SASL_SIMPLE,
                         state->pw, request_controls, NULL, &msgid);
    ldap_control_free(request_controls[0]);
    if (ret == -1 || msgid == -1) {
        ret = ldap_get_option(state->sh->ldap,
                              LDAP_OPT_RESULT_CODE, &ldap_err);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_bind failed (couldn't get ldap error)\n"));
            ret = LDAP_LOCAL_ERROR;
        } else {
            DEBUG(1, ("ldap_bind failed (%d)[%s]\n",
                      ldap_err, ldap_err2string(ldap_err)));
            ret = ldap_err;
        }
        goto fail;
    }
    DEBUG(8, ("ldap simple bind sent, msgid = %d\n", msgid));

    if (!sh->connected) {
        ret = sdap_set_connected(sh, ev);
        if (ret) goto fail;
    }

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, sh, msgid,
                      simple_bind_done, req, 5, &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    if (ret == LDAP_SERVER_DOWN) {
        tevent_req_error(req, ETIMEDOUT);
    } else {
        tevent_req_error(req, EIO);
    }
    tevent_req_post(req, ev);
    return req;
}

static void simple_bind_done(struct sdap_op *op,
                             struct sdap_msg *reply,
                             int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct simple_bind_state *state = tevent_req_data(req,
                                            struct simple_bind_state);
    char *errmsg;
    int ret;
    LDAPControl **response_controls;
    int c;
    ber_int_t pp_grace;
    ber_int_t pp_expire;
    LDAPPasswordPolicyError pp_error;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    ret = ldap_parse_result(state->sh->ldap, state->reply->msg,
                            &state->result, NULL, &errmsg, NULL,
                            &response_controls, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
        ret = EIO;
        goto done;
    }

    if (response_controls == NULL) {
        DEBUG(5, ("Server returned no controls.\n"));
        state->ppolicy = NULL;
    } else {
        for (c = 0; response_controls[c] != NULL; c++) {
            DEBUG(9, ("Server returned control [%s].\n",
                      response_controls[c]->ldctl_oid));
            if (strcmp(response_controls[c]->ldctl_oid,
                       LDAP_CONTROL_PASSWORDPOLICYRESPONSE) == 0) {
                ret = ldap_parse_passwordpolicy_control(state->sh->ldap,
                                                        response_controls[c],
                                                        &pp_expire, &pp_grace,
                                                        &pp_error);
                if (ret != LDAP_SUCCESS) {
                    DEBUG(1, ("ldap_parse_passwordpolicy_control failed.\n"));
                    ret = EIO;
                    goto done;
                }

                DEBUG(7, ("Password Policy Response: expire [%d] grace [%d] "
                          "error [%s].\n", pp_expire, pp_grace,
                          ldap_passwordpolicy_err2txt(pp_error)));
                state->ppolicy = talloc(state, struct sdap_ppolicy_data);
                if (state->ppolicy == NULL) {
                    DEBUG(1, ("talloc failed.\n"));
                    ret = ENOMEM;
                    goto done;
                }
                state->ppolicy->grace = pp_grace;
                state->ppolicy->expire = pp_expire;
                if (state->result == LDAP_SUCCESS) {
                    if (pp_error == PP_changeAfterReset) {
                        DEBUG(4, ("Password was reset. "
                                  "User must set a new password.\n"));
                        state->result = LDAP_X_SSSD_PASSWORD_EXPIRED;
                    } else if (pp_grace > 0) {
                        DEBUG(4, ("Password expired. "
                                  "[%d] grace logins remaining.\n", pp_grace));
                    } else if (pp_expire > 0) {
                        DEBUG(4, ("Password will expire in [%d] seconds.\n",
                                  pp_expire));
                    }
                } else if (state->result == LDAP_INVALID_CREDENTIALS &&
                           pp_error == PP_passwordExpired) {
                    DEBUG(4,
                          ("Password expired user must set a new password.\n"));
                    state->result = LDAP_X_SSSD_PASSWORD_EXPIRED;
                }
            }
        }
    }

    DEBUG(3, ("Bind result: %s(%d), %s\n",
              ldap_err2string(state->result), state->result, errmsg));

    ret = LDAP_SUCCESS;
done:
    ldap_controls_free(response_controls);

    if (ret == LDAP_SUCCESS) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static int simple_bind_recv(struct tevent_req *req,
                            TALLOC_CTX *memctx,
                            int *ldaperr,
                            struct sdap_ppolicy_data **ppolicy)
{
    struct simple_bind_state *state = tevent_req_data(req,
                                            struct simple_bind_state);

    *ldaperr = LDAP_OTHER;
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *ldaperr = state->result;
    *ppolicy = talloc_steal(memctx, state->ppolicy);
    return EOK;
}

/* ==SASL-Bind============================================================ */

struct sasl_bind_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;

    const char *sasl_mech;
    const char *sasl_user;
    struct berval *sasl_cred;

    int result;
};

static int sdap_sasl_interact(LDAP *ld, unsigned flags,
                              void *defaults, void *interact);

static struct tevent_req *sasl_bind_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_handle *sh,
                                         const char *sasl_mech,
                                         const char *sasl_user,
                                         struct berval *sasl_cred)
{
    struct tevent_req *req;
    struct sasl_bind_state *state;
    int ret = EOK;

    req = tevent_req_create(memctx, &state, struct sasl_bind_state);
    if (!req) return NULL;

    state->ev = ev;
    state->sh = sh;
    state->sasl_mech = sasl_mech;
    state->sasl_user = sasl_user;
    state->sasl_cred = sasl_cred;

    DEBUG(4, ("Executing sasl bind mech: %s, user: %s\n",
              sasl_mech, sasl_user));

    /* FIXME: Warning, this is a sync call!
     * No async variant exist in openldap libraries yet */

    ret = ldap_sasl_interactive_bind_s(state->sh->ldap, NULL,
                                       sasl_mech, NULL, NULL,
                                       LDAP_SASL_QUIET,
                                       (*sdap_sasl_interact), state);
    state->result = ret;
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_sasl_bind failed (%d)[%s]\n",
                  ret, ldap_err2string(ret)));
        goto fail;
    }

    if (!sh->connected) {
        ret = sdap_set_connected(sh, ev);
        if (ret) goto fail;
    }

    tevent_req_post(req, ev);
    return req;

fail:
    if (ret == LDAP_SERVER_DOWN) {
        tevent_req_error(req, ETIMEDOUT);
    } else {
        tevent_req_error(req, EIO);
    }
    tevent_req_post(req, ev);
    return req;
}

static int sdap_sasl_interact(LDAP *ld, unsigned flags,
                              void *defaults, void *interact)
{
    struct sasl_bind_state *state = talloc_get_type(defaults,
                                                    struct sasl_bind_state);
    sasl_interact_t *in = (sasl_interact_t *)interact;

    if (!ld) return LDAP_PARAM_ERROR;

    while (in->id != SASL_CB_LIST_END) {

        switch (in->id) {
        case SASL_CB_GETREALM:
        case SASL_CB_AUTHNAME:
        case SASL_CB_PASS:
            if (in->defresult) {
                in->result = in->defresult;
            } else {
                in->result = "";
            }
            in->len = strlen(in->result);
            break;
        case SASL_CB_USER:
            if (state->sasl_user) {
                in->result = state->sasl_user;
            } else if (in->defresult) {
                in->result = in->defresult;
            } else {
                in->result = "";
            }
            in->len = strlen(in->result);
            break;
        case SASL_CB_NOECHOPROMPT:
        case SASL_CB_ECHOPROMPT:
            goto fail;
        }

        in++;
    }

    return LDAP_SUCCESS;

fail:
    return LDAP_UNAVAILABLE;
}

static int sasl_bind_recv(struct tevent_req *req, int *ldaperr)
{
    struct sasl_bind_state *state = tevent_req_data(req,
                                            struct sasl_bind_state);
    enum tevent_req_state tstate;
    uint64_t err = EIO;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (tstate != TEVENT_REQ_IN_PROGRESS) {
            *ldaperr = LDAP_OTHER;
            return err;
        }
    }

    *ldaperr = state->result;
    return EOK;
}

/* ==Perform-Kinit-given-keytab-and-principal============================= */

struct sdap_kinit_state {
    int result;
};

static void sdap_kinit_done(struct tevent_req *subreq);

struct tevent_req *sdap_kinit_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_handle *sh,
                                   int    timeout,
                                   const char *keytab,
                                   const char *principal,
                                   const char *realm,
                                   int lifetime)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_kinit_state *state;
    int ret;

    DEBUG(6, ("Attempting kinit (%s, %s, %s, %d)\n", keytab, principal, realm,
                                                     lifetime));

    if (lifetime < 0 || lifetime > INT32_MAX) {
        DEBUG(1, ("Ticket lifetime out of range.\n"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct sdap_kinit_state);
    if (!req) return NULL;

    state->result = SDAP_AUTH_FAILED;

    if (keytab) {
        ret = setenv("KRB5_KTNAME", keytab, 1);
        if (ret == -1) {
            DEBUG(2, ("Failed to set KRB5_KTNAME to %s\n", keytab));
            return NULL;
        }
    }

    subreq = sdap_get_tgt_send(state, ev, realm, principal, keytab, lifetime,
                               timeout);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_kinit_done, req);

    return req;
}

static void sdap_kinit_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_kinit_state *state = tevent_req_data(req,
                                                     struct sdap_kinit_state);

    int ret;
    int result;
    char *ccname = NULL;

    ret = sdap_get_tgt_recv(subreq, state, &result, &ccname);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->result = SDAP_AUTH_FAILED;
        DEBUG(1, ("child failed (%d [%s])\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    if (result == EOK) {
        ret = setenv("KRB5CCNAME", ccname, 1);
        if (ret == -1) {
            DEBUG(2, ("Unable to set env. variable KRB5CCNAME!\n"));
            state->result = SDAP_AUTH_FAILED;
            tevent_req_error(req, EFAULT);
        }

        state->result = SDAP_AUTH_SUCCESS;
        tevent_req_done(req);
        return;
    }

    DEBUG(4, ("Could not get TGT: %d [%s]\n", result, strerror(result)));
    state->result = SDAP_AUTH_FAILED;
    tevent_req_error(req, EIO);
}

int sdap_kinit_recv(struct tevent_req *req, enum sdap_result *result)
{
    struct sdap_kinit_state *state = tevent_req_data(req,
                                                     struct sdap_kinit_state);
    enum tevent_req_state tstate;
    uint64_t err = EIO;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (tstate != TEVENT_REQ_IN_PROGRESS) {
            *result = SDAP_ERROR;
            return err;
        }
    }

    *result = state->result;
    return EOK;
}


/* ==Authenticaticate-User-by-DN========================================== */

struct sdap_auth_state {
    const char *user_dn;
    struct berval pw;
    struct sdap_ppolicy_data *ppolicy;

    int result;
    bool is_sasl;
};

static void sdap_auth_done(struct tevent_req *subreq);

/* TODO: handle sasl_cred */
struct tevent_req *sdap_auth_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_handle *sh,
                                  const char *sasl_mech,
                                  const char *sasl_user,
                                  const char *user_dn,
                                  const char *authtok_type,
                                  struct dp_opt_blob authtok)
{
    struct tevent_req *req, *subreq;
    struct sdap_auth_state *state;

    if (authtok_type != NULL && strcasecmp(authtok_type,"password") != 0) {
        DEBUG(1,("Authentication token type [%s] is not supported"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct sdap_auth_state);
    if (!req) return NULL;

    state->user_dn = user_dn;
    state->pw.bv_val = (char *)authtok.data;
    state->pw.bv_len = authtok.length;

    if (sasl_mech) {
        state->is_sasl = true;
        subreq = sasl_bind_send(state, ev, sh, sasl_mech, sasl_user, NULL);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return tevent_req_post(req, ev);
        }
    } else {
        state->is_sasl = false;
        subreq = simple_bind_send(state, ev, sh, user_dn, &state->pw);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return tevent_req_post(req, ev);
        }
    }

    tevent_req_set_callback(subreq, sdap_auth_done, req);
    return req;
}

static void sdap_auth_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_auth_state *state = tevent_req_data(req,
                                                 struct sdap_auth_state);
    int ret;

    if (state->is_sasl) {
        ret = sasl_bind_recv(subreq, &state->result);
        state->ppolicy = NULL;
    } else {
        ret = simple_bind_recv(subreq, state, &state->result, &state->ppolicy);
    }
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_auth_recv(struct tevent_req *req,
                   TALLOC_CTX *memctx,
                   enum sdap_result *result,
                   struct sdap_ppolicy_data **ppolicy)
{
    struct sdap_auth_state *state = tevent_req_data(req,
                                                 struct sdap_auth_state);

    *result = SDAP_ERROR;
    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (ppolicy != NULL) {
        *ppolicy = talloc_steal(memctx, state->ppolicy);
    }
    switch (state->result) {
        case LDAP_SUCCESS:
            *result = SDAP_AUTH_SUCCESS;
            break;
        case LDAP_INVALID_CREDENTIALS:
            *result = SDAP_AUTH_FAILED;
            break;
        case LDAP_X_SSSD_PASSWORD_EXPIRED:
            *result = SDAP_AUTH_PW_EXPIRED;
            break;
        default:
            break;
    }

    return EOK;
}

/* ==Client connect============================================ */

struct sdap_cli_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_service *service;
    struct be_ctx *be;

    bool use_rootdse;
    struct sysdb_attrs *rootdse;

    struct sdap_handle *sh;

    struct fo_server *srv;
};

static int sdap_cli_resolve_next(struct tevent_req *req);
static void sdap_cli_resolve_done(struct tevent_req *subreq);
static void sdap_cli_connect_done(struct tevent_req *subreq);
static void sdap_cli_rootdse_step(struct tevent_req *req);
static void sdap_cli_rootdse_done(struct tevent_req *subreq);
static void sdap_cli_kinit_step(struct tevent_req *req);
static void sdap_cli_kinit_done(struct tevent_req *subreq);
static void sdap_cli_auth_step(struct tevent_req *req);
static void sdap_cli_auth_done(struct tevent_req *subreq);

struct tevent_req *sdap_cli_connect_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct be_ctx *be,
                                         struct sdap_service *service,
                                         struct sysdb_attrs **rootdse)
{
    struct sdap_cli_connect_state *state;
    struct tevent_req *req;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_cli_connect_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->service = service;
    state->be = be;
    state->srv = NULL;
    state->be = be;

    if (rootdse) {
        state->use_rootdse = true;
        state->rootdse = *rootdse;
    } else {
        state->use_rootdse = false;
        state->rootdse = NULL;
    }

    ret = sdap_cli_resolve_next(req);
    if (ret) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static int sdap_cli_resolve_next(struct tevent_req *req)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    struct tevent_req *subreq;

    /* NOTE: this call may cause service->uri to be refreshed
     * with a new valid server. Do not use service->uri before */
    subreq = be_resolve_server_send(state, state->ev,
                                    state->be, state->service->name);
    if (!subreq) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_cli_resolve_done, req);
    return EOK;
}

static void sdap_cli_resolve_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    int ret;

    ret = be_resolve_server_recv(subreq, &state->srv);
    talloc_zfree(subreq);
    if (ret) {
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, EIO);
        return;
    }

    subreq = sdap_connect_send(state, state->ev, state->opts,
                               state->service->uri,
                               dp_opt_get_bool(state->opts->basic,
                                               SDAP_ID_TLS));
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_cli_connect_done, req);
}

static void sdap_cli_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    const char *sasl_mech;
    int ret;

    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ETIMEDOUT) { /* retry another server */
            fo_set_port_status(state->srv, PORT_NOT_WORKING);
            ret = sdap_cli_resolve_next(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }

        tevent_req_error(req, ret);
        return;
    }

    if (state->use_rootdse && !state->rootdse) {
        /* fetch the rootDSE this time */
        sdap_cli_rootdse_step(req);
        return;
    }

    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);

    if (sasl_mech && state->use_rootdse) {
        /* check if server claims to support GSSAPI */
        if (!sdap_rootdse_sasl_mech_is_supported(state->rootdse,
                                                 sasl_mech)) {
            tevent_req_error(req, ENOTSUP);
            return;
        }
    }

    if (sasl_mech && (strcasecmp(sasl_mech, "GSSAPI") == 0)) {
        if (dp_opt_get_bool(state->opts->basic, SDAP_KRB5_KINIT)) {
            sdap_cli_kinit_step(req);
            return;
        }
    }

    sdap_cli_auth_step(req);
}

static void sdap_cli_rootdse_step(struct tevent_req *req)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    struct tevent_req *subreq;
    int ret;

    subreq = sdap_get_rootdse_send(state, state->ev, state->opts, state->sh);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_cli_rootdse_done, req);

    if (!state->sh->connected) {
    /* this rootdse search is performed before we actually do a bind,
     * so we need to set up the callbacks or we will never get notified
     * of a reply */

        ret = sdap_set_connected(state->sh, state->ev);
        if (ret) {
            tevent_req_error(req, ret);
        }
    }
}

static void sdap_cli_rootdse_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    const char *sasl_mech;
    int ret;

    ret = sdap_get_rootdse_recv(subreq, state, &state->rootdse);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ETIMEDOUT) { /* retry another server */
            fo_set_port_status(state->srv, PORT_NOT_WORKING);
            ret = sdap_cli_resolve_next(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }

        tevent_req_error(req, ret);
        return;
    }

    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);

    if (sasl_mech && state->use_rootdse) {
        /* check if server claims to support GSSAPI */
        if (!sdap_rootdse_sasl_mech_is_supported(state->rootdse,
                                                 sasl_mech)) {
            tevent_req_error(req, ENOTSUP);
            return;
        }
    }

    if (sasl_mech && (strcasecmp(sasl_mech, "GSSAPI") == 0)) {
        if (dp_opt_get_bool(state->opts->basic, SDAP_KRB5_KINIT)) {
            sdap_cli_kinit_step(req);
            return;
        }
    }

    sdap_cli_auth_step(req);
}

static void sdap_cli_kinit_step(struct tevent_req *req)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    struct tevent_req *subreq;

    subreq = sdap_kinit_send(state, state->ev,
                             state->sh,
                        dp_opt_get_int(state->opts->basic,
                                                   SDAP_OPT_TIMEOUT),
                        dp_opt_get_string(state->opts->basic,
                                                   SDAP_KRB5_KEYTAB),
                        dp_opt_get_string(state->opts->basic,
                                                   SDAP_SASL_AUTHID),
                        dp_opt_get_string(state->opts->basic,
                                                   SDAP_KRB5_REALM),
                        dp_opt_get_int(state->opts->basic,
                                                   SDAP_KRB5_TICKET_LIFETIME));
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_cli_kinit_done, req);
}

static void sdap_cli_kinit_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    enum sdap_result result;
    int ret;

    ret = sdap_kinit_recv(subreq, &result);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ETIMEDOUT) { /* child timed out, retry another server */
            fo_set_port_status(state->srv, PORT_NOT_WORKING);
            ret = sdap_cli_resolve_next(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }

        tevent_req_error(req, ret);
        return;
    }
    if (result != SDAP_AUTH_SUCCESS) {
        tevent_req_error(req, EACCES);
        return;
    }

    sdap_cli_auth_step(req);
}

static void sdap_cli_auth_step(struct tevent_req *req)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    struct tevent_req *subreq;

    subreq = sdap_auth_send(state,
                            state->ev,
                            state->sh,
                            dp_opt_get_string(state->opts->basic,
                                                          SDAP_SASL_MECH),
                            dp_opt_get_string(state->opts->basic,
                                                        SDAP_SASL_AUTHID),
                            dp_opt_get_string(state->opts->basic,
                                                    SDAP_DEFAULT_BIND_DN),
                            dp_opt_get_string(state->opts->basic,
                                               SDAP_DEFAULT_AUTHTOK_TYPE),
                            dp_opt_get_blob(state->opts->basic,
                                                    SDAP_DEFAULT_AUTHTOK));
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_cli_auth_done, req);
}

static void sdap_cli_auth_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    enum sdap_result result;
    int ret;

    ret = sdap_auth_recv(subreq, NULL, &result, NULL);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    if (result != SDAP_AUTH_SUCCESS) {
        tevent_req_error(req, EACCES);
        return;
    }

    /* Reconnection succeeded
     * Run any post-connection routines
     */
    be_run_online_cb(state->be);

    tevent_req_done(req);
}

int sdap_cli_connect_recv(struct tevent_req *req,
                          TALLOC_CTX *memctx,
                          struct sdap_handle **gsh,
                          struct sysdb_attrs **rootdse)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        /* mark the server as bad if connection failed */
        if (state->srv) {
            fo_set_port_status(state->srv, PORT_NOT_WORKING);
        }

        if (tstate == TEVENT_REQ_USER_ERROR) {
            return err;
        }
        return EIO;
    } else if (state->srv) {
        fo_set_port_status(state->srv, PORT_WORKING);
    }

    if (gsh) {
        if (*gsh) {
            talloc_zfree(*gsh);
        }
        *gsh = talloc_steal(memctx, state->sh);
        if (!*gsh) {
            return ENOMEM;
        }
    } else {
        talloc_zfree(state->sh);
    }

    if (rootdse) {
        if (state->use_rootdse) {
            *rootdse = talloc_steal(memctx, state->rootdse);
            if (!*rootdse) {
                return ENOMEM;
            }
        } else {
            *rootdse = NULL;
        }
    } else {
        talloc_zfree(rootdse);
    }

    return EOK;
}

