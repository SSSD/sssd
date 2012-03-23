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

#include <unistd.h>
#include <fcntl.h>
#include <sasl/sasl.h>
#include "util/util.h"
#include "util/sss_krb5.h"
#include "util/sss_ldap.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"

errno_t deref_string_to_val(const char *str, int *val)
{
    if (strcasecmp(str, "never") == 0) {
        *val = LDAP_DEREF_NEVER;
    } else if (strcasecmp(str, "searching") == 0) {
        *val = LDAP_DEREF_SEARCHING;
    } else if (strcasecmp(str, "finding") == 0) {
        *val = LDAP_DEREF_FINDING;
    } else if (strcasecmp(str, "always") == 0) {
        *val = LDAP_DEREF_ALWAYS;
    } else {
        DEBUG(1, ("Illegal deref option [%s].\n", str));
        return EINVAL;
    }

    return EOK;
}

/* ==Connect-to-LDAP-Server=============================================== */

struct sdap_rebind_proc_params {
    struct sdap_options *opts;
    struct sdap_handle *sh;
    bool use_start_tls;
};

static int sdap_rebind_proc(LDAP *ldap, LDAP_CONST char *url, ber_tag_t request,
                            ber_int_t msgid, void *params);

struct sdap_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    const char *uri;
    bool use_start_tls;

    struct sdap_op *op;

    struct sdap_msg *reply;
    int result;
};

static void sdap_sys_connect_done(struct tevent_req *subreq);
static void sdap_connect_done(struct sdap_op *op,
                              struct sdap_msg *reply,
                              int error, void *pvt);

struct tevent_req *sdap_connect_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sdap_options *opts,
                                     const char *uri,
                                     struct sockaddr_storage *sockaddr,
                                     bool use_start_tls)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_connect_state *state;
    int ret;
    int timeout;

    req = tevent_req_create(memctx, &state, struct sdap_connect_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->use_start_tls = use_start_tls;

    state->uri = talloc_asprintf(state, "%s", uri);
    if (!state->uri) {
        talloc_zfree(req);
        return NULL;
    }

    state->sh = sdap_handle_create(state);
    if (!state->sh) {
        talloc_zfree(req);
        return NULL;
    }

    state->sh->page_size = dp_opt_get_int(state->opts->basic,
                                          SDAP_PAGE_SIZE);

    timeout = dp_opt_get_int(state->opts->basic, SDAP_NETWORK_TIMEOUT);

    subreq = sss_ldap_init_send(state, ev, state->uri, sockaddr,
                                sizeof(struct sockaddr_storage),
                                timeout);
    if (subreq == NULL) {
        ret = ENOMEM;
        DEBUG(1, ("sss_ldap_init_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(subreq, sdap_sys_connect_done, req);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_sys_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_connect_state *state = tevent_req_data(req,
                                                     struct sdap_connect_state);
    struct timeval tv;
    int ver;
    int lret;
    int optret;
    int ret = EOK;
    int msgid;
    char *errmsg = NULL;
    bool ldap_referrals;
    const char *ldap_deref;
    int ldap_deref_val;
    struct sdap_rebind_proc_params *rebind_proc_params;
    int sd;
    bool sasl_nocanon;
    const char *sasl_mech;
    int sasl_minssf;

    ret = sss_ldap_init_recv(subreq, &state->sh->ldap, &sd);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("sdap_async_connect_call request failed.\n"));
        tevent_req_error(req, ret);
        return;
    }

    ret = setup_ldap_connection_callbacks(state->sh, state->ev);
    if (ret != EOK) {
        DEBUG(1, ("setup_ldap_connection_callbacks failed.\n"));
        goto fail;
    }

    /* If sss_ldap_init_recv() does not return a valid file descriptor we have
     * to assume that the connection callback will be called by internally by
     * the OpenLDAP client library. */
    if (sd != -1) {
        ret = sdap_call_conn_cb(state->uri, sd, state->sh);
        if (ret != EOK) {
            DEBUG(1, ("sdap_call_conn_cb failed.\n"));
            goto fail;
        }
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
    tv.tv_sec = dp_opt_get_int(state->opts->basic, SDAP_NETWORK_TIMEOUT);
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set network timeout to %d\n",
                  dp_opt_get_int(state->opts->basic, SDAP_NETWORK_TIMEOUT)));
        goto fail;
    }

    /* Set Default Timeout */
    tv.tv_sec = dp_opt_get_int(state->opts->basic, SDAP_OPT_TIMEOUT);
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set default timeout to %d\n",
                  dp_opt_get_int(state->opts->basic, SDAP_OPT_TIMEOUT)));
        goto fail;
    }

    /* Set Referral chasing */
    ldap_referrals = dp_opt_get_bool(state->opts->basic, SDAP_REFERRALS);
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_REFERRALS,
                           (ldap_referrals ? LDAP_OPT_ON : LDAP_OPT_OFF));
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set referral chasing to %s\n",
                  (ldap_referrals ? "LDAP_OPT_ON" : "LDAP_OPT_OFF")));
        goto fail;
    }

    if (ldap_referrals) {
        rebind_proc_params = talloc_zero(state->sh,
                                         struct sdap_rebind_proc_params);
        if (rebind_proc_params == NULL) {
            DEBUG(1, ("talloc_zero failed.\n"));
            ret = ENOMEM;
            goto fail;
        }

        rebind_proc_params->opts = state->opts;
        rebind_proc_params->sh = state->sh;
        rebind_proc_params->use_start_tls = state->use_start_tls;

        lret = ldap_set_rebind_proc(state->sh->ldap, sdap_rebind_proc,
                                    rebind_proc_params);
        if (lret != LDAP_SUCCESS) {
            DEBUG(1, ("ldap_set_rebind_proc failed.\n"));
            goto fail;
        }
    }

    /* Set alias dereferencing */
    ldap_deref = dp_opt_get_string(state->opts->basic, SDAP_DEREF);
    if (ldap_deref != NULL) {
        ret = deref_string_to_val(ldap_deref, &ldap_deref_val);
        if (ret != EOK) {
            DEBUG(1, ("deref_string_to_val failed.\n"));
            goto fail;
        }

        lret = ldap_set_option(state->sh->ldap, LDAP_OPT_DEREF, &ldap_deref_val);
        if (lret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("Failed to set deref option to %d\n", ldap_deref_val));
            goto fail;
        }

    }

    /* Set host name canonicalization for LDAP SASL bind */
    sasl_nocanon = !dp_opt_get_bool(state->opts->basic, SDAP_SASL_CANONICALIZE);
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_X_SASL_NOCANON,
                           sasl_nocanon ? LDAP_OPT_ON : LDAP_OPT_OFF);
    if (lret != LDAP_OPT_SUCCESS) {
        /* Do not fail, just warn into both debug logs and syslog */
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to set LDAP SASL nocanon option to %s. If your system "
               "is configured to use SASL, LDAP operations might fail.\n",
              sasl_nocanon ? "true" : "false"));
        sss_log(SSS_LOG_INFO,
                "Failed to set LDAP SASL nocanon option to %s. If your system "
                "is configured to use SASL, LDAP operations might fail.\n",
                sasl_nocanon ? "true" : "false");
    }

    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);
    if (sasl_mech != NULL) {
        sasl_minssf = dp_opt_get_int(state->opts->basic, SDAP_SASL_MINSSF);
        if (sasl_minssf >= 0) {
            lret = ldap_set_option(state->sh->ldap, LDAP_OPT_X_SASL_SSF_MIN,
                                   &sasl_minssf);
            if (lret != LDAP_OPT_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      ("Failed to set LDAP MIN SSF option to %d\n",
                       sasl_minssf));
                goto fail;
            }
        }
    }

    /* if we do not use start_tls the connection is not really connected yet
     * just fake an async procedure and leave connection to the bind call */
    if (!state->use_start_tls) {
        tevent_req_done(req);
        return;
    }

    DEBUG(4, ("Executing START TLS\n"));

    lret = ldap_start_tls(state->sh->ldap, NULL, NULL, &msgid);
    if (lret != LDAP_SUCCESS) {
        optret = sss_ldap_get_diagnostic_msg(state, state->sh->ldap,
                                             &errmsg);
        if (optret == LDAP_SUCCESS) {
            DEBUG(3, ("ldap_start_tls failed: [%s] [%s]\n",
                      sss_ldap_err2string(lret),
                      errmsg));
            sss_log(SSS_LOG_ERR, "Could not start TLS. %s", errmsg);
        }
        else {
            DEBUG(3, ("ldap_start_tls failed: [%s]\n",
                      sss_ldap_err2string(lret)));
            sss_log(SSS_LOG_ERR, "Could not start TLS. "
                                 "Check for certificate issues.");
        }
        goto fail;
    }

    ret = sdap_set_connected(state->sh, state->ev);
    if (ret) goto fail;

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, state->ev, state->sh, msgid,
                      sdap_connect_done, req, 5, &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return;

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
    return;
}

static void sdap_connect_done(struct sdap_op *op,
                              struct sdap_msg *reply,
                              int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_connect_state *state = tevent_req_data(req,
                                          struct sdap_connect_state);
    char *errmsg = NULL;
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
              sss_ldap_err2string(state->result), state->result, errmsg));
    ldap_memfree(errmsg);

    if (ldap_tls_inplace(state->sh->ldap)) {
        DEBUG(9, ("SSL/TLS handler already in place.\n"));
        tevent_req_done(req);
        return;
    }

/* FIXME: take care that ldap_install_tls might block */
    ret = ldap_install_tls(state->sh->ldap);
    if (ret != LDAP_SUCCESS) {

        optret = sss_ldap_get_diagnostic_msg(state, state->sh->ldap,
                                             &tlserr);
        if (optret == LDAP_SUCCESS) {
            DEBUG(3, ("ldap_install_tls failed: [%s] [%s]\n",
                      sss_ldap_err2string(ret),
                      tlserr));
            sss_log(SSS_LOG_ERR, "Could not start TLS encryption. %s", tlserr);
        }
        else {
            DEBUG(3, ("ldap_install_tls failed: [%s]\n",
                      sss_ldap_err2string(ret)));
            sss_log(SSS_LOG_ERR, "Could not start TLS encryption. "
                                 "Check for certificate issues.");
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

    TEVENT_REQ_RETURN_ON_ERROR(req);

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
    LDAPControl **request_controls = NULL;
    LDAPControl *ctrls[2] = { NULL, NULL };

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
                                  0, NULL, 0, &ctrls[0]);
    if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
        DEBUG(1, ("sss_ldap_control_create failed to create "
                  "Password Policy control.\n"));
        goto fail;
    }
    request_controls = ctrls;

    DEBUG(4, ("Executing simple bind as: %s\n", state->user_dn));

    ret = ldap_sasl_bind(state->sh->ldap, state->user_dn, LDAP_SASL_SIMPLE,
                         state->pw, request_controls, NULL, &msgid);
    if (ctrls[0]) ldap_control_free(ctrls[0]);
    if (ret == -1 || msgid == -1) {
        ret = ldap_get_option(state->sh->ldap,
                              LDAP_OPT_RESULT_CODE, &ldap_err);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_bind failed (couldn't get ldap error)\n"));
            ret = LDAP_LOCAL_ERROR;
        } else {
            DEBUG(1, ("ldap_bind failed (%d)[%s]\n",
                      ldap_err, sss_ldap_err2string(ldap_err)));
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
    char *errmsg = NULL;
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
              sss_ldap_err2string(state->result), state->result,
              errmsg ? errmsg : "no errmsg set"));

    ret = LDAP_SUCCESS;
done:
    ldap_controls_free(response_controls);
    ldap_memfree(errmsg);

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
                  ret, sss_ldap_err2string(ret)));
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
        case SASL_CB_USER:
        case SASL_CB_PASS:
            if (in->defresult) {
                in->result = in->defresult;
            } else {
                in->result = "";
            }
            in->len = strlen(in->result);
            break;
        case SASL_CB_AUTHNAME:
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
    const char *keytab;
    const char *principal;
    const char *realm;
    int    timeout;
    int    lifetime;

    const char *krb_service_name;
    struct tevent_context *ev;
    struct be_ctx *be;

    struct fo_server *kdc_srv;
    int result;
    time_t expire_time;
};

static void sdap_kinit_done(struct tevent_req *subreq);
static struct tevent_req *sdap_kinit_next_kdc(struct tevent_req *req);
static void sdap_kinit_kdc_resolved(struct tevent_req *subreq);

struct tevent_req *sdap_kinit_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *be,
                                   struct sdap_handle *sh,
                                   const char *krb_service_name,
                                   int    timeout,
                                   const char *keytab,
                                   const char *principal,
                                   const char *realm,
                                   bool canonicalize,
                                   int lifetime)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_kinit_state *state;
    int ret;

    DEBUG(6, ("Attempting kinit (%s, %s, %s, %d)\n",
              keytab ? keytab : "default",
              principal, realm, lifetime));

    if (lifetime < 0 || lifetime > INT32_MAX) {
        DEBUG(1, ("Ticket lifetime out of range.\n"));
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct sdap_kinit_state);
    if (!req) return NULL;

    state->result = SDAP_AUTH_FAILED;
    state->keytab = keytab;
    state->principal = principal;
    state->realm = realm;
    state->ev = ev;
    state->be = be;
    state->timeout = timeout;
    state->lifetime = lifetime;
    state->krb_service_name = krb_service_name;

    if (keytab) {
        ret = setenv("KRB5_KTNAME", keytab, 1);
        if (ret == -1) {
            DEBUG(2, ("Failed to set KRB5_KTNAME to %s\n", keytab));
            talloc_free(req);
            return NULL;
        }
    }

    if (canonicalize) {
        ret = setenv("KRB5_CANONICALIZE", "true", 1);
    } else {
        ret = setenv("KRB5_CANONICALIZE", "false", 1);
    }
    if (ret == -1) {
        DEBUG(2, ("Failed to set KRB5_CANONICALIZE to %s\n",
                  ((canonicalize)?"true":"false")));
        talloc_free(req);
        return NULL;
    }

    subreq = sdap_kinit_next_kdc(req);
    if (!subreq) {
        talloc_free(req);
        return NULL;
    }

    return req;
}

static struct tevent_req *sdap_kinit_next_kdc(struct tevent_req *req)
{
    struct tevent_req *next_req;
    struct sdap_kinit_state *state = tevent_req_data(req,
                                                    struct sdap_kinit_state);

    DEBUG(7, ("Resolving next KDC for service %s\n", state->krb_service_name));

    next_req = be_resolve_server_send(state, state->ev,
                                      state->be,
                                      state->krb_service_name,
                                      state->kdc_srv == NULL ? true : false);
    if (next_req == NULL) {
        DEBUG(1, ("be_resolve_server_send failed.\n"));
        return NULL;
    }
    tevent_req_set_callback(next_req, sdap_kinit_kdc_resolved, req);

    return next_req;
}

static void sdap_kinit_kdc_resolved(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_kinit_state *state = tevent_req_data(req,
                                                     struct sdap_kinit_state);
    struct tevent_req *tgtreq;
    int ret;

    ret = be_resolve_server_recv(subreq, &state->kdc_srv);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(7, ("KDC resolved, attempting to get TGT...\n"));

    tgtreq = sdap_get_tgt_send(state, state->ev, state->realm,
                               state->principal, state->keytab,
                               state->lifetime, state->timeout);
    if (!tgtreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(tgtreq, sdap_kinit_done, req);
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
    time_t expire_time;
    krb5_error_code kerr;
    struct tevent_req *nextreq;

    ret = sdap_get_tgt_recv(subreq, state, &result,
                            &kerr, &ccname, &expire_time);
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

        state->expire_time = expire_time;
        state->result = SDAP_AUTH_SUCCESS;
        tevent_req_done(req);
        return;
    } else {
        if (kerr == KRB5_KDC_UNREACH) {
            be_fo_set_port_status(state->be, state->kdc_srv, PORT_NOT_WORKING);
            nextreq = sdap_kinit_next_kdc(req);
            if (!nextreq) {
                tevent_req_error(req, ENOMEM);
            }
            return;
        }

    }

    DEBUG(4, ("Could not get TGT: %d [%s]\n", result, strerror(result)));
    state->result = SDAP_AUTH_FAILED;
    tevent_req_error(req, EIO);
}

int sdap_kinit_recv(struct tevent_req *req,
                    enum sdap_result *result,
                    time_t *expire_time)
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
    *expire_time = state->expire_time;
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
static int sdap_auth_get_authtok(const char *authtok_type,
                                 struct dp_opt_blob authtok,
                                 struct berval *pw);

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
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_auth_state);
    if (!req) return NULL;

    state->user_dn = user_dn;

    ret = sdap_auth_get_authtok(authtok_type, authtok, &state->pw);
    if (ret != EOK) {
        if (ret == ENOSYS) {
            DEBUG(1, ("Getting authtok is not supported with the "
                      "crypto library compiled with, authentication "
                      "might fail!\n"));
        } else {
            DEBUG(1, ("Cannot parse authtok.\n"));
            tevent_req_error(req, ret);
            return tevent_req_post(req, ev);
        }
    }

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

static int sdap_auth_get_authtok(const char *authtok_type,
                                 struct dp_opt_blob authtok,
                                 struct berval *pw)
{
    if (!authtok_type) return EOK;
    if (!pw) return EINVAL;

    if (strcasecmp(authtok_type,"password") == 0) {
        pw->bv_len = authtok.length;
        pw->bv_val = (char *) authtok.data;
    } else {
        DEBUG(1, ("Authentication token type [%s] is not supported\n",
                  authtok_type));
        return EINVAL;
    }

    return EOK;
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

    struct sdap_handle *sh;

    struct fo_server *srv;

    struct sdap_server_opts *srv_opts;

    enum connect_tls force_tls;
    bool do_auth;
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
                                         bool skip_rootdse,
                                         enum connect_tls force_tls,
                                         bool skip_auth)
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
    state->srv_opts = NULL;
    state->use_rootdse = !skip_rootdse;
    state->force_tls = force_tls;
    state->do_auth = !skip_auth;

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

    /* Before stepping to next server  destroy any connection from previous attempt */
    talloc_zfree(state->sh);

    /* NOTE: this call may cause service->uri to be refreshed
     * with a new valid server. Do not use service->uri before */
    subreq = be_resolve_server_send(state, state->ev,
                                    state->be, state->service->name,
                                    state->srv == NULL ? true : false);
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
    bool use_tls;

    switch (state->force_tls) {
    case CON_TLS_DFL:
        use_tls = dp_opt_get_bool(state->opts->basic, SDAP_ID_TLS);
        break;
    case CON_TLS_ON:
        use_tls = true;
        break;
    case CON_TLS_OFF:
        use_tls = false;
        break;
    default:
        tevent_req_error(req, EINVAL);
        break;
    }

    ret = be_resolve_server_recv(subreq, &state->srv);
    talloc_zfree(subreq);
    if (ret) {
        state->srv = NULL;
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, EIO);
        return;
    }

    if (use_tls && sdap_is_secure_uri(state->service->uri)) {
        DEBUG(8, ("[%s] is a secure channel. No need to run START_TLS\n",
                  state->service->uri));
        use_tls = false;
    }

    subreq = sdap_connect_send(state, state->ev, state->opts,
                               state->service->uri,
                               state->service->sockaddr,
                               use_tls);
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

    talloc_zfree(state->sh);
    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret) {
        /* retry another server */
        be_fo_set_port_status(state->be, state->srv, PORT_NOT_WORKING);
        ret = sdap_cli_resolve_next(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    if (state->use_rootdse) {
        /* fetch the rootDSE this time */
        sdap_cli_rootdse_step(req);
        return;
    }

    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);

    if (state->do_auth && sasl_mech && state->use_rootdse) {
        /* check if server claims to support GSSAPI */
        if (!sdap_is_sasl_mech_supported(state->sh, sasl_mech)) {
            tevent_req_error(req, ENOTSUP);
            return;
        }
    }

    if (state->do_auth && sasl_mech && (strcasecmp(sasl_mech, "GSSAPI") == 0)) {
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
    struct sysdb_attrs *rootdse;
    const char *sasl_mech;
    int ret;

    ret = sdap_get_rootdse_recv(subreq, state, &rootdse);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ETIMEDOUT) { /* retry another server */
            be_fo_set_port_status(state->be, state->srv, PORT_NOT_WORKING);
            ret = sdap_cli_resolve_next(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }

        /* RootDSE was not available on
         * the server.
         * Continue, and just assume that the
         * features requested by the config
         * work properly.
         */
        state->use_rootdse = false;
        rootdse = NULL;
    }

    if (state->use_rootdse) {
        /* save rootdse data about supported features */
        ret = sdap_set_rootdse_supported_lists(rootdse, state->sh);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }

        ret = sdap_set_config_options_with_rootdse(rootdse, state->opts);
        if (ret) {
            DEBUG(1, ("sdap_set_config_options_with_rootdse failed.\n"));
            tevent_req_error(req, ret);
            return;
        }

    }

    ret = sdap_get_server_opts_from_rootdse(state,
                                            state->service->uri, rootdse,
                                            state->opts, &state->srv_opts);
    if (ret) {
        DEBUG(1, ("sdap_get_server_opts_from_rootdse failed.\n"));
        tevent_req_error(req, ret);
        return;
    }

    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);

    if (state->do_auth && sasl_mech && state->use_rootdse) {
        /* check if server claims to support GSSAPI */
        if (!sdap_is_sasl_mech_supported(state->sh, sasl_mech)) {
            tevent_req_error(req, ENOTSUP);
            return;
        }
    }

    if (state->do_auth && sasl_mech && (strcasecmp(sasl_mech, "GSSAPI") == 0)) {
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
    const char *realm;

    realm = dp_opt_get_string(state->opts->basic, SDAP_SASL_REALM);
    if (!realm) {
        realm = dp_opt_get_string(state->opts->basic, SDAP_KRB5_REALM);
    }

    subreq = sdap_kinit_send(state, state->ev,
                             state->be,
                             state->sh,
                             state->service->kinit_service_name,
                        dp_opt_get_int(state->opts->basic,
                                                   SDAP_OPT_TIMEOUT),
                        dp_opt_get_string(state->opts->basic,
                                                   SDAP_KRB5_KEYTAB),
                        dp_opt_get_string(state->opts->basic,
                                                   SDAP_SASL_AUTHID),
                        realm,
                        dp_opt_get_bool(state->opts->basic,
                                                   SDAP_KRB5_CANONICALIZE),
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
    time_t expire_time;
    int ret;

    ret = sdap_kinit_recv(subreq, &result, &expire_time);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ETIMEDOUT) { /* child timed out, retry another server */
            be_fo_set_port_status(state->be, state->srv, PORT_NOT_WORKING);
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
    state->sh->expire_time = expire_time;

    sdap_cli_auth_step(req);
}

static void sdap_cli_auth_step(struct tevent_req *req)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    struct tevent_req *subreq;
    time_t now;
    int expire_timeout;

    if (!state->do_auth) {
        /* No authentication requested or GSSAPI auth forced off */
        tevent_req_done(req);
        return;
    }

    /* Set the LDAP expiration time
     * If SASL has already set it, use the sooner of the two
     */
    now = time(NULL);
    expire_timeout = dp_opt_get_int(state->opts->basic, SDAP_EXPIRE_TIMEOUT);
    if (!state->sh->expire_time
            || (state->sh->expire_time > (now + expire_timeout))) {
        state->sh->expire_time = now + expire_timeout;
    }

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

    tevent_req_done(req);
}

int sdap_cli_connect_recv(struct tevent_req *req,
                          TALLOC_CTX *memctx,
                          bool *can_retry,
                          struct sdap_handle **gsh,
                          struct sdap_server_opts **srv_opts)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (can_retry) {
        *can_retry = true;
    }
    if (tevent_req_is_error(req, &tstate, &err)) {
        /* mark the server as bad if connection failed */
        if (state->srv) {
            be_fo_set_port_status(state->be, state->srv, PORT_NOT_WORKING);
        } else {
            if (can_retry) {
                *can_retry = false;
            }
        }

        if (tstate == TEVENT_REQ_USER_ERROR) {
            return err;
        }
        return EIO;
    } else if (state->srv) {
        be_fo_set_port_status(state->be, state->srv, PORT_WORKING);
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

    if (srv_opts) {
        *srv_opts = talloc_steal(memctx, state->srv_opts);
    }

    return EOK;
}

static int synchronous_tls_setup(LDAP *ldap)
{
    int lret;
    int optret;
    int ldaperr;
    int msgid;
    char *errmsg = NULL;
    char *diag_msg;
    LDAPMessage *result = NULL;
    TALLOC_CTX *tmp_ctx;

    DEBUG(4, ("Executing START TLS\n"));

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return LDAP_NO_MEMORY;

    lret = ldap_start_tls(ldap, NULL, NULL, &msgid);
    if (lret != LDAP_SUCCESS) {
        optret = sss_ldap_get_diagnostic_msg(tmp_ctx, ldap, &diag_msg);
        if (optret == LDAP_SUCCESS) {
            DEBUG(3, ("ldap_start_tls failed: [%s] [%s]\n",
                      sss_ldap_err2string(lret), diag_msg));
            sss_log(SSS_LOG_ERR, "Could not start TLS. %s", diag_msg);
        } else {
            DEBUG(3, ("ldap_start_tls failed: [%s]\n", sss_ldap_err2string(lret)));
            sss_log(SSS_LOG_ERR, "Could not start TLS. "
                                 "Check for certificate issues.");
        }
        goto done;
    }

    lret = ldap_result(ldap, msgid, 1, NULL, &result);
    if (lret != LDAP_RES_EXTENDED) {
        DEBUG(2, ("Unexpected ldap_result, expected [%d] got [%d].\n",
                  LDAP_RES_EXTENDED, lret));
        lret = LDAP_PARAM_ERROR;
        goto done;
    }

    lret = ldap_parse_result(ldap, result, &ldaperr, NULL, &errmsg, NULL, NULL,
                             0);
    if (lret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d) [%d][%s]\n", msgid, lret,
                  sss_ldap_err2string(lret)));
        goto done;
    }

    DEBUG(3, ("START TLS result: %s(%d), %s\n",
              sss_ldap_err2string(ldaperr), ldaperr, errmsg));

    if (ldap_tls_inplace(ldap)) {
        DEBUG(9, ("SSL/TLS handler already in place.\n"));
        lret = LDAP_SUCCESS;
        goto done;
    }

    lret = ldap_install_tls(ldap);
    if (lret != LDAP_SUCCESS) {

        optret = sss_ldap_get_diagnostic_msg(tmp_ctx, ldap, &diag_msg);
        if (optret == LDAP_SUCCESS) {
            DEBUG(3, ("ldap_install_tls failed: [%s] [%s]\n",
                      sss_ldap_err2string(lret), diag_msg));
            sss_log(SSS_LOG_ERR, "Could not start TLS encryption. %s", diag_msg);
        } else {
            DEBUG(3, ("ldap_install_tls failed: [%s]\n",
                      sss_ldap_err2string(lret)));
            sss_log(SSS_LOG_ERR, "Could not start TLS encryption. "
                                 "Check for certificate issues.");
        }

        goto done;
    }

    lret = LDAP_SUCCESS;
done:
    if (result) ldap_msgfree(result);
    if (errmsg) ldap_memfree(errmsg);
    talloc_zfree(tmp_ctx);
    return lret;
}

static int sdap_rebind_proc(LDAP *ldap, LDAP_CONST char *url, ber_tag_t request,
                            ber_int_t msgid, void *params)
{
    struct sdap_rebind_proc_params *p = talloc_get_type(params,
                                                struct sdap_rebind_proc_params);
    const char *sasl_mech;
    const char *user_dn;
    struct berval password = {0, NULL};
    LDAPControl **request_controls = NULL;
    LDAPControl *ctrls[2] = { NULL, NULL };
    TALLOC_CTX *tmp_ctx = NULL;
    struct sasl_bind_state *sasl_bind_state;
    int ret;

    if (p->use_start_tls) {
        ret = synchronous_tls_setup(ldap);
        if (ret != LDAP_SUCCESS) {
            DEBUG(1, ("synchronous_tls_setup failed.\n"));
            return ret;
        }
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return LDAP_NO_MEMORY;
    }

    sasl_mech = dp_opt_get_string(p->opts->basic, SDAP_SASL_MECH);

    if (sasl_mech == NULL) {
        ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                      0, NULL, 0, &ctrls[0]);
        if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
            DEBUG(1, ("sss_ldap_control_create failed to create "
                      "Password Policy control.\n"));
            goto done;
        }
        request_controls = ctrls;

        user_dn = dp_opt_get_string(p->opts->basic, SDAP_DEFAULT_BIND_DN);
        if (user_dn != NULL) {
            ret = sdap_auth_get_authtok(dp_opt_get_string(p->opts->basic,
                                                     SDAP_DEFAULT_AUTHTOK_TYPE),
                                        dp_opt_get_blob(p->opts->basic,
                                                        SDAP_DEFAULT_AUTHTOK),
                                        &password);
            if (ret != EOK) {
                DEBUG(1, ("sdap_auth_get_authtok failed.\n"));
                ret = LDAP_LOCAL_ERROR;
                goto done;
            }
        }

        ret = ldap_sasl_bind_s(ldap, user_dn, LDAP_SASL_SIMPLE, &password,
                               request_controls, NULL, NULL);
        if (ret != LDAP_SUCCESS) {
            DEBUG(1, ("ldap_sasl_bind_s failed (%d)[%s]\n", ret,
                      sss_ldap_err2string(ret)));
        }
    } else {
        sasl_bind_state = talloc_zero(tmp_ctx, struct sasl_bind_state);
        if (sasl_bind_state == NULL) {
            DEBUG(1, ("talloc_zero failed.\n"));
            ret = LDAP_NO_MEMORY;
            goto done;
        }
        sasl_bind_state->sasl_user = dp_opt_get_string(p->opts->basic,
                                                      SDAP_SASL_AUTHID);
        ret = ldap_sasl_interactive_bind_s(ldap, NULL,
                                           sasl_mech, NULL, NULL,
                                           LDAP_SASL_QUIET,
                                           (*sdap_sasl_interact),
                                           sasl_bind_state);
        if (ret != LDAP_SUCCESS) {
            DEBUG(1, ("ldap_sasl_interactive_bind_s failed (%d)[%s]\n", ret,
                      sss_ldap_err2string(ret)));
        }
    }

    DEBUG(7, ("%s bind to [%s].\n",
             (ret == LDAP_SUCCESS ? "Successfully" : "Failed to"), url));

done:
    talloc_free(tmp_ctx);

    return ret;
}
