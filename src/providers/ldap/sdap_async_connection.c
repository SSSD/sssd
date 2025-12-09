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
#include "util/strtonum.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"

#define MAX_RETRY_ATTEMPTS 1

/* ==Connect-to-LDAP-Server=============================================== */

struct sdap_rebind_proc_params {
    struct sdap_options *opts;
    struct sdap_handle *sh;
    bool use_start_tls;
    bool use_ppolicy;
};

enum sdap_rootdse_read_opts {
    SDAP_ROOTDSE_READ_ANONYMOUS,
    SDAP_ROOTDSE_READ_AUTHENTICATED,
    SDAP_ROOTDSE_READ_NEVER,
    SDAP_ROOTDSE_READ_INVALID,
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
                                     struct sockaddr *sockaddr,
                                     socklen_t sockaddr_len,
                                     bool use_start_tls)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_connect_state *state;
    int ret;
    int timeout;

    req = tevent_req_create(memctx, &state, struct sdap_connect_state);
    if (!req) return NULL;

    if (uri == NULL || sockaddr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid uri or sockaddr\n");
        ret = EINVAL;
        goto fail;
    }

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
                                sockaddr_len, timeout);
    if (subreq == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_ldap_init_send failed.\n");
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
    int lret = 0;
    int ret = EOK;
    int msgid;
    bool ldap_referrals;
    const char *ldap_deref;
    int ldap_deref_val;
    struct sdap_rebind_proc_params *rebind_proc_params;
    int sd;
    bool sasl_nocanon;
    const char *sasl_mech;
    int sasl_minssf;
    ber_len_t ber_sasl_minssf;
    int sasl_maxssf;
    ber_len_t ber_sasl_maxssf;
    char *stat_info;

    ret = sss_ldap_init_recv(subreq, &state->sh->ldap, &sd);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sdap_async_connect_call request failed: [%d]: %s.\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = setup_ldap_connection_callbacks(state->sh, state->ev);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setup_ldap_connection_callbacks failed: [%d]: %s.\n",
              ret, sss_strerror(ret));
        goto fail;
    }

    /* If sss_ldap_init_recv() does not return a valid file descriptor we have
     * to assume that the connection callback will be called by internally by
     * the OpenLDAP client library. */
    if (sd != -1) {
        ret = sdap_call_conn_cb(state->uri, sd, state->sh);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sdap_call_conn_cb failed.\n");
            goto fail;
        }
    }

    /* Force ldap version to 3 */
    ver = LDAP_VERSION3;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set ldap version to 3\n");
        goto fail;
    }

    /* TODO: maybe this can be remove when we go async, currently we need it
     * to handle EINTR during poll(). */
    ret = ldap_set_option(state->sh->ldap, LDAP_OPT_RESTART, LDAP_OPT_ON);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set restart option.\n");
    }

    /* Set Network Timeout */
    tv.tv_sec = dp_opt_get_int(state->opts->basic, SDAP_NETWORK_TIMEOUT);
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set network timeout to %d\n",
                  dp_opt_get_int(state->opts->basic, SDAP_NETWORK_TIMEOUT));
        goto fail;
    }

    /* Set Default Timeout */
    tv.tv_sec = dp_opt_get_int(state->opts->basic, SDAP_OPT_TIMEOUT);
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set default timeout to %d\n",
                  dp_opt_get_int(state->opts->basic, SDAP_OPT_TIMEOUT));
        goto fail;
    }

    /* Set Referral chasing */
    ldap_referrals = dp_opt_get_bool(state->opts->basic, SDAP_REFERRALS);
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_REFERRALS,
                           (ldap_referrals ? LDAP_OPT_ON : LDAP_OPT_OFF));
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set referral chasing to %s\n",
                  (ldap_referrals ? "LDAP_OPT_ON" : "LDAP_OPT_OFF"));
        goto fail;
    }

    if (ldap_referrals) {
        rebind_proc_params = talloc_zero(state->sh,
                                         struct sdap_rebind_proc_params);
        if (rebind_proc_params == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto fail;
        }

        rebind_proc_params->opts = state->opts;
        rebind_proc_params->sh = state->sh;
        rebind_proc_params->use_start_tls = state->use_start_tls;
        rebind_proc_params->use_ppolicy = dp_opt_get_bool(state->opts->basic,
                                                          SDAP_USE_PPOLICY);

        lret = ldap_set_rebind_proc(state->sh->ldap, sdap_rebind_proc,
                                    rebind_proc_params);
        if (lret != LDAP_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "ldap_set_rebind_proc failed.\n");
            goto fail;
        }
    }

    /* Set alias dereferencing */
    ldap_deref = dp_opt_get_string(state->opts->basic, SDAP_DEREF);
    if (ldap_deref != NULL) {
        ret = deref_string_to_val(ldap_deref, &ldap_deref_val);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "deref_string_to_val failed.\n");
            goto fail;
        }

        lret = ldap_set_option(state->sh->ldap, LDAP_OPT_DEREF, &ldap_deref_val);
        if (lret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to set deref option to %d\n", ldap_deref_val);
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
              "Failed to set LDAP SASL nocanon option to %s. If your system "
               "is configured to use SASL, LDAP operations might fail.\n",
              sasl_nocanon ? "true" : "false");
        sss_ldap_error_debug(SSSDBG_MINOR_FAILURE, "libldap error", state->sh->ldap, lret);
        sss_log(SSS_LOG_INFO,
                "Failed to set LDAP SASL nocanon option to %s. If your system "
                "is configured to use SASL, LDAP operations might fail.\n",
                sasl_nocanon ? "true" : "false");
    }

    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);
    if (sasl_mech != NULL) {
        sasl_minssf = dp_opt_get_int(state->opts->basic, SDAP_SASL_MINSSF);
        if (sasl_minssf >= 0) {
            ber_sasl_minssf = (ber_len_t)sasl_minssf;
            lret = ldap_set_option(state->sh->ldap, LDAP_OPT_X_SASL_SSF_MIN,
                                   &ber_sasl_minssf);
            if (lret != LDAP_OPT_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set LDAP MIN SSF option "
                                            "to %d\n", sasl_minssf);
                goto fail;
            }
        }

        sasl_maxssf = dp_opt_get_int(state->opts->basic, SDAP_SASL_MAXSSF);
        if (sasl_maxssf >= 0) {
            ber_sasl_maxssf = (ber_len_t)sasl_maxssf;
            lret = ldap_set_option(state->sh->ldap, LDAP_OPT_X_SASL_SSF_MAX,
                                   &ber_sasl_maxssf);
            if (lret != LDAP_OPT_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set LDAP MAX SSF option "
                                            "to %d\n", sasl_maxssf);
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

    DEBUG(SSSDBG_CONF_SETTINGS, "Executing START TLS\n");

    lret = ldap_start_tls(state->sh->ldap, NULL, NULL, &msgid);
    if (lret != LDAP_SUCCESS) {
        sss_ldap_error_debug(SSSDBG_MINOR_FAILURE, "ldap_start_tls failed",
                             state->sh->ldap, lret);
        sss_log(SSS_LOG_ERR, "Could not start TLS.");
        goto fail;
    }

    stat_info = talloc_asprintf(state, "server: [%s] START TLS",
                                sdap_get_server_peer_str_safe(state->sh));
    if (stat_info == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create info string, ignored.\n");
    }

    ret = sdap_set_connected(state->sh, state->ev);
    if (ret) goto fail;

    ret = sdap_op_add(state, state->ev, state->sh, msgid, stat_info,
                      sdap_connect_done, req,
                      dp_opt_get_int(state->opts->basic, SDAP_OPT_TIMEOUT),
                      &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
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
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    ret = ldap_parse_result(state->sh->ldap, state->reply->msg,
                            &state->result, NULL, &errmsg, NULL, NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldap_parse_result failed (%d)\n", sdap_op_get_msgid(state->op));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "START TLS result: %s(%d), %s\n",
              sss_ldap_err2string(state->result), state->result, errmsg);
    ldap_memfree(errmsg);

    if (ldap_tls_inplace(state->sh->ldap)) {
        DEBUG(SSSDBG_TRACE_ALL, "SSL/TLS handler already in place.\n");
        tevent_req_done(req);
        return;
    }

/* FIXME: take care that ldap_install_tls might block */
    ret = ldap_install_tls(state->sh->ldap);
    if (ret != LDAP_SUCCESS) {
        sss_ldap_error_debug(SSSDBG_MINOR_FAILURE, "ldap_install_tls failed",
                             state->sh->ldap, ret);
        sss_log(SSS_LOG_ERR, "Could not start TLS encryption.");
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

struct sdap_connect_host_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    char *uri;
    char *protocol;
    char *host;
    int port;
    bool use_start_tls;

    struct sdap_handle *sh;
};

static void sdap_connect_host_resolv_done(struct tevent_req *subreq);
static void sdap_connect_host_done(struct tevent_req *subreq);

struct tevent_req *sdap_connect_host_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sdap_options *opts,
                                          struct resolv_ctx *resolv_ctx,
                                          enum restrict_family family_order,
                                          enum host_database *host_db,
                                          const char *protocol,
                                          const char *host,
                                          int port,
                                          bool use_start_tls)
{
    struct sdap_connect_host_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_connect_host_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->port = port;
    state->use_start_tls = use_start_tls;

    state->protocol = talloc_strdup(state, protocol);
    if (state->protocol == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->host = talloc_strdup(state, host);
    if (state->host == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->uri = talloc_asprintf(state, "%s://%s:%d", protocol, host, port);
    if (state->uri == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Resolving host %s\n", host);

    subreq = resolv_gethostbyname_send(state, state->ev, resolv_ctx,
                                       host, family_order, host_db);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_connect_host_resolv_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void sdap_connect_host_resolv_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_connect_host_state *state = NULL;
    struct resolv_hostent *hostent = NULL;
    struct sockaddr *sockaddr = NULL;
    socklen_t sockaddr_len;
    int status;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_connect_host_state);

    ret = resolv_gethostbyname_recv(subreq, state, &status, NULL, &hostent);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to resolve host %s: %s\n",
                                  state->host, resolv_strerror(status));
        goto done;
    }

    sockaddr = resolv_get_sockaddr_address(state, hostent, state->port,
                                           &sockaddr_len);
    if (sockaddr == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "resolv_get_sockaddr_address() failed\n");
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Connecting to %s\n", state->uri);

    subreq = sdap_connect_send(state, state->ev, state->opts,
                               state->uri, sockaddr, sockaddr_len,
                               state->use_start_tls);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_connect_host_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void sdap_connect_host_done(struct tevent_req *subreq)
{
    struct sdap_connect_host_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_connect_host_state);

    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    /* if TLS was used, the sdap handle is already marked as connected */
    if (!state->use_start_tls) {
        /* we need to mark handle as connected to allow anonymous bind */
        ret = sdap_set_connected(state->sh, state->ev);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sdap_set_connected() failed\n");
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Successful connection to %s\n", state->uri);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t sdap_connect_host_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               struct sdap_handle **_sh)
{
    struct sdap_connect_host_state *state = NULL;
    state = tevent_req_data(req, struct sdap_connect_host_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_sh = talloc_steal(mem_ctx, state->sh);

    return EOK;
}


/* ==Simple-Bind========================================================== */

struct simple_bind_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    const char *user_dn;
    enum pwmodify_mode pwmodify_mode;

    struct sdap_op *op;

    struct sdap_msg *reply;
    struct sdap_ppolicy_data *ppolicy;
};

static void simple_bind_done(struct sdap_op *op,
                             struct sdap_msg *reply,
                             int error, void *pvt);

static struct tevent_req *simple_bind_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           int timeout,
                                           const char *user_dn,
                                           struct berval *pw,
                                           bool use_ppolicy,
                                           enum pwmodify_mode pwmodify_mode)
{
    struct tevent_req *req;
    struct simple_bind_state *state;
    int ret = EOK;
    int msgid;
    int ldap_err;
    LDAPControl **request_controls = NULL;
    LDAPControl *ctrls[2] = { NULL, NULL };
    char *stat_info;

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
    state->pwmodify_mode = pwmodify_mode;

    if (use_ppolicy) {
        ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                      0, NULL, 0, &ctrls[0]);
        if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_ldap_control_create failed to create "
                                       "Password Policy control.\n");
            goto fail;
        }
        request_controls = ctrls;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Executing simple bind as: %s\n", state->user_dn);

    ret = ldap_sasl_bind(state->sh->ldap, state->user_dn, LDAP_SASL_SIMPLE,
                         pw, request_controls, NULL, &msgid);
    if (ctrls[0]) ldap_control_free(ctrls[0]);
    if (ret == -1 || msgid == -1) {
        ret = ldap_get_option(state->sh->ldap,
                              LDAP_OPT_RESULT_CODE, &ldap_err);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_sasl_bind failed (couldn't get ldap error)\n");
            ret = LDAP_LOCAL_ERROR;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "ldap_sasl_bind failed (%d)[%s]\n",
                      ldap_err, sss_ldap_err2string(ldap_err));
            ret = ldap_err;
        }
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "ldap simple bind sent, msgid = %d\n", msgid);

    if (!sh->connected) {
        ret = sdap_set_connected(sh, ev);
        if (ret) goto fail;
    }

    stat_info = talloc_asprintf(state, "server: [%s] simple bind: [%s]",
                                sdap_get_server_peer_str_safe(state->sh),
                                state->user_dn);
    if (stat_info == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create info string, ignored.\n");
    }

    ret = sdap_op_add(state, ev, sh, msgid, stat_info,
                      simple_bind_done, req, timeout, &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
        goto fail;
    }

    return req;

fail:
    if (ret == LDAP_SERVER_DOWN) {
        tevent_req_error(req, ETIMEDOUT);
    } else {
        tevent_req_error(req, ERR_NETWORK_IO);
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
    char *nval;
    errno_t ret = ERR_INTERNAL;
    int lret;
    LDAPControl **response_controls;
    int c;
    ber_int_t pp_grace;
    ber_int_t pp_expire;
    LDAPPasswordPolicyError pp_error;
    int result = LDAP_OTHER;
    bool on_grace_login_limit = false;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    lret = ldap_parse_result(state->sh->ldap, state->reply->msg,
                            &result, NULL, &errmsg, NULL,
                            &response_controls, 0);
    if (lret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldap_parse_result failed (%d)\n", sdap_op_get_msgid(state->op));
        ret = ERR_INTERNAL;
        goto done;
    }

    if (result == LDAP_SUCCESS) {
        ret = EOK;
    } else if (result == LDAP_INVALID_CREDENTIALS
                   && errmsg != NULL && strstr(errmsg, "data 775,") != NULL) {
        /* Value 775 is described in
         * https://msdn.microsoft.com/en-us/library/windows/desktop/ms681386%28v=vs.85%29.aspx
         * for more details please see commit message. */
        ret = ERR_ACCOUNT_LOCKED;
    } else {
        ret = ERR_AUTH_FAILED;
    }

    if (response_controls == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "Server returned no controls.\n");
        state->ppolicy = NULL;
    } else {
        for (c = 0; response_controls[c] != NULL; c++) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Server returned control [%s].\n",
                   response_controls[c]->ldctl_oid);

            if (strcmp(response_controls[c]->ldctl_oid,
                       LDAP_CONTROL_PASSWORDPOLICYRESPONSE) == 0) {
                lret = ldap_parse_passwordpolicy_control(state->sh->ldap,
                                                        response_controls[c],
                                                        &pp_expire, &pp_grace,
                                                        &pp_error);
                if (lret != LDAP_SUCCESS) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "ldap_parse_passwordpolicy_control failed.\n");
                    ret = ERR_INTERNAL;
                    goto done;
                }

                DEBUG(SSSDBG_TRACE_LIBS,
                      "Password Policy Response: expire [%d] grace [%d] "
                          "error [%s].\n", pp_expire, pp_grace,
                          ldap_passwordpolicy_err2txt(pp_error));
                if (!state->ppolicy)
                    state->ppolicy = talloc_zero(state,
                                                 struct sdap_ppolicy_data);
                if (state->ppolicy == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                state->ppolicy->grace = pp_grace;
                state->ppolicy->expire = pp_expire;
                if (result == LDAP_SUCCESS) {
                    /* We have to set the on_grace_login_limit as when going
                     * through the response controls 389-ds may return both
                     * an warning and an error (and the order is not ensured)
                     * for the GraceLimit:
                     * - [1.3.6.1.4.1.42.2.27.8.5.1] for the GraceLimit itself
                     * - [2.16.840.1.113730.3.4.4] for the PasswordExpired
                     *
                     * So, in order to avoid bulldozing the GraceLimit, let's
                     * set it to true when pp_grace >= 0 and, in the end of
                     * this function, just return EOK when LDAP returns the
                     * PasswordExpired error but the GraceLimit is still valid.
                     */
                    on_grace_login_limit = false;
                    if (pp_error == PP_changeAfterReset) {
                        DEBUG(SSSDBG_TRACE_LIBS,
                              "Password was reset. "
                               "User must set a new password.\n");
                        ret = ERR_PASSWORD_EXPIRED;
                    } else if (pp_grace >= 0) {
                        on_grace_login_limit = true;
                        DEBUG(SSSDBG_TRACE_LIBS,
                              "Password expired. "
                               "[%d] grace logins remaining.\n",
                               pp_grace);
                    } else if (pp_expire > 0) {
                        DEBUG(SSSDBG_TRACE_LIBS,
                              "Password will expire in [%d] seconds.\n",
                               pp_expire);
                    }
                } else if (result == LDAP_INVALID_CREDENTIALS &&
                           pp_error == PP_passwordExpired) {
                    /* According to
                     * https://www.ietf.org/archive/id/draft-behera-ldap-password-policy-11.txt
                     * section 8.1.2.3.2. this condition means "No Remaining
                     * Grace Authentications". */
                    DEBUG(SSSDBG_TRACE_LIBS,
                          "Password expired, grace logins exhausted.\n");
                    if (state->pwmodify_mode == SDAP_PWMODIFY_EXOP_FORCE) {
                        DEBUG(SSSDBG_TRACE_LIBS, "Password change forced.\n");
                        ret = ERR_PASSWORD_EXPIRED;
                    } else {
                        ret = ERR_AUTH_FAILED;
                    }
                }
            } else if (strcmp(response_controls[c]->ldctl_oid,
                              LDAP_CONTROL_PWEXPIRED) == 0) {
                /* I haven't found a proper documentation of this control only
                 * the Red Hat Directory Server documentation has a short
                 * description in the section "Understanding Password
                 * Expiration Controls", e.g.
                 * https://access.redhat.com/documentation/en-us/red_hat_directory_server/11/html/administration_guide/understanding_password_expiration_controls
                 */
                if (result == LDAP_INVALID_CREDENTIALS) {
                    DEBUG(SSSDBG_TRACE_LIBS,
                          "Password expired, grace logins exhausted.\n");
                    if (state->pwmodify_mode == SDAP_PWMODIFY_EXOP_FORCE) {
                        DEBUG(SSSDBG_TRACE_LIBS, "Password change forced.\n");
                        ret = ERR_PASSWORD_EXPIRED;
                    } else {
                        ret = ERR_AUTH_FAILED;
                    }
                } else {
                    DEBUG(SSSDBG_TRACE_LIBS,
                          "Password expired, user must set a new password.\n");
                    ret = ERR_PASSWORD_EXPIRED;
                }
            } else if (strcmp(response_controls[c]->ldctl_oid,
                              LDAP_CONTROL_PWEXPIRING) == 0) {
                /* ignore controls with suspiciously long values */
                if (response_controls[c]->ldctl_value.bv_len > 32) {
                    continue;
                }

                if (!state->ppolicy) {
                    state->ppolicy = talloc(state, struct sdap_ppolicy_data);
                }

                if (state->ppolicy == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                /* ensure that bv_val is a null-terminated string */
                nval = talloc_strndup(NULL,
                                      response_controls[c]->ldctl_value.bv_val,
                                      response_controls[c]->ldctl_value.bv_len);
                if (nval == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                state->ppolicy->expire = strtouint32(nval, NULL, 10);
                lret = errno;
                talloc_zfree(nval);
                if (lret != EOK) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "Couldn't convert control response "
                           "to an integer [%s].\n", strerror(lret));
                    ret = ERR_INTERNAL;
                    goto done;
                }

                DEBUG(SSSDBG_TRACE_LIBS,
                      "Password will expire in [%d] seconds.\n",
                       state->ppolicy->expire);
            }
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Bind result: %s(%d), %s\n",
              sss_ldap_err2string(result), result,
              errmsg ? errmsg : "no errmsg set");

    if (result != LDAP_SUCCESS && ret == EOK) {
        ret = ERR_AUTH_FAILED;
    }

    if (ret == ERR_PASSWORD_EXPIRED && on_grace_login_limit) {
        ret = EOK;
    }

done:
    ldap_controls_free(response_controls);
    ldap_memfree(errmsg);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static errno_t simple_bind_recv(struct tevent_req *req,
                                TALLOC_CTX *memctx,
                                struct sdap_ppolicy_data **ppolicy)
{
    struct simple_bind_state *state = tevent_req_data(req,
                                            struct simple_bind_state);

    if (ppolicy != NULL) {
        *ppolicy = talloc_steal(memctx, state->ppolicy);
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==SASL-Bind============================================================ */

struct sasl_bind_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;

    const char *sasl_mech;
    const char *sasl_user;
    struct berval *sasl_cred;
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

    DEBUG(SSSDBG_CONF_SETTINGS, "Executing sasl bind mech: %s, user: %s\n",
              sasl_mech, sasl_user);

    /* FIXME: Warning, this is a sync call!
     * No async variant exist in openldap libraries yet */

    if (state->sh == NULL || state->sh->ldap == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Trying LDAP search while not connected.\n");
        ret = ERR_NETWORK_IO;
        goto fail;
    }

    ret = ldap_sasl_interactive_bind_s(state->sh->ldap, NULL,
                                       sasl_mech, NULL, NULL,
                                       LDAP_SASL_QUIET,
                                       (*sdap_sasl_interact), state);
    if (ret != LDAP_SUCCESS) {
        sss_ldap_error_debug(SSSDBG_CRIT_FAILURE, "ldap_sasl_interactive_bind_s failed",
                             state->sh->ldap, ret);
        goto fail;
    }

    if (!sh->connected) {
        ret = sdap_set_connected(sh, ev);
        if (ret) goto fail;
    }

    /* This is a hack, relies on the fact that tevent_req_done() will always
     * set the state but will not complain if no callback has been set.
     * tevent_req_post() will only set the immediate event and then just call
     * the async callback set by the caller right after we return using the
     * state value set previously by tevent_req_done() */
    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;

fail:
    if (ret == LDAP_SERVER_DOWN || ret == LDAP_TIMEOUT) {
        tevent_req_error(req, ETIMEDOUT);
    } else {
        tevent_req_error(req, ERR_AUTH_FAILED);
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

static errno_t sasl_bind_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

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
    time_t expire_time;
};

static void sdap_kinit_done(struct tevent_req *subreq);
static struct tevent_req *sdap_kinit_next_kdc(struct tevent_req *req);
static void sdap_kinit_kdc_resolved(struct tevent_req *subreq);

static
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

    DEBUG(SSSDBG_TRACE_FUNC, "Attempting kinit (%s, %s, %s, %d)\n",
              keytab ? keytab : "default",
              principal, realm, lifetime);

    if (lifetime < 0 || lifetime > INT32_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Ticket lifetime out of range.\n");
        return NULL;
    }

    req = tevent_req_create(memctx, &state, struct sdap_kinit_state);
    if (!req) return NULL;

    state->keytab = keytab;
    state->principal = principal;
    state->realm = realm;
    state->ev = ev;
    state->be = be;
    state->timeout = timeout;
    state->lifetime = lifetime;
    state->krb_service_name = krb_service_name;

    if (canonicalize) {
        ret = setenv("KRB5_CANONICALIZE", "true", 1);
    } else {
        ret = setenv("KRB5_CANONICALIZE", "false", 1);
    }
    if (ret == -1) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set KRB5_CANONICALIZE to %s\n",
                  ((canonicalize)?"true":"false"));
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

    DEBUG(SSSDBG_TRACE_LIBS,
          "Resolving next KDC for service %s\n", state->krb_service_name);

    next_req = be_resolve_server_send(state, state->ev,
                                      state->be,
                                      state->krb_service_name,
                                      state->kdc_srv == NULL ? true : false);
    if (next_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_resolve_server_send failed.\n");
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

    ret = be_resolve_server_recv(subreq, state, &state->kdc_srv);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, ERR_NETWORK_IO);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "KDC resolved, attempting to get TGT...\n");

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
    time_t expire_time = 0;
    krb5_error_code kerr;
    struct tevent_req *nextreq;

    ret = sdap_get_tgt_recv(subreq, state, &result,
                            &kerr, &ccname, &expire_time);
    talloc_zfree(subreq);
    if (ret == ETIMEDOUT) {
        /* The child didn't even respond. Perhaps the KDC is too busy,
         * retry with another KDC */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Communication with KDC timed out, trying the next one\n");
        be_fo_set_port_status(state->be, state->krb_service_name,
                              state->kdc_srv, PORT_NOT_WORKING);
        nextreq = sdap_kinit_next_kdc(req);
        if (!nextreq) {
            tevent_req_error(req, ENOMEM);
        }
        return;
    } else if (ret != EOK) {
        /* A severe error while executing the child. Abort the operation. */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "child failed (%d [%s])\n", ret, strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (result == EOK) {
        ret = setenv("KRB5CCNAME", ccname, 1);
        if (ret == -1) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unable to set env. variable KRB5CCNAME!\n");
            tevent_req_error(req, ERR_AUTH_FAILED);
            return;
        }

        state->expire_time = expire_time;
        tevent_req_done(req);
        return;
    } else {
        if (kerr == KRB5_KDC_UNREACH) {
            be_fo_set_port_status(state->be, state->krb_service_name,
                                  state->kdc_srv, PORT_NOT_WORKING);
            nextreq = sdap_kinit_next_kdc(req);
            if (!nextreq) {
                tevent_req_error(req, ENOMEM);
            }
            return;
        }

    }
    if (result == EFAULT || result == EIO || result == EPERM) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Could not get TGT from server %s: %d [%s]\n",
              state->kdc_srv ? fo_get_server_name(state->kdc_srv) : "NULL",
              result, sss_strerror(result));
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Could not get TGT: %d [%s]\n", result, sss_strerror(result));
    }
    tevent_req_error(req, ERR_AUTH_FAILED);
}

static errno_t sdap_kinit_recv(struct tevent_req *req,
                               time_t *expire_time)
{
    struct sdap_kinit_state *state = tevent_req_data(req,
                                                     struct sdap_kinit_state);
    enum tevent_req_state tstate;
    uint64_t err_uint64 = ERR_INTERNAL;
    errno_t err;

    if (tevent_req_is_error(req, &tstate, &err_uint64)) {
        if (tstate != TEVENT_REQ_IN_PROGRESS) {
            err = (errno_t)err_uint64;
            if (err == EOK) {
                return ERR_INTERNAL;
            }
            return err;
        }
    }

    *expire_time = state->expire_time;
    return EOK;
}


/* ==Authenticaticate-User-by-DN========================================== */

struct sdap_auth_state {
    struct sdap_ppolicy_data *ppolicy;
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
                                  struct sss_auth_token *authtok,
                                  int simple_bind_timeout,
                                  bool use_ppolicy,
                                  enum pwmodify_mode pwmodify_mode)
{
    struct tevent_req *req, *subreq;
    struct sdap_auth_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_auth_state);
    if (!req) return NULL;

    if (sasl_mech) {
        state->is_sasl = true;
        subreq = sasl_bind_send(state, ev, sh, sasl_mech, sasl_user, NULL);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return tevent_req_post(req, ev);
        }
    } else {
        const char *password = NULL;
        struct berval pw;
        size_t pwlen;
        errno_t ret;

        /* this code doesn't make copies of password
         * but only uses pointer to authtok internals
         */
        ret = sss_authtok_get_password(authtok, &password, &pwlen);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot parse authtok.\n");
            tevent_req_error(req, ret);
            return tevent_req_post(req, ev);
        }
        /* Treat a zero-length password as a failure */
        if (*password == '\0') {
            tevent_req_error(req, ENOENT);
            return tevent_req_post(req, ev);
        }
        pw.bv_val = discard_const(password);
        pw.bv_len = pwlen;

        state->is_sasl = false;
        subreq = simple_bind_send(state, ev, sh, simple_bind_timeout, user_dn, &pw, use_ppolicy, pwmodify_mode);
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
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Authentication token type [%s] is not supported\n",
                  authtok_type);
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
        ret = sasl_bind_recv(subreq);
        state->ppolicy = NULL;
    } else {
        ret = simple_bind_recv(subreq, state, &state->ppolicy);
    }

    if (tevent_req_error(req, ret)) {
        return;
    }

    tevent_req_done(req);
}

errno_t sdap_auth_recv(struct tevent_req *req,
                       TALLOC_CTX *memctx,
                       struct sdap_ppolicy_data **ppolicy)
{
    struct sdap_auth_state *state = tevent_req_data(req,
                                                 struct sdap_auth_state);

    if (ppolicy != NULL) {
        *ppolicy = talloc_steal(memctx, state->ppolicy);
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==Client connect============================================ */

struct sdap_cli_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    const char *uri;
    struct sockaddr *sockaddr;
    socklen_t sockaddr_len;

    bool use_rootdse;
    enum sdap_rootdse_read_opts rootdse_access;
    struct sysdb_attrs *rootdse;

    struct sdap_handle *sh;

    struct sdap_server_opts *srv_opts;

    enum connect_tls force_tls;
    bool do_auth;
    bool use_tls;
    time_t kinit_expire_time;

    int retry_attempts;
};

static int sdap_cli_connect_step(struct tevent_req *req);
static void sdap_cli_connect_done(struct tevent_req *subreq);
static void sdap_cli_rootdse_step(struct tevent_req *req);
static void sdap_cli_rootdse_done(struct tevent_req *subreq);
static errno_t sdap_cli_use_rootdse(struct sdap_cli_connect_state *state);
static void sdap_cli_auth_step(struct tevent_req *req);
static void sdap_cli_auth_done(struct tevent_req *subreq);
static errno_t sdap_cli_auth_reconnect(struct tevent_req *subreq);
static void sdap_cli_auth_reconnect_done(struct tevent_req *subreq);
static void sdap_cli_rootdse_auth_done(struct tevent_req *subreq);


enum sdap_rootdse_read_opts
decide_rootdse_access(struct dp_option *basic)
{
    int i;
    char *str;
    struct read_rootdse_enum_str {
        enum sdap_rootdse_read_opts option_enum;
        const char *option_str;
    };
    static struct read_rootdse_enum_str read_rootdse_enum_str[] = {
        { SDAP_ROOTDSE_READ_ANONYMOUS, "anonymous"},
        { SDAP_ROOTDSE_READ_AUTHENTICATED, "authenticated"},
        { SDAP_ROOTDSE_READ_NEVER, "never"},
        { SDAP_ROOTDSE_READ_INVALID, NULL}
    };

    str = dp_opt_get_string (basic, SDAP_READ_ROOTDSE);
    for (i = 0; read_rootdse_enum_str[i].option_str != NULL; i++) {
        if (strcasecmp(read_rootdse_enum_str[i].option_str, str) == 0) {
            return read_rootdse_enum_str[i].option_enum;
        }
    }
    DEBUG(SSSDBG_CONF_SETTINGS,
          "The ldap_read_rootdse option has an invalid value [%s], "
          "using [anonymous]\n", str);
    return SDAP_ROOTDSE_READ_ANONYMOUS;
}

static errno_t
decide_tls_usage(enum connect_tls force_tls, struct dp_option *basic,
                 const char *uri, bool *_use_tls)
{
    bool use_tls = true;

    switch (force_tls) {
    case CON_TLS_DFL:
        use_tls = dp_opt_get_bool(basic, SDAP_ID_TLS);
        break;
    case CON_TLS_ON:
        use_tls = true;
        break;
    case CON_TLS_OFF:
        use_tls = false;
        break;
    default:
        return EINVAL;
        break;
    }

    if (use_tls && sdap_is_secure_uri(uri)) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "[%s] is a secure channel. No need to run START_TLS\n", uri);
        use_tls = false;
    }

    *_use_tls = use_tls;
    return EOK;
}

struct tevent_req *sdap_cli_connect_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         const char *uri,
                                         struct sockaddr *sockaddr,
                                         socklen_t sockaddr_len,
                                         bool skip_rootdse,
                                         enum connect_tls force_tls,
                                         bool skip_auth,
                                         time_t kinit_expire_time)
{
    struct sdap_cli_connect_state *state;
    struct tevent_req *req;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_cli_connect_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->uri = uri;
    state->sockaddr = sockaddr;
    state->sockaddr_len = sockaddr_len;
    state->srv_opts = NULL;
    state->use_rootdse = !skip_rootdse;
    state->rootdse_access = decide_rootdse_access(opts->basic);
    state->force_tls = force_tls;
    state->do_auth = !skip_auth;
    state->kinit_expire_time = kinit_expire_time;

    ret = sdap_cli_connect_step(req);
    if (ret) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static int sdap_cli_connect_step(struct tevent_req *req)
{
    struct sdap_cli_connect_state *state;
    struct tevent_req *subreq;
    errno_t ret;

    state = tevent_req_data(req, struct sdap_cli_connect_state);

    ret = decide_tls_usage(state->force_tls, state->opts->basic,
                           state->uri, &state->use_tls);

    if (ret != EOK) {
        return EINVAL;
    }

    subreq = sdap_connect_send(state, state->ev, state->opts,
                               state->uri,
                               state->sockaddr,
                               state->sockaddr_len,
                               state->use_tls);
    if (!subreq) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_cli_connect_done, req);
    return EOK;
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
    if (ret == ERR_TLS_HANDSHAKE_INTERRUPTED &&
        state->retry_attempts < MAX_RETRY_ATTEMPTS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "TLS handshake was interruped, provider will retry\n");
        state->retry_attempts++;
        subreq = sdap_connect_send(state, state->ev, state->opts,
                                   state->uri,
                                   state->sockaddr,
                                   state->sockaddr_len,
                                   state->use_tls);

        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        tevent_req_set_callback(subreq, sdap_cli_connect_done, req);
        return;
    } else if (ret != EOK) {
        state->retry_attempts = 0;
        /* retry another server */
        tevent_req_error(req, ERR_SERVER_FAILURE);
        return;
    }
    state->retry_attempts = 0;

    if (state->use_rootdse &&
        state->rootdse_access == SDAP_ROOTDSE_READ_ANONYMOUS) {

        /* fetch the rootDSE this time */
        sdap_cli_rootdse_step(req);
        return;
    }

    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);

    if (state->do_auth && sasl_mech && state->use_rootdse &&
        state->rootdse_access == SDAP_ROOTDSE_READ_ANONYMOUS) {

        /* check if server claims to support the configured SASL MECH */
        if (!sdap_is_sasl_mech_supported(state->sh, sasl_mech)) {
            tevent_req_error(req, ENOTSUP);
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
            tevent_req_error(req, ERR_SERVER_FAILURE);
            return;
        }

        /* RootDSE was not available on
         * the server.
         * Continue, and just assume that the
         * features requested by the config
         * work properly.
         */
        state->rootdse = NULL;
    }


    ret = sdap_cli_use_rootdse(state);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_cli_use_rootdse failed\n");
        tevent_req_error(req, ret);
        return;
    }

    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);

    if (state->do_auth && sasl_mech && state->rootdse) {
        /* check if server claims to support the configured SASL MECH */
        if (!sdap_is_sasl_mech_supported(state->sh, sasl_mech)) {
            tevent_req_error(req, ENOTSUP);
            return;
        }
    }

    sdap_cli_auth_step(req);
}

static errno_t sdap_cli_use_rootdse(struct sdap_cli_connect_state *state)
{
    errno_t ret;

    if (state->rootdse) {
        /* save rootdse data about supported features */
        ret = sdap_set_rootdse_supported_lists(state->rootdse, state->sh);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_set_rootdse_supported_lists failed\n");
            return ret;
        }

        ret = sdap_set_config_options_with_rootdse(state->rootdse, state->opts,
                                                   state->opts->sdom);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_set_config_options_with_rootdse failed.\n");
            return ret;
        }

    }

    ret = sdap_get_server_opts_from_rootdse(state,
                                            state->uri,
                                            state->rootdse,
                                            state->opts, &state->srv_opts);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_get_server_opts_from_rootdse failed.\n");
        return ret;
    }

    return EOK;
}

static void sdap_cli_auth_step(struct tevent_req *req)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    struct tevent_req *subreq;
    time_t now;
    int expire_timeout;
    int expire_offset;

    const char *sasl_mech = dp_opt_get_string(state->opts->basic,
                                              SDAP_SASL_MECH);
    const char *user_dn = dp_opt_get_string(state->opts->basic,
                                            SDAP_DEFAULT_BIND_DN);
    const char *authtok_type;
    struct dp_opt_blob authtok_blob;
    struct sss_auth_token *authtok;
    errno_t ret;

    /* It's possible that connection was terminated by server (e.g. #2435),
       to overcome this try to connect again. */
    if (state->sh == NULL || !state->sh->connected) {
        DEBUG(SSSDBG_TRACE_FUNC, "No connection available. "
              "Trying to reconnect.\n");
        ret = sdap_cli_auth_reconnect(req);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "sdap_cli_auth_reconnect failed: %d:[%s]\n",
                  ret, sss_strerror(ret));
            tevent_req_error(req, ret);
        }
        return;
    }

    /* Set the LDAP expiration time
     * If SASL has already set it, use the sooner of the two
     */
    state->sh->expire_time = state->kinit_expire_time;
    now = time(NULL);
    expire_timeout = dp_opt_get_int(state->opts->basic, SDAP_EXPIRE_TIMEOUT);
    expire_offset = dp_opt_get_int(state->opts->basic, SDAP_EXPIRE_OFFSET);
    if (expire_offset > 0) {
        expire_timeout += sss_rand() % (expire_offset + 1);
    } else if (expire_offset < 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Negative value [%d] of ldap_connection_expire_offset "
              "is not allowed.\n",
              expire_offset);
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "expire timeout is %d\n", expire_timeout);
    if (!state->sh->expire_time
            || (state->sh->expire_time > (now + expire_timeout))) {
        state->sh->expire_time = now + expire_timeout;
        DEBUG(SSSDBG_TRACE_LIBS,
              "the connection will expire at %"SPRItime"\n",
              state->sh->expire_time);
    }

    if (!state->do_auth ||
        (sasl_mech == NULL && user_dn == NULL)) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "No authentication requested or SASL auth forced off\n");
        tevent_req_done(req);
        return;
    }

    authtok_type = dp_opt_get_string(state->opts->basic,
                                     SDAP_DEFAULT_AUTHTOK_TYPE);
    authtok = sss_authtok_new(state);
    if(authtok == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    if (authtok_type != NULL) {
        if (strcasecmp(authtok_type, "password") != 0) {
            DEBUG(SSSDBG_TRACE_LIBS, "Invalid authtoken type\n");
            tevent_req_error(req, EINVAL);
            return;
        }

        authtok_blob = dp_opt_get_blob(state->opts->basic,
                                       SDAP_DEFAULT_AUTHTOK);
        if (authtok_blob.data) {
            ret = sss_authtok_set_password(authtok,
                                        (const char *)authtok_blob.data,
                                        authtok_blob.length);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
        }
    }

    subreq = sdap_auth_send(state, state->ev,
                            state->sh, sasl_mech,
                            dp_opt_get_string(state->opts->basic,
                                              SDAP_SASL_AUTHID),
                            user_dn, authtok,
                            dp_opt_get_int(state->opts->basic,
                                           SDAP_OPT_TIMEOUT),
                            dp_opt_get_bool(state->opts->basic,
                                            SDAP_USE_PPOLICY),
                            state->opts->pwmodify_mode);
    talloc_free(authtok);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_cli_auth_done, req);
}

static errno_t sdap_cli_auth_reconnect(struct tevent_req *req)
{
    struct sdap_cli_connect_state *state;
    struct tevent_req *subreq;
    errno_t ret;

    state = tevent_req_data(req, struct sdap_cli_connect_state);

    ret = decide_tls_usage(state->force_tls, state->opts->basic,
                           state->uri, &state->use_tls);
    if (ret != EOK) {
        goto done;
    }

    subreq = sdap_connect_send(state, state->ev, state->opts,
                               state->uri,
                               state->sockaddr,
                               state->sockaddr_len,
                               state->use_tls);

    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_cli_auth_reconnect_done, req);

    ret = EOK;

done:
    return ret;
}

static void sdap_cli_auth_reconnect_done(struct tevent_req *subreq)
{
    struct sdap_cli_connect_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_cli_connect_state);

    talloc_zfree(state->sh);

    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    /* if TLS was used, the sdap handle is already marked as connected */
    if (!state->use_tls) {
        /* we need to mark handle as connected to allow anonymous bind */
        ret = sdap_set_connected(state->sh, state->ev);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sdap_set_connected() failed.\n");
            goto done;
        }
    }

    /* End request if reconnecting failed to avoid endless loop */
    if (state->sh == NULL || !state->sh->connected) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to reconnect.\n");
        ret = EIO;
        goto done;
    }

    sdap_cli_auth_step(req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void sdap_cli_auth_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);
    int ret;

    ret = sdap_auth_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->use_rootdse && !state->rootdse &&
        state->rootdse_access != SDAP_ROOTDSE_READ_NEVER) {
        /* We did not read rootDSE during unauthenticated bind becase
         * it is unaccessible for anonymous user or because
         * ldap_read_rootdse is set to "authenticated"
         * Let's try to read it now */
        subreq = sdap_get_rootdse_send(state, state->ev,
                                       state->opts, state->sh);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_cli_rootdse_auth_done, req);
        return;
    }

    tevent_req_done(req);
}

static void sdap_cli_rootdse_auth_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);

    ret = sdap_get_rootdse_recv(subreq, state, &state->rootdse);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ETIMEDOUT) {
            /* The server we authenticated against went down. Retry another
             * one */
            tevent_req_error(req, ERR_SERVER_FAILURE);
            return;
        }

        /* RootDSE was not available on
         * the server.
         * Continue, and just assume that the
         * features requested by the config
         * work properly.
         */
        state->use_rootdse = false;
        state->rootdse = NULL;
        tevent_req_done(req);
        return;
    }

    /* We were able to get rootDSE after authentication */
    ret = sdap_cli_use_rootdse(state);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_cli_use_rootdse failed\n");
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_cli_connect_recv(struct tevent_req *req,
                          TALLOC_CTX *memctx,
                          struct sdap_handle **gsh,
                          struct sdap_server_opts **srv_opts)
{
    struct sdap_cli_connect_state *state = tevent_req_data(req,
                                             struct sdap_cli_connect_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

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

struct sdap_cli_resolve_and_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_service *service;
    struct be_ctx *be;

    bool use_rootdse;
    struct sysdb_attrs *rootdse;

    struct sdap_handle *sh;

    struct fo_server *srv;

    struct sdap_server_opts *srv_opts;

    enum connect_tls force_tls;
    bool do_auth;

    bool can_retry;
    time_t kinit_expire_time;
};

static errno_t sdap_cli_resolve_and_connect_kinit_step(struct tevent_req *req);
static void sdap_cli_resolve_and_connect_kinit_done(struct tevent_req *subreq);
static errno_t sdap_cli_resolve_and_connect_next_server(struct tevent_req *req);
static void sdap_cli_resolve_and_connect_next_server_done(struct tevent_req *subreq);
static void sdap_cli_resolve_and_connect_done(struct tevent_req *subreq);

struct tevent_req *
sdap_cli_resolve_and_connect_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sdap_options *opts,
                                  struct be_ctx *be,
                                  struct sdap_service *service,
                                  bool skip_rootdse,
                                  enum connect_tls force_tls,
                                  bool skip_auth)
{
    struct sdap_cli_resolve_and_connect_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_cli_resolve_and_connect_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->service = service;
    state->be = be;
    state->srv = NULL;
    state->srv_opts = NULL;
    state->use_rootdse = !skip_rootdse;
    state->force_tls = force_tls;
    state->do_auth = !skip_auth;
    state->can_retry = true;

    ret = sdap_cli_resolve_and_connect_kinit_step(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t sdap_cli_resolve_and_connect_kinit_step(struct tevent_req *req)
{
    struct sdap_cli_resolve_and_connect_state *state;
    struct tevent_req *subreq;
    const char *sasl_mech;

    state = tevent_req_data(req, struct sdap_cli_resolve_and_connect_state);
    sasl_mech = dp_opt_get_string(state->opts->basic, SDAP_SASL_MECH);

    if (!state->do_auth || sasl_mech == NULL
        || !sdap_sasl_mech_needs_kinit(sasl_mech)
        || !dp_opt_get_bool(state->opts->basic, SDAP_KRB5_KINIT)) {
        /* kinit is not needed, skip this step */
        return sdap_cli_resolve_and_connect_next_server(req);
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
                             sdap_gssapi_realm(state->opts->basic),
                             dp_opt_get_bool(state->opts->basic,
                                             SDAP_KRB5_CANONICALIZE),
                             dp_opt_get_int(state->opts->basic,
                                            SDAP_KRB5_TICKET_LIFETIME));
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_cli_resolve_and_connect_kinit_done, req);
    return EOK;
}

static void sdap_cli_resolve_and_connect_kinit_done(struct tevent_req *subreq)
{
    struct sdap_cli_resolve_and_connect_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_cli_resolve_and_connect_state);

    ret = sdap_kinit_recv(subreq, &state->kinit_expire_time);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* We're not able to authenticate to the LDAP server.
         * There's not much we can do except for going offline */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Cannot get a TGT: ret [%d](%s)\n", ret, sss_strerror(ret));
        tevent_req_error(req, EACCES);
        return;
    }

    ret = sdap_cli_resolve_and_connect_next_server(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static errno_t sdap_cli_resolve_and_connect_next_server(struct tevent_req *req)
{
    struct sdap_cli_resolve_and_connect_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sdap_cli_resolve_and_connect_state);

    /* Before stepping to next server  destroy any connection from previous
     * attempt */
    talloc_zfree(state->sh);

    /* NOTE: this call may cause service->uri to be refreshed
     * with a new valid server. Do not use service->uri before */
    subreq = be_resolve_server_send(state, state->ev,
                                    state->be, state->service->name,
                                    state->srv == NULL ? true : false);
    if (!subreq) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq,
                            sdap_cli_resolve_and_connect_next_server_done, req);
    return EOK;
}

static void sdap_cli_resolve_and_connect_next_server_done(struct tevent_req *subreq)
{
    struct sdap_cli_resolve_and_connect_state *state;
    struct tevent_req *req;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_cli_resolve_and_connect_state);

    ret = be_resolve_server_recv(subreq, state, &state->srv);
    talloc_zfree(subreq);
    if (ret) {
        state->srv = NULL;
        state->can_retry = false;
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, EIO);
        return;
    }

    subreq = sdap_cli_connect_send(state, state->ev, state->opts,
                                   state->service->uri,
                                   state->service->sockaddr,
                                   state->service->sockaddr_len,
                                   !state->use_rootdse,
                                   state->force_tls,
                                   !state->do_auth,
                                   state->kinit_expire_time);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_cli_resolve_and_connect_done, req);
}

static void
sdap_cli_resolve_and_connect_done(struct tevent_req *subreq)
{
    struct sdap_cli_resolve_and_connect_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_cli_resolve_and_connect_state);

    ret = sdap_cli_connect_recv(subreq, state, &state->sh, &state->srv_opts);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to establish connection "
              "[%d]: %s\n", ret, sss_strerror(ret));
        be_fo_set_port_status(state->be, state->service->name,
                              state->srv, PORT_NOT_WORKING);
    }

    if (ret == ERR_SERVER_FAILURE) {
        /* try next server */
        ret = sdap_cli_resolve_and_connect_next_server(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Connection established.\n");
    be_fo_set_port_status(state->be, state->service->name, state->srv,
                          PORT_WORKING);

    tevent_req_done(req);
}

errno_t
sdap_cli_resolve_and_connect_recv(struct tevent_req *req,
                                  TALLOC_CTX *memctx,
                                  bool *can_retry,
                                  struct sdap_handle **gsh,
                                  struct sdap_server_opts **srv_opts)
{
    struct sdap_cli_resolve_and_connect_state *state = NULL;
    state = tevent_req_data(req, struct sdap_cli_resolve_and_connect_state);

    if (can_retry != NULL) {
        *can_retry = state->can_retry;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

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
    int ldaperr;
    int msgid;
    char *errmsg = NULL;
    LDAPMessage *result = NULL;
    TALLOC_CTX *tmp_ctx;

    DEBUG(SSSDBG_CONF_SETTINGS, "Executing START TLS\n");

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return LDAP_NO_MEMORY;

    lret = ldap_start_tls(ldap, NULL, NULL, &msgid);
    if (lret != LDAP_SUCCESS) {
        sss_ldap_error_debug(SSSDBG_MINOR_FAILURE, "ldap_start_tls failed",
                             ldap, lret);
        sss_log(SSS_LOG_ERR, "Could not start TLS.");
        goto done;
    }

    lret = ldap_result(ldap, msgid, 1, NULL, &result);
    if (lret != LDAP_RES_EXTENDED) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unexpected ldap_result, expected [%lu] got [%d].\n",
               LDAP_RES_EXTENDED, lret);
        lret = LDAP_PARAM_ERROR;
        goto done;
    }

    lret = ldap_parse_result(ldap, result, &ldaperr, NULL, &errmsg, NULL, NULL,
                             0);
    if (lret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldap_parse_result failed (%d) [%d][%s]\n", msgid, lret,
                  sss_ldap_err2string(lret));
        goto done;
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "START TLS result: %s(%d), %s\n",
              sss_ldap_err2string(ldaperr), ldaperr, errmsg);

    if (ldap_tls_inplace(ldap)) {
        DEBUG(SSSDBG_TRACE_ALL, "SSL/TLS handler already in place.\n");
        lret = LDAP_SUCCESS;
        goto done;
    }

    lret = ldap_install_tls(ldap);
    if (lret != LDAP_SUCCESS) {
        sss_ldap_error_debug(SSSDBG_MINOR_FAILURE, "ldap_install_tls failed",
                             ldap, lret);
        sss_log(SSS_LOG_ERR, "Could not start TLS encryption.");
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

    if (ldap == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Trying LDAP rebind while not connected.\n");
        return ERR_NETWORK_IO;
    }

    if (p->use_start_tls) {
        ret = synchronous_tls_setup(ldap);
        if (ret != LDAP_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "synchronous_tls_setup failed.\n");
            return ret;
        }
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        return LDAP_NO_MEMORY;
    }

    sasl_mech = dp_opt_get_string(p->opts->basic, SDAP_SASL_MECH);

    if (sasl_mech == NULL) {
        if (p->use_ppolicy) {
            ret = sss_ldap_control_create(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                                          0, NULL, 0, &ctrls[0]);
            if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sss_ldap_control_create failed to create "
                      "Password Policy control.\n");
                goto done;
            }
            request_controls = ctrls;
        }

        user_dn = dp_opt_get_string(p->opts->basic, SDAP_DEFAULT_BIND_DN);
        if (user_dn != NULL) {
            /* this code doesn't make copies of password
             * but only keeps pointer to opts internals
             */
            ret = sdap_auth_get_authtok(dp_opt_get_string(p->opts->basic,
                                                     SDAP_DEFAULT_AUTHTOK_TYPE),
                                        dp_opt_get_blob(p->opts->basic,
                                                        SDAP_DEFAULT_AUTHTOK),
                                        &password);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                     "sdap_auth_get_authtok failed.\n");
                ret = LDAP_LOCAL_ERROR;
                goto done;
            }
        }

        ret = ldap_sasl_bind_s(ldap, user_dn, LDAP_SASL_SIMPLE, &password,
                               request_controls, NULL, NULL);
        if (ret != LDAP_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_sasl_bind_s failed (%d)[%s]\n", ret,
                  sss_ldap_err2string(ret));
        }
    } else {
        sasl_bind_state = talloc_zero(tmp_ctx, struct sasl_bind_state);
        if (sasl_bind_state == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
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
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_sasl_interactive_bind_s failed (%d)[%s]\n", ret,
                      sss_ldap_err2string(ret));
        }
    }

    DEBUG(SSSDBG_TRACE_LIBS, "%s bind to [%s].\n",
             (ret == LDAP_SUCCESS ? "Successfully" : "Failed to"), url);

done:
    if (ctrls[0]) ldap_control_free(ctrls[0]);
    talloc_free(tmp_ctx);
    return ret;
}
