/*
    SSSD

    Kerberos 5 Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009-2010 Red Hat

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

#include <errno.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <sys/stat.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/find_uid.h"
#include "util/auth_utils.h"
#include "db/sysdb.h"
#include "util/sss_utf8.h"
#include "util/child_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_ccache.h"

#define  NON_POSIX_CCNAME_FMT       "MEMORY:sssd_nonposix_dummy_%u"

static int krb5_mod_ccname(TALLOC_CTX *mem_ctx,
                           struct sysdb_ctx *sysdb,
                           struct sss_domain_info *domain,
                           const char *name,
                           const char *ccname,
                           int mod_op)
{
    TALLOC_CTX *tmpctx;
    struct sysdb_attrs *attrs;
    int ret;
    errno_t sret;
    bool in_transaction = false;

    if (name == NULL || ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing user or ccache name.\n");
        return EINVAL;
    }

    if (mod_op != SYSDB_MOD_REP && mod_op != SYSDB_MOD_DEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported operation [%d].\n", mod_op);
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_ALL, "%s ccname [%s] for user [%s].\n",
              mod_op == SYSDB_MOD_REP ? "Save" : "Delete", ccname, name);

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    attrs = sysdb_new_attrs(tmpctx);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_CCACHE_FILE, ccname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_add_string failed.\n");
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error %d starting transaction (%s)\n", ret, strerror(ret));
        goto done;
    }
    in_transaction = true;

    ret = sysdb_set_user_attr(domain, name, attrs, mod_op);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction!\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }
    talloc_zfree(tmpctx);
    return ret;
}

static int krb5_save_ccname(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            struct sss_domain_info *domain,
                            const char *name,
                            const char *ccname)
{
    return krb5_mod_ccname(mem_ctx, sysdb, domain, name, ccname,
                           SYSDB_MOD_REP);
}

static int krb5_delete_ccname(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              struct sss_domain_info *domain,
                              const char *name,
                              const char *ccname)
{
    return krb5_mod_ccname(mem_ctx, sysdb, domain, name, ccname,
                           SYSDB_MOD_DEL);
}

static int krb5_cleanup(void *ptr)
{
    struct krb5child_req *kr = talloc_get_type(ptr, struct krb5child_req);

    if (kr == NULL) return EOK;

    memset(kr, 0, sizeof(struct krb5child_req));

    return EOK;
}

static errno_t
get_krb_primary(struct map_id_name_to_krb_primary *name_to_primary,
                char *id_prov_name, bool cs, const char **_krb_primary)
{
    errno_t ret;
    int i = 0;

    while(name_to_primary != NULL &&
          name_to_primary[i].id_name != NULL &&
          name_to_primary[i].krb_primary != NULL) {

        if (sss_string_equal(cs, name_to_primary[i].id_name, id_prov_name)) {
            *_krb_primary = name_to_primary[i].krb_primary;
            ret = EOK;
            goto done;
        }
        i++;
    }

    /* Handle also the case of name_to_primary being NULL */
    ret = ENOENT;

done:
    return ret;
}

errno_t krb5_setup(TALLOC_CTX *mem_ctx,
                   struct pam_data *pd,
                   struct sss_domain_info *dom,
                   struct krb5_ctx *krb5_ctx,
                   struct krb5child_req **_krb5_req)
{
    struct krb5child_req *kr;
    const char *mapped_name;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    kr = talloc_zero(tmp_ctx, struct krb5child_req);
    if (kr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto done;
    }
    kr->is_offline = false;
    talloc_set_destructor((TALLOC_CTX *) kr, krb5_cleanup);

    kr->pd = pd;
    kr->dom = dom;
    kr->krb5_ctx = krb5_ctx;

    ret = get_krb_primary(krb5_ctx->name_to_primary,
                          pd->user, dom->case_sensitive, &mapped_name);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Setting mapped name to: %s\n", mapped_name);
        kr->user = mapped_name;

        kr->kuserok_user = sss_output_name(kr, kr->user,
                                           dom->case_sensitive, 0);
        if (kr->kuserok_user == NULL) {
            ret = ENOMEM;
            goto done;
        }
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No mapping for: %s\n", pd->user);
        kr->user = pd->user;

        kr->kuserok_user = sss_output_name(kr, kr->user,
                                           dom->case_sensitive, 0);
        if (kr->kuserok_user == NULL) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "get_krb_primary failed - %s:[%d]\n",
              sss_strerror(ret), ret);
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_krb5_req = talloc_steal(mem_ctx, kr);
    }
    talloc_free(tmp_ctx);
    return ret;
}


static void krb5_auth_cache_creds(struct krb5_ctx *krb5_ctx,
                                  struct sss_domain_info *domain,
                                  struct confdb_ctx *cdb,
                                  struct pam_data *pd, uid_t uid,
                                  int *pam_status, int *dp_err)
{
    const char *password = NULL;
    errno_t ret;

    ret = sss_authtok_get_password(pd->authtok, &password, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get password [%d] %s. Delayed authentication is only "
              "available for password authentication (single factor).\n",
              ret, strerror(ret));
        *pam_status = PAM_SYSTEM_ERR;
        *dp_err = DP_ERR_OK;
        return;
    }

    ret = sysdb_cache_auth(domain, pd->user,
                           password, cdb, true, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Offline authentication failed\n");
        *pam_status = cached_login_pam_status(ret);
        *dp_err = DP_ERR_OK;
        return;
    }

    ret = add_user_to_delayed_online_authentication(krb5_ctx, domain, pd, uid);
    if (ret == ENOTSUP) {
        /* This error is not fatal */
        DEBUG(SSSDBG_MINOR_FAILURE, "Delayed authentication not supported\n");
    } else if (ret != EOK) {
        /* This error is not fatal */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "add_user_to_delayed_online_authentication failed.\n");
    }
    *pam_status = PAM_AUTHINFO_UNAVAIL;
    *dp_err = DP_ERR_OFFLINE;
}

static errno_t krb5_auth_prepare_ccache_name(struct krb5child_req *kr,
                                             struct ldb_message *user_msg,
                                             struct be_ctx *be_ctx)
{
    const char *ccname_template;

    switch (kr->dom->type) {
    case DOM_TYPE_POSIX:
        ccname_template = dp_opt_get_cstring(kr->krb5_ctx->opts, KRB5_CCNAME_TMPL);

        kr->ccname = expand_ccname_template(kr, kr, ccname_template,
                                            kr->krb5_ctx->illegal_path_re, true,
                                            be_ctx->domain->case_sensitive);
        if (kr->ccname == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "expand_ccname_template failed.\n");
            return ENOMEM;
        }

        kr->old_ccname = ldb_msg_find_attr_as_string(user_msg,
                                                    SYSDB_CCACHE_FILE, NULL);
        if (kr->old_ccname == NULL) {
            DEBUG(SSSDBG_TRACE_LIBS,
                    "No ccache file for user [%s] found.\n", kr->pd->user);
        }
        break;
    case DOM_TYPE_APPLICATION:
        DEBUG(SSSDBG_TRACE_FUNC,
               "Domain type application, will use in-memory ccache\n");
        kr->ccname = talloc_asprintf(kr,
                                     NON_POSIX_CCNAME_FMT,
                                     sss_rand() % UINT_MAX);
        if (kr->ccname == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
            return ENOMEM;
        }

        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE, "Unsupported domain type\n");
        return EINVAL;
    }

    return EOK;
}

static void krb5_auth_store_creds(struct sss_domain_info *domain,
                                  struct pam_data *pd)
{
    const char *password = NULL;
    const char *fa2;
    size_t password_len;
    size_t fa2_len = 0;
    int ret = EOK;

    switch(pd->cmd) {
        case SSS_CMD_RENEW:
            /* The authtok is set to the credential cache
             * during renewal. We don't want to save this
             * as the cached password.
             */
            break;
        case SSS_PAM_PREAUTH:
            /* There are no credentials available during pre-authentication,
             * nothing to do. */
            break;
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            if (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_2FA) {
                ret = sss_authtok_get_2fa(pd->authtok, &password, &password_len,
                                          &fa2, &fa2_len);
                if (ret == EOK && password_len <
                                      domain->cache_credentials_min_ff_length) {
                    DEBUG(SSSDBG_FATAL_FAILURE,
                          "First factor is too short to be cache, "
                          "minimum length is [%u].\n",
                          domain->cache_credentials_min_ff_length);
                    ret = EINVAL;
                }
            } else if (sss_authtok_get_type(pd->authtok) ==
                                                    SSS_AUTHTOK_TYPE_PASSWORD) {
                ret = sss_authtok_get_password(pd->authtok, &password, NULL);
            } else {
                DEBUG(SSSDBG_MINOR_FAILURE, "Cannot cache authtok type [%d].\n",
                      sss_authtok_get_type(pd->authtok));
                ret = EINVAL;
            }
            break;
        case SSS_PAM_CHAUTHTOK:
            ret = sss_authtok_get_password(pd->newauthtok, &password, NULL);
            break;
        default:
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "unsupported PAM command [%d].\n", pd->cmd);
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get password [%d] %s\n", ret, strerror(ret));
        /* password caching failures are not fatal errors */
        return;
    }

    if (password == NULL) {
        if (pd->cmd != SSS_CMD_RENEW && pd->cmd != SSS_PAM_PREAUTH) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "password not available, offline auth may not work.\n");
            /* password caching failures are not fatal errors */
        }
        return;
    }

    ret = sysdb_cache_password_ex(domain, pd->user, password,
                                  sss_authtok_get_type(pd->authtok), fa2_len);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to cache password, offline auth may not work."
                  " (%d)[%s]!?\n", ret, strerror(ret));
        /* password caching failures are not fatal errors */
    }
}

static bool is_otp_enabled(struct ldb_message *user_msg)
{
    struct ldb_message_element *el;
    size_t i;

    el = ldb_msg_find_element(user_msg, SYSDB_AUTH_TYPE);
    if (el == NULL) {
        return false;
    }

    for (i = 0; i < el->num_values; i++) {
        if (strcmp((const char * )el->values[i].data, "otp") == 0) {
            return true;
        }
    }

    return false;
}

/* krb5_auth request */

struct krb5_auth_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct pam_data *pd;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct krb5_ctx *krb5_ctx;
    struct krb5child_req *kr;

    bool search_kpasswd;

    int pam_status;
    int dp_err;
};

static void krb5_auth_resolve_done(struct tevent_req *subreq);
static void krb5_auth_done(struct tevent_req *subreq);

struct tevent_req *krb5_auth_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct pam_data *pd,
                                  struct krb5_ctx *krb5_ctx)
{
    const char **attrs;
    struct krb5_auth_state *state;
    struct ldb_result *res;
    struct krb5child_req *kr = NULL;
    const char *realm;
    struct tevent_req *req;
    struct tevent_req *subreq;
    enum sss_authtok_type authtok_type;
    int ret;
    bool otp;

    req = tevent_req_create(mem_ctx, &state, struct krb5_auth_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->pd = pd;
    state->krb5_ctx = krb5_ctx;
    state->kr = NULL;
    state->pam_status = PAM_SYSTEM_ERR;
    state->dp_err = DP_ERR_FATAL;

    ret = get_domain_or_subdomain(be_ctx, pd->domain, &state->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_domain_or_subdomain failed.\n");
        goto done;
    }

    state->sysdb = state->domain->sysdb;

    authtok_type = sss_authtok_get_type(pd->authtok);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_CHAUTHTOK:
            if (authtok_type != SSS_AUTHTOK_TYPE_PASSWORD
                    && authtok_type != SSS_AUTHTOK_TYPE_2FA
                    && authtok_type != SSS_AUTHTOK_TYPE_2FA_SINGLE
                    && authtok_type != SSS_AUTHTOK_TYPE_SC_PIN
                    && authtok_type != SSS_AUTHTOK_TYPE_SC_KEYPAD
                    && authtok_type != SSS_AUTHTOK_TYPE_OAUTH2
                    && authtok_type != SSS_AUTHTOK_TYPE_PASSKEY
                    && authtok_type != SSS_AUTHTOK_TYPE_PASSKEY_KRB
                    && authtok_type != SSS_AUTHTOK_TYPE_PASSKEY_REPLY) {
                /* handle empty password gracefully */
                if (authtok_type == SSS_AUTHTOK_TYPE_EMPTY) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Illegal empty authtok for user [%s]\n",
                           pd->user);
                    state->pam_status = PAM_AUTH_ERR;
                    state->dp_err = DP_ERR_OK;
                    ret = EOK;
                    goto done;
                }

                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Wrong authtok type for user [%s]. " \
                       "Expected [%d], got [%d]\n", pd->user,
                          SSS_AUTHTOK_TYPE_PASSWORD,
                          authtok_type);
                state->pam_status = PAM_SYSTEM_ERR;
                state->dp_err = DP_ERR_FATAL;
                ret = EINVAL;
                goto done;
            }
            break;
        case SSS_PAM_CHAUTHTOK_PRELIM:
            if (pd->priv == 1 &&
                authtok_type != SSS_AUTHTOK_TYPE_PASSWORD) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Password reset by root is not supported.\n");
                state->pam_status = PAM_PERM_DENIED;
                state->dp_err = DP_ERR_OK;
                ret = EOK;
                goto done;
            }

            /* If krb5_child is still running from SSS_PAM_PREAUTH,
             * terminate the waiting krb5_child and send the
             * CHAUTHTOK_PRELIM request again */
            if (pd->child_pid != 0) {
                soft_terminate_krb5_child(state, pd, krb5_ctx);
                state->pam_status = PAM_TRY_AGAIN;
                state->dp_err = DP_ERR_OK;
                ret = EOK;
                goto done;
             }

            break;
        case SSS_CMD_RENEW:
            if (authtok_type != SSS_AUTHTOK_TYPE_CCFILE) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Wrong authtok type for user [%s]. " \
                       "Expected [%d], got [%d]\n", pd->user,
                          SSS_AUTHTOK_TYPE_CCFILE,
                          authtok_type);
                state->pam_status = PAM_SYSTEM_ERR;
                state->dp_err = DP_ERR_FATAL;
                ret = EINVAL;
                goto done;
            }
            break;
        case SSS_PAM_PREAUTH:
            break;
        default:
            DEBUG(SSSDBG_CONF_SETTINGS, "Unexpected pam task %d.\n", pd->cmd);
            state->pam_status = PAM_SYSTEM_ERR;
            state->dp_err = DP_ERR_FATAL;
            ret = EINVAL;
            goto done;
    }

    if (be_is_offline(be_ctx) &&
        (pd->cmd == SSS_PAM_CHAUTHTOK || pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM ||
         pd->cmd == SSS_CMD_RENEW)) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Password changes and ticket renewal are not possible "
                  "while offline.\n");
        state->pam_status = PAM_AUTHINFO_UNAVAIL;
        state->dp_err = DP_ERR_OFFLINE;
        ret = EOK;
        goto done;
    }

    attrs = talloc_array(state, const char *, 8);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    attrs[0] = SYSDB_UPN;
    attrs[1] = SYSDB_HOMEDIR;
    attrs[2] = SYSDB_CCACHE_FILE;
    attrs[3] = SYSDB_UIDNUM;
    attrs[4] = SYSDB_GIDNUM;
    attrs[5] = SYSDB_CANONICAL_UPN;
    attrs[6] = SYSDB_AUTH_TYPE;
    attrs[7] = NULL;

    ret = krb5_setup(state, pd, state->domain, krb5_ctx,
                     &state->kr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_setup failed.\n");
        goto done;
    }
    kr = state->kr;

    ret = sysdb_get_user_attr_with_views(state, state->domain, state->pd->user,
                                         attrs, &res);
    if (ret) {
        DEBUG(SSSDBG_FUNC_DATA,
              "sysdb search for upn of user [%s] failed.\n", pd->user);
        state->pam_status = PAM_SYSTEM_ERR;
        state->dp_err = DP_ERR_OK;
        goto done;
    }

    realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing Kerberos realm.\n");
        ret = ENOENT;
        goto done;
    }

    switch (res->count) {
    case 0:
        DEBUG(SSSDBG_FUNC_DATA,
              "No attributes for user [%s] found.\n", pd->user);
        ret = ENOENT;
        goto done;
        break;

    case 1:
        ret = find_or_guess_upn(state, res->msgs[0], krb5_ctx, be_ctx->domain,
                                kr->user, pd->domain, &kr->upn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "find_or_guess_upn failed.\n");
            goto done;
        }

        ret = compare_principal_realm(kr->upn, realm,
                                      &kr->upn_from_different_realm);
        if (ret != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "compare_principal_realm failed.\n");
            goto done;
        }

        kr->homedir = sss_view_ldb_msg_find_attr_as_string(state->domain,
                                                           res->msgs[0],
                                                           SYSDB_HOMEDIR,
                                                           NULL);
        if (kr->homedir == NULL) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Home directory for user [%s] not known.\n", pd->user);
        }

        kr->uid = sss_view_ldb_msg_find_attr_as_uint64(state->domain,
                                                       res->msgs[0],
                                                       SYSDB_UIDNUM, 0);
        if (kr->uid == 0 && state->domain->type == DOM_TYPE_POSIX) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "UID for user [%s] not known.\n", pd->user);
            ret = ENOENT;
            goto done;
        }

        kr->gid = sss_view_ldb_msg_find_attr_as_uint64(state->domain,
                                                       res->msgs[0],
                                                       SYSDB_GIDNUM, 0);
        if (kr->gid == 0 && state->domain->type == DOM_TYPE_POSIX) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "GID for user [%s] not known.\n", pd->user);
            ret = ENOENT;
            goto done;
        }

        ret = krb5_auth_prepare_ccache_name(kr, res->msgs[0], state->be_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot prepare ccache names!\n");
            goto done;
        }
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "User search for (%s) returned > 1 results!\n", pd->user);
        ret = EINVAL;
        goto done;
        break;
    }

    otp = is_otp_enabled(res->msgs[0]);
    if (pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM && otp == true) {
        /* To avoid consuming the OTP */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Skipping password checks for OTP-enabled user\n");
        state->pam_status = PAM_SUCCESS;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;
    }

    kr->srv = NULL;
    kr->kpasswd_srv = NULL;

    state->search_kpasswd = false;
    subreq = be_resolve_server_send(state, state->ev, state->be_ctx,
                                    state->krb5_ctx->service->name,
                                    state->kr->srv == NULL ? true : false);
    if (!subreq) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed resolver request.\n");
        ret = EIO;
        goto done;
    }
    tevent_req_set_callback(subreq, krb5_auth_resolve_done, req);

    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, state->ev);
    return req;
}

static void krb5_auth_resolve_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    struct krb5child_req *kr = state->kr;
    int ret;

    if (!state->search_kpasswd) {
        ret = be_resolve_server_recv(subreq, kr, &kr->srv);
    } else {
        ret = be_resolve_server_recv(subreq, kr, &kr->kpasswd_srv);
    }
    talloc_zfree(subreq);

    if (state->search_kpasswd) {
        if ((ret != EOK) &&
            (kr->pd->cmd == SSS_PAM_CHAUTHTOK ||
             kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM)) {
            /* all kpasswd servers have been tried and none was found good,
             * but the kdc seems ok. Password changes are not possible but
             * authentication is. We return an PAM error here, but do not
             * mark the backend offline. */
            state->pam_status = PAM_AUTHTOK_LOCK_BUSY;
            state->dp_err = DP_ERR_OK;
            ret = EOK;
            goto done;
        }
    } else {
        if (ret != EOK) {
            /* all servers have been tried and none
             * was found good, setting offline,
             * but we still have to call the child to setup
             * the ccache file if we are performing auth */
            be_mark_dom_offline(state->domain, state->be_ctx);
            kr->is_offline = true;

            if (kr->pd->cmd == SSS_PAM_CHAUTHTOK ||
                kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "No KDC suitable for password change is available\n");
                state->pam_status = PAM_AUTHTOK_LOCK_BUSY;
                state->dp_err = DP_ERR_OK;
                ret = EOK;
                goto done;
            }
        } else {
            if (kr->krb5_ctx->kpasswd_service != NULL) {
                state->search_kpasswd = true;
                subreq = be_resolve_server_send(state,
                                    state->ev, state->be_ctx,
                                    state->krb5_ctx->kpasswd_service->name,
                                    kr->kpasswd_srv == NULL ? true : false);
                if (subreq == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Resolver request failed.\n");
                    ret = EIO;
                    goto done;
                }
                tevent_req_set_callback(subreq, krb5_auth_resolve_done, req);
                return;
            }
        }
    }

    if (!kr->is_offline) {
        kr->is_offline = be_is_offline(state->be_ctx);
    }

    if (!kr->is_offline
            && sss_domain_get_state(state->domain) == DOM_INACTIVE) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Subdomain %s is inactive, will proceed offline\n",
              state->domain->name);
        kr->is_offline = true;
    }

    if (kr->is_offline
            && sss_krb5_realm_has_proxy(dp_opt_get_cstring(kr->krb5_ctx->opts,
                                        KRB5_REALM))) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Resetting offline status, KDC proxy is in use\n");
        kr->is_offline = false;
    }

    subreq = handle_child_send(state, state->ev, kr);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "handle_child_send failed.\n");
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, krb5_auth_done, req);
    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static void krb5_auth_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    struct krb5child_req *kr = state->kr;
    struct pam_data *pd = state->pd;
    int ret;
    uint8_t *buf = NULL;
    ssize_t len = -1;
    struct krb5_child_response *res;
    struct fo_server *search_srv;
    krb5_deltat renew_interval_delta;
    char *renew_interval_str;
    time_t renew_interval_time = 0;
    bool use_enterprise_principal;
    bool canonicalize;

    ret = handle_child_recv(subreq, pd, &buf, &len);
    talloc_zfree(subreq);
    if (ret == ETIMEDOUT) {

        DEBUG(SSSDBG_CRIT_FAILURE, "child timed out!\n");

        switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_CMD_RENEW:
            state->search_kpasswd = false;
            search_srv = kr->srv;
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            if (state->kr->kpasswd_srv) {
                state->search_kpasswd = true;
                search_srv = kr->kpasswd_srv;
                break;
            } else {
                state->search_kpasswd = false;
                search_srv = kr->srv;
                break;
            }
        case SSS_PAM_PREAUTH:
            state->pam_status = PAM_CRED_UNAVAIL;
            state->dp_err = DP_ERR_OK;
            ret = EOK;
            goto done;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected PAM task %d\n", pd->cmd);
            ret = EINVAL;
            goto done;
        }

        be_fo_set_port_status(state->be_ctx, state->krb5_ctx->service->name,
                              search_srv, PORT_NOT_WORKING);
        subreq = be_resolve_server_send(state, state->ev, state->be_ctx,
                                        state->krb5_ctx->service->name,
                                        search_srv == NULL ? true : false);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed resolved request.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, krb5_auth_resolve_done, req);
        return;

    } else if (ret != EOK) {

        DEBUG(SSSDBG_CRIT_FAILURE,
              "child failed (%d [%s])\n", ret, strerror(ret));
        goto done;
    }

    /* EOK */

    ret = parse_krb5_child_response(state, buf, len, pd,
                        state->be_ctx->domain->pwd_expiration_warning,
                        &res);
    if (ret) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "The krb5_child process returned an error. Please inspect the "
              "krb5_child.log file or the journal for more information\n");
        DEBUG(SSSDBG_OP_FAILURE, "Could not parse child response [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    if (res->ccname) {
        kr->ccname = talloc_strdup(kr, res->ccname);
        if (!kr->ccname) {
            ret = ENOMEM;
            goto done;
        }
    }

    use_enterprise_principal = dp_opt_get_bool(kr->krb5_ctx->opts,
                                               KRB5_USE_ENTERPRISE_PRINCIPAL);
    canonicalize = dp_opt_get_bool(kr->krb5_ctx->opts, KRB5_CANONICALIZE);

    /* Check if the cases of our upn are correct and update it if needed.
     * Fail if the upn differs by more than just the case for non-enterprise
     * principals. */
    if (res->correct_upn != NULL &&
        strcmp(kr->upn, res->correct_upn) != 0) {
        if (strcasecmp(kr->upn, res->correct_upn) == 0 ||
            canonicalize == true ||
            use_enterprise_principal == true) {
            talloc_free(kr->upn);
            kr->upn = talloc_strdup(kr, res->correct_upn);
            if (kr->upn == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }

            ret = check_if_cached_upn_needs_update(state->sysdb, state->domain,
                                                   pd->user, res->correct_upn);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "check_if_cached_upn_needs_update failed.\n");
                goto done;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "UPN used in the request [%s] and " \
                                        "returned UPN [%s] differ by more " \
                                        "than just the case.\n",
                                        kr->upn, res->correct_upn);
            ret = EINVAL;
            goto done;
        }
    }

    /* If the child request failed, but did not return an offline error code,
     * return with the status */
    switch (res->msg_status) {
    case ERR_OK:
        /* If the child request was successful and we run the first pass of the
         * change password request just return success. */
        if (pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
            state->pam_status = PAM_SUCCESS;
            state->dp_err = DP_ERR_OK;
            ret = EOK;
            goto done;
        }
        break;

    case ERR_NETWORK_IO:
        if (kr->kpasswd_srv != NULL &&
            (pd->cmd == SSS_PAM_CHAUTHTOK ||
             pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM)) {
            /* if using a dedicated kpasswd server for a chpass operation... */

            be_fo_set_port_status(state->be_ctx,
                                  state->krb5_ctx->kpasswd_service->name,
                                  kr->kpasswd_srv, PORT_NOT_WORKING);
            /* ..try to resolve next kpasswd server */
            state->search_kpasswd = true;
            subreq = be_resolve_server_send(state, state->ev, state->be_ctx,
                                state->krb5_ctx->kpasswd_service->name,
                                state->kr->kpasswd_srv == NULL ?  true : false);
            if (subreq == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Resolver request failed.\n");
                ret = ENOMEM;
                goto done;
            }
            tevent_req_set_callback(subreq, krb5_auth_resolve_done, req);
            return;
        } else if (kr->srv != NULL) {
            /* failed to use the KDC... */
            be_fo_set_port_status(state->be_ctx,
                                  state->krb5_ctx->service->name,
                                  kr->srv, PORT_NOT_WORKING);
            /* ..try to resolve next KDC */
            state->search_kpasswd = false;
            subreq = be_resolve_server_send(state, state->ev, state->be_ctx,
                                            state->krb5_ctx->service->name,
                                            kr->srv == NULL ?  true : false);
            if (subreq == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Resolver request failed.\n");
                ret = ENOMEM;
                goto done;
            }
            tevent_req_set_callback(subreq, krb5_auth_resolve_done, req);
            return;
        }
        break;

    case ERR_CREDS_EXPIRED_CCACHE:
        ret = krb5_delete_ccname(state, state->sysdb, state->domain,
                pd->user, kr->old_ccname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_delete_ccname failed.\n");
        }
        /* FALLTHROUGH */
        SSS_ATTRIBUTE_FALLTHROUGH;

    case ERR_CREDS_EXPIRED:
        /* If the password is expired we can safely remove the ccache from the
         * cache and disk if it is not actively used anymore. This will allow
         * to create a new random ccache if sshd with privilege separation is
         * used. */
        if (pd->cmd == SSS_PAM_AUTHENTICATE && !kr->active_ccache) {
            if (kr->old_ccname != NULL) {
                ret = krb5_delete_ccname(state, state->sysdb, state->domain,
                                         pd->user, kr->old_ccname);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "krb5_delete_ccname failed.\n");
                }
            }
        }

        state->pam_status = PAM_NEW_AUTHTOK_REQD;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;

    case ERR_CREDS_INVALID:
        state->pam_status = PAM_CRED_ERR;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;

    case ERR_ACCOUNT_EXPIRED:
        state->pam_status = PAM_ACCT_EXPIRED;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;

    case ERR_ACCOUNT_LOCKED:
        state->pam_status = PAM_PERM_DENIED;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;

    case ERR_NO_CREDS:
        state->pam_status = PAM_CRED_UNAVAIL;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;

    case ERR_AUTH_FAILED:
        state->pam_status = PAM_AUTH_ERR;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;

    case ERR_CHPASS_FAILED:
        state->pam_status = PAM_AUTHTOK_ERR;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;

    case ERR_NO_AUTH_METHOD_AVAILABLE:
        state->pam_status = PAM_NO_MODULE_DATA;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;

    default:
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "The krb5_child process returned an error. Please inspect the "
              "krb5_child.log file or the journal for more information\n");
        state->pam_status = PAM_SYSTEM_ERR;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;
    }

    if (kr->kpasswd_srv != NULL &&
        (pd->cmd == SSS_PAM_CHAUTHTOK ||
         pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM)) {
        /* found a dedicated kpasswd server for a chpass operation */
        be_fo_set_port_status(state->be_ctx,
                              state->krb5_ctx->service->name,
                              kr->kpasswd_srv, PORT_WORKING);
    } else if (kr->srv != NULL) {
        /* found a KDC */
        be_fo_set_port_status(state->be_ctx, state->krb5_ctx->service->name,
                              kr->srv, PORT_WORKING);
    }

    if (pd->cmd == SSS_PAM_PREAUTH) {
        state->pam_status = PAM_SUCCESS;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;
    }

    /* Now only a successful authentication or password change is left.
     *
     * We expect that one of the messages in the received buffer contains
     * the name of the credential cache file. */
    if (kr->ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing ccache name in child response.\n");
        ret = EINVAL;
        goto done;
    }

    ret = krb5_save_ccname(state, state->sysdb, state->domain,
                           pd->user, kr->ccname);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_save_ccname failed.\n");
        goto done;
    }
    renew_interval_str = dp_opt_get_string(kr->krb5_ctx->opts,
                         KRB5_RENEW_INTERVAL);
    if (renew_interval_str != NULL) {
        ret = krb5_string_to_deltat(renew_interval_str, &renew_interval_delta);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                 "Reading krb5_renew_interval failed.\n");
            renew_interval_delta = 0;
        }
        renew_interval_time = renew_interval_delta;
    }
    if (res->msg_status == ERR_OK && renew_interval_time > 0 &&
        (pd->cmd == SSS_PAM_AUTHENTICATE ||
         pd->cmd == SSS_CMD_RENEW ||
         pd->cmd == SSS_PAM_CHAUTHTOK) &&
        (res->tgtt.renew_till > res->tgtt.endtime) &&
        (kr->ccname != NULL)) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Adding [%s] for automatic renewal.\n", kr->ccname);
        ret = add_tgt_to_renew_table(kr->krb5_ctx, kr->ccname, &(res->tgtt),
                                     pd, kr->upn);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "add_tgt_to_renew_table failed, "
                      "automatic renewal not possible.\n");
        }
    }

    if (kr->is_offline) {
        if (dp_opt_get_bool(kr->krb5_ctx->opts,
                            KRB5_STORE_PASSWORD_IF_OFFLINE)
                && sss_authtok_get_type(pd->authtok)
                            == SSS_AUTHTOK_TYPE_PASSWORD) {
            krb5_auth_cache_creds(state->kr->krb5_ctx,
                                  state->domain,
                                  state->be_ctx->cdb,
                                  state->pd, state->kr->uid,
                                  &state->pam_status, &state->dp_err);
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Backend is marked offline, retry later!\n");
            state->pam_status = PAM_AUTHINFO_UNAVAIL;
            state->dp_err = DP_ERR_OFFLINE;
        }
        ret = EOK;
        goto done;
    }

    if (state->be_ctx->domain->cache_credentials == TRUE
            && (!res->otp
                || (res->otp && sss_authtok_get_type(pd->authtok) ==
                                                       SSS_AUTHTOK_TYPE_2FA))) {
        krb5_auth_store_creds(state->domain, pd);
    }

    /* The SSS_OTP message will prevent pam_sss from putting the entered
     * password on the PAM stack for other modules to use. This is not needed
     * when both factors were entered separately because here the first factor
     * (long term password) can be passed to the other modules. */
    if (res->otp == true && pd->cmd == SSS_PAM_AUTHENTICATE
            && sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_2FA) {
        uint32_t otp_flag = 1;
        ret = pam_add_response(pd, SSS_OTP, sizeof(uint32_t),
                               (const uint8_t *) &otp_flag);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "pam_add_response failed: %d (%s).\n",
                  ret, sss_strerror(ret));
            state->pam_status = PAM_SYSTEM_ERR;
            state->dp_err = DP_ERR_OK;
            goto done;
        }
    }

    state->pam_status = PAM_SUCCESS;
    state->dp_err = DP_ERR_OK;
    ret = EOK;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

}

int krb5_auth_recv(struct tevent_req *req, int *pam_status, int *dp_err)
{
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    *pam_status = state->pam_status;
    *dp_err = state->dp_err;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct krb5_pam_handler_state {
    struct pam_data *pd;
};

static void krb5_pam_handler_auth_done(struct tevent_req *subreq);
static void krb5_pam_handler_access_done(struct tevent_req *subreq);

struct tevent_req *
krb5_pam_handler_send(TALLOC_CTX *mem_ctx,
                      struct krb5_ctx *krb5_ctx,
                      struct pam_data *pd,
                      struct dp_req_params *params)
{
    struct krb5_pam_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct krb5_pam_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_PREAUTH:
        case SSS_CMD_RENEW:
        case SSS_PAM_CHAUTHTOK_PRELIM:
        case SSS_PAM_CHAUTHTOK:
            subreq = krb5_auth_queue_send(state, params->ev, params->be_ctx,
                                          pd, krb5_ctx);
            if (subreq == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "krb5_auth_send failed.\n");
                pd->pam_status = PAM_SYSTEM_ERR;
                goto immediately;
            }

            tevent_req_set_callback(subreq, krb5_pam_handler_auth_done, req);
            break;
        case SSS_PAM_ACCT_MGMT:
            subreq = krb5_access_send(state, params->ev, params->be_ctx,
                                      pd, krb5_ctx);
            if (subreq == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "krb5_access_send failed.\n");
                pd->pam_status = PAM_SYSTEM_ERR;
                goto immediately;
            }

            tevent_req_set_callback(subreq, krb5_pam_handler_access_done, req);
            break;
        case SSS_PAM_SETCRED:
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_CLOSE_SESSION:
            pd->pam_status = PAM_SUCCESS;
            goto immediately;
            break;
        default:
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "krb5 does not handles pam task %d.\n", pd->cmd);
            pd->pam_status = PAM_MODULE_UNKNOWN;
            goto immediately;
    }

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void krb5_pam_handler_auth_done(struct tevent_req *subreq)
{
    struct krb5_pam_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct krb5_pam_handler_state);

    ret = krb5_auth_queue_recv(subreq, &state->pd->pam_status, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }

    /* PAM_CRED_ERR is used to indicate to the IPA provider that trying
     * password migration would make sense. From this point on it isn't
     * necessary to keep this status, so it can be translated to PAM_AUTH_ERR.
     */
    if (state->pd->pam_status == PAM_CRED_ERR) {
        state->pd->pam_status = PAM_AUTH_ERR;
    }

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

static void krb5_pam_handler_access_done(struct tevent_req *subreq)
{
    struct krb5_pam_handler_state *state;
    struct tevent_req *req;
    bool access_allowed;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct krb5_pam_handler_state);

    ret = krb5_access_recv(subreq, &access_allowed);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }


    DEBUG(SSSDBG_TRACE_LIBS, "Access %s for user [%s].\n",
          access_allowed ? "allowed" : "denied", state->pd->user);
    state->pd->pam_status = access_allowed ? PAM_SUCCESS : PAM_PERM_DENIED;

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
krb5_pam_handler_recv(TALLOC_CTX *mem_ctx,
                      struct tevent_req *req,
                      struct pam_data **_data)
{
    struct krb5_pam_handler_state *state = NULL;

    state = tevent_req_data(req, struct krb5_pam_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
