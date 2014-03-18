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
#include "util/find_uid.h"
#include "util/auth_utils.h"
#include "db/sysdb.h"
#include "util/child_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"

static errno_t safe_remove_old_ccache_file(const char *old_ccache,
                                           const char *new_ccache,
                                           uid_t uid, gid_t gid)
{
    if ((old_ccache == new_ccache)
        || (old_ccache && new_ccache
            && (strcmp(old_ccache, new_ccache) == 0))) {
        DEBUG(SSSDBG_TRACE_FUNC, "New and old ccache file are the same, "
                                  "none will be deleted.\n");
        return EOK;
    }

    return sss_krb5_cc_destroy(old_ccache, uid, gid);
}

static errno_t
check_old_ccache(const char *old_ccache, struct krb5child_req *kr,
                 const char *realm, bool *active, bool *valid)
{
    errno_t ret;

    *active = false;
    *valid = false;

    ret = sss_krb5_cc_verify_ccache(old_ccache,
                                    kr->uid, kr->gid,
                                    realm, kr->upn);
    switch (ret) {
    case ERR_NOT_FOUND:
    case ENOENT:
        DEBUG(SSSDBG_TRACE_FUNC,
              "Saved ccache %s doesn't exist.\n", old_ccache);
        return ENOENT;
    case EINVAL:
        /* cache found but no tgt or expired */
    case EOK:
        *valid = true;
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot check if saved ccache %s is valid\n",
               old_ccache);
        return ret;
    }

    ret = check_if_uid_is_active(kr->uid, active);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "check_if_uid_is_active failed.\n");
        return ret;
    }

    return EOK;
}

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

static struct krb5_ctx *get_krb5_ctx(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct pam_data *pd;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_CMD_RENEW:
            return talloc_get_type(be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                                   struct krb5_ctx);
            break;
        case SSS_PAM_ACCT_MGMT:
            return talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                   struct krb5_ctx);
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            return talloc_get_type(be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                                   struct krb5_ctx);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported PAM task.\n");
            return NULL;
    }
}

static int krb5_cleanup(void *ptr)
{
    struct krb5child_req *kr = talloc_get_type(ptr, struct krb5child_req);

    if (kr == NULL) return EOK;

    memset(kr, 0, sizeof(struct krb5child_req));

    return EOK;
}

errno_t krb5_setup(TALLOC_CTX *mem_ctx, struct pam_data *pd,
                   struct krb5_ctx *krb5_ctx, struct krb5child_req **krb5_req)
{
    struct krb5child_req *kr = NULL;

    kr = talloc_zero(mem_ctx, struct krb5child_req);
    if (kr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }
    kr->is_offline = false;
    kr->active_ccache = true;
    kr->run_as_user = true;
    talloc_set_destructor((TALLOC_CTX *) kr, krb5_cleanup);

    kr->pd = pd;
    kr->krb5_ctx = krb5_ctx;

    *krb5_req = kr;

    return EOK;
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
              "Failed to get password [%d] %s\n", ret, strerror(ret));
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

    ret = add_user_to_delayed_online_authentication(krb5_ctx, pd, uid);
    if (ret != EOK) {
        /* This error is not fatal */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "add_user_to_delayed_online_authentication failed.\n");
    }
    *pam_status = PAM_AUTHINFO_UNAVAIL;
    *dp_err = DP_ERR_OFFLINE;
}

static errno_t krb5_auth_prepare_ccache_name(struct krb5child_req *kr,
                                             struct be_ctx *be_ctx)
{
    const char *ccname_template;
    errno_t ret;

    if (!kr->is_offline) {
        kr->is_offline = be_is_offline(be_ctx);
    }

    /* The ccache file should be (re)created if one of the following conditions
     * is true:
     * - it doesn't exist (kr->ccname == NULL)
     * - the backend is online and the current ccache file is not used, i.e
     *   the related user is currently not logged in and it is not a renewal
     *   request
     *   (!kr->is_offline && !kr->active_ccache && kr->pd->cmd != SSS_CMD_RENEW)
     * - the backend is offline and the current cache file not used and
     *   it does not contain a valid tgt
     *   (kr->is_offline && !kr->active_ccache && !kr->valid_tgt)
     */
    if (kr->ccname == NULL ||
        (kr->is_offline && !kr->active_ccache && !kr->valid_tgt) ||
        (!kr->is_offline && !kr->active_ccache && kr->pd->cmd != SSS_CMD_RENEW)) {
            DEBUG(SSSDBG_TRACE_ALL, "Recreating  ccache file.\n");
            ccname_template = dp_opt_get_cstring(kr->krb5_ctx->opts,
                                                 KRB5_CCNAME_TMPL);
            kr->ccname = expand_ccname_template(kr, kr, ccname_template, true,
                                                be_ctx->domain->case_sensitive);
            if (kr->ccname == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "expand_ccname_template failed.\n");
                return ENOMEM;
            }

            ret = sss_krb5_precreate_ccache(kr->ccname,
                                            kr->krb5_ctx->illegal_path_re,
                                            kr->uid, kr->gid);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "ccache creation failed.\n");
                return ret;
            }
    }

    return EOK;
}

static void krb5_auth_store_creds(struct sss_domain_info *domain,
                                  struct pam_data *pd)
{
    const char *password = NULL;
    int ret = EOK;

    switch(pd->cmd) {
        case SSS_CMD_RENEW:
            /* The authtok is set to the credential cache
             * during renewal. We don't want to save this
             * as the cached password.
             */
            break;
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            ret = sss_authtok_get_password(pd->authtok, &password, NULL);
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
        if (pd->cmd != SSS_CMD_RENEW) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "password not available, offline auth may not work.\n");
            /* password caching failures are not fatal errors */
        }
        return;
    }

    ret = sysdb_cache_password(domain, pd->user, password);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to cache password, offline auth may not work."
                  " (%d)[%s]!?\n", ret, strerror(ret));
        /* password caching failures are not fatal errors */
    }
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
    const char *ccache_file = NULL;
    const char *realm;
    struct tevent_req *req;
    struct tevent_req *subreq;
    int authtok_type;
    int ret;

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
            if (authtok_type != SSS_AUTHTOK_TYPE_PASSWORD) {
                /* handle empty password gracefully */
                if (authtok_type == SSS_AUTHTOK_TYPE_EMPTY) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Illegal zero-length authtok for user [%s]\n",
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

    attrs = talloc_array(state, const char *, 7);
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
    attrs[6] = NULL;

    ret = krb5_setup(state, pd, krb5_ctx, &state->kr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_setup failed.\n");
        goto done;
    }
    kr = state->kr;

    ret = sysdb_get_user_attr(state, state->domain, state->pd->user, attrs,
                              &res);
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
        ret = find_or_guess_upn(state, res->msgs[0], krb5_ctx,
                                be_ctx->domain, pd->user, pd->domain,
                                &kr->upn);
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

        kr->homedir = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_HOMEDIR,
                                                  NULL);
        if (kr->homedir == NULL) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Home directory for user [%s] not known.\n", pd->user);
        }

        kr->uid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_UIDNUM, 0);
        if (kr->uid == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "UID for user [%s] not known.\n", pd->user);
            ret = ENOENT;
            goto done;
        }

        kr->gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM, 0);
        if (kr->gid == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "GID for user [%s] not known.\n", pd->user);
            ret = ENOENT;
            goto done;
        }

        ccache_file = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_CCACHE_FILE,
                                                  NULL);
        if (ccache_file != NULL) {
            ret = check_old_ccache(ccache_file, kr, realm,
                                   &kr->active_ccache,
                                   &kr->valid_tgt);
            if (ret == ENOENT) {
                DEBUG(SSSDBG_FUNC_DATA,
                      "Ignoring ccache attribute [%s], because it doesn't"
                       "exist.\n", ccache_file);
                ccache_file = NULL;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "check_if_ccache_file_is_used failed.\n");
                ccache_file = NULL;
            }
        } else {
            kr->active_ccache = false;
            kr->valid_tgt = false;
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "No ccache file for user [%s] found.\n", pd->user);
        }
        DEBUG(SSSDBG_TRACE_ALL,
              "Ccache_file is [%s] and is %s active and TGT is %s valid.\n",
                  ccache_file ? ccache_file : "not set",
                  kr->active_ccache ? "" : "not",
                  kr->valid_tgt ? "" : "not");
        if (ccache_file != NULL) {
            kr->ccname = ccache_file;
            kr->old_ccname = talloc_strdup(kr, ccache_file);
            if (kr->old_ccname == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else {
            kr->ccname = NULL;
            kr->old_ccname = NULL;
        }
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "User search for (%s) returned > 1 results!\n", pd->user);
        ret = EINVAL;
        goto done;
        break;
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
    char *msg;
    int ret;

    if (!state->search_kpasswd) {
        ret = be_resolve_server_recv(subreq, &kr->srv);
    } else {
        ret = be_resolve_server_recv(subreq, &kr->kpasswd_srv);
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
            be_mark_offline(state->be_ctx);
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

    ret = krb5_auth_prepare_ccache_name(kr, state->be_ctx);
    if (ret) {
        goto done;
    }

    if (kr->is_offline) {
        DEBUG(SSSDBG_TRACE_ALL, "Preparing for offline operation.\n");

        if (kr->valid_tgt || kr->active_ccache) {
            DEBUG(SSSDBG_TRACE_ALL, "Valid TGT available or "
                      "ccache file is already in use.\n");
            kr->ccname = kr->old_ccname;
            msg = talloc_asprintf(kr->pd,
                                  "%s=%s", CCACHE_ENV_NAME, kr->ccname);
            if (msg == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
            } else {
                ret = pam_add_response(kr->pd, SSS_PAM_ENV_ITEM,
                                       strlen(msg) + 1, (uint8_t *) msg);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                }
            }

            if (dp_opt_get_bool(kr->krb5_ctx->opts,
                                KRB5_STORE_PASSWORD_IF_OFFLINE)) {
                krb5_auth_cache_creds(state->kr->krb5_ctx,
                                      state->domain,
                                      state->be_ctx->cdb,
                                      kr->pd, kr->uid,
                                      &state->pam_status, &state->dp_err);
            } else {
                state->pam_status = PAM_AUTHINFO_UNAVAIL;
                state->dp_err = DP_ERR_OFFLINE;
            }
            ret = EOK;
            goto done;

        }
    }

    /* We need to keep the root privileges to read the keytab file if
     * validation or FAST is enabled, otherwise we can drop them and run
     * krb5_child with user privileges.
     * If we are offline we want to create an empty ccache file. In this
     * case we can drop the privileges, too. */
    if ((dp_opt_get_bool(kr->krb5_ctx->opts, KRB5_VALIDATE) ||
         kr->krb5_ctx->use_fast) &&
        (!kr->is_offline)) {
        kr->run_as_user = false;
    } else {
        kr->run_as_user = true;
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
    uint32_t user_info_type;

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
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected PAM task\n");
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

    /* Check if the cases of our upn are correct and update it if needed.
     * Fail if the upn differs by more than just the case for non-enterprise
     * principals. */
    if (res->correct_upn != NULL &&
        strcmp(kr->upn, res->correct_upn) != 0) {
        if (strcasecmp(kr->upn, res->correct_upn) == 0 ||
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

    case ERR_CREDS_EXPIRED:
        /* If the password is expired we can safely remove the ccache from the
         * cache and disk if it is not actively used anymore. This will allow
         * to create a new random ccache if sshd with privilege separation is
         * used. */
        if (pd->cmd == SSS_PAM_AUTHENTICATE && !kr->active_ccache) {
            if (kr->old_ccname != NULL) {
                ret = safe_remove_old_ccache_file(kr->old_ccname, NULL,
                                                  kr->uid, kr->gid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed to remove old ccache file [%s], "
                              "please remove it manually.\n", kr->old_ccname);
                }

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

    default:
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

    /* Now only a successful authentication or password change is left.
     *
     * We expect that one of the messages in the received buffer contains
     * the name of the credential cache file. */
    if (kr->ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing ccache name in child response.\n");
        ret = EINVAL;
        goto done;
    }

    ret = sss_krb5_check_ccache_princ(kr->uid, kr->gid, kr->ccname, kr->upn);
    if (ret) {
        if (res->otp == true && pd->cmd == SSS_PAM_CHAUTHTOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "Password change succeeded but currently "
                  "post-chpass kinit is not implemented\n");

            user_info_type = SSS_PAM_USER_INFO_OTP_CHPASS;
            ret = pam_add_response(pd, SSS_PAM_USER_INFO, sizeof(uint32_t),
                                   (const uint8_t *) &user_info_type);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                /* Not fatal */
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "No ccache for %s in %s?\n", kr->upn, kr->ccname);
            goto done;
        }
    }

    if (kr->old_ccname) {
        ret = safe_remove_old_ccache_file(kr->old_ccname, kr->ccname,
                                          kr->uid, kr->gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to remove old ccache file [%s], "
                   "please remove it manually.\n", kr->old_ccname);
        }
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
                            KRB5_STORE_PASSWORD_IF_OFFLINE)) {
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

    if (state->be_ctx->domain->cache_credentials == TRUE && !res->otp) {
        krb5_auth_store_creds(state->domain, pd);
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

void krb5_pam_handler_auth_done(struct tevent_req *req);
static void krb5_pam_handler_access_done(struct tevent_req *req);

void krb5_pam_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct tevent_req *req;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    int dp_err = DP_ERR_FATAL;
    int ret;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);
    pd->pam_status = PAM_SYSTEM_ERR;

    krb5_ctx = get_krb5_ctx(be_req);
    if (krb5_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Kerberos context not available.\n");
        goto done;
    }

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_CMD_RENEW:
        case SSS_PAM_CHAUTHTOK_PRELIM:
        case SSS_PAM_CHAUTHTOK:
            ret = add_to_wait_queue(be_req, pd, krb5_ctx);
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "Request successfully added to wait queue "
                          "of user [%s].\n", pd->user);
                return;
            } else if (ret == ENOENT) {
                DEBUG(SSSDBG_TRACE_LIBS, "Wait queue of user [%s] is empty, "
                          "running request immediately.\n", pd->user);
            } else {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "Failed to add request to wait queue of user [%s], "
                          "running request immediately.\n", pd->user);
            }

            req = krb5_auth_send(be_req, be_ctx->ev, be_ctx, pd, krb5_ctx);
            if (req == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "krb5_auth_send failed.\n");
                goto done;
            }

            tevent_req_set_callback(req, krb5_pam_handler_auth_done, be_req);
            break;
        case SSS_PAM_ACCT_MGMT:
            req = krb5_access_send(be_req, be_ctx->ev, be_ctx, pd, krb5_ctx);
            if (req == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "krb5_access_send failed.\n");
                goto done;
            }

            tevent_req_set_callback(req, krb5_pam_handler_access_done, be_req);
            break;
        case SSS_PAM_SETCRED:
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_CLOSE_SESSION:
            pd->pam_status = PAM_SUCCESS;
            dp_err = DP_ERR_OK;
            goto done;
            break;
        default:
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "krb5 does not handles pam task %d.\n", pd->cmd);
            pd->pam_status = PAM_MODULE_UNKNOWN;
            dp_err = DP_ERR_OK;
            goto done;
    }

    return;

done:
    be_req_terminate(be_req, dp_err, pd->pam_status, NULL);
}

void krb5_pam_handler_auth_done(struct tevent_req *req)
{
    int ret;
    struct be_req *be_req = tevent_req_callback_data(req, struct be_req);
    int pam_status;
    int dp_err;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    ret = krb5_auth_recv(req, &pam_status, &dp_err);
    talloc_zfree(req);
    if (ret) {
        pd->pam_status = PAM_SYSTEM_ERR;
        dp_err = DP_ERR_OK;
    } else {
        pd->pam_status = pam_status;
    }

    krb5_ctx = get_krb5_ctx(be_req);
    if (krb5_ctx != NULL) {
        check_wait_queue(krb5_ctx, pd->user);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Kerberos context not available.\n");
    }

    be_req_terminate(be_req, dp_err, pd->pam_status, NULL);
}

static void krb5_pam_handler_access_done(struct tevent_req *req)
{
    int ret;
    struct be_req *be_req = tevent_req_callback_data(req, struct be_req);
    bool access_allowed;
    struct pam_data *pd;
    int dp_err = DP_ERR_OK;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);
    pd->pam_status = PAM_SYSTEM_ERR;

    ret = krb5_access_recv(req, &access_allowed);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "krb5_access request failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Access %s for user [%s].\n",
              access_allowed ? "allowed" : "denied", pd->user);
    pd->pam_status = access_allowed ? PAM_SUCCESS : PAM_PERM_DENIED;
    dp_err = DP_ERR_OK;

done:
    be_req_terminate(be_req, dp_err, pd->pam_status, NULL);
}
