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

static errno_t safe_remove_old_ccache_file(struct sss_krb5_cc_be *cc_be,
                                           const char *princ,
                                           const char *old_ccache,
                                           const char *new_ccache)
{
    int ret;
    enum sss_krb5_cc_type old_type;
    struct sss_krb5_cc_be *old_cc_ops;

    if (old_ccache == NULL) {
        DEBUG(SSSDBG_FUNC_DATA, ("No old ccache, nothing to do\n"));
        return EOK;
    }

    if (new_ccache == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Missing new ccache file, old ccache file is not deleted.\n"));
        return EINVAL;
    }

    old_type = sss_krb5_get_type(old_ccache);
    old_cc_ops = get_cc_be_ops(old_type);
    if (!old_cc_ops) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot get ccache operations\n"));
        return EINVAL;
    }

    if (cc_be->type == old_type &&
        strcmp(old_ccache, new_ccache) == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, ("New and old ccache file are the same, "
                                  "no one will be deleted.\n"));
        return EOK;
    }

    ret = old_cc_ops->remove(old_ccache);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                ("Cannot remove ccache [%s]\n", old_ccache));
        return EIO;
    }

    return EOK;
}

static errno_t
check_old_ccache(const char *old_ccache, struct krb5child_req *kr,
                 const char *realm, bool *active, bool *valid)
{
    struct sss_krb5_cc_be *old_cc_ops;
    const char *cc_template;
    errno_t ret;

    /* ccache file might be of a different type if the user changed
     * configuration
     */
    old_cc_ops = get_cc_be_ops_ccache(old_ccache);
    if (old_cc_ops == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot get operations on saved ccache %s\n", old_ccache));
        return EINVAL;
    }

    cc_template = dp_opt_get_cstring(kr->krb5_ctx->opts, KRB5_CCNAME_TMPL);

    ret = old_cc_ops->check_existing(old_ccache, kr->uid, realm, kr->upn,
                                     cc_template, active, valid);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Saved ccache %s doesn't exist.\n", old_ccache));
        return ret;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Cannot check if saved ccache %s is active and valid\n",
               old_ccache));
        return ret;
    }

    return EOK;
}

static int krb5_mod_ccname(TALLOC_CTX *mem_ctx,
                           struct sysdb_ctx *sysdb,
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
        DEBUG(1, ("Missing user or ccache name.\n"));
        return EINVAL;
    }

    if (mod_op != SYSDB_MOD_REP && mod_op != SYSDB_MOD_DEL) {
        DEBUG(1, ("Unsupported operation [%d].\n", mod_op));
        return EINVAL;
    }

    DEBUG(9, ("%s ccname [%s] for user [%s].\n",
              mod_op == SYSDB_MOD_REP ? "Save" : "Delete", ccname, name));

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
        DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error %d starting transaction (%s)\n", ret, strerror(ret)));
        goto done;
    }
    in_transaction = true;

    ret = sysdb_set_user_attr(sysdb, name, attrs, mod_op);
    if (ret != EOK) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction!\n"));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction\n"));
        }
    }
    talloc_zfree(tmpctx);
    return ret;
}

static int krb5_save_ccname(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            const char *name,
                            const char *ccname)
{
    return krb5_mod_ccname(mem_ctx, sysdb, name, ccname,
                           SYSDB_MOD_REP);
}

static int krb5_delete_ccname(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              const char *name,
                              const char *ccname)
{
    return krb5_mod_ccname(mem_ctx, sysdb, name, ccname,
                           SYSDB_MOD_DEL);
}

static struct krb5_ctx *get_krb5_ctx(struct be_req *be_req)
{
    struct pam_data *pd;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_CMD_RENEW:
            return talloc_get_type(be_req->be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                                   struct krb5_ctx);
            break;
        case SSS_PAM_ACCT_MGMT:
            return talloc_get_type(be_req->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                   struct krb5_ctx);
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            return talloc_get_type(be_req->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                                   struct krb5_ctx);
            break;
        default:
            DEBUG(1, ("Unsupported PAM task.\n"));
            return NULL;
    }
}

static void krb_reply(struct be_req *req, int dp_err, int result);

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
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }
    kr->is_offline = false;
    kr->active_ccache_present = true;
    kr->run_as_user = true;
    talloc_set_destructor((TALLOC_CTX *) kr, krb5_cleanup);

    kr->pd = pd;
    kr->krb5_ctx = krb5_ctx;

    *krb5_req = kr;

    return EOK;
}

static void krb5_resolve_kdc_done(struct tevent_req *subreq);
static void krb5_resolve_kpasswd_done(struct tevent_req *subreq);
static void krb5_find_ccache_step(struct tevent_req *req);
static void krb5_save_ccname_done(struct tevent_req *req);
static void krb5_child_done(struct tevent_req *req);
static void krb5_pam_handler_cache_auth_step(struct tevent_req *req);

struct krb5_auth_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct pam_data *pd;
    struct sysdb_ctx *sysdb;
    struct krb5_ctx *krb5_ctx;
    struct krb5child_req *kr;

    int pam_status;
    int dp_err;
};

int krb5_auth_recv(struct tevent_req *req, int *pam_status, int *dp_err)
{
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);

    *pam_status = state->pam_status;
    *dp_err = state->dp_err;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static struct tevent_req *krb5_next_kdc(struct tevent_req *req);
static struct tevent_req *krb5_next_kpasswd(struct tevent_req *req);

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
    int ret;
    struct sss_domain_info *dom;

    req = tevent_req_create(mem_ctx, &state, struct krb5_auth_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->pd = pd;
    state->krb5_ctx = krb5_ctx;
    state->kr = NULL;
    state->pam_status = PAM_SYSTEM_ERR;
    state->dp_err = DP_ERR_FATAL;

    ret = get_domain_or_subdomain(state, be_ctx, pd->domain, &dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("get_domain_or_subdomain failed.\n"));
        goto done;
    }

    state->sysdb = dom->sysdb;

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_CMD_RENEW:
        case SSS_PAM_CHAUTHTOK:
            break;
        case SSS_PAM_CHAUTHTOK_PRELIM:
            if (pd->priv == 1 && pd->authtok_size == 0) {
                DEBUG(4, ("Password reset by root is not supported.\n"));
                state->pam_status = PAM_PERM_DENIED;
                state->dp_err = DP_ERR_OK;
                ret = EOK;
                goto done;
            }
            break;
        default:
            DEBUG(4, ("Unexpected pam task %d.\n", pd->cmd));
            state->pam_status = PAM_SYSTEM_ERR;
            state->dp_err = DP_ERR_FATAL;
            ret = EINVAL;
            goto done;
    }

    if (be_is_offline(be_ctx) &&
        (pd->cmd == SSS_PAM_CHAUTHTOK || pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM ||
         pd->cmd == SSS_CMD_RENEW)) {
        DEBUG(9, ("Password changes and ticket renewal are not possible "
                  "while offline.\n"));
        state->pam_status = PAM_AUTHINFO_UNAVAIL;
        state->dp_err = DP_ERR_OFFLINE;
        ret = EOK;
        goto done;
    }

    attrs = talloc_array(state, const char *, 6);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    attrs[0] = SYSDB_UPN;
    attrs[1] = SYSDB_HOMEDIR;
    attrs[2] = SYSDB_CCACHE_FILE;
    attrs[3] = SYSDB_UIDNUM;
    attrs[4] = SYSDB_GIDNUM;
    attrs[5] = NULL;

    ret = krb5_setup(state, pd, krb5_ctx, &state->kr);
    if (ret != EOK) {
        DEBUG(1, ("krb5_setup failed.\n"));
        goto done;
    }
    kr = state->kr;

    ret = sysdb_get_user_attr(state, state->sysdb, state->pd->user, attrs,
                              &res);
    if (ret) {
        DEBUG(5, ("sysdb search for upn of user [%s] failed.\n", pd->user));
        state->pam_status = PAM_SYSTEM_ERR;
        state->dp_err = DP_ERR_OK;
        goto done;
    }

    realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
    if (realm == NULL) {
        DEBUG(1, ("Missing Kerberos realm.\n"));
        ret = ENOENT;
        goto done;
    }

    switch (res->count) {
    case 0:
        DEBUG(5, ("No attributes for user [%s] found.\n", pd->user));
        ret = ENOENT;
        goto done;
        break;

    case 1:
        ret = find_or_guess_upn(state, res->msgs[0], krb5_ctx,
                                be_ctx->domain->name, pd->user, pd->domain,
                                &kr->upn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("find_or_guess_upn failed.\n"));
            goto done;
        }

        ret = compare_principal_realm(kr->upn, realm,
                                      &kr->upn_from_different_realm);
        if (ret != 0) {
            DEBUG(SSSDBG_OP_FAILURE, ("compare_principal_realm failed.\n"));
            goto done;
        }

        kr->homedir = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_HOMEDIR,
                                                  NULL);
        if (kr->homedir == NULL) {
            DEBUG(4, ("Home directory for user [%s] not known.\n", pd->user));
        }

        kr->uid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_UIDNUM, 0);
        if (kr->uid == 0) {
            DEBUG(4, ("UID for user [%s] not known.\n", pd->user));
            ret = ENOENT;
            goto done;
        }

        kr->gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM, 0);
        if (kr->gid == 0) {
            DEBUG(4, ("GID for user [%s] not known.\n", pd->user));
            ret = ENOENT;
            goto done;
        }

        /* The type of the ccache might change during the request if we
         * end up reusing an old ccache */
        kr->cc_be = krb5_ctx->cc_be;

        ccache_file = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_CCACHE_FILE,
                                                  NULL);
        if (ccache_file != NULL) {
            ret = check_old_ccache(ccache_file, kr, realm,
                                   &kr->active_ccache_present,
                                   &kr->valid_tgt_present);
            if (ret == ENOENT) {
                DEBUG(SSSDBG_FUNC_DATA,
                      ("Ignoring ccache attribute [%s], because it doesn't"
                       "exist.\n", ccache_file));
                ccache_file = NULL;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      ("check_if_ccache_file_is_used failed.\n"));
                goto done;
            }
        } else {
            kr->active_ccache_present = false;
            kr->valid_tgt_present = false;
            DEBUG(4, ("No ccache file for user [%s] found.\n", pd->user));
        }
        DEBUG(9, ("Ccache_file is [%s] and is %s active and TGT is %s valid.\n",
                  ccache_file ? ccache_file : "not set",
                  kr->active_ccache_present ? "" : "not",
                  kr->valid_tgt_present ? "" : "not"));
        if (ccache_file != NULL) {
            kr->ccname = ccache_file;
            kr->old_ccname = talloc_strdup(kr, ccache_file);
            if (kr->old_ccname == NULL) {
                DEBUG(1, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
        } else {
            kr->ccname = NULL;
            kr->old_ccname = NULL;
        }
        break;

    default:
        DEBUG(1, ("User search for (%s) returned > 1 results!\n", pd->user));
        ret = EINVAL;
        goto done;
        break;
    }

    kr->srv = NULL;
    kr->kpasswd_srv = NULL;

    subreq = krb5_next_kdc(req);
    if (!subreq) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_next_kdc failed.\n"));
        ret = EIO;
        goto done;
    }

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

static void krb5_resolve_kdc_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    struct krb5child_req *kr = state->kr;
    int ret;

    ret = be_resolve_server_recv(subreq, &kr->srv);
    talloc_zfree(subreq);
    if (ret) {
        /* all servers have been tried and none
         * was found good, setting offline,
         * but we still have to call the child to setup
         * the ccache file if we are performing auth */
        be_mark_offline(state->be_ctx);
        kr->is_offline = true;

        if (kr->pd->cmd == SSS_PAM_CHAUTHTOK ||
            kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("No KDC suitable for password change is available\n"));
            state->pam_status = PAM_AUTHTOK_LOCK_BUSY;
            state->dp_err = DP_ERR_OK;
            tevent_req_done(req);
            return;
        }
    } else {
        if (kr->krb5_ctx->kpasswd_service != NULL) {
            subreq = krb5_next_kpasswd(req);
            if (subreq == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_next_kpasswd failed.\n"));
                ret = EIO;
                goto failed;
            }
            return;
        }
    }

    krb5_find_ccache_step(req);
    return;

failed:
    tevent_req_error(req, ret);
}

static void krb5_resolve_kpasswd_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    int ret;

    ret = be_resolve_server_recv(subreq, &state->kr->kpasswd_srv);
    talloc_zfree(subreq);
    if (ret != EOK &&
        (state->kr->pd->cmd == SSS_PAM_CHAUTHTOK ||
         state->kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM)) {
        /* all kpasswd servers have been tried and none was found good, but the
         * kdc seems ok. Password changes are not possible but
         * authentication is. We return an PAM error here, but do not mark the
         * backend offline. */
        state->pam_status = PAM_AUTHTOK_LOCK_BUSY;
        state->dp_err = DP_ERR_OK;
        tevent_req_done(req);
        return;
    }

    krb5_find_ccache_step(req);
}

static void krb5_find_ccache_step(struct tevent_req *req)
{
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    int ret;
    struct krb5child_req *kr = state->kr;
    struct pam_data *pd = kr->pd;
    char *msg;
    bool private_path = false;
    struct tevent_req *subreq = NULL;

    if (!kr->is_offline) {
        kr->is_offline = be_is_offline(state->be_ctx);
    }

    /* The ccache file should be (re)created if one of the following conditions
     * is true:
     * - it doesn't exist (kr->ccname == NULL)
     * - the backend is online and the current ccache file is not used, i.e
     *   the related user is currently not logged in and it is not a renewal
     *   request
     *   (!kr->is_offline && !kr->active_ccache_present &&
     *    pd->cmd != SSS_CMD_RENEW)
     * - the backend is offline and the current cache file not used and
     *   it does not contain a valid tgt
     *   (kr->is_offline &&
     *    !kr->active_ccache_present && !kr->valid_tgt_present)
     */
    if (kr->ccname == NULL ||
        (kr->is_offline && !kr->active_ccache_present &&
            !kr->valid_tgt_present) ||
        (!kr->is_offline && !kr->active_ccache_present &&
         pd->cmd != SSS_CMD_RENEW)) {
            DEBUG(9, ("Recreating  ccache file.\n"));
            kr->ccname = expand_ccname_template(kr, kr,
                                          dp_opt_get_cstring(kr->krb5_ctx->opts,
                                                             KRB5_CCNAME_TMPL),
                                                true,
                                                state->be_ctx->domain->case_sensitive,
                                                &private_path);
            if (kr->ccname == NULL) {
                DEBUG(1, ("expand_ccname_template failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            if (!kr->cc_be) {
                kr->cc_be = get_cc_be_ops_ccache(kr->ccname);
                if (kr->cc_be == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          ("Cannot get operations on new ccache %s\n",
                           kr->ccname));
                    ret = EINVAL;
                    goto done;
                }
            }

            ret = kr->cc_be->create(kr->ccname,
                                    kr->krb5_ctx->illegal_path_re,
                                    kr->uid, kr->gid, private_path);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("ccache creation failed.\n"));
                goto done;
            }
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Saved ccache %s if of different type than ccache in "
               "configuration file, reusing the old ccache\n",
               kr->old_ccname));

        kr->cc_be = get_cc_be_ops_ccache(kr->old_ccname);
        if (kr->cc_be == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Cannot get operations on saved ccache %s\n",
                   kr->old_ccname));
            ret = EINVAL;
            goto done;
        }

    }

    if (kr->is_offline) {
        DEBUG(9, ("Preparing for offline operation.\n"));

        if (kr->valid_tgt_present || kr->active_ccache_present) {
            DEBUG(9, ("Valid TGT available or "
                      "ccache file is already in use.\n"));
            kr->ccname = kr->old_ccname;
            msg = talloc_asprintf(pd, "%s=%s", CCACHE_ENV_NAME, kr->ccname);
            if (msg == NULL) {
                DEBUG(1, ("talloc_asprintf failed.\n"));
            } else {
                ret = pam_add_response(pd, SSS_PAM_ENV_ITEM, strlen(msg) + 1,
                                       (uint8_t *) msg);
                if (ret != EOK) {
                    DEBUG(1, ("pam_add_response failed.\n"));
                }
            }

            if (dp_opt_get_bool(kr->krb5_ctx->opts,
                                KRB5_STORE_PASSWORD_IF_OFFLINE)) {
                krb5_pam_handler_cache_auth_step(req);
                return;
            }

            state->pam_status = PAM_AUTHINFO_UNAVAIL;
            state->dp_err = DP_ERR_OFFLINE;
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
        !kr->is_offline) {
        kr->run_as_user = false;
    } else {
        kr->run_as_user = true;
    }

    subreq = handle_child_send(state, state->ev, kr);
    if (subreq == NULL) {
        DEBUG(1, ("handle_child_send failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, krb5_child_done, req);
    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static struct tevent_req *krb5_next_server(struct tevent_req *req);
static struct tevent_req *krb5_next_kpasswd(struct tevent_req *req);

static void krb5_child_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);

    struct krb5child_req *kr = state->kr;
    struct pam_data *pd = state->pd;
    int ret;
    uint8_t *buf = NULL;
    ssize_t len = -1;
    struct krb5_child_response *res;
    const char *store_ccname;

    ret = handle_child_recv(subreq, pd, &buf, &len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("child failed (%d [%s])\n", ret, strerror(ret)));
        if (ret == ETIMEDOUT) {
            if (krb5_next_server(req) == NULL) {
                tevent_req_error(req, ENOMEM);
            }
        } else {
            tevent_req_error(req, ret);
        }
        return;
    }

    ret = parse_krb5_child_response(state, buf, len, pd,
                        state->be_ctx->domain->pwd_expiration_warning,
                        &res);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not parse child response [%d]: %s\n",
              ret, strerror(ret)));
        goto done;
    }

    if (res->ccname) {
        kr->ccname = talloc_strdup(kr, res->ccname);
        if (!kr->ccname) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* Check if the cases of our upn are correct and update it if needed.
     * Fail if the upn differs by more than just the case. */
    if (res->correct_upn != NULL &&
        strcmp(kr->upn, res->correct_upn) != 0) {
        if (strcasecmp(kr->upn, res->correct_upn) == 0) {
            talloc_free(kr->upn);
            kr->upn = talloc_strdup(kr, res->correct_upn);
            if (kr->upn == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            ret = check_if_cached_upn_needs_update(state->sysdb, pd->user,
                                                   res->correct_upn);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("check_if_cached_upn_needs_update failed.\n"));
                goto done;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, ("UPN used in the request [%s] and " \
                                        "returned UPN [%s] differ by more " \
                                        "than just the case.\n",
                                        kr->upn, res->correct_upn));
            ret = EINVAL;
            goto done;
        }
    }

    /* If the child request failed, but did not return an offline error code,
     * return with the status */
    if (res->msg_status != PAM_SUCCESS &&
        res->msg_status != PAM_AUTHINFO_UNAVAIL &&
        res->msg_status != PAM_AUTHTOK_LOCK_BUSY &&
        res->msg_status != PAM_NEW_AUTHTOK_REQD) {
        state->pam_status = res->msg_status;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;
    } else {
        state->pam_status = res->msg_status;
    }

    /* If the password is expired we can safely remove the ccache from the
     * cache and disk if it is not actively used anymore. This will allow to
     * create a new random ccache if sshd with privilege separation is used. */
    if (res->msg_status == PAM_NEW_AUTHTOK_REQD) {
        if (pd->cmd == SSS_PAM_AUTHENTICATE && !kr->active_ccache_present) {
            if (kr->old_ccname != NULL) {
                ret = safe_remove_old_ccache_file(kr->cc_be, kr->upn,
                                                  kr->old_ccname, "dummy");
                if (ret != EOK) {
                    DEBUG(1, ("Failed to remove old ccache file [%s], "
                              "please remove it manually.\n", kr->old_ccname));
                }

                ret = krb5_delete_ccname(state, state->sysdb,
                                         pd->user, kr->old_ccname);
                if (ret != EOK) {
                    DEBUG(1, ("krb5_delete_ccname failed.\n"));
                }
            }
        }

        state->pam_status = res->msg_status;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;
    }

    /* If the child request was successful and we run the first pass of the
     * change password request just return success. */
    if (res->msg_status == PAM_SUCCESS && pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
        state->pam_status = PAM_SUCCESS;
        state->dp_err = DP_ERR_OK;
        ret = EOK;
        goto done;
    }

    /* if using a dedicated kpasswd server for a chpass operation... */
    if (kr->kpasswd_srv != NULL &&
        (pd->cmd == SSS_PAM_CHAUTHTOK || pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM)) {
        /* ..which is unreachable by now.. */
        if (res->msg_status == PAM_AUTHTOK_LOCK_BUSY) {
            be_fo_set_port_status(state->be_ctx,
                                  state->krb5_ctx->kpasswd_service->name,
                                  kr->kpasswd_srv, PORT_NOT_WORKING);
            /* ..try to resolve next kpasswd server */
            if (krb5_next_kpasswd(req) == NULL) {
                tevent_req_error(req, ENOMEM);
            }
            return;
        } else {
            be_fo_set_port_status(state->be_ctx,
                                  state->krb5_ctx->kpasswd_service->name,
                                  kr->kpasswd_srv, PORT_WORKING);
        }
    }

    /* if the KDC for auth (PAM_AUTHINFO_UNAVAIL) or
     * chpass (PAM_AUTHTOK_LOCK_BUSY) was not available while using KDC
     * also for chpass operation... */
    if (res->msg_status == PAM_AUTHINFO_UNAVAIL ||
        (kr->kpasswd_srv == NULL && res->msg_status == PAM_AUTHTOK_LOCK_BUSY)) {
        if (kr->srv != NULL) {
            be_fo_set_port_status(state->be_ctx, state->krb5_ctx->service->name,
                                  kr->srv, PORT_NOT_WORKING);
            /* ..try to resolve next KDC */
            if (krb5_next_kdc(req) == NULL) {
                tevent_req_error(req, ENOMEM);
            }
            return;
        }
    } else if (kr->srv != NULL) {
        be_fo_set_port_status(state->be_ctx, state->krb5_ctx->service->name,
                              kr->srv, PORT_WORKING);
    }

    /* Now only a successful authentication or password change is left.
     *
     * We expect that one of the messages in the received buffer contains
     * the name of the credential cache file. */
    if (kr->ccname == NULL) {
        DEBUG(1, ("Missing ccache name in child response.\n"));
        ret = EINVAL;
        goto done;
    }

    store_ccname = kr->cc_be->ccache_for_princ(kr, kr->ccname,
                                               kr->upn);
    if (store_ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                ("No ccache for %s in %s?\n", kr->upn, kr->ccname));
        ret = EIO;
        goto done;
    }

    ret = safe_remove_old_ccache_file(kr->cc_be, kr->upn,
                                      kr->old_ccname, store_ccname);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to remove old ccache file [%s], "
               "please remove it manually.\n", kr->old_ccname));
    }

    ret = krb5_save_ccname(state, state->sysdb,
                           pd->user, store_ccname);
    if (ret) {
        DEBUG(1, ("krb5_save_ccname failed.\n"));
        goto done;
    }

    if (res->msg_status == PAM_SUCCESS &&
        dp_opt_get_int(kr->krb5_ctx->opts, KRB5_RENEW_INTERVAL) > 0 &&
        (pd->cmd == SSS_PAM_AUTHENTICATE || pd->cmd == SSS_CMD_RENEW ||
         pd->cmd == SSS_PAM_CHAUTHTOK) &&
        res->tgtt.renew_till > res->tgtt.endtime && kr->ccname != NULL) {
        DEBUG(7, ("Adding [%s] for automatic renewal.\n", kr->ccname));
        ret = add_tgt_to_renew_table(kr->krb5_ctx, kr->ccname, &(res->tgtt),
                                     pd, kr->upn);
        if (ret != EOK) {
            DEBUG(1, ("add_tgt_to_renew_table failed, "
                      "automatic renewal not possible.\n"));
        }
    }

    krb5_save_ccname_done(req);

    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static struct tevent_req *krb5_next_server(struct tevent_req *req)
{
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    struct pam_data *pd = state->pd;
    struct tevent_req *next_req = NULL;

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_CMD_RENEW:
            be_fo_set_port_status(state->be_ctx, state->krb5_ctx->service->name,
                                  state->kr->srv, PORT_NOT_WORKING);
            next_req = krb5_next_kdc(req);
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            if (state->kr->kpasswd_srv) {
                be_fo_set_port_status(state->be_ctx,
                                      state->krb5_ctx->kpasswd_service->name,
                                      state->kr->kpasswd_srv, PORT_NOT_WORKING);
                next_req = krb5_next_kpasswd(req);
                break;
            } else {
                be_fo_set_port_status(state->be_ctx, state->krb5_ctx->service->name,
                                      state->kr->srv, PORT_NOT_WORKING);
                next_req = krb5_next_kdc(req);
                break;
            }
        default:
            DEBUG(1, ("Unexpected PAM task\n"));
    }

    return next_req;
}

static struct tevent_req *krb5_next_kdc(struct tevent_req *req)
{
    struct tevent_req *next_req;
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);

    next_req = be_resolve_server_send(state, state->ev,
                                      state->be_ctx,
                                      state->krb5_ctx->service->name,
                                      state->kr->srv == NULL ? true : false);
    if (next_req == NULL) {
        DEBUG(1, ("be_resolve_server_send failed.\n"));
        return NULL;
    }
    tevent_req_set_callback(next_req, krb5_resolve_kdc_done, req);

    return next_req;
}

static struct tevent_req *krb5_next_kpasswd(struct tevent_req *req)
{
    struct tevent_req *next_req;
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);

    next_req = be_resolve_server_send(state, state->ev,
                                state->be_ctx,
                                state->krb5_ctx->kpasswd_service->name,
                                state->kr->kpasswd_srv == NULL ? true : false);
    if (next_req == NULL) {
        DEBUG(1, ("be_resolve_server_send failed.\n"));
        return NULL;
    }
    tevent_req_set_callback(next_req, krb5_resolve_kpasswd_done, req);

    return next_req;
}

static void krb5_save_ccname_done(struct tevent_req *req)
{
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    struct krb5child_req *kr = state->kr;
    struct pam_data *pd = state->pd;
    int ret;
    char *password = NULL;

    if (kr->is_offline) {
        if (dp_opt_get_bool(kr->krb5_ctx->opts,KRB5_STORE_PASSWORD_IF_OFFLINE)) {
            krb5_pam_handler_cache_auth_step(req);
            return;
        }

        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        state->pam_status = PAM_AUTHINFO_UNAVAIL;
        state->dp_err = DP_ERR_OFFLINE;
        ret = EOK;
        goto done;
    }

    if (state->be_ctx->domain->cache_credentials == TRUE) {

        /* password caching failures are not fatal errors */
        state->pam_status = PAM_SUCCESS;
        state->dp_err = DP_ERR_OK;

        switch(pd->cmd) {
            case SSS_CMD_RENEW:
                /* The authtok is set to the credential cache
                 * during renewal. We don't want to save this
                 * as the cached password.
                 */
                break;
            case SSS_PAM_AUTHENTICATE:
            case SSS_PAM_CHAUTHTOK_PRELIM:
                password = talloc_size(state, pd->authtok_size + 1);
                if (password != NULL) {
                    memcpy(password, pd->authtok, pd->authtok_size);
                    password[pd->authtok_size] = '\0';
                }
                break;
            case SSS_PAM_CHAUTHTOK:
                password = talloc_size(state, pd->newauthtok_size + 1);
                if (password != NULL) {
                    memcpy(password, pd->newauthtok, pd->newauthtok_size);
                    password[pd->newauthtok_size] = '\0';
                }
                break;
            default:
                DEBUG(0, ("unsupported PAM command [%d].\n", pd->cmd));
        }

        if (password == NULL) {
            if (pd->cmd != SSS_CMD_RENEW) {
                DEBUG(0, ("password not available, offline auth may not work.\n"));
                /* password caching failures are not fatal errors */
            }
            ret = EOK;
            goto done;
        }

        talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

        ret = sysdb_cache_password(state->sysdb, pd->user, password);
        if (ret) {
            DEBUG(2, ("Failed to cache password, offline auth may not work."
                      " (%d)[%s]!?\n", ret, strerror(ret)));
            /* password caching failures are not fatal errors */
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

static void krb5_pam_handler_cache_auth_step(struct tevent_req *req)
{
    struct krb5_auth_state *state = tevent_req_data(req, struct krb5_auth_state);
    struct pam_data *pd = state->pd;
    struct krb5_ctx *krb5_ctx = state->kr->krb5_ctx;
    int ret;

    ret = sysdb_cache_auth(state->sysdb, pd->user, pd->authtok,
                           pd->authtok_size, state->be_ctx->cdb, true, NULL,
                           NULL);
    if (ret != EOK) {
        DEBUG(1, ("Offline authentication failed\n"));
        state->pam_status = cached_login_pam_status(ret);
        state->dp_err = DP_ERR_OK;
    } else {
        ret = add_user_to_delayed_online_authentication(krb5_ctx, pd,
                                                       state->kr->uid);
        if (ret != EOK) {
            /* This error is not fatal */
            DEBUG(1, ("add_user_to_delayed_online_authentication failed.\n"));
        }
        state->pam_status = PAM_AUTHINFO_UNAVAIL;
        state->dp_err = DP_ERR_OFFLINE;
    }

    tevent_req_done(req);
}

static void krb_reply(struct be_req *req, int dp_err, int result)
{
    req->fn(req, dp_err, result, NULL);
}

void krb5_auth_done(struct tevent_req *req);
static void krb5_access_done(struct tevent_req *req);

void krb5_pam_handler(struct be_req *be_req)
{
    struct tevent_req *req;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    int dp_err = DP_ERR_FATAL;
    int ret;

    pd = talloc_get_type(be_req->req_data, struct pam_data);
    pd->pam_status = PAM_SYSTEM_ERR;

    krb5_ctx = get_krb5_ctx(be_req);
    if (krb5_ctx == NULL) {
        DEBUG(1, ("Kerberos context not available.\n"));
        goto done;
    }

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_CMD_RENEW:
        case SSS_PAM_CHAUTHTOK_PRELIM:
        case SSS_PAM_CHAUTHTOK:
            ret = add_to_wait_queue(be_req, pd, krb5_ctx);
            if (ret == EOK) {
                DEBUG(7, ("Request successfully added to wait queue "
                          "of user [%s].\n", pd->user));
                return;
            } else if (ret == ENOENT) {
                DEBUG(7, ("Wait queue of user [%s] is empty, "
                          "running request immediately.\n", pd->user));
            } else {
                DEBUG(7, ("Failed to add request to wait queue of user [%s], "
                          "running request immediately.\n", pd->user));
            }

            req = krb5_auth_send(be_req, be_req->be_ctx->ev, be_req->be_ctx, pd,
                                 krb5_ctx);
            if (req == NULL) {
                DEBUG(1, ("krb5_auth_send failed.\n"));
                goto done;
            }

            tevent_req_set_callback(req, krb5_auth_done, be_req);
            break;
        case SSS_PAM_ACCT_MGMT:
            req = krb5_access_send(be_req, be_req->be_ctx->ev, be_req->be_ctx,
                                   pd, krb5_ctx);
            if (req == NULL) {
                DEBUG(1, ("krb5_access_send failed.\n"));
                goto done;
            }

            tevent_req_set_callback(req, krb5_access_done, be_req);
            break;
        case SSS_PAM_SETCRED:
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_CLOSE_SESSION:
            pd->pam_status = PAM_SUCCESS;
            dp_err = DP_ERR_OK;
            goto done;
            break;
        default:
            DEBUG(4, ("krb5 does not handles pam task %d.\n", pd->cmd));
            pd->pam_status = PAM_MODULE_UNKNOWN;
            dp_err = DP_ERR_OK;
            goto done;
    }

    return;

done:
    krb_reply(be_req, dp_err, pd->pam_status);
}

void krb5_auth_done(struct tevent_req *req)
{
    int ret;
    struct be_req *be_req = tevent_req_callback_data(req, struct be_req);
    int pam_status;
    int dp_err;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

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
        DEBUG(1, ("Kerberos context not available.\n"));
    }

    krb_reply(be_req, dp_err, pd->pam_status);
}

static void krb5_access_done(struct tevent_req *req)
{
    int ret;
    struct be_req *be_req = tevent_req_callback_data(req, struct be_req);
    bool access_allowed;
    struct pam_data *pd;
    int dp_err = DP_ERR_OK;

    pd = talloc_get_type(be_req->req_data, struct pam_data);
    pd->pam_status = PAM_SYSTEM_ERR;

    ret = krb5_access_recv(req, &access_allowed);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("krb5_access request failed [%d][%s]\n", ret, strerror(ret)));
        goto done;
    }

    DEBUG(7, ("Access %s for user [%s].\n",
              access_allowed ? "allowed" : "denied", pd->user));
    pd->pam_status = access_allowed ? PAM_SUCCESS : PAM_PERM_DENIED;
    dp_err = DP_ERR_OK;

done:
    krb_reply(be_req, dp_err, pd->pam_status);
}
