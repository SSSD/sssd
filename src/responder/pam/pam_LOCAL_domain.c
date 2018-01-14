/*
   SSSD

   PAM e credentials

   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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

#include <time.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "util/crypto/sss_crypto.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"


#define NULL_CHECK_OR_JUMP(var, msg, ret, err, label) do { \
    if (var == NULL) { \
        DEBUG(SSSDBG_CRIT_FAILURE, msg); \
        ret = (err); \
        goto label; \
    } \
} while(0)

#define NEQ_CHECK_OR_JUMP(var, val, msg, ret, err, label) do { \
    if (var != (val)) { \
        DEBUG(SSSDBG_CRIT_FAILURE, msg); \
        ret = (err); \
        goto label; \
    } \
} while(0)


struct LOCAL_request {
    struct tevent_context *ev;
    struct sysdb_ctx *dbctx;
    struct sss_domain_info *domain;
    struct sysdb_attrs *mod_attrs;

    struct ldb_result *res;
    int error;

    struct pam_auth_req *preq;
};

static void prepare_reply(struct LOCAL_request *lreq)
{
    struct pam_data *pd;

    pd = lreq->preq->pd;

    if (lreq->error != EOK && pd->pam_status == PAM_SUCCESS)
        pd->pam_status = PAM_SYSTEM_ERR;

    lreq->preq->callback(lreq->preq);
}

static void do_successful_login(struct LOCAL_request *lreq)
{
    int ret;

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, "sysdb_new_attrs failed.\n",
                       lreq->error, ENOMEM, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               SYSDB_LAST_LOGIN, (long)time(NULL));
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_attrs_add_long failed.\n",
                      lreq->error, ret, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs, SYSDB_FAILED_LOGIN_ATTEMPTS, 0L);
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_attrs_add_long failed.\n",
                      lreq->error, ret, done);

    ret = sysdb_set_user_attr(lreq->domain,
                              lreq->preq->pd->user,
                              lreq->mod_attrs, SYSDB_MOD_REP);
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_set_user_attr failed.\n",
                      lreq->error, ret, done);

done:
    return;
}

static void do_failed_login(struct LOCAL_request *lreq)
{
    int ret;
    int failedLoginAttempts;
    struct pam_data *pd;

    pd = lreq->preq->pd;
    pd->pam_status = PAM_AUTH_ERR;
/* TODO: maybe add more intelligent delay calculation */
    pd->response_delay = 3;

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, "sysdb_new_attrs failed.\n",
                       lreq->error, ENOMEM, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               SYSDB_LAST_FAILED_LOGIN, (long)time(NULL));
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_attrs_add_long failed.\n",
                      lreq->error, ret, done);

    failedLoginAttempts = ldb_msg_find_attr_as_int(lreq->res->msgs[0],
                                                   SYSDB_FAILED_LOGIN_ATTEMPTS,
                                                   0);
    failedLoginAttempts++;

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               SYSDB_FAILED_LOGIN_ATTEMPTS,
                               (long)failedLoginAttempts);
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_attrs_add_long failed.\n",
                      lreq->error, ret, done);

    ret = sysdb_set_user_attr(lreq->domain,
                              lreq->preq->pd->user,
                              lreq->mod_attrs, SYSDB_MOD_REP);
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_set_user_attr failed.\n",
                      lreq->error, ret, done);

done:
    return;
}

static void do_pam_acct_mgmt(struct LOCAL_request *lreq)
{
    const char *disabled;
    struct pam_data *pd;

    pd = lreq->preq->pd;

    disabled = ldb_msg_find_attr_as_string(lreq->res->msgs[0],
                                           SYSDB_DISABLED, NULL);
    if ((disabled != NULL) &&
        (strncasecmp(disabled, "false",5) != 0) &&
        (strncasecmp(disabled, "no",2) != 0) ) {
        pd->pam_status = PAM_PERM_DENIED;
    }
}

static void do_pam_chauthtok(struct LOCAL_request *lreq)
{
    int ret;
    const char *password;
    char *salt;
    char *new_hash;
    struct pam_data *pd;

    pd = lreq->preq->pd;

    ret = sss_authtok_get_password(pd->newauthtok, &password, NULL);
    if (ret) {
        /* TODO: should we allow null passwords via a config option? */
        if (ret == ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Empty passwords are not allowed!\n");
        }
        lreq->error = EINVAL;
        goto done;
    }

    ret = s3crypt_gen_salt(lreq, &salt);
    NEQ_CHECK_OR_JUMP(ret, EOK, "Salt generation failed.\n",
                      lreq->error, ret, done);
    DEBUG(SSSDBG_CONF_SETTINGS, "Using salt [%s]\n", salt);

    ret = s3crypt_sha512(lreq, password, salt, &new_hash);
    NEQ_CHECK_OR_JUMP(ret, EOK, "Hash generation failed.\n",
                      lreq->error, ret, done);
    DEBUG(SSSDBG_CONF_SETTINGS, "New hash [%s]\n", new_hash);

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, "sysdb_new_attrs failed.\n",
                       lreq->error, ENOMEM, done);

    ret = sysdb_attrs_add_string(lreq->mod_attrs, SYSDB_PWD, new_hash);
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_attrs_add_string failed.\n",
                      lreq->error, ret, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               "lastPasswordChange", (long)time(NULL));
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_attrs_add_long failed.\n",
                      lreq->error, ret, done);

    ret = sysdb_set_user_attr(lreq->domain,
                              lreq->preq->pd->user,
                              lreq->mod_attrs, SYSDB_MOD_REP);
    NEQ_CHECK_OR_JUMP(ret, EOK, "sysdb_set_user_attr failed.\n",
                      lreq->error, ret, done);

done:
    sss_authtok_set_empty(pd->newauthtok);
}

int LOCAL_pam_handler(struct pam_auth_req *preq)
{
    struct LOCAL_request *lreq;
    static const char *attrs[] = {SYSDB_NAME,
                                  SYSDB_PWD,
                                  SYSDB_DISABLED,
                                  SYSDB_LAST_LOGIN,
                                  "lastPasswordChange",
                                  "accountExpires",
                                  SYSDB_FAILED_LOGIN_ATTEMPTS,
                                  "passwordHint",
                                  "passwordHistory",
                                  SYSDB_LAST_FAILED_LOGIN,
                                  NULL};
    struct ldb_result *res;
    const char *username = NULL;
    const char *pwdhash = NULL;
    char *new_hash = NULL;
    const char *password;
    struct pam_data *pd = preq->pd;
    int ret;

    DEBUG(SSSDBG_CONF_SETTINGS, "LOCAL pam handler.\n");

    lreq = talloc_zero(preq, struct LOCAL_request);
    if (!lreq) {
        return ENOMEM;
    }

    lreq->dbctx = preq->domain->sysdb;
    if (lreq->dbctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Fatal: Sysdb CTX not found for this domain!\n");
        talloc_free(lreq);
        return ENOENT;
    }
    lreq->domain = preq->domain;
    lreq->ev = preq->cctx->ev;
    lreq->preq = preq;

    pd->pam_status = PAM_SUCCESS;

    ret = sysdb_get_user_attr(lreq, preq->domain, preq->pd->user, attrs,
                              &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_get_user_attr failed.\n");
        talloc_free(lreq);
        return ret;
    }

    if (res->count < 1) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No user found with filter ["SYSDB_PWNAM_FILTER"]\n",
                  pd->user, pd->user, pd->user);
        pd->pam_status = PAM_USER_UNKNOWN;
        goto done;
    } else if (res->count > 1) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "More than one object found with filter ["SYSDB_PWNAM_FILTER"]\n",
                  pd->user, pd->user, pd->user);
        lreq->error = EFAULT;
        goto done;
    }

    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    if (strcmp(username, pd->user) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected username [%s] get [%s].\n", pd->user, username);
        lreq->error = EINVAL;
        goto done;
    }

    lreq->res = res;

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            if ((pd->cmd == SSS_PAM_CHAUTHTOK ||
                 pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) &&
                lreq->preq->cctx->priv == 1) {
/* TODO: maybe this is a candidate for an explicit audit message. */
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "allowing root to reset a password.\n");
                break;
            }
            ret = sss_authtok_get_password(pd->authtok, &password, NULL);
            NEQ_CHECK_OR_JUMP(ret, EOK, "Failed to get password.\n",
                              lreq->error, ret, done);

            pwdhash = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_PWD, NULL);
            NULL_CHECK_OR_JUMP(pwdhash, "No password stored.\n",
                               lreq->error, LDB_ERR_NO_SUCH_ATTRIBUTE, done);
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "user: [%s], password hash: [%s]\n", username, pwdhash);

            ret = s3crypt_sha512(lreq, password, pwdhash, &new_hash);
            NEQ_CHECK_OR_JUMP(ret, EOK, "nss_sha512_crypt failed.\n",
                              lreq->error, ret, done);

            DEBUG(SSSDBG_CONF_SETTINGS,
                  "user: [%s], new hash: [%s]\n", username, new_hash);

            if (strcmp(new_hash, pwdhash) != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Passwords do not match.\n");
                do_failed_login(lreq);
                goto done;
            }

            break;
    }

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            do_successful_login(lreq);
            break;
        case SSS_PAM_CHAUTHTOK:
            do_pam_chauthtok(lreq);
            break;
        case SSS_PAM_ACCT_MGMT:
            do_pam_acct_mgmt(lreq);
            break;
        case SSS_PAM_SETCRED:
            break;
        case SSS_PAM_OPEN_SESSION:
            break;
        case SSS_PAM_CLOSE_SESSION:
            break;
        case SSS_PAM_CHAUTHTOK_PRELIM:
            break;
        default:
            lreq->error = EINVAL;
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknown PAM task [%d].\n", pd->cmd);
    }

done:
    sss_authtok_set_empty(pd->newauthtok);
    sss_authtok_set_empty(pd->authtok);
    prepare_reply(lreq);
    return EOK;
}

