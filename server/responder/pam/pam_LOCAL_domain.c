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
#include "util/nss_sha512crypt.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"


#define NULL_CHECK_OR_JUMP(var, msg, ret, err, label) do { \
    if (var == NULL) { \
        DEBUG(1, (msg)); \
        ret = (err); \
        goto label; \
    } \
} while(0)

#define NEQ_CHECK_OR_JUMP(var, val, msg, ret, err, label) do { \
    if (var != (val)) { \
        DEBUG(1, (msg)); \
        ret = (err); \
        goto label; \
    } \
} while(0)


struct LOCAL_request {
    struct tevent_context *ev;
    struct sysdb_ctx *dbctx;
    struct sysdb_attrs *mod_attrs;
    struct sysdb_handle *handle;

    struct ldb_result *res;
    int error;

    struct pam_auth_req *preq;
};

static int authtok2str(const void *mem_ctx, uint8_t *src, const int src_size, char **dest)
{
    if ((src == NULL && src_size != 0) ||
        (src != NULL && *src != '\0' && src_size == 0)) {
        return EINVAL;
    }

    *dest = talloc_size(mem_ctx, src_size + 1);
    if (*dest == NULL) {
        return ENOMEM;
    }
    memcpy(*dest, src, src_size);
    (*dest)[src_size]='\0';

    return EOK;
}

static void prepare_reply(struct LOCAL_request *lreq)
{
    struct pam_data *pd;

    pd = lreq->preq->pd;

    if (lreq->error != EOK && pd->pam_status == PAM_SUCCESS)
        pd->pam_status = PAM_SYSTEM_ERR;

    lreq->preq->callback(lreq->preq);
}

static void set_user_attr_done(struct tevent_req *req)
{
    struct LOCAL_request *lreq;
    int ret;

    lreq = tevent_req_callback_data(req, struct LOCAL_request);

    ret = sysdb_transaction_commit_recv(req);
    if (ret) {
        DEBUG(2, ("set_user_attr failed.\n"));
        lreq->error =ret;
    }

    prepare_reply(lreq);
}

static void set_user_attr_req_done(struct tevent_req *subreq);
static void set_user_attr_req(struct tevent_req *req)
{
    struct LOCAL_request *lreq = tevent_req_callback_data(req,
                                                          struct LOCAL_request);
    struct tevent_req *subreq;
    int ret;

    DEBUG(4, ("entering set_user_attr_req\n"));

    ret = sysdb_transaction_recv(req, lreq, &lreq->handle);
    if (ret) {
        lreq->error = ret;
        return prepare_reply(lreq);
    }

    subreq = sysdb_set_user_attr_send(lreq, lreq->ev, lreq->handle,
                                      lreq->preq->domain,
                                      lreq->preq->pd->user,
                                      lreq->mod_attrs, SYSDB_MOD_REP);
    if (!subreq) {
        /* cancel transaction */
        talloc_zfree(lreq->handle);
        lreq->error = ret;
        return prepare_reply(lreq);
    }
    tevent_req_set_callback(subreq, set_user_attr_req_done, lreq);
}

static void set_user_attr_req_done(struct tevent_req *subreq)
{
    struct LOCAL_request *lreq = tevent_req_callback_data(subreq,
                                                          struct LOCAL_request);
    struct tevent_req *req;
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);

    DEBUG(4, ("set_user_attr_callback, status [%d][%s]\n", ret, strerror(ret)));

    if (ret) {
        lreq->error = ret;
        goto fail;
    }

    req = sysdb_transaction_commit_send(lreq, lreq->ev, lreq->handle);
    if (!req) {
        lreq->error = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, set_user_attr_done, lreq);

    return;

fail:
    DEBUG(2, ("set_user_attr failed.\n"));

    /* cancel transaction */
    talloc_zfree(lreq->handle);

    prepare_reply(lreq);
}

static void do_successful_login(struct LOCAL_request *lreq)
{
    struct tevent_req *req;
    int ret;

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, ("sysdb_new_attrs failed.\n"),
                       lreq->error, ENOMEM, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               SYSDB_LAST_LOGIN, (long)time(NULL));
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_long failed.\n"),
                      lreq->error, ret, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs, "failedLoginAttempts", 0L);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_long failed.\n"),
                      lreq->error, ret, done);

    req = sysdb_transaction_send(lreq, lreq->ev, lreq->dbctx);
    if (!req) {
        lreq->error = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(req, set_user_attr_req, lreq);

    return;

done:

    prepare_reply(lreq);
}

static void do_failed_login(struct LOCAL_request *lreq)
{
    struct tevent_req *req;
    int ret;
    int failedLoginAttempts;
    struct pam_data *pd;

    pd = lreq->preq->pd;
    pd->pam_status = PAM_AUTH_ERR;
/* TODO: maybe add more inteligent delay calculation */
    pd->response_delay = 3;

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, ("sysdb_new_attrs failed.\n"),
                       lreq->error, ENOMEM, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               "lastFailedLogin", (long)time(NULL));
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_long failed.\n"),
                      lreq->error, ret, done);

    failedLoginAttempts = ldb_msg_find_attr_as_int(lreq->res->msgs[0],
                                                   "failedLoginAttempts", 0);
    failedLoginAttempts++;

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               "failedLoginAttempts",
                               (long)failedLoginAttempts);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_long failed.\n"),
                      lreq->error, ret, done);

    req = sysdb_transaction_send(lreq, lreq->ev, lreq->dbctx);
    if (!req) {
        lreq->error = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(req, set_user_attr_req, lreq);

    return;

done:

    prepare_reply(lreq);
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

    prepare_reply(lreq);
}

static void do_pam_chauthtok(struct LOCAL_request *lreq)
{
    struct tevent_req *req;
    int ret;
    char *newauthtok;
    char *salt;
    char *new_hash;
    struct pam_data *pd;

    pd = lreq->preq->pd;

    ret = authtok2str(lreq, pd->newauthtok, pd->newauthtok_size, &newauthtok);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("authtok2str failed.\n"),
                      lreq->error, ret, done);
    memset(pd->newauthtok, 0, pd->newauthtok_size);

    if (strlen(newauthtok) == 0) {
        /* TODO: should we allow null passwords via a config option ? */
        DEBUG(1, ("Empty passwords are not allowed!"));
        ret = EINVAL;
        goto done;
    }

    ret = s3crypt_gen_salt(lreq, &salt);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("Salt generation failed.\n"),
                      lreq->error, ret, done);
    DEBUG(4, ("Using salt [%s]\n", salt));

    ret = s3crypt_sha512(lreq, newauthtok, salt, &new_hash);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("Hash generation failed.\n"),
                      lreq->error, ret, done);
    DEBUG(4, ("New hash [%s]\n", new_hash));
    memset(newauthtok, 0, pd->newauthtok_size);

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, ("sysdb_new_attrs failed.\n"),
                       lreq->error, ENOMEM, done);

    ret = sysdb_attrs_add_string(lreq->mod_attrs, SYSDB_PWD, new_hash);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_string failed.\n"),
                      lreq->error, ret, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               "lastPasswordChange", (long)time(NULL));
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_long failed.\n"),
                      lreq->error, ret, done);

    req = sysdb_transaction_send(lreq, lreq->ev, lreq->dbctx);
    if (!req) {
        lreq->error = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(req, set_user_attr_req, lreq);

    return;
done:

    prepare_reply(lreq);
}

static void local_handler_callback(void *pvt, int ldb_status,
                                   struct ldb_result *res)
{
    struct LOCAL_request *lreq;
    const char *username = NULL;
    const char *password = NULL;
    char *newauthtok = NULL;
    char *new_hash = NULL;
    char *authtok = NULL;
    struct pam_data *pd;
    int ret;

    lreq = talloc_get_type(pvt, struct LOCAL_request);
    pd = lreq->preq->pd;

    DEBUG(4, ("pam_handler_callback called with ldb_status [%d].\n",
              ldb_status));

    NEQ_CHECK_OR_JUMP(ldb_status, LDB_SUCCESS, ("ldb search failed.\n"),
                      lreq->error, sysdb_error_to_errno(ldb_status), done);


    if (res->count < 1) {
        DEBUG(4, ("No user found with filter ["SYSDB_PWNAM_FILTER"]\n",
                  pd->user));
        pd->pam_status = PAM_USER_UNKNOWN;
        goto done;
    } else if (res->count > 1) {
        DEBUG(4, ("More than one object found with filter ["SYSDB_PWNAM_FILTER"]\n"));
        lreq->error = EFAULT;
        goto done;
    }

    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    if (strcmp(username, pd->user) != 0) {
        DEBUG(1, ("Expected username [%s] get [%s].\n", pd->user, username));
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
/* TODO: maybe this is a candiate for an explicit audit message. */
                DEBUG(4, ("allowing root to reset a password.\n"));
                break;
            }
            ret = authtok2str(lreq, pd->authtok, pd->authtok_size, &authtok);
            NEQ_CHECK_OR_JUMP(ret, EOK, ("authtok2str failed.\n"),
                              lreq->error, ret, done);
            memset(pd->authtok, 0, pd->authtok_size);

            password = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_PWD, NULL);
            NULL_CHECK_OR_JUMP(password, ("No password stored.\n"),
                               lreq->error, LDB_ERR_NO_SUCH_ATTRIBUTE, done);
            DEBUG(4, ("user: [%s], password hash: [%s]\n", username, password));

            ret = s3crypt_sha512(lreq, authtok, password, &new_hash);
            memset(authtok, 0, pd->authtok_size);
            NEQ_CHECK_OR_JUMP(ret, EOK, ("nss_sha512_crypt failed.\n"),
                              lreq->error, ret, done);

            DEBUG(4, ("user: [%s], new hash: [%s]\n", username, new_hash));

            if (strcmp(new_hash, password) != 0) {
                DEBUG(1, ("Passwords do not match.\n"));
                do_failed_login(lreq);
                return;
            }

            break;
    }

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            do_successful_login(lreq);
            return;
            break;
        case SSS_PAM_CHAUTHTOK:
            do_pam_chauthtok(lreq);
            return;
            break;
        case SSS_PAM_ACCT_MGMT:
            do_pam_acct_mgmt(lreq);
            return;
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
            DEBUG(1, ("Unknown PAM task [%d].\n"));
    }

done:
    if (pd->authtok != NULL)
        memset(pd->authtok, 0, pd->authtok_size);
    if (authtok != NULL)
        memset(authtok, 0, pd->authtok_size);
    if (pd->newauthtok != NULL)
        memset(pd->newauthtok, 0, pd->newauthtok_size);
    if (newauthtok != NULL)
        memset(newauthtok, 0, pd->newauthtok_size);

    prepare_reply(lreq);
}

int LOCAL_pam_handler(struct pam_auth_req *preq)
{
    int ret;
    struct LOCAL_request *lreq;

    static const char *attrs[] = {SYSDB_NAME,
                                  SYSDB_PWD,
                                  SYSDB_DISABLED,
                                  SYSDB_LAST_LOGIN,
                                  "lastPasswordChange",
                                  "accountExpires",
                                  "failedLoginAttempts",
                                  "passwordHint",
                                  "passwordHistory",
                                  "lastFailedLogin",
                                  NULL};

    DEBUG(4, ("LOCAL pam handler.\n"));

    lreq = talloc_zero(preq, struct LOCAL_request);
    if (!lreq) {
        return ENOMEM;
    }

    ret = sysdb_get_ctx_from_list(preq->cctx->rctx->db_list,
                                  preq->domain, &lreq->dbctx);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        talloc_free(lreq);
        return ret;
    }
    lreq->ev = preq->cctx->ev;
    lreq->preq = preq;

    preq->pd->pam_status = PAM_SUCCESS;

    ret = sysdb_get_user_attr(lreq, lreq->dbctx,
                              preq->domain, preq->pd->user, attrs,
                              local_handler_callback, lreq);

    if (ret != EOK) {
        DEBUG(1, ("sysdb_get_user_attr failed.\n"));
        talloc_free(lreq);
        return ret;
    }

    return EOK;
}
