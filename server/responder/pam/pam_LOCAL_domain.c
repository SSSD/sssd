#include <time.h>
#include <security/pam_modules.h>
#include <ldb.h>

#include "util/util.h"
#include "responder/pam/pamsrv.h"
#include "db/sysdb.h"
#include "util/nss_sha512crypt.h"


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
    struct cli_ctx *cctx;
    struct pam_data *pd;
    pam_dp_callback_t callback;
    struct sysdb_ctx *dbctx;
    struct sss_domain_info *domain_info;
    struct sysdb_attrs *mod_attrs;
    struct sysdb_req *sysdb_req;
    struct ldb_result *res;
    int pam_status;
    int error;
    int callback_delay;
};

static int authtok2str(const void *mem_ctx, uint8_t *src, const int src_size, char **dest)
{
    if ((src == NULL && src_size != 0) ||
        (src != NULL && *src != '\0' && src_size == 0)) {
        return EINVAL;
    }

    *dest = talloc_size(mem_ctx, src_size + 1);
    if (dest == NULL) {
        return ENOMEM;
    }
    memcpy(*dest, src, src_size);
    (*dest)[src_size]='\0';

    return EOK;
}

static void LOCAL_call_callback(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval tv, void *pvt) {

    struct LOCAL_request *lreq;
    int pam_status;

    lreq = talloc_get_type(pvt, struct LOCAL_request);

    if (lreq->error != EOK) pam_status = PAM_SYSTEM_ERR;
    else pam_status = lreq->pam_status;

    lreq->callback(lreq->cctx, pam_status, "LOCAL");

    talloc_free(lreq);
}

static void prepare_reply(struct LOCAL_request *lreq)
{
    int ret;
    struct timeval tv;
    struct tevent_timer *te;

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    if (lreq->callback_delay > 0) {
        ret = gettimeofday(&tv, NULL);
        if (ret != 0) {
            DEBUG(1, ("gettimeofday failed, continuing.\n"));
        }
        tv.tv_sec += lreq->callback_delay;
        tv.tv_usec = 0;
    }

    te = tevent_add_timer(lreq->cctx->ev, lreq, tv, LOCAL_call_callback, lreq);
    if (te == NULL) {
        DEBUG(1, ("Cannot add callback to event loop.\n"));
        return;
    }
}

static void set_user_attr_callback(void *pvt, int ldb_status, struct ldb_result *res)
{
    struct LOCAL_request *lreq;

    DEBUG(4, ("entering set_user_attr_callback, status [%d][%s]\n",
              ldb_status, ldb_strerror(ldb_status)));

    lreq = talloc_get_type(pvt, struct LOCAL_request);

    sysdb_transaction_done(lreq->sysdb_req, sysdb_error_to_errno(ldb_status));

    NEQ_CHECK_OR_JUMP(ldb_status, LDB_SUCCESS, ("set_user_attr failed.\n"),
                      lreq->error, sysdb_error_to_errno(ldb_status), done);

done:
    prepare_reply(lreq);
}

static void set_user_attr_req(struct sysdb_req *req, void *pvt)
{
    int ret;
    struct LOCAL_request *lreq;

    DEBUG(4, ("entering set_user_attr_req\n"));

    lreq = talloc_get_type(pvt, struct LOCAL_request);

    lreq->sysdb_req = req;

    ret = sysdb_set_user_attr(req, lreq->dbctx, lreq->domain_info->name,
                              lreq->pd->user, lreq->mod_attrs,
                              set_user_attr_callback, lreq);
    if (ret != EOK)
        sysdb_transaction_done(lreq->sysdb_req, ret);

    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_set_user_attr failed.\n"),
                      lreq->error, ret, done);

    return;
done:
    prepare_reply(lreq);
}

static void do_successful_login(struct LOCAL_request *lreq)
{
    int ret;

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, ("sysdb_new_attrs failed.\n"),
                       lreq->error, ENOMEM, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               SYSDB_USER_ATTR_LAST_LOGIN, (long)time(NULL));
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_long failed.\n"),
                      lreq->error, ret, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs, "failedLoginAttempts", 0L);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_long failed.\n"),
                      lreq->error, ret, done);

    ret = sysdb_transaction(lreq, lreq->dbctx, set_user_attr_req, lreq);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_transaction failed.\n"),
                      lreq->error, ret, done);
    return;

done:

    prepare_reply(lreq);
}

static void do_failed_login(struct LOCAL_request *lreq)
{
    int ret;
    int failedLoginAttempts;

    lreq->pam_status = PAM_AUTH_ERR;
/* TODO: maybe add more inteligent delay calculation */
    lreq->callback_delay = 3;

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

    ret = sysdb_transaction(lreq, lreq->dbctx, set_user_attr_req, lreq);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_transaction failed.\n"),
                      lreq->error, ret, done);
    return;

done:

    prepare_reply(lreq);
}

static void do_pam_acct_mgmt(struct LOCAL_request *lreq)
{
    const char *disabled=NULL;

    disabled = ldb_msg_find_attr_as_string(lreq->res->msgs[0],
                                           SYSDB_PW_DISABLED, NULL);
    if (disabled != NULL &&
        strncasecmp(disabled, "false",5)!=0 &&
        strncasecmp(disabled, "no",2)!=0 ) {
        lreq->pam_status = PAM_PERM_DENIED;
    }

    prepare_reply(lreq);
}

static void do_pam_chauthtok(struct LOCAL_request *lreq)
{
    int ret;
    char *newauthtok;
    char *salt;
    char *new_hash;

    ret = authtok2str(lreq, lreq->pd->newauthtok, lreq->pd->newauthtok_size,
                      &newauthtok);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("authtok2str failed.\n"),
                      lreq->error, ret, done);
    memset(lreq->pd->newauthtok, 0, lreq->pd->newauthtok_size);

    salt = gen_salt();
    NULL_CHECK_OR_JUMP(salt, ("Salt generation failed.\n"),
                       lreq->error, EFAULT, done);
    DEBUG(4, ("Using salt [%s]\n", salt));

    new_hash = nss_sha512_crypt(newauthtok, salt);
    NULL_CHECK_OR_JUMP(new_hash, ("Hash generation failed.\n"),
                       lreq->error, EFAULT, done);
    DEBUG(4, ("New hash [%s]\n", new_hash));
    memset(newauthtok, 0, lreq->pd->newauthtok_size);

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, ("sysdb_new_attrs failed.\n"),
                       lreq->error, ENOMEM, done);

    ret = sysdb_attrs_add_string(lreq->mod_attrs, SYSDB_PW_PWD, new_hash);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_string failed.\n"),
                      lreq->error, ret, done);

    ret = sysdb_attrs_add_long(lreq->mod_attrs,
                               "lastPasswordChange", (long)time(NULL));
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_long failed.\n"),
                      lreq->error, ret, done);

    ret = sysdb_transaction(lreq, lreq->dbctx, set_user_attr_req, lreq);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_transaction failed.\n"),
                      lreq->error, ret, done);
    return;
done:

    prepare_reply(lreq);
}

static void pam_handler_callback(void *pvt, int ldb_status,
                                 struct ldb_result *res)
{
    struct LOCAL_request *lreq;
    const char *username = NULL;
    const char *password = NULL;
    char *newauthtok = NULL;
    char *new_hash = NULL;
    char *authtok = NULL;
    int ret;

    lreq = talloc_get_type(pvt, struct LOCAL_request);

    DEBUG(4, ("pam_handler_callback called with ldb_status [%d].\n",
              ldb_status));

    NEQ_CHECK_OR_JUMP(ldb_status, LDB_SUCCESS, ("ldb search failed.\n"),
                      lreq->error, sysdb_error_to_errno(ldb_status), done);


    if (res->count < 1) {
        DEBUG(4, ("No user found with filter ["SYSDB_PWNAM_FILTER"]\n",
                  lreq->pd->user));
        lreq->pam_status = PAM_USER_UNKNOWN;
        goto done;
    } else if (res->count > 1) {
        DEBUG(4, ("More than one object found with filter ["SYSDB_PWNAM_FILTER"]\n"));
        lreq->error = EFAULT;
        goto done;
    }

    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_PW_NAME, NULL);
    if (strcmp(username, lreq->pd->user) != 0) {
        DEBUG(1, ("Expected username [%s] get [%s].\n", lreq->pd->user, username));
        lreq->error = EINVAL;
        goto done;
    }

    lreq->res = res;

    switch (lreq->pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_CHAUTHTOK:
            ret = authtok2str(lreq, lreq->pd->authtok,
                              lreq->pd->authtok_size, &authtok);
            NEQ_CHECK_OR_JUMP(ret, EOK, ("authtok2str failed.\n"),
                              lreq->error, ret, done);
            memset(lreq->pd->authtok, 0, lreq->pd->authtok_size);

            password = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_PW_PWD, NULL);
            NULL_CHECK_OR_JUMP(password, ("No password stored.\n"),
                               lreq->error, ret, done);
            DEBUG(4, ("user: [%s], password hash: [%s]\n", username, password));

            new_hash = nss_sha512_crypt(authtok, password);
            memset(authtok, 0, lreq->pd->authtok_size);
            NULL_CHECK_OR_JUMP(new_hash, ("nss_sha512_crypt failed.\n"),
                               lreq->error, EFAULT, done);

            DEBUG(4, ("user: [%s], new hash: [%s]\n", username, new_hash));

            if (strcmp(new_hash, password) != 0) {
                DEBUG(1, ("Passwords do not match.\n"));
                do_failed_login(lreq);
                return;
            }

            break;
    }

    switch (lreq->pd->cmd) {
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
        default:
            lreq->error = EINVAL;
            DEBUG(1, ("Unknown PAM task [%d].\n"));
    }

done:
    if (lreq->pd->authtok != NULL)
        memset(lreq->pd->authtok, 0, lreq->pd->authtok_size);
    if (authtok != NULL)
        memset(authtok, 0, lreq->pd->authtok_size);
    if (lreq->pd->newauthtok != NULL)
        memset(lreq->pd->newauthtok, 0, lreq->pd->newauthtok_size);
    if (newauthtok != NULL)
        memset(newauthtok, 0, lreq->pd->newauthtok_size);

    prepare_reply(lreq);
}

int LOCAL_pam_handler(struct cli_ctx *cctx, pam_dp_callback_t callback,
                      struct pam_data *pd)
{
    int ret;
    struct LOCAL_request *lreq=NULL;

    static const char *attrs[] = {SYSDB_PW_NAME,
                                  SYSDB_PW_PWD,
                                  SYSDB_PW_DISABLED,
                                  SYSDB_USER_ATTR_LAST_LOGIN,
                                  "lastPasswordChange",
                                  "accountExpires",
                                  "failedLoginAttempts",
                                  "passwordHint",
                                  "passwordHistory",
                                  "lastFailedLogin",
                                  NULL};

    lreq = talloc_zero(cctx, struct LOCAL_request);
    if (!lreq) {
        return ENOMEM;
    }
    lreq->cctx = cctx;
    lreq->pd = pd;
    lreq->callback = callback;
    lreq->pam_status = PAM_SUCCESS;
    lreq->error = EOK;
    lreq->callback_delay = 0;


    DEBUG(4, ("LOCAL pam handler.\n"));

    lreq->domain_info = btreemap_get_value(lreq->cctx->nctx->domain_map,
                                     lreq->pd->domain);
    NULL_CHECK_OR_JUMP(lreq->domain_info, ("Domain info not found.\n"),
                       ret, EINVAL, done);

    lreq->dbctx = lreq->cctx->nctx->sysdb;

    ret = sysdb_get_user_attr(lreq, lreq->dbctx, lreq->domain_info->name,
                              lreq->pd->user, attrs, 0, pam_handler_callback,
                              lreq);

    if(ret != EOK) {
        DEBUG(1, ("sysdb_get_user_attr failed.\n"));
        goto done;
    }

    return EOK;

done:
    talloc_free(lreq);
    return ret;
}
