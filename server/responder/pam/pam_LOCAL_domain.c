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
    int global_pam_status;
    int callback_delay;
};

struct callback_ctx {
    struct cli_ctx *cctx;
    pam_dp_callback_t callback;
    int pam_status;
    char *domain;
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

    struct callback_ctx *callback_ctx;
    struct cli_ctx *cctx;
    pam_dp_callback_t callback;
    int pam_status;
    char *domain;

    callback_ctx = talloc_get_type(pvt, struct callback_ctx);
    cctx = callback_ctx->cctx;
    callback = callback_ctx->callback;
    pam_status = callback_ctx->pam_status;
    domain = callback_ctx->domain;

    talloc_free(callback_ctx);

    callback(cctx, pam_status, domain);
}

static void prepare_reply(struct LOCAL_request *lreq, const int pam_status)
{
    int ret;
    struct callback_ctx *callback_ctx;
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

    callback_ctx = talloc(lreq->cctx, struct callback_ctx);
    if (callback_ctx == NULL) {
        DEBUG(1, ("Cannot prepare callback data.\n"));
        return;
    }

    callback_ctx->cctx = lreq->cctx;
    callback_ctx->callback = lreq->callback;
    callback_ctx->pam_status = (lreq->global_pam_status!=PAM_SUCCESS) ?
                                    lreq->global_pam_status :
                                    pam_status;
    callback_ctx->domain = "LOCAL";

    talloc_free(lreq);

    te = tevent_add_timer(callback_ctx->cctx->ev, callback_ctx->cctx, tv,
                          LOCAL_call_callback, callback_ctx);
    if (te == NULL) {
        DEBUG(1, ("Cannot add callback to event loop.\n"));
        return;
    }
}

static void set_user_attr_callback(void *pvt, int ldb_status, struct ldb_result *res)
{
    int pam_status=PAM_SUCCESS;
    struct LOCAL_request *lreq;

    DEBUG(4, ("entering set_user_attr_callback, status [%d][%s]\n",
              ldb_status, ldb_strerror(ldb_status)));

    lreq = talloc_get_type(pvt, struct LOCAL_request);

    sysdb_transaction_done(lreq->sysdb_req, ldb_status);

    NEQ_CHECK_OR_JUMP(ldb_status, LDB_SUCCESS, ("set_user_attr failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);

done:
    prepare_reply(lreq, pam_status);
}

static void set_user_attr_req(struct sysdb_req *req, void *pvt)
{
    int ret;
    int pam_status=PAM_SUCCESS;
    struct LOCAL_request *lreq;

    DEBUG(4, ("entering set_user_attr_req\n"));

    lreq = talloc_get_type(pvt, struct LOCAL_request);

    lreq->sysdb_req = req;

    ret = sysdb_set_user_attr(req, lreq->dbctx, lreq->domain_info->name,
                              lreq->pd->user, lreq->mod_attrs,
                              set_user_attr_callback, lreq);
    if (ret != EOK) sysdb_transaction_done(lreq->sysdb_req, ret);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_set_user_attr failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);

    return;
done:
    prepare_reply(lreq, pam_status);
}

static void do_successful_login(struct LOCAL_request *lreq)
{
    int ret;
    int pam_status;
    char *buffer;

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, ("sysdb_new_attrs failed.\n"),
                       pam_status, PAM_SYSTEM_ERR, done);

    buffer = talloc_asprintf(lreq, "%d", (int) time(NULL));
    NULL_CHECK_OR_JUMP(buffer, ("talloc_asprintf failed.\n"), pam_status,
                       PAM_SYSTEM_ERR, done);

    ret = sysdb_attrs_add_string(lreq->mod_attrs, SYSDB_USER_ATTR_LAST_LOGIN, buffer);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_string failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);
    talloc_free(buffer);

    buffer = talloc_asprintf(lreq, "0");
    ret = sysdb_attrs_add_string(lreq->mod_attrs, "failedLoginAttempts", buffer);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_string failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);
    talloc_free(buffer);

    ret = sysdb_transaction(lreq, lreq->dbctx, set_user_attr_req, lreq);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_transaction failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);
    return;

done:

    prepare_reply(lreq, pam_status);
}

static void do_failed_login(struct LOCAL_request *lreq)
{
    int ret;
    int pam_status;
    char *buffer;
    int failedLoginAttempts;

    lreq->global_pam_status = PAM_AUTH_ERR;
/* TODO: maybe add more inteligent delay calculation */
    lreq->callback_delay = 3;

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, ("sysdb_new_attrs failed.\n"),
                       pam_status, PAM_SYSTEM_ERR, done);

    buffer = talloc_asprintf(lreq, "%d", (int) time(NULL));
    NULL_CHECK_OR_JUMP(buffer, ("talloc_asprintf failed.\n"), pam_status,
                       PAM_SYSTEM_ERR, done);

    ret = sysdb_attrs_add_string(lreq->mod_attrs, "lastFailedLogin", buffer);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_string failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);
    talloc_free(buffer);

    failedLoginAttempts = ldb_msg_find_attr_as_int(lreq->res->msgs[0],
                                                   "failedLoginAttempts", 0);
    buffer = talloc_asprintf(lreq, "%d", ++failedLoginAttempts);
    NULL_CHECK_OR_JUMP(buffer, ("talloc_asprintf failed.\n"), pam_status,
                       PAM_SYSTEM_ERR, done);

    ret = sysdb_attrs_add_string(lreq->mod_attrs, "failedLoginAttempts", buffer);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_string failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);
    talloc_free(buffer);

    ret = sysdb_transaction(lreq, lreq->dbctx, set_user_attr_req, lreq);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_transaction failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);
    return;

done:

    prepare_reply(lreq, pam_status);
}

static void do_pam_acct_mgmt(struct LOCAL_request *lreq)
{
    int pam_status=PAM_SUCCESS;
    const char *disabled=NULL;

    disabled = ldb_msg_find_attr_as_string(lreq->res->msgs[0],
                                           SYSDB_PW_DISABLED, NULL);
    if (disabled != NULL &&
        strncasecmp(disabled, "false",5)!=0 &&
        strncasecmp(disabled, "no",2)!=0 ) {
        lreq->global_pam_status = PAM_PERM_DENIED;
    }

    prepare_reply(lreq, pam_status);
}

static void do_pam_chauthtok(struct LOCAL_request *lreq)
{
    int ret;
    int pam_status;
    char *newauthtok;
    char *salt;
    char *new_hash;
    char *timestamp;

    ret = authtok2str(lreq, lreq->pd->newauthtok, lreq->pd->newauthtok_size,
                      &newauthtok);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("authtok2str failed.\n"), pam_status,
                      PAM_SYSTEM_ERR, done);
    memset(lreq->pd->newauthtok, 0, lreq->pd->newauthtok_size);

    salt = gen_salt();
    NULL_CHECK_OR_JUMP(salt, ("Salt generation failed.\n"), pam_status,
                       PAM_SYSTEM_ERR, done);
    DEBUG(4, ("Using salt [%s]\n", salt));

    new_hash = nss_sha512_crypt(newauthtok, salt);
    NULL_CHECK_OR_JUMP(new_hash, ("Hash generation failed.\n"), pam_status,
                       PAM_SYSTEM_ERR, done);
    DEBUG(4, ("New hash [%s]\n", new_hash));
    memset(newauthtok, 0, lreq->pd->newauthtok_size);
    talloc_free(newauthtok);

    lreq->mod_attrs = sysdb_new_attrs(lreq);
    NULL_CHECK_OR_JUMP(lreq->mod_attrs, ("sysdb_new_attrs failed.\n"),
                       pam_status, PAM_SYSTEM_ERR, done);

    ret = sysdb_attrs_add_string(lreq->mod_attrs, SYSDB_PW_PWD, new_hash);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_string failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);

    timestamp = talloc_asprintf(lreq, "%d", (int) time(NULL));
    NULL_CHECK_OR_JUMP(timestamp, ("talloc_asprintf failed.\n"), pam_status,
                       PAM_SYSTEM_ERR, done);

    ret = sysdb_attrs_add_string(lreq->mod_attrs, "lastPasswordChange",
                                 timestamp);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_attrs_add_string failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);
    talloc_free(timestamp);

    ret = sysdb_transaction(lreq, lreq->dbctx, set_user_attr_req, lreq);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("sysdb_transaction failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);
    return;
done:

    prepare_reply(lreq, pam_status);
}

static void pam_handler_callback(void *pvt, int ldb_status,
                                 struct ldb_result *res)
{
    int ret;
    int pam_status = PAM_SUCCESS;
    struct LOCAL_request *lreq;
    struct ldb_dn *user_base_dn=NULL;
    char *authtok=NULL;
    char *newauthtok=NULL;
    const char *username=NULL;
    const char *password=NULL;
    char *new_hash=NULL;

    lreq = talloc_get_type(pvt, struct LOCAL_request);

    DEBUG(4, ("pam_handler_callback called with ldb_status [%d].\n",
              ldb_status));

    NEQ_CHECK_OR_JUMP(ldb_status,LDB_SUCCESS, ("ldb search failed.\n"),
                      pam_status, PAM_SYSTEM_ERR, done);


    if (res->count < 1) {
        DEBUG(4, ("No user found with filter ["SYSDB_PWNAM_FILTER"]\n",
                  lreq->pd->user));
        pam_status = PAM_USER_UNKNOWN;
        goto done;
    } else if (res->count > 1) {
        DEBUG(4, ("More than one object found with filter ["SYSDB_PWNAM_FILTER"]\n"));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_PW_NAME, NULL);
    if (strcmp(username, lreq->pd->user) != 0) {
        DEBUG(1, ("Expected username [%s] get [%s].\n", lreq->pd->user, username));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    lreq->res = res;

    switch (lreq->pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_CHAUTHTOK:
            ret = authtok2str(lreq, lreq->pd->authtok,
                              lreq->pd->authtok_size, &authtok);
            NEQ_CHECK_OR_JUMP(ret, EOK, ("authtok2str failed.\n"),
                              pam_status, PAM_SYSTEM_ERR, done);
            memset(lreq->pd->authtok, 0, lreq->pd->authtok_size);

            password = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_PW_PWD, NULL);
            NULL_CHECK_OR_JUMP(password, ("No password stored.\n"),
                               pam_status, PAM_SYSTEM_ERR, done);
            DEBUG(4, ("user: [%s], password hash: [%s]\n", username, password));

            new_hash = nss_sha512_crypt(authtok, password);
            memset(authtok, 0, lreq->pd->authtok_size);
            talloc_free(authtok);

            if (strcmp(new_hash, password) != 0) {
                DEBUG(1, ("Passwords do not match.\n"));
                do_failed_login(lreq);
                return;
            }

            pam_status = PAM_SUCCESS;
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
            pam_status = PAM_SUCCESS;
            break;
        case SSS_PAM_OPEN_SESSION:
            pam_status = PAM_SUCCESS;
            break;
        case SSS_PAM_CLOSE_SESSION:
            pam_status = PAM_SUCCESS;
            break;
        default:
            pam_status = PAM_SYSTEM_ERR;
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
    talloc_free(res);
    talloc_free(user_base_dn);

    prepare_reply(lreq, pam_status);
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

    lreq = talloc(cctx, struct LOCAL_request);
    if (!lreq) {
        return ENOMEM;
    }
    lreq->cctx = cctx;
    lreq->pd = pd;
    lreq->callback = callback;
    lreq->global_pam_status = PAM_SUCCESS;
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
