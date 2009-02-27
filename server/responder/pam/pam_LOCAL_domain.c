#include <security/pam_modules.h>

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

static void LOCAL_pam_handler(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval tv, void *pvt)
{
    int ret;
    int pam_status = PAM_SUCCESS;
    struct LOCAL_request *lreq;
    struct sysdb_ctx *dbctx=NULL;
    struct ldb_result *res=NULL;
    struct ldb_context *ldb_ctx;
    struct ldb_dn *user_base_dn=NULL;
    struct ldb_message *msg;
    const char *attrs[] = {SYSDB_PW_NAME, SYSDB_PW_PWD, SYSDB_PW_DISABLED,
                           NULL};
    char *authtok=NULL;
    char *newauthtok=NULL;
    const char *username=NULL;
    const char *password=NULL;
    char *new_hash=NULL;
    const char *disabled=NULL;
    char *salt=NULL;
    struct callback_ctx *callback_ctx;
    int callback_delay;

    DEBUG(4, ("LOCAL pam handler.\n"));
    lreq = talloc_get_type(pvt, struct LOCAL_request);

    ret = sysdb_init(lreq, lreq->cctx->ev, lreq->cctx->nctx->cdb, NULL, &dbctx);
    NEQ_CHECK_OR_JUMP(ret, EOK, ("Could not set up LOCAL db"),
                      pam_status, PAM_SYSTEM_ERR, done);

    ldb_ctx = sysdb_ctx_get_ldb(dbctx);

/* FIXME: replace with proper sysdb calls */
    user_base_dn = ldb_dn_new_fmt(lreq, ldb_ctx, SYSDB_TMPL_USER_BASE,
                                  "LOCAL");
    NULL_CHECK_OR_JUMP(user_base_dn, ("Could not set up user base dn"),
                       pam_status, PAM_SYSTEM_ERR, done);

    ret = ldb_search(ldb_ctx, lreq, &res, user_base_dn, LDB_SCOPE_SUBTREE,
                     attrs, SYSDB_PWNAM_FILTER, lreq->pd->user);
    NEQ_CHECK_OR_JUMP(ret, LDB_SUCCESS, ("ldb_search failed"),
                      pam_status, PAM_SYSTEM_ERR, done);

    if (res->count < 1) {
        DEBUG(4, ("No user found with filter ["SYSDB_PWNAM_FILTER"]\n", lreq->pd->user));
        pam_status = PAM_USER_UNKNOWN;
        goto done;
    } else if (res->count > 1) {
        DEBUG(4, ("More than one object found with filter ["SYSDB_PWNAM_FILTER"]\n", lreq->pd->user));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_PW_NAME, NULL);
    if (strcmp(username, lreq->pd->user) != 0) {
        DEBUG(1, ("Expected username [%s] get [%s].\n", lreq->pd->user, username));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    switch (lreq->pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_CHAUTHTOK:
            ret = authtok2str(lreq, lreq->pd->authtok,
                              lreq->pd->authtok_size, &authtok);
            NEQ_CHECK_OR_JUMP(ret, EOK, ("authtok2str failed.\n"),
                              pam_status, PAM_SYSTEM_ERR, done);

            ret = authtok2str(lreq, lreq->pd->newauthtok,
                              lreq->pd->newauthtok_size, &newauthtok);
            NEQ_CHECK_OR_JUMP(ret, EOK, ("authtok2str failed.\n"),
                              pam_status, PAM_SYSTEM_ERR, done);

            password = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_PW_PWD, NULL);
            NULL_CHECK_OR_JUMP(password, ("No password stored.\n"),
                               pam_status, PAM_SYSTEM_ERR, done);
            DEBUG(4, ("user: [%s], password hash: [%s]\n", username, password));

            new_hash = nss_sha512_crypt(authtok, password);
            if (strcmp(new_hash, password) != 0) {
                DEBUG(1, ("Passwords do not match.\n"));
                pam_status = PAM_AUTH_ERR;
/* TODO: maybe add more inteligent delay calculation */
                callback_delay = 3;
                goto done;
            }
            pam_status = PAM_SUCCESS;
            break;
    }

    switch (lreq->pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            /* already done */
            break;
        case SSS_PAM_CHAUTHTOK:
            salt = gen_salt();
            NULL_CHECK_OR_JUMP(salt, ("Salt generation failed.\n"),
                               pam_status, PAM_SYSTEM_ERR, done);
            DEBUG(4, ("Using salt [%s]\n", salt));

            new_hash = nss_sha512_crypt(newauthtok, salt);
            NULL_CHECK_OR_JUMP(new_hash, ("Hash generation failed.\n"),
                               pam_status, PAM_SYSTEM_ERR, done);
            DEBUG(4, ("New hash [%s]\n", new_hash));

            msg = ldb_msg_new(lreq);
            msg->dn = res->msgs[0]->dn;
            NULL_CHECK_OR_JUMP(msg, ("ldb_msg_new failed.\n"),
                               pam_status, PAM_SYSTEM_ERR, done);

            ret = ldb_msg_add_empty(msg, SYSDB_PW_PWD, LDB_FLAG_MOD_REPLACE,
                                    NULL);
            NEQ_CHECK_OR_JUMP(ret, LDB_SUCCESS, ("ldb_msg_add_empty failed.\n"),
                              pam_status, PAM_SYSTEM_ERR, done);

            ret = ldb_msg_add_string(msg, SYSDB_PW_PWD, new_hash);
            NEQ_CHECK_OR_JUMP(ret, LDB_SUCCESS, ("ldb_msg_add_string failed.\n"),
                              pam_status, PAM_SYSTEM_ERR, done);

            ret = ldb_modify(ldb_ctx, msg);
            NEQ_CHECK_OR_JUMP(ret, LDB_SUCCESS, ("ldb_modify failed.\n"),
                              pam_status, PAM_SYSTEM_ERR, done);

            pam_status = PAM_SUCCESS;
            break;
        case SSS_PAM_ACCT_MGMT:
            disabled = ldb_msg_find_attr_as_string(res->msgs[0],
                                                   SYSDB_PW_DISABLED, NULL);
            if (disabled == NULL ||
                strncasecmp(disabled, "false",5)==0 ||
                strncasecmp(disabled, "no",2)==0 ) {
                pam_status = PAM_SUCCESS;
            } else {
                pam_status = PAM_PERM_DENIED;
            }
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
    talloc_free(dbctx);

    callback_ctx = talloc(lreq->cctx, struct callback_ctx);
    if (callback_ctx == NULL) {
        DEBUG(1, ("Cannot prepare callback data.\n"));
        return;
    }

    callback_ctx->cctx = lreq->cctx;
    callback_ctx->callback = lreq->callback;
    callback_ctx->pam_status = pam_status;
    callback_ctx->domain = "LOCAL";

    talloc_free(lreq);

    ret = gettimeofday(&tv, NULL);
    if (ret != 0) {
        DEBUG(1, ("gettimeofday failed, continuing.\n"));
    }
    tv.tv_sec += callback_delay;
    tv.tv_usec = 0;

    te = tevent_add_timer(ev, callback_ctx->cctx, tv, LOCAL_call_callback,
                          callback_ctx);
    if (te == NULL) {
        DEBUG(1, ("Cannot add callback to event loop.\n"));
        return;
    }
}

int LOCAL_schedule_request(struct cli_ctx *cctx, pam_dp_callback_t callback,
                           struct pam_data *pd)
{
    struct LOCAL_request *lreq;
    struct tevent_timer *te;
    struct timeval tv;

    lreq = talloc(cctx, struct LOCAL_request);
    if (!lreq) {
        return ENOMEM;
    }
    lreq->cctx = cctx;
    lreq->pd = pd;
    lreq->callback = callback;

    /* fire immediately */
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    te = tevent_add_timer(cctx->ev, cctx, tv, LOCAL_pam_handler, lreq);
    if (te == NULL) {
        return EIO;
    }

    return EOK;
}
