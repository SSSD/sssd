/*
   SSSD

   Proxy Module

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008-2009

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

#include <nss.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <dlfcn.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "db/sysdb.h"

struct proxy_nss_ops {
    enum nss_status (*getpwnam_r)(const char *name, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getpwuid_r)(uid_t uid, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setpwent)(void);
    enum nss_status (*getpwent_r)(struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endpwent)(void);

    enum nss_status (*getgrnam_r)(const char *name, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getgrgid_r)(gid_t gid, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setgrent)(void);
    enum nss_status (*getgrent_r)(struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endgrent)(void);
    enum nss_status (*initgroups_dyn)(const char *user, gid_t group,
                                      long int *start, long int *size,
                                      gid_t **groups, long int limit,
                                      int *errnop);
};

struct proxy_ctx {
    struct be_ctx *be;
    int entry_cache_timeout;
    struct proxy_nss_ops ops;
};

struct proxy_auth_ctx {
    struct be_ctx *be;
    char *pam_target;
};

struct authtok_conv {
    uint32_t authtok_size;
    uint8_t *authtok;
};

static int proxy_internal_conv(int num_msg, const struct pam_message **msgm,
                            struct pam_response **response,
                            void *appdata_ptr) {
    int i;
    struct pam_response *reply;
    struct authtok_conv *auth_data;

    auth_data = talloc_get_type(appdata_ptr, struct authtok_conv);

    if (num_msg <= 0) return PAM_CONV_ERR;

    reply = (struct pam_response *) calloc(num_msg,
                                           sizeof(struct pam_response));
    if (reply == NULL) return PAM_CONV_ERR;

    for (i=0; i < num_msg; i++) {
        switch( msgm[i]->msg_style ) {
            case PAM_PROMPT_ECHO_OFF:
                DEBUG(4, ("Conversation message: [%s]\n", msgm[i]->msg));
                reply[i].resp_retcode = 0;
                reply[i].resp = calloc(auth_data->authtok_size + 1,
                                       sizeof(char));
                if (reply[i].resp == NULL) goto failed;
                memcpy(reply[i].resp, auth_data->authtok, auth_data->authtok_size);

                break;
            default:
                DEBUG(1, ("Conversation style %d not supported.\n",
                           msgm[i]->msg_style));
                goto failed;
        }
    }

    *response = reply;
    reply = NULL;

    return PAM_SUCCESS;

failed:
    free(reply);
    return PAM_CONV_ERR;
}

static void proxy_pam_handler_cache_done(struct tevent_req *treq);
static void proxy_reply(struct be_req *req, int dp_err,
                        int error, const char *errstr);

static void proxy_pam_handler(struct be_req *req) {
    int ret;
    int pam_status;
    pam_handle_t *pamh=NULL;
    struct authtok_conv *auth_data;
    struct pam_conv conv;
    struct pam_data *pd;
    struct proxy_auth_ctx *ctx;;
    bool cache_auth_data = false;

    pd = talloc_get_type(req->req_data, struct pam_data);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        case SSS_PAM_ACCT_MGMT:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        default:
            DEBUG(1, ("Unsupported PAM task.\n"));
            pd->pam_status = PAM_SUCCESS;
            proxy_reply(req, DP_ERR_OK, PAM_SUCCESS, NULL);
            return;
    }

    conv.conv=proxy_internal_conv;
    auth_data = talloc_zero(req, struct authtok_conv);
    conv.appdata_ptr=auth_data;

    ret = pam_start(ctx->pam_target, pd->user, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        DEBUG(1, ("Pam transaction started.\n"));
        ret = pam_set_item(pamh, PAM_TTY, pd->tty);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_TTY failed: %s.\n", pam_strerror(pamh, ret)));
        }
        ret = pam_set_item(pamh, PAM_RUSER, pd->ruser);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_RUSER failed: %s.\n", pam_strerror(pamh, ret)));
        }
        ret = pam_set_item(pamh, PAM_RHOST, pd->rhost);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_RHOST failed: %s.\n", pam_strerror(pamh, ret)));
        }
        switch (pd->cmd) {
            case SSS_PAM_AUTHENTICATE:
                auth_data->authtok_size = pd->authtok_size;
                auth_data->authtok = pd->authtok;
                pam_status = pam_authenticate(pamh, 0);
                if ((pam_status == PAM_SUCCESS) &&
                    (req->be_ctx->domain->cache_credentials)) {
                    cache_auth_data = true;
                }
                break;
            case SSS_PAM_SETCRED:
                pam_status=pam_setcred(pamh, 0);
                break;
            case SSS_PAM_ACCT_MGMT:
                pam_status=pam_acct_mgmt(pamh, 0);
                break;
            case SSS_PAM_OPEN_SESSION:
                pam_status=pam_open_session(pamh, 0);
                break;
            case SSS_PAM_CLOSE_SESSION:
                pam_status=pam_close_session(pamh, 0);
                break;
            case SSS_PAM_CHAUTHTOK:
                if (pd->priv != 1) {
                    auth_data->authtok_size = pd->authtok_size;
                    auth_data->authtok = pd->authtok;
                    pam_status = pam_authenticate(pamh, 0);
                    if (pam_status != PAM_SUCCESS) break;
                }
                auth_data->authtok_size = pd->newauthtok_size;
                auth_data->authtok = pd->newauthtok;
                pam_status = pam_chauthtok(pamh, 0);
                if ((pam_status == PAM_SUCCESS) &&
                    (req->be_ctx->domain->cache_credentials)) {
                    cache_auth_data = true;
                }
                break;
            case SSS_PAM_CHAUTHTOK_PRELIM:
                if (pd->priv != 1) {
                    auth_data->authtok_size = pd->authtok_size;
                    auth_data->authtok = pd->authtok;
                    pam_status = pam_authenticate(pamh, 0);
                } else {
                    pam_status = PAM_SUCCESS;
                }
                break;
            default:
                DEBUG(1, ("unknown PAM call"));
                pam_status=PAM_ABORT;
        }

        DEBUG(4, ("Pam result: [%d][%s]\n", pam_status,
                  pam_strerror(pamh, pam_status)));

        if (pam_status == PAM_AUTHINFO_UNAVAIL) {
            be_mark_offline(req->be_ctx);
        }

        ret = pam_end(pamh, pam_status);
        if (ret != PAM_SUCCESS) {
            pamh=NULL;
            DEBUG(1, ("Cannot terminate pam transaction.\n"));
        }

    } else {
        DEBUG(1, ("Failed to initialize pam transaction.\n"));
        pam_status = PAM_SYSTEM_ERR;
    }

    pd->pam_status = pam_status;

    if (cache_auth_data) {
        struct tevent_req *subreq;
        char *password;

        password = talloc_size(req, auth_data->authtok_size + 1);
        if (!password) {
            /* password caching failures are not fatal errors */
            return proxy_reply(req, DP_ERR_OK, EOK, NULL);
        }
        memcpy(password, auth_data->authtok, auth_data->authtok_size);
        password[auth_data->authtok_size] = '\0';
        talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

        subreq = sysdb_cache_password_send(req, req->be_ctx->ev,
                                           req->be_ctx->sysdb, NULL,
                                           req->be_ctx->domain,
                                           pd->user, password);
        if (!subreq) {
            /* password caching failures are not fatal errors */
            return proxy_reply(req, DP_ERR_OK, EOK, NULL);
        }
        tevent_req_set_callback(subreq, proxy_pam_handler_cache_done, req);
    }

    proxy_reply(req, DP_ERR_OK, EOK, NULL);
}

static void proxy_pam_handler_cache_done(struct tevent_req *subreq)
{
    struct be_req *req = tevent_req_callback_data(subreq, struct be_req);
    int ret;

    /* password caching failures are not fatal errors */
    ret = sysdb_cache_password_recv(subreq);
    talloc_zfree(subreq);

    /* so we just log it any return */
    if (ret) {
        DEBUG(2, ("Failed to cache password (%d)[%s]!?\n",
                  ret, strerror(ret)));
    }

    return proxy_reply(req, DP_ERR_OK, EOK, NULL);
}

static void proxy_reply(struct be_req *req, int dp_err,
                        int error, const char *errstr)
{
    return req->fn(req, dp_err, error, errstr);
}

/* =Common-proxy-tevent_req-utils=========================================*/

#define DEFAULT_BUFSIZE 4096
#define MAX_BUF_SIZE 1024*1024 /* max 1MiB */

struct proxy_state {
    struct tevent_context *ev;
    struct proxy_ctx *ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    const char *name;

    struct sysdb_handle *handle;
    struct passwd *pwd;
    struct group *grp;
    uid_t uid;
    gid_t gid;
};

static void proxy_default_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int proxy_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* =Getpwnam-wrapper======================================================*/

static void get_pw_name_process(struct tevent_req *subreq);
static void get_pw_name_remove_done(struct tevent_req *subreq);
static void get_pw_name_add_done(struct tevent_req *subreq);

static struct tevent_req *get_pw_name_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct proxy_ctx *ctx,
                                           struct sysdb_ctx *sysdb,
                                           struct sss_domain_info *domain,
                                           const char *name)
{
    struct tevent_req *req, *subreq;
    struct proxy_state *state;

    req = tevent_req_create(mem_ctx, &state, struct proxy_state);
    if (!req) return NULL;

    memset(state, 0, sizeof(struct proxy_state));

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = sysdb;
    state->domain = domain;
    state->name = name;

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, get_pw_name_process, req);

    return req;
}

static void get_pw_name_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    struct proxy_ctx *ctx = state->ctx;
    struct sss_domain_info *dom = ctx->be->domain;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    bool delete_user = false;
    int ret;

    DEBUG(7, ("Searching user by name (%s)\n", state->name));

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(subreq);

    state->pwd = talloc(state, struct passwd);
    if (!state->pwd) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(state, buflen);
    if (!buffer) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.getpwnam_r(state->name, state->pwd,
                                 buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("User %s not found.\n", state->name));
        delete_user = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User %s found: (%s, %d, %d)\n",
                  state->name, state->pwd->pw_name,
                  state->pwd->pw_uid, state->pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(state->pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(state->pwd->pw_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                          state->name));
            delete_user = true;
            break;
        }

        subreq = sysdb_store_user_send(state, state->ev, state->handle,
                                       state->domain,
                                       state->pwd->pw_name,
                                       state->pwd->pw_passwd,
                                       state->pwd->pw_uid,
                                       state->pwd->pw_gid,
                                       state->pwd->pw_gecos,
                                       state->pwd->pw_dir,
                                       state->pwd->pw_shell,
                                       NULL, ctx->entry_cache_timeout);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_pw_name_add_done, req);
        return;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        tevent_req_error(req, ENXIO);
        return;

    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' <%d>\n",
                  state->name, status));
        tevent_req_error(req, EIO);
        return;
    }

    if (delete_user) {
        struct ldb_dn *dn;

        DEBUG(7, ("User %s does not exist (or is invalid) on remote server,"
                  " deleting!\n", state->name));

        dn = sysdb_user_dn(state->sysdb, state,
                           state->domain->name, state->name);
        if (!dn) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        subreq = sysdb_delete_entry_send(state, state->ev, state->handle, dn, true);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_pw_name_remove_done, req);
    }
}

static void get_pw_name_add_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    int ret;

    ret = sysdb_store_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, proxy_default_done, req);
}

static void get_pw_name_remove_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, proxy_default_done, req);
}

/* =Getpwuid-wrapper======================================================*/

static void get_pw_uid_process(struct tevent_req *subreq);
static void get_pw_uid_remove_done(struct tevent_req *subreq);

static struct tevent_req *get_pw_uid_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct proxy_ctx *ctx,
                                           struct sysdb_ctx *sysdb,
                                           struct sss_domain_info *domain,
                                           uid_t uid)
{
    struct tevent_req *req, *subreq;
    struct proxy_state *state;

    req = tevent_req_create(mem_ctx, &state, struct proxy_state);
    if (!req) return NULL;

    memset(state, 0, sizeof(struct proxy_state));

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = sysdb;
    state->domain = domain;
    state->uid = uid;

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, get_pw_uid_process, req);

    return req;
}

static void get_pw_uid_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    struct proxy_ctx *ctx = state->ctx;
    struct sss_domain_info *dom = ctx->be->domain;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    bool delete_user = false;
    int ret;

    DEBUG(7, ("Searching user by uid (%d)\n", state->uid));

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(subreq);

    state->pwd = talloc(state, struct passwd);
    if (!state->pwd) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(state, buflen);
    if (!buffer) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* always zero out the pwd structure */
    memset(state->pwd, 0, sizeof(struct passwd));

    status = ctx->ops.getpwuid_r(state->uid, state->pwd,
                                 buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("User %d not found.\n", state->uid));
        delete_user = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User %d found (%s, %d, %d)\n",
                  state->uid, state->pwd->pw_name,
                  state->pwd->pw_uid, state->pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(state->pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(state->pwd->pw_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                          state->name));
            delete_user = true;
            break;
        }

        subreq = sysdb_store_user_send(state, state->ev, state->handle,
                                       state->domain,
                                       state->pwd->pw_name,
                                       state->pwd->pw_passwd,
                                       state->pwd->pw_uid,
                                       state->pwd->pw_gid,
                                       state->pwd->pw_gecos,
                                       state->pwd->pw_dir,
                                       state->pwd->pw_shell,
                                       NULL, ctx->entry_cache_timeout);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_pw_name_add_done, req);
        return;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        tevent_req_error(req, ENXIO);
        return;

    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' <%d>\n",
                  state->name, status));
        tevent_req_error(req, EIO);
        return;
    }

    if (delete_user) {
        DEBUG(7, ("User %d does not exist (or is invalid) on remote server,"
                  " deleting!\n", state->uid));

        subreq = sysdb_delete_user_send(state, state->ev,
                                        NULL, state->handle,
                                        state->domain,
                                        NULL, state->uid);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_pw_uid_remove_done, req);
    }
}

static void get_pw_uid_remove_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    int ret;

    ret = sysdb_delete_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, proxy_default_done, req);
}

/* =Getpwent-wrapper======================================================*/

struct enum_users_state {
    struct tevent_context *ev;
    struct proxy_ctx *ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct sysdb_handle *handle;

    struct passwd *pwd;

    size_t buflen;
    char *buffer;

    bool in_transaction;
};

static void enum_users_process(struct tevent_req *subreq);

static struct tevent_req *enum_users_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct proxy_ctx *ctx,
                                          struct sysdb_ctx *sysdb,
                                          struct sss_domain_info *domain)
{
    struct tevent_req *req, *subreq;
    struct enum_users_state *state;
    enum nss_status status;

    DEBUG(7, ("Enumerating users\n"));

    req = tevent_req_create(mem_ctx, &state, struct enum_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = sysdb;
    state->domain = domain;
    state->handle = NULL;

    state->pwd = talloc(state, struct passwd);
    if (!state->pwd) {
        tevent_req_error(req, ENOMEM);
        goto fail;
    }

    state->buflen = DEFAULT_BUFSIZE;
    state->buffer = talloc_size(state, state->buflen);
    if (!state->buffer) {
        tevent_req_error(req, ENOMEM);
        goto fail;
    }

    state->in_transaction = false;

    status = ctx->ops.setpwent();
    if (status != NSS_STATUS_SUCCESS) {
        tevent_req_error(req, EIO);
        goto fail;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        goto fail;
    }
    tevent_req_set_callback(subreq, enum_users_process, req);

    return req;

fail:
    tevent_req_post(req, ev);
    return req;
}

static void enum_users_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct enum_users_state *state = tevent_req_data(req,
                                                struct enum_users_state);
    struct proxy_ctx *ctx = state->ctx;
    struct sss_domain_info *dom = ctx->be->domain;
    enum nss_status status;
    char *newbuf;
    int ret;

    if (!state->in_transaction) {
        ret = sysdb_transaction_recv(subreq, state, &state->handle);
        if (ret) {
            goto fail;
        }
        talloc_zfree(subreq);

        state->in_transaction = true;
    } else {
        ret = sysdb_store_user_recv(subreq);
        if (ret) {
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            DEBUG(2, ("Failed to store user. Ignoring.\n"));
        }
        talloc_zfree(subreq);
    }

again:
    /* always zero out the pwd structure */
    memset(state->pwd, 0, sizeof(struct passwd));

    /* get entry */
    status = ctx->ops.getpwent_r(state->pwd,
                                 state->buffer, state->buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (state->buflen < MAX_BUF_SIZE) {
            state->buflen *= 2;
        }
        if (state->buflen > MAX_BUF_SIZE) {
            state->buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(state, state->buffer, state->buflen);
        if (!newbuf) {
            ret = ENOMEM;
            goto fail;
        }
        state->buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        /* we are done here */
        DEBUG(7, ("Enumeration completed.\n"));

        ctx->ops.endpwent();
        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, proxy_default_done, req);
        return;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("User found (%s, %d, %d)\n", state->pwd->pw_name,
                  state->pwd->pw_uid, state->pwd->pw_gid));

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(state->pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(state->pwd->pw_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                          state->pwd->pw_name));

            goto again; /* skip */
        }

        subreq = sysdb_store_user_send(state, state->ev, state->handle,
                                       state->domain,
                                       state->pwd->pw_name,
                                       state->pwd->pw_passwd,
                                       state->pwd->pw_uid,
                                       state->pwd->pw_gid,
                                       state->pwd->pw_gecos,
                                       state->pwd->pw_dir,
                                       state->pwd->pw_shell,
                                       NULL, ctx->entry_cache_timeout);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, enum_users_process, req);
        return;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto fail;

    default:
        DEBUG(2, ("proxy -> getpwent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        goto fail;
    }

fail:
    ctx->ops.endpwent();
    tevent_req_error(req, ret);
}

/* =Getgrnam-wrapper======================================================*/

#define DEBUG_GR_MEM(level, state) \
    do { \
        if (debug_level >= level) { \
            if (!state->grp->gr_mem || !state->grp->gr_mem[0]) { \
                DEBUG(level, ("Group %s has no members!\n", \
                              state->grp->gr_name)); \
            } else { \
                int i = 0; \
                while (state->grp->gr_mem[i]) { \
                    /* count */ \
                    i++; \
                } \
                DEBUG(level, ("Group %s has %d members!\n", \
                              state->grp->gr_name, i)); \
            } \
        } \
    } while(0)

static void get_gr_name_process(struct tevent_req *subreq);
static void get_gr_name_remove_done(struct tevent_req *subreq);
static void get_gr_name_add_done(struct tevent_req *subreq);

static struct tevent_req *get_gr_name_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct proxy_ctx *ctx,
                                           struct sysdb_ctx *sysdb,
                                           struct sss_domain_info *domain,
                                           const char *name)
{
    struct tevent_req *req, *subreq;
    struct proxy_state *state;

    req = tevent_req_create(mem_ctx, &state, struct proxy_state);
    if (!req) return NULL;

    memset(state, 0, sizeof(struct proxy_state));

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = sysdb;
    state->domain = domain;
    state->name = name;

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, get_gr_name_process, req);

    return req;
}

static void get_gr_name_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    struct proxy_ctx *ctx = state->ctx;
    struct sss_domain_info *dom = ctx->be->domain;
    enum nss_status status;
    char *buffer;
    char *newbuf;
    size_t buflen;
    bool delete_group = false;
    struct sysdb_attrs *members;
    int ret;

    DEBUG(7, ("Searching group by name (%s)\n", state->name));

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(subreq);

    state->grp = talloc(state, struct group);
    if (!state->grp) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(state, buflen);
    if (!buffer) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
again:
    /* always zero out the grp structure */
    memset(state->grp, 0, sizeof(struct group));

    status = ctx->ops.getgrnam_r(state->name, state->grp,
                                 buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (buflen < MAX_BUF_SIZE) {
            buflen *= 2;
        }
        if (buflen > MAX_BUF_SIZE) {
            buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(state, buffer, buflen);
        if (!newbuf) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("Group %s not found.\n", state->name));
        delete_group = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group %s found: (%s, %d)\n", state->name,
                  state->grp->gr_name, state->grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(state->grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          state->name));
            delete_group = true;
            break;
        }

        DEBUG_GR_MEM(7, state);

        if (state->grp->gr_mem && state->grp->gr_mem[0]) {
            members = sysdb_new_attrs(state);
            if (!members) {
                tevent_req_error(req, ENOMEM);
                return;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  state->domain->name,
                                                  (const char **)state->grp->gr_mem);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
        } else {
            members = NULL;
        }

        subreq = sysdb_store_group_send(state, state->ev, state->handle,
                                        state->domain,
                                        state->grp->gr_name,
                                        state->grp->gr_gid,
                                        members,
                                        ctx->entry_cache_timeout);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_gr_name_add_done, req);
        return;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        tevent_req_error(req, ENXIO);
        return;

    default:
        DEBUG(2, ("proxy -> getgrnam_r failed for '%s' <%d>\n",
                  state->name, status));
        tevent_req_error(req, EIO);
        return;
    }

    if (delete_group) {
        struct ldb_dn *dn;

        DEBUG(7, ("Group %s does not exist (or is invalid) on remote server,"
                  " deleting!\n", state->name));

        dn = sysdb_group_dn(state->sysdb, state,
                            state->domain->name, state->name);
        if (!dn) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        subreq = sysdb_delete_entry_send(state, state->ev, state->handle, dn, true);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_gr_name_remove_done, req);
    }
}

static void get_gr_name_add_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    int ret;

    ret = sysdb_store_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, proxy_default_done, req);
}

static void get_gr_name_remove_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, proxy_default_done, req);
}

/* =Getgrgid-wrapper======================================================*/

static void get_gr_gid_process(struct tevent_req *subreq);
static void get_gr_gid_remove_done(struct tevent_req *subreq);

static struct tevent_req *get_gr_gid_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct proxy_ctx *ctx,
                                           struct sysdb_ctx *sysdb,
                                           struct sss_domain_info *domain,
                                           gid_t gid)
{
    struct tevent_req *req, *subreq;
    struct proxy_state *state;

    req = tevent_req_create(mem_ctx, &state, struct proxy_state);
    if (!req) return NULL;

    memset(state, 0, sizeof(struct proxy_state));

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = sysdb;
    state->domain = domain;
    state->gid = gid;

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, get_gr_gid_process, req);

    return req;
}

static void get_gr_gid_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    struct proxy_ctx *ctx = state->ctx;
    struct sss_domain_info *dom = ctx->be->domain;
    enum nss_status status;
    char *buffer;
    char *newbuf;
    size_t buflen;
    bool delete_group = false;
    struct sysdb_attrs *members;
    int ret;

    DEBUG(7, ("Searching group by gid (%d)\n", state->gid));

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(subreq);

    state->grp = talloc(state, struct group);
    if (!state->grp) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(state, buflen);
    if (!buffer) {
        tevent_req_error(req, ENOMEM);
        return;
    }

again:
    /* always zero out the group structure */
    memset(state->grp, 0, sizeof(struct group));

    status = ctx->ops.getgrgid_r(state->gid, state->grp,
                                 buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (buflen < MAX_BUF_SIZE) {
            buflen *= 2;
        }
        if (buflen > MAX_BUF_SIZE) {
            buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(state, buffer, buflen);
        if (!newbuf) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        DEBUG(7, ("Group %d not found.\n", state->gid));
        delete_group = true;
        break;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group %d found (%s, %d)\n", state->gid,
                  state->grp->gr_name, state->grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(state->grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          state->grp->gr_name));
            delete_group = true;
            break;
        }

        DEBUG_GR_MEM(7, state);

        if (state->grp->gr_mem && state->grp->gr_mem[0]) {
            members = sysdb_new_attrs(state);
            if (!members) {
                tevent_req_error(req, ENOMEM);
                return;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  state->domain->name,
                                                  (const char **)state->grp->gr_mem);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
        } else {
            members = NULL;
        }

        subreq = sysdb_store_group_send(state, state->ev, state->handle,
                                        state->domain,
                                        state->grp->gr_name,
                                        state->grp->gr_gid,
                                        members,
                                        ctx->entry_cache_timeout);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_gr_name_add_done, req);
        return;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        tevent_req_error(req, ENXIO);
        return;

    default:
        DEBUG(2, ("proxy -> getgrgid_r failed for '%d' <%d>\n",
                  state->gid, status));
        tevent_req_error(req, EIO);
        return;
    }

    if (delete_group) {

        DEBUG(7, ("Group %d does not exist (or is invalid) on remote server,"
                  " deleting!\n", state->gid));

        subreq = sysdb_delete_group_send(state, state->ev,
                                         NULL, state->handle,
                                         state->domain,
                                         NULL, state->gid);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_gr_gid_remove_done, req);
    }
}

static void get_gr_gid_remove_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    int ret;

    ret = sysdb_delete_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, proxy_default_done, req);
}

/* =Getgrent-wrapper======================================================*/

struct enum_groups_state {
    struct tevent_context *ev;
    struct proxy_ctx *ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct sysdb_handle *handle;

    struct group *grp;

    size_t buflen;
    char *buffer;

    bool in_transaction;
};

static void enum_groups_process(struct tevent_req *subreq);

static struct tevent_req *enum_groups_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct proxy_ctx *ctx,
                                          struct sysdb_ctx *sysdb,
                                          struct sss_domain_info *domain)
{
    struct tevent_req *req, *subreq;
    struct enum_groups_state *state;
    enum nss_status status;

    DEBUG(7, ("Enumerating groups\n"));

    req = tevent_req_create(mem_ctx, &state, struct enum_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = sysdb;
    state->domain = domain;
    state->handle = NULL;

    state->grp = talloc(state, struct group);
    if (!state->grp) {
        tevent_req_error(req, ENOMEM);
        goto fail;
    }

    state->buflen = DEFAULT_BUFSIZE;
    state->buffer = talloc_size(state, state->buflen);
    if (!state->buffer) {
        tevent_req_error(req, ENOMEM);
        goto fail;
    }

    state->in_transaction = false;

    status = ctx->ops.setgrent();
    if (status != NSS_STATUS_SUCCESS) {
        tevent_req_error(req, EIO);
        goto fail;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        goto fail;
    }
    tevent_req_set_callback(subreq, enum_groups_process, req);

    return req;

fail:
    tevent_req_post(req, ev);
    return req;
}

static void enum_groups_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct enum_groups_state *state = tevent_req_data(req,
                                                struct enum_groups_state);
    struct proxy_ctx *ctx = state->ctx;
    struct sss_domain_info *dom = ctx->be->domain;
    enum nss_status status;
    struct sysdb_attrs *members;
    char *newbuf;
    int ret;

    if (!state->in_transaction) {
        ret = sysdb_transaction_recv(subreq, state, &state->handle);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
        talloc_zfree(subreq);

        state->in_transaction = true;
    } else {
        ret = sysdb_store_group_recv(subreq);
        if (ret) {
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            DEBUG(2, ("Failed to store group. Ignoring.\n"));
        }
        talloc_zfree(subreq);
    }

again:
    /* always zero out the grp structure */
    memset(state->grp, 0, sizeof(struct group));

    /* get entry */
    status = ctx->ops.getgrent_r(state->grp,
                                 state->buffer, state->buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (state->buflen < MAX_BUF_SIZE) {
            state->buflen *= 2;
        }
        if (state->buflen > MAX_BUF_SIZE) {
            state->buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(state, state->buffer, state->buflen);
        if (!newbuf) {
            ret = ENOMEM;
            goto fail;
        }
        state->buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        /* we are done here */
        DEBUG(7, ("Enumeration completed.\n"));

        ctx->ops.endgrent();
        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, proxy_default_done, req);
        return;

    case NSS_STATUS_SUCCESS:

        DEBUG(7, ("Group found (%s, %d)\n",
                  state->grp->gr_name, state->grp->gr_gid));

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(state->grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          state->grp->gr_name));

            goto again; /* skip */
        }

        DEBUG_GR_MEM(7, state);

        if (state->grp->gr_mem && state->grp->gr_mem[0]) {
            members = sysdb_new_attrs(state);
            if (!members) {
                tevent_req_error(req, ENOMEM);
                return;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  state->domain->name,
                                                  (const char **)state->grp->gr_mem);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
        } else {
            members = NULL;
        }

        subreq = sysdb_store_group_send(state, state->ev, state->handle,
                                       state->domain,
                                       state->grp->gr_name,
                                       state->grp->gr_gid,
                                       members,
                                       ctx->entry_cache_timeout);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, enum_groups_process, req);
        return;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto fail;

    default:
        DEBUG(2, ("proxy -> getgrent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        goto fail;
    }

fail:
    ctx->ops.endgrent();
    tevent_req_error(req, ret);
}


/* =Initgroups-wrapper====================================================*/

static void get_initgr_process(struct tevent_req *subreq);
static void get_initgr_groups_process(struct tevent_req *subreq);
static void get_initgr_groups_done(struct tevent_req *subreq);
static struct tevent_req *get_groups_by_gid_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_handle *handle,
                                                 struct proxy_ctx *ctx,
                                                 struct sss_domain_info *domain,
                                                 gid_t *gids, int num_gids);
static int get_groups_by_gid_recv(struct tevent_req *req);
static void get_groups_by_gid_process(struct tevent_req *subreq);
static struct tevent_req *get_group_from_gid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_handle *handle,
                                                  struct proxy_ctx *ctx,
                                                  struct sss_domain_info *domain,
                                                  gid_t gid);
static int get_group_from_gid_recv(struct tevent_req *req);
static void get_group_from_gid_send_del_done(struct tevent_req *subreq);
static void get_group_from_gid_send_add_done(struct tevent_req *subreq);


static struct tevent_req *get_initgr_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct proxy_ctx *ctx,
                                          struct sysdb_ctx *sysdb,
                                          struct sss_domain_info *domain,
                                          const char *name)
{
    struct tevent_req *req, *subreq;
    struct proxy_state *state;

    req = tevent_req_create(mem_ctx, &state, struct proxy_state);
    if (!req) return NULL;

    memset(state, 0, sizeof(struct proxy_state));

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = sysdb;
    state->domain = domain;
    state->name = name;

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, get_initgr_process, req);

    return req;
}

static void get_initgr_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    struct proxy_ctx *ctx = state->ctx;
    struct sss_domain_info *dom = ctx->be->domain;
    enum nss_status status;
    char *buffer;
    size_t buflen;
    bool delete_user = false;
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(subreq);

    state->pwd = talloc(state, struct passwd);
    if (!state->pwd) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(state, buflen);
    if (!buffer) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.getpwnam_r(state->name, state->pwd,
                                 buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:

        delete_user = true;
        break;

    case NSS_STATUS_SUCCESS:

        /* uid=0 or gid=0 are invalid values */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(state->pwd->pw_uid, dom->id_min, dom->id_max) ||
            OUT_OF_ID_RANGE(state->pwd->pw_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("User [%s] filtered out! (id out of range)\n",
                          state->name));
            delete_user = true;
            break;
        }

        subreq = sysdb_store_user_send(state, state->ev, state->handle,
                                       state->domain,
                                       state->pwd->pw_name,
                                       state->pwd->pw_passwd,
                                       state->pwd->pw_uid,
                                       state->pwd->pw_gid,
                                       state->pwd->pw_gecos,
                                       state->pwd->pw_dir,
                                       state->pwd->pw_shell,
                                       NULL, ctx->entry_cache_timeout);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_initgr_groups_process, req);
        return;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        tevent_req_error(req, ENXIO);
        return;

    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' <%d>\n",
                  state->name, status));
        tevent_req_error(req, EIO);
        return;
    }

    if (delete_user) {
        struct ldb_dn *dn;

        dn = sysdb_user_dn(state->sysdb, state,
                           state->domain->name, state->name);
        if (!dn) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        subreq = sysdb_delete_entry_send(state, state->ev, state->handle, dn, true);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_pw_name_remove_done, req);
    }
}

static void get_initgr_groups_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    struct proxy_ctx *ctx = state->ctx;
    enum nss_status status;
    long int limit;
    long int size;
    long int num;
    long int num_gids;
    gid_t *gids;
    int ret;

    ret = sysdb_store_user_recv(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(subreq);

    num_gids = 0;
    limit = 4096;
    num = 4096;
    size = num*sizeof(gid_t);
    gids = talloc_size(state, size);
    if (!gids) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    state->gid = state->pwd->pw_gid;

again:
    /* FIXME: should we move this call outside the transaction to keep the
     * transaction as short as possible ? */
    status = ctx->ops.initgroups_dyn(state->name, state->gid, &num_gids,
                                     &num, &gids, limit, &ret);
    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (size < MAX_BUF_SIZE) {
            num *= 2;
            size = num*sizeof(gid_t);
        }
        if (size > MAX_BUF_SIZE) {
            size = MAX_BUF_SIZE;
            num = size/sizeof(gid_t);
        }
        limit = num;
        gids = talloc_realloc_size(state, gids, size);
        if (!gids) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        goto again; /* retry with more memory */

    case NSS_STATUS_SUCCESS:
        DEBUG(4, ("User [%s] appears to be member of %lu groups\n",
                  state->name, num_gids));

        subreq = get_groups_by_gid_send(state, state->ev, state->handle,
                                        state->ctx, state->domain,
                                        gids, num_gids);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, get_initgr_groups_done, req);
        break;

    default:
        DEBUG(2, ("proxy -> initgroups_dyn failed (%d)[%s]\n",
                  ret, strerror(ret)));
        tevent_req_error(req, EIO);
        return;
    }
}

static void get_initgr_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct proxy_state *state = tevent_req_data(req,
                                                struct proxy_state);
    int ret;

    ret = get_groups_by_gid_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, proxy_default_done, req);
}

struct get_groups_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct proxy_ctx *ctx;
    struct sss_domain_info *domain;

    gid_t *gids;
    int num_gids;
    int cur_gid;
};

static struct tevent_req *get_groups_by_gid_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_handle *handle,
                                                 struct proxy_ctx *ctx,
                                                 struct sss_domain_info *domain,
                                                 gid_t *gids, int num_gids)
{
    struct tevent_req *req, *subreq;
    struct get_groups_state *state;

    req = tevent_req_create(mem_ctx, &state, struct get_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ctx = ctx;
    state->domain = domain;
    state->gids = gids;
    state->num_gids = num_gids;
    state->cur_gid = 0;

    subreq = get_group_from_gid_send(state, ev, handle, ctx, domain, gids[0]);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, get_groups_by_gid_process, req);

    return req;
}

static void get_groups_by_gid_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_groups_state *state = tevent_req_data(req,
                                                struct get_groups_state);
    int ret;

    ret = get_group_from_gid_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    state->cur_gid++;
    if (state->cur_gid >= state->num_gids) {
        tevent_req_done(req);
        return;
    }

    subreq = get_group_from_gid_send(state,
                                     state->ev, state->handle,
                                     state->ctx, state->domain,
                                     state->gids[state->cur_gid]);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, get_groups_by_gid_process, req);
}

static int get_groups_by_gid_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static struct tevent_req *get_group_from_gid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_handle *handle,
                                                  struct proxy_ctx *ctx,
                                                  struct sss_domain_info *domain,
                                                  gid_t gid)
{
    struct tevent_req *req, *subreq;
    struct proxy_state *state;
    struct sss_domain_info *dom = ctx->be->domain;
    enum nss_status status;
    char *buffer;
    char *newbuf;
    size_t buflen;
    bool delete_group = false;
    struct sysdb_attrs *members;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct proxy_state);
    if (!req) return NULL;

    memset(state, 0, sizeof(struct proxy_state));

    state->ev = ev;
    state->handle = handle;
    state->ctx = ctx;
    state->domain = domain;
    state->gid = gid;

    state->grp = talloc(state, struct group);
    if (!state->grp) {
        ret = ENOMEM;
        goto fail;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(state, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto fail;
    }

again:
    /* always zero out the grp structure */
    memset(state->grp, 0, sizeof(struct group));

    status = ctx->ops.getgrgid_r(state->gid, state->grp,
                                 buffer, buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (buflen < MAX_BUF_SIZE) {
            buflen *= 2;
        }
        if (buflen > MAX_BUF_SIZE) {
            buflen = MAX_BUF_SIZE;
        }
        newbuf = talloc_realloc_size(state, buffer, buflen);
        if (!newbuf) {
            ret = ENOMEM;
            goto fail;
        }
        buffer = newbuf;
        goto again;

    case NSS_STATUS_NOTFOUND:

        delete_group = true;
        break;

    case NSS_STATUS_SUCCESS:

        /* gid=0 is an invalid value */
        /* also check that the id is in the valid range for this domain */
        if (OUT_OF_ID_RANGE(state->grp->gr_gid, dom->id_min, dom->id_max)) {

                DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                          state->grp->gr_name));
            delete_group = true;
            break;
        }

        if (state->grp->gr_mem && state->grp->gr_mem[0]) {
            members = sysdb_new_attrs(state);
            if (!members) {
                ret = ENOMEM;
                goto fail;
            }
            ret = sysdb_attrs_users_from_str_list(members, SYSDB_MEMBER,
                                                  state->domain->name,
                                                  (const char **)state->grp->gr_mem);
            if (ret) {
                goto fail;
            }
        } else {
            members = NULL;
        }

        subreq = sysdb_store_group_send(state, state->ev, state->handle,
                                        state->domain,
                                        state->grp->gr_name,
                                        state->grp->gr_gid,
                                        members,
                                        ctx->entry_cache_timeout);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, get_group_from_gid_send_add_done, req);
        break;

    case NSS_STATUS_UNAVAIL:
        /* "remote" backend unavailable. Enter offline mode */
        ret = ENXIO;
        goto fail;

    default:
        DEBUG(2, ("proxy -> getgrgid_r failed for '%d' <%d>\n",
                  state->gid, status));
        ret = EIO;
        goto fail;
    }

    if (delete_group) {
        subreq = sysdb_delete_group_send(state, state->ev,
                                         NULL, state->handle,
                                         state->domain,
                                         NULL, state->gid);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, get_group_from_gid_send_del_done, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void get_group_from_gid_send_add_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_store_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void get_group_from_gid_send_del_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);
    if (ret && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int get_group_from_gid_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* =Proxy_Id-Functions====================================================*/

static void proxy_get_account_info_done(struct tevent_req *subreq);

/* TODO: See if we can use async_req code */
static void proxy_get_account_info(struct be_req *breq)
{
    struct tevent_req *subreq;
    struct be_acct_req *ar;
    struct proxy_ctx *ctx;
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    uid_t uid;
    gid_t gid;

    ar = talloc_get_type(breq->req_data, struct be_acct_req);
    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data, struct proxy_ctx);
    ev = breq->be_ctx->ev;
    sysdb = breq->be_ctx->sysdb;
    domain = breq->be_ctx->domain;

    if (be_is_offline(breq->be_ctx)) {
        return proxy_reply(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    /* for now we support only core attrs */
    if (ar->attr_type != BE_ATTR_CORE) {
        return proxy_reply(breq, DP_ERR_FATAL, EINVAL, "Invalid attr type");
    }

    switch (ar->entry_type & 0xFFF) {
    case BE_REQ_USER: /* user */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            if (strchr(ar->filter_value, '*')) {
                subreq = enum_users_send(breq, ev, ctx,
                                         sysdb, domain);
                if (!subreq) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       ENOMEM, "Out of memory");
                }
                tevent_req_set_callback(subreq,
                               proxy_get_account_info_done, breq);
                return;
            } else {
                subreq = get_pw_name_send(breq, ev, ctx,
                                          sysdb, domain,
                                          ar->filter_value);
                if (!subreq) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       ENOMEM, "Out of memory");
                }
                tevent_req_set_callback(subreq,
                               proxy_get_account_info_done, breq);
                return;
            }
            break;

        case BE_FILTER_IDNUM:
            if (strchr(ar->filter_value, '*')) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   EINVAL, "Invalid attr type");
            } else {
                char *endptr;
                errno = 0;
                uid = (uid_t)strtol(ar->filter_value, &endptr, 0);
                if (errno || *endptr || (ar->filter_value == endptr)) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       EINVAL, "Invalid attr type");
                }
                subreq = get_pw_uid_send(breq, ev, ctx,
                                         sysdb, domain, uid);
                if (!subreq) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       ENOMEM, "Out of memory");
                }
                tevent_req_set_callback(subreq,
                               proxy_get_account_info_done, breq);
                return;
            }
            break;
        default:
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_GROUP: /* group */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            if (strchr(ar->filter_value, '*')) {
                subreq = enum_groups_send(breq, ev, ctx,
                                          sysdb, domain);
                if (!subreq) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       ENOMEM, "Out of memory");
                }
                tevent_req_set_callback(subreq,
                               proxy_get_account_info_done, breq);
                return;
            } else {
                subreq = get_gr_name_send(breq, ev, ctx,
                                          sysdb, domain,
                                          ar->filter_value);
                if (!subreq) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       ENOMEM, "Out of memory");
                }
                tevent_req_set_callback(subreq,
                               proxy_get_account_info_done, breq);
                return;
            }
            break;
        case BE_FILTER_IDNUM:
            if (strchr(ar->filter_value, '*')) {
                return proxy_reply(breq, DP_ERR_FATAL,
                                   EINVAL, "Invalid attr type");
            } else {
                char *endptr;
                errno = 0;
                gid = (gid_t)strtol(ar->filter_value, &endptr, 0);
                if (errno || *endptr || (ar->filter_value == endptr)) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       EINVAL, "Invalid attr type");
                }
                subreq = get_gr_gid_send(breq, ev, ctx,
                                         sysdb, domain, gid);
                if (!subreq) {
                    return proxy_reply(breq, DP_ERR_FATAL,
                                       ENOMEM, "Out of memory");
                }
                tevent_req_set_callback(subreq,
                               proxy_get_account_info_done, breq);
                return;
            }
            break;
        default:
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter type");
        }
        if (strchr(ar->filter_value, '*')) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               EINVAL, "Invalid filter value");
        }
        if (ctx->ops.initgroups_dyn == NULL) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               ENODEV, "Initgroups call not supported");
        }
        subreq = get_initgr_send(breq, ev, ctx, sysdb,
                                 domain, ar->filter_value);
        if (!subreq) {
            return proxy_reply(breq, DP_ERR_FATAL,
                               ENOMEM, "Out of memory");
        }
        tevent_req_set_callback(subreq,
                       proxy_get_account_info_done, breq);
        return;

    default: /*fail*/
        break;
    }

    return proxy_reply(breq, DP_ERR_FATAL,
                       EINVAL, "Invalid request type");
}

static void proxy_get_account_info_done(struct tevent_req *subreq)
{
    struct be_req *breq = tevent_req_callback_data(subreq,
                                                   struct be_req);
    int ret;
    ret = proxy_default_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ENXIO) {
            DEBUG(2, ("proxy returned UNAVAIL error, going offline!\n"));
            be_mark_offline(breq->be_ctx);
        }
        proxy_reply(breq, DP_ERR_FATAL, ret, NULL);
        return;
    }
    proxy_reply(breq, DP_ERR_OK, EOK, NULL);
}

static void proxy_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    req->fn(req, DP_ERR_OK, EOK, NULL);
}

static void proxy_auth_shutdown(struct be_req *req)
{
    talloc_free(req->be_ctx->bet_info[BET_AUTH].pvt_bet_data);
    req->fn(req, DP_ERR_OK, EOK, NULL);
}

struct bet_ops proxy_id_ops = {
    .handler = proxy_get_account_info,
    .finalize = proxy_shutdown
};

struct bet_ops proxy_auth_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

struct bet_ops proxy_access_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

struct bet_ops proxy_chpass_ops = {
    .handler = proxy_pam_handler,
    .finalize = proxy_auth_shutdown
};

static void *proxy_dlsym(void *handle, const char *functemp, char *libname)
{
    char *funcname;
    void *funcptr;

    funcname = talloc_asprintf(NULL, functemp, libname);
    if (funcname == NULL) return NULL;

    funcptr = dlsym(handle, funcname);
    talloc_free(funcname);

    return funcptr;
}

int sssm_proxy_init(struct be_ctx *bectx,
                    struct bet_ops **ops, void **pvt_data)
{
    struct proxy_ctx *ctx;
    char *libname;
    char *libpath;
    void *handle;
    int ret;

    ctx = talloc_zero(bectx, struct proxy_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;

    ret = confdb_get_int(bectx->cdb, ctx, bectx->conf_path,
                         CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT, 600,
                         &ctx->entry_cache_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_PROXY_LIBNAME, NULL, &libname);
    if (ret != EOK) goto done;
    if (libname == NULL) {
        ret = ENOENT;
        goto done;
    }

    libpath = talloc_asprintf(ctx, "libnss_%s.so.2", libname);
    if (!libpath) {
        ret = ENOMEM;
        goto done;
    }

    handle = dlopen(libpath, RTLD_NOW);
    if (!handle) {
        DEBUG(0, ("Unable to load %s module with path, error: %s\n",
                  libpath, dlerror()));
        ret = ELIBACC;
        goto done;
    }

    ctx->ops.getpwnam_r = proxy_dlsym(handle, "_nss_%s_getpwnam_r", libname);
    if (!ctx->ops.getpwnam_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwuid_r = proxy_dlsym(handle, "_nss_%s_getpwuid_r", libname);
    if (!ctx->ops.getpwuid_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setpwent = proxy_dlsym(handle, "_nss_%s_setpwent", libname);
    if (!ctx->ops.setpwent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwent_r = proxy_dlsym(handle, "_nss_%s_getpwent_r", libname);
    if (!ctx->ops.getpwent_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endpwent = proxy_dlsym(handle, "_nss_%s_endpwent", libname);
    if (!ctx->ops.endpwent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrnam_r = proxy_dlsym(handle, "_nss_%s_getgrnam_r", libname);
    if (!ctx->ops.getgrnam_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrgid_r = proxy_dlsym(handle, "_nss_%s_getgrgid_r", libname);
    if (!ctx->ops.getgrgid_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setgrent = proxy_dlsym(handle, "_nss_%s_setgrent", libname);
    if (!ctx->ops.setgrent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrent_r = proxy_dlsym(handle, "_nss_%s_getgrent_r", libname);
    if (!ctx->ops.getgrent_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endgrent = proxy_dlsym(handle, "_nss_%s_endgrent", libname);
    if (!ctx->ops.endgrent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.initgroups_dyn = proxy_dlsym(handle, "_nss_%s_initgroups_dyn",
                                                  libname);
    if (!ctx->ops.initgroups_dyn) {
        DEBUG(1, ("The '%s' library does not provides the "
                  "_nss_XXX_initgroups_dyn function!\n"
                  "initgroups will be slow as it will require "
                  "full groups enumeration!\n", libname));
    }

    *ops = &proxy_id_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_proxy_auth_init(struct be_ctx *bectx,
                         struct bet_ops **ops, void **pvt_data)
{
    struct proxy_auth_ctx *ctx;
    int ret;

    ctx = talloc(bectx, struct proxy_auth_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            CONFDB_PROXY_PAM_TARGET, NULL,
                            &ctx->pam_target);
    if (ret != EOK) goto done;
    if (!ctx->pam_target) {
        DEBUG(1, ("Missing option proxy_pam_target.\n"));
        ret = EINVAL;
        goto done;
    }

    *ops = &proxy_auth_ops;
    *pvt_data = ctx;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_proxy_access_init(struct be_ctx *bectx,
                           struct bet_ops **ops, void **pvt_data)
{
    int ret;
    ret = sssm_proxy_auth_init(bectx, ops, pvt_data);
    *ops = &proxy_access_ops;
    return ret;
}

int sssm_proxy_chpass_init(struct be_ctx *bectx,
                           struct bet_ops **ops, void **pvt_data)
{
    int ret;
    ret = sssm_proxy_auth_init(bectx, ops, pvt_data);
    *ops = &proxy_chpass_ops;
    return ret;
}
