/*
   SSSD

   Proxy Module

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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
#include "../sss_client/sss_cli.h"

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
    struct proxy_nss_ops ops;
};

struct proxy_auth_ctx {
    char *pam_target;
};

struct authtok_conv {
    char *authtok;
    char *oldauthtok;
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
                reply[i].resp = strdup(auth_data->authtok);
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

static void proxy_pam_handler(struct be_req *req) {
    int ret;
    int pam_status;
    pam_handle_t *pamh=NULL;
    struct authtok_conv *auth_data;
    struct pam_conv conv;
    struct pam_data *pd;
    struct proxy_auth_ctx *ctx;;

    ctx = talloc_get_type(req->be_ctx->pvt_auth_data, struct proxy_auth_ctx);
    pd = talloc_get_type(req->req_data, struct pam_data);

    conv.conv=proxy_internal_conv;
    auth_data = talloc_zero(req->be_ctx, struct authtok_conv);
    conv.appdata_ptr=auth_data;

    ret = pam_start(ctx->pam_target, pd->user, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        DEBUG(1, ("Pam transaction started.\n"));
        pam_set_item(pamh, PAM_TTY, pd->tty);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_TTY failed: %s.\n", pam_strerror(pamh, ret)));
        }
        pam_set_item(pamh, PAM_RUSER, pd->ruser);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_RUSER failed: %s.\n", pam_strerror(pamh, ret)));
        }
        pam_set_item(pamh, PAM_RHOST, pd->rhost);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_RHOST failed: %s.\n", pam_strerror(pamh, ret)));
        }
        switch (pd->cmd) {
            case SSS_PAM_AUTHENTICATE:
/* FIXME: \0 missing at the end */
                auth_data->authtok=(char *) pd->authtok;
                auth_data->oldauthtok=NULL;
                pam_status=pam_authenticate(pamh, 0);
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
/* FIXME: \0 missing at the end */
                auth_data->authtok=(char *) pd->newauthtok;
                auth_data->oldauthtok=(char *) pd->authtok;
                pam_status=pam_chauthtok(pamh, 0);
                break;
            default:
                DEBUG(1, ("unknown PAM call"));
                pam_status=PAM_ABORT;
        }

        DEBUG(4, ("Pam result: [%d][%s]\n", pam_status, pam_strerror(pamh, pam_status)));

        ret = pam_end(pamh, pam_status);
        if (ret != PAM_SUCCESS) {
            pamh=NULL;
            DEBUG(1, ("Cannot terminate pam transaction.\n"));
        }

    } else {
        DEBUG(1, ("Failed to initialize pam transaction.\n"));
        pam_status = PAM_SYSTEM_ERR;
    }

    talloc_free(auth_data);

    pd->pam_status = pam_status;
    req->fn(req, EOK, NULL);
}

static void proxy_reply(struct be_req *req, int error, const char *errstr)
{
    return req->fn(req, error, errstr);
}

struct proxy_data {
    struct sysdb_req *sysreq;
    struct proxy_ctx *ctx;
    struct be_req *req;

    char *buffer;
    size_t buflen;

    struct passwd *pwd;
    struct group *grp;

    gid_t *groups;
    long int num;
    long int cur;

    struct ldb_dn *dn;

    sysdb_callback_t next_fn;
};

static void proxy_return(void *pvt, int error, struct ldb_result *ignore)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    const char *err = "Success";

    if (error != EOK) err = "Operation failed";

    sysdb_transaction_done(data->sysreq, error);
    return proxy_reply(data->req, error, err);
}

static void del_db_entry(struct sysdb_req *req, void *pvt)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_delete_entry(req, data->dn, data->next_fn, data);
    if (ret != EOK) {
        proxy_return(data, ret, NULL);
    }
}

static void del_pw_uid(struct sysdb_req *req, void *pvt)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_delete_user_by_uid(req,
                                   data->req->be_ctx->domain,
                                   data->pwd->pw_uid,
                                   data->next_fn, data);
    if (ret != EOK) {
        proxy_return(data, ret, NULL);
    }
}

static void set_pw_name(struct sysdb_req *req, void *pvt)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_legacy_store_user(req, data->req->be_ctx->domain,
                                  data->pwd->pw_name, data->pwd->pw_passwd,
                                  data->pwd->pw_uid, data->pwd->pw_gid,
                                  data->pwd->pw_gecos, data->pwd->pw_dir,
                                  data->pwd->pw_shell,
                                  data->next_fn, data);
    if (ret != EOK) {
        proxy_return(data, ret, NULL);
    }
}

static void get_pw_name(struct be_req *req, char *name)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct proxy_data *data;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_id_data, struct proxy_ctx);

    data = talloc_zero(req, struct proxy_data);
    if (!data)
        return proxy_reply(req, ENOMEM, "Out of memory");
    data->req = req;
    data->ctx = ctx;
    data->next_fn = proxy_return;
    data->pwd = talloc(data, struct passwd);
    if (!data->pwd)
        return proxy_reply(req, ENOMEM, "Out of memory");

    data->buflen = 4096;
    data->buffer = talloc_size(data, data->buflen);
    if (!data->buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getpwnam_r(name, data->pwd,
                                 data->buffer, data->buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        data->dn = sysdb_user_dn(req->be_ctx->sysdb, data,
                                 req->be_ctx->domain, name);
        if (!data->dn)
            return proxy_reply(req, ENOMEM, "Out of memory");

        ret = sysdb_transaction(data, req->be_ctx->sysdb, del_db_entry, data);
        break;

    case NSS_STATUS_SUCCESS:
        /* FIXME: verify user does not have uid=0 or gid=0 as these are invalid
         * values */
        if (data->pwd->pw_uid == 0 || data->pwd->pw_gid == 0) {
            ret = sysdb_transaction(data, req->be_ctx->sysdb, del_db_entry, data);
            break;
        }

        ret = sysdb_transaction(data, req->be_ctx->sysdb, set_pw_name, data);
        break;

    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' (%d)[%s]\n",
                  name, ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction (%d)[%s]!?\n",
                  ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }
}

static void get_pw_uid(struct be_req *req, uid_t uid)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct proxy_data *data;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_id_data, struct proxy_ctx);

    data = talloc_zero(req, struct proxy_data);
    if (!data)
        return proxy_reply(req, ENOMEM, "Out of memory");
    data->req = req;
    data->ctx = ctx;
    data->next_fn = proxy_return;
    data->pwd = talloc(data, struct passwd);
    if (!data->pwd)
        return proxy_reply(req, ENOMEM, "Out of memory");

    data->buflen = 4096;
    data->buffer = talloc_size(data, data->buflen);
    if (!data->buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getpwuid_r(uid, data->pwd,
                                 data->buffer, data->buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        data->pwd->pw_uid = uid;
        ret = sysdb_transaction(data, req->be_ctx->sysdb, del_pw_uid, data);
        break;

    case NSS_STATUS_SUCCESS:
        /* FIXME: verify user does not have gid=0 as these are invalid values */
        if (data->pwd->pw_gid == 0) {
            data->dn = sysdb_user_dn(req->be_ctx->sysdb, data,
                                     req->be_ctx->domain, data->pwd->pw_name);
            ret = sysdb_transaction(data, req->be_ctx->sysdb, del_db_entry, data);
            break;
        }

        ret = sysdb_transaction(data, req->be_ctx->sysdb, set_pw_name, data);
        break;

    default:
        DEBUG(2, ("proxy -> getpwuid_r failed for '%lu' (%d)[%s]\n",
                  (unsigned long)uid, ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction (%d)[%s]!?\n",
                  ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }
}

#define MAX_BUF_SIZE 1024*1024 /* max 1MiB */

static void get_pw_entry(struct sysdb_req *req, void *pvt);

static void get_next_pw_entry(void *pvt, int error, struct ldb_result *ignore)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);

    if (error != EOK) proxy_return(data, error, NULL);

    get_pw_entry(data->sysreq, data);
}

static void get_pw_entry(struct sysdb_req *req, void *pvt)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    enum nss_status status;
    struct sysdb_ctx *ctx;
    char *newb;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

retry:
    status = data->ctx->ops.getpwent_r(data->pwd,
                                       data->buffer, data->buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (data->buflen < MAX_BUF_SIZE) {
            data->buflen *= 2;
        }
        if (data->buflen > MAX_BUF_SIZE) {
            data->buflen = MAX_BUF_SIZE;
        }
        newb = talloc_realloc_size(data, data->buffer, data->buflen);
        if (!newb) {
            return proxy_return(data, ENOMEM, NULL);
        }
        data->buffer = newb;
        goto retry;

    case NSS_STATUS_NOTFOUND:

        data->ctx->ops.endpwent();
        data->next_fn(data, EOK, NULL);
        break;

    case NSS_STATUS_SUCCESS:
        /* FIXME: verify user does not have uid=0 or gid=0 as these are invalid
         * values */
        if (data->pwd->pw_uid == 0 || data->pwd->pw_gid == 0) {
            goto retry; /* skip */
        }

        ret = sysdb_legacy_store_user(req, data->req->be_ctx->domain,
                                      data->pwd->pw_name,
                                      data->pwd->pw_passwd,
                                      data->pwd->pw_uid,
                                      data->pwd->pw_gid,
                                      data->pwd->pw_gecos,
                                      data->pwd->pw_dir,
                                      data->pwd->pw_shell,
                                      get_next_pw_entry, data);
        if (ret != EOK) {
            DEBUG(1, ("Failed to update LDB Cache for '%s' (%d)[%s] !?\n",
                      data->pwd->pw_name, ret, strerror(ret)));
            proxy_return(data, ret, NULL);
        }
        break;

    default:
        DEBUG(2, ("proxy -> getpwent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        proxy_return(data, ret, NULL);
    }
}

static void enum_users(struct be_req *req)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct proxy_data *data;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_id_data, struct proxy_ctx);

    data = talloc_zero(req, struct proxy_data);
    if (!data)
        return proxy_reply(req, ENOMEM, "Out of memory");
    data->req = req;
    data->ctx = ctx;
    data->next_fn = proxy_return;
    data->pwd = talloc(data, struct passwd);
    if (!data->pwd)
        return proxy_reply(req, ENOMEM, "Out of memory");

    data->buflen = 4096;
    data->buffer = talloc_size(data, data->buflen);
    if (!data->buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.setpwent();
    if (status != NSS_STATUS_SUCCESS)
        return proxy_reply(req, EIO, "Operation failed");

    ret = sysdb_transaction(data, req->be_ctx->sysdb, get_pw_entry, data);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction (%d)[%s]!?\n",
                  ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }
}

static void del_gr_gid(struct sysdb_req *req, void *pvt)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_delete_group_by_gid(req,
                                    data->req->be_ctx->domain,
                                    data->grp->gr_gid,
                                    data->next_fn, data);
    if (ret != EOK) {
        proxy_return(data, ret, NULL);
    }
}

static void set_gr_name(struct sysdb_req *req, void *pvt)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_legacy_store_group(req, data->req->be_ctx->domain,
                                   data->grp->gr_name,
                                   data->grp->gr_gid,
                                   (const char **)data->grp->gr_mem,
                                   data->next_fn, data);
    if (ret != EOK) {
        proxy_return(data, ret, NULL);
    }
}

static void get_gr_name(struct be_req *req, char *name)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct proxy_data *data;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_id_data, struct proxy_ctx);

    data = talloc_zero(req, struct proxy_data);
    if (!data)
        return proxy_reply(req, ENOMEM, "Out of memory");
    data->req = req;
    data->ctx = ctx;
    data->next_fn = proxy_return;
    data->grp = talloc(data, struct group);
    if (!data->grp)
        return proxy_reply(req, ENOMEM, "Out of memory");

    data->buflen = 4096;
    data->buffer = talloc_size(data, data->buflen);
    if (!data->buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getgrnam_r(name, data->grp,
                                 data->buffer, data->buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        data->dn = sysdb_group_dn(req->be_ctx->sysdb, data,
                                  req->be_ctx->domain, name);
        if (!data->dn)
            return proxy_reply(req, ENOMEM, "Out of memory");

        ret = sysdb_transaction(data, req->be_ctx->sysdb, del_db_entry, data);
        break;

    case NSS_STATUS_SUCCESS:
        /* FIXME: verify group does not have gid=0 as this is invalid */
        if (data->grp->gr_gid == 0) {
            ret = sysdb_transaction(data, req->be_ctx->sysdb, del_db_entry, data);
            break;
        }

        ret = sysdb_transaction(data, req->be_ctx->sysdb, set_gr_name, data);
        break;

    default:
        DEBUG(2, ("proxy -> getgrnam_r failed for '%s' (%d)[%s]\n",
                  name, ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction (%d)[%s]!?\n",
                  ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }
}

static void get_gr_gid(struct be_req *req, gid_t gid)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct proxy_data *data;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_id_data, struct proxy_ctx);

    data = talloc_zero(req, struct proxy_data);
    if (!data)
        return proxy_reply(req, ENOMEM, "Out of memory");
    data->req = req;
    data->ctx = ctx;
    data->next_fn = proxy_return;
    data->grp = talloc(data, struct group);
    if (!data->grp)
        return proxy_reply(req, ENOMEM, "Out of memory");

    data->buflen = 4096;
    data->buffer = talloc_size(data, data->buflen);
    if (!data->buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getgrgid_r(gid, data->grp,
                                 data->buffer, data->buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        data->grp->gr_gid = gid;
        ret = sysdb_transaction(data, req->be_ctx->sysdb, del_gr_gid, data);
        break;

    case NSS_STATUS_SUCCESS:
        /* FIXME: verify group does not have gid=0 as this is invalid */
        if (data->grp->gr_gid == 0) {
            data->dn = sysdb_group_dn(req->be_ctx->sysdb, data,
                                      req->be_ctx->domain, data->grp->gr_name);
            ret = sysdb_transaction(data, req->be_ctx->sysdb, del_db_entry, data);
            break;
        }

        ret = sysdb_transaction(data, req->be_ctx->sysdb, set_gr_name, data);
        break;

    default:
        DEBUG(2, ("proxy -> getgrgid_r failed for '%lu' (%d)[%s]\n",
                  (unsigned long)gid, ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction (%d)[%s]!?\n",
                  ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }
}

static void get_gr_entry(struct sysdb_req *req, void *pvt);

static void get_next_gr_entry(void *pvt, int error, struct ldb_result *ignore)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);

    if (error != EOK) proxy_return(data, error, NULL);

    get_gr_entry(data->sysreq, data);
}

static void get_gr_entry(struct sysdb_req *req, void *pvt)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    enum nss_status status;
    struct sysdb_ctx *ctx;
    char *newb;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

retry:
    status = data->ctx->ops.getgrent_r(data->grp,
                                       data->buffer, data->buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (data->buflen < MAX_BUF_SIZE) {
            data->buflen *= 2;
        }
        if (data->buflen > MAX_BUF_SIZE) {
            data->buflen = MAX_BUF_SIZE;
        }
        newb = talloc_realloc_size(data, data->buffer, data->buflen);
        if (!newb) {
            return proxy_return(data, ENOMEM, NULL);
        }
        data->buffer = newb;
        goto retry;

    case NSS_STATUS_NOTFOUND:

        data->ctx->ops.endgrent();
        data->next_fn(data, EOK, NULL);
        break;

    case NSS_STATUS_SUCCESS:
        /* FIXME: verify group does not have gid=0 as this is invalid */
        if (data->grp->gr_gid == 0) {
            goto retry;
        }
        ret = sysdb_legacy_store_group(req, data->req->be_ctx->domain,
                                       data->grp->gr_name,
                                       data->grp->gr_gid,
                                       (const char **)data->grp->gr_mem,
                                       get_next_gr_entry, data);
        if (ret != EOK) {
            DEBUG(1, ("Failed to update LDB Cache for '%s' (%d)[%s] !?\n",
                      data->grp->gr_name, ret, strerror(ret)));
            proxy_return(data, ret, NULL);
        }
        break;

    default:
        DEBUG(2, ("proxy -> getgrent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        proxy_return(data, ret, NULL);
    }
}

static void enum_groups(struct be_req *req)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct proxy_data *data;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_id_data, struct proxy_ctx);

    data = talloc_zero(req, struct proxy_data);
    if (!data)
        return proxy_reply(req, ENOMEM, "Out of memory");
    data->req = req;
    data->ctx = ctx;
    data->next_fn = proxy_return;
    data->grp = talloc(data, struct group);
    if (!data->grp)
        return proxy_reply(req, ENOMEM, "Out of memory");

    data->buflen = 4096;
    data->buffer = talloc_size(data, data->buflen);
    if (!data->buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.setgrent();
    if (status != NSS_STATUS_SUCCESS)
        return proxy_reply(req, EIO, "Operation failed");

    ret = sysdb_transaction(data, req->be_ctx->sysdb, get_gr_entry, data);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction (%d)[%s]!?\n",
                  ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }
}

static void get_gid_entry(struct sysdb_req *req, void *pvt);

static void get_next_gid_entry(void *pvt, int error, struct ldb_result *ignore)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);

    if (error != EOK) proxy_return(data, error, NULL);

    get_gid_entry(data->sysreq, data);
}

static void get_gid_entry(struct sysdb_req *req, void *pvt)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    enum nss_status status;
    struct sysdb_ctx *ctx;
    char *newb;
    int ret;

    ctx = sysdb_req_get_ctx(req);

    /* all done */
    if (data->cur == data->num)
        return data->next_fn(data, EOK, NULL);

retry:
    status = data->ctx->ops.getgrgid_r(data->groups[data->cur], data->grp,
                                       data->buffer, data->buflen, &ret);

    switch (status) {
    case NSS_STATUS_TRYAGAIN:
        /* buffer too small ? */
        if (data->buflen < MAX_BUF_SIZE) {
            data->buflen *= 2;
        }
        if (data->buflen > MAX_BUF_SIZE) {
            data->buflen = MAX_BUF_SIZE;
        }
        newb = talloc_realloc_size(data, data->buffer, data->buflen);
        if (!newb) {
            return proxy_return(data, ENOMEM, NULL);
        }
        data->buffer = newb;
        goto retry;

    case NSS_STATUS_NOTFOUND:
        data->cur++;
        DEBUG(4, ("gid [%lu] not found, removing group\n",
                  (unsigned long)(data->groups[data->cur])));
        ret = sysdb_delete_group_by_gid(req, data->req->be_ctx->domain,
                                        data->groups[data->cur-1],
                                        get_next_gid_entry, data);
        if (ret != EOK) {
            DEBUG(1, ("Failed to update LDB Cache for '%s' (%d)[%s] !?\n",
                      data->grp->gr_name, ret, strerror(ret)));
            proxy_return(data, ret, NULL);
        }
        break;

    case NSS_STATUS_SUCCESS:
        data->cur++;
        ret = sysdb_legacy_store_group(req, data->req->be_ctx->domain,
                                       data->grp->gr_name,
                                       data->grp->gr_gid,
                                       (const char **)data->grp->gr_mem,
                                       get_next_gid_entry, data);
        if (ret != EOK) {
            DEBUG(1, ("Failed to update LDB Cache for '%s' (%d)[%s] !?\n",
                      data->grp->gr_name, ret, strerror(ret)));
            proxy_return(data, ret, NULL);
        }
        break;

    default:
        DEBUG(2, ("proxy -> getgrgid_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        proxy_return(data, ret, NULL);
    }
}

static void get_user_groups(void *pvt, int error, struct ldb_result *ignore)
{
    struct proxy_data *data = talloc_get_type(pvt, struct proxy_data);
    enum nss_status status;
    long int limit;
    long int start;
    long int size;
    long int num;
    char *name;
    gid_t gid;
    int ret;

    if (error != EOK) proxy_return(data, error, NULL);
    data->next_fn = proxy_return;

    start = 0;
    limit = 4096;
    num = 4096;
    size = num*sizeof(gid_t);
    data->groups = talloc_size(data, size);
    if (!data->groups)
        return proxy_return(data, ENOMEM, NULL);

    gid = data->pwd->pw_gid;
    name = data->pwd->pw_name;

retry:
    status = data->ctx->ops.initgroups_dyn(name, gid,
                                           &start, &num,
                                           &data->groups, limit, &ret);

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
        data->groups = talloc_realloc_size(data, data->groups, size);
        if (!data->groups) {
            return proxy_return(data, ENOMEM, NULL);
        }
        goto retry;

    case NSS_STATUS_SUCCESS:
        data->num = start;
        DEBUG(4, ("User [%s] appears to be member of %lu groups\n",
                  name, data->num));
        get_gid_entry(data->sysreq, data);
        break;

    default:
        DEBUG(2, ("proxy -> getgrent_r failed (%d)[%s]\n",
                  ret, strerror(ret)));
        proxy_return(data, ret, NULL);
    }
}

static void get_initgr_user(struct be_req *req, char *name)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct proxy_data *data;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_id_data, struct proxy_ctx);

    data = talloc_zero(req, struct proxy_data);
    if (!data)
        return proxy_reply(req, ENOMEM, "Out of memory");
    data->req = req;
    data->ctx = ctx;
    data->next_fn = proxy_return;
    data->pwd = talloc(data, struct passwd);
    if (!data->pwd)
        return proxy_reply(req, ENOMEM, "Out of memory");
    data->grp = talloc(data, struct group);
    if (!data->grp)
        return proxy_reply(req, ENOMEM, "Out of memory");

    data->buflen = 4096;
    data->buffer = talloc_size(data, data->buflen);
    if (!data->buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getpwnam_r(name, data->pwd,
                                 data->buffer, data->buflen, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        data->dn = sysdb_user_dn(req->be_ctx->sysdb, data,
                                 req->be_ctx->domain, name);
        if (!data->dn)
            return proxy_reply(req, ENOMEM, "Out of memory");

        ret = sysdb_transaction(data, req->be_ctx->sysdb, del_db_entry, data);
        break;

    case NSS_STATUS_SUCCESS:
        /* FIXME: verify user does not have uid=0 or gid=0 as these are invalid
         * values */
        if (data->pwd->pw_uid == 0 || data->pwd->pw_gid == 0) {
            ret = sysdb_transaction(data, req->be_ctx->sysdb, del_db_entry, data);
            break;
        }

        if (ctx->ops.initgroups_dyn) {
            data->next_fn = get_user_groups;
            ret = sysdb_transaction(data, req->be_ctx->sysdb, set_pw_name, data);
        } else {
            status = ctx->ops.setgrent();
            if (status != NSS_STATUS_SUCCESS)
                return proxy_reply(req, EIO, "Operation failed");

            ret = sysdb_transaction(data, req->be_ctx->sysdb, get_gr_entry, data);
            break;
        }

    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' (%d)[%s]\n",
                  name, ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction (%d)[%s]!?\n",
                  ret, strerror(ret)));
        return proxy_reply(req, ret, "Operation failed");
    }
}

/* TODO: actually do check something */
static void proxy_check_online(struct be_req *req)
{
    struct be_online_req *oreq;

    oreq = talloc_get_type(req->req_data, struct be_online_req);

    oreq->online = MOD_ONLINE;

    req->fn(req, EOK, NULL);
}

/* TODO: See if we can use async_req code */
static void proxy_get_account_info(struct be_req *req)
{
    struct be_acct_req *ar;
    uid_t uid;
    gid_t gid;

    ar = talloc_get_type(req->req_data, struct be_acct_req);

    switch (ar->entry_type) {
    case BE_REQ_USER: /* user */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            switch (ar->attr_type) {
            case BE_ATTR_CORE:
                if (strchr(ar->filter_value, '*')) {
                    return enum_users(req);
                } else {
                    return get_pw_name(req, ar->filter_value);
                }
                break;
            default:
                return proxy_reply(req, EINVAL, "Invalid attr type");
            }
            break;
        case BE_FILTER_IDNUM:
            switch (ar->attr_type) {
            case BE_ATTR_CORE:
                if (strchr(ar->filter_value, '*')) {
                    return proxy_reply(req, EINVAL, "Invalid attr type");
                } else {
                    char *endptr;
                    errno = 0;
                    uid = (uid_t)strtol(ar->filter_value, &endptr, 0);
                    if (errno || *endptr || (ar->filter_value == endptr)) {
                        return proxy_reply(req, EINVAL, "Invalid attr type");
                    }
                    return get_pw_uid(req, uid);
                }
                break;
            default:
                return proxy_reply(req, EINVAL, "Invalid attr type");
            }
            break;
        default:
            return proxy_reply(req, EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_GROUP: /* group */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            switch (ar->attr_type) {
            case BE_ATTR_CORE:
                if (strchr(ar->filter_value, '*')) {
                    return enum_groups(req);
                } else {
                    return get_gr_name(req, ar->filter_value);
                }
                break;
            default:
                return proxy_reply(req, EINVAL, "Invalid attr type");
            }
            break;
        case BE_FILTER_IDNUM:
            switch (ar->attr_type) {
            case BE_ATTR_CORE:
                if (strchr(ar->filter_value, '*')) {
                    return proxy_reply(req, EINVAL, "Invalid attr type");
                } else {
                    char *endptr;
                    errno = 0;
                    gid = (gid_t)strtol(ar->filter_value, &endptr, 0);
                    if (errno || *endptr || (ar->filter_value == endptr)) {
                        return proxy_reply(req, EINVAL, "Invalid attr type");
                    }
                    return get_gr_gid(req, gid);
                }
                break;
            default:
                return proxy_reply(req, EINVAL, "Invalid attr type");
            }
            break;
        default:
            return proxy_reply(req, EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            return proxy_reply(req, EINVAL, "Invalid filter type");
        }
        if (ar->attr_type != BE_ATTR_CORE) {
            return proxy_reply(req, EINVAL, "Invalid attr type");
        }
        if (strchr(ar->filter_value, '*')) {
            return proxy_reply(req, EINVAL, "Invalid filter value");
        }
        return get_initgr_user(req, ar->filter_value);

    default: /*fail*/
        return proxy_reply(req, EINVAL, "Invalid request type");
    }
}

static void proxy_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    req->fn(req, EOK, NULL);
}

static void proxy_auth_shutdown(struct be_req *req)
{
    talloc_free(req->be_ctx->pvt_auth_data);
    req->fn(req, EOK, NULL);
}

struct be_id_ops proxy_id_ops = {
    .check_online = proxy_check_online,
    .get_account_info = proxy_get_account_info,
    .finalize = proxy_shutdown
};

struct be_auth_ops proxy_auth_ops = {
    .pam_handler = proxy_pam_handler,
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
                    struct be_id_ops **ops, void **pvt_data)
{
    struct proxy_ctx *ctx;
    char *libname;
    char *libpath;
    void *handle;
    int ret;

    ctx = talloc(bectx, struct proxy_ctx);
    if (!ctx) {
        return ENOMEM;
    }

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "libName", NULL, &libname);
    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "libPath", NULL, &libpath);
    if (ret != EOK) goto done;
    if (libpath == NULL || libname == NULL) {
        ret = ENOENT;
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
                         struct be_auth_ops **ops, void **pvt_data)
{
    struct proxy_auth_ctx *ctx;
    int ret;

    ctx = talloc(bectx, struct proxy_auth_ctx);
    if (!ctx) return ENOMEM;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "pam-target", NULL, &ctx->pam_target);
    if (ret != EOK) goto done;
    if (!ctx->pam_target) {
        ctx->pam_target = talloc_strdup(ctx, "sssd_pam_proxy_default");
        if (!ctx->pam_target) {
            ret = ENOMEM;
            goto done;
        }
    }

    *ops = &proxy_auth_ops;
    *pvt_data = ctx;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}
