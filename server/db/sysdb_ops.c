/*
   SSSD

   System Database

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

#include "util/util.h"
#include "db/sysdb_private.h"
#include <time.h>

#define return_error(ctx, ret) ctx->fn(ctx->pvt, ret, NULL)
#define return_done(ctx) ctx->fn(ctx->pvt, EOK, NULL)

static int add_string(struct ldb_message *msg, int flags,
                      const char *attr, const char *value)
{
    int ret;

    ret = ldb_msg_add_empty(msg, attr, flags, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_msg_add_string(msg, attr, value);
    }
    return ret;
}

static int add_ulong(struct ldb_message *msg, int flags,
                     const char *attr, unsigned long value)
{
    int ret;

    ret = ldb_msg_add_empty(msg, attr, flags, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_msg_add_fmt(msg, attr, "%lu", value);
    }
    return ret;
}

/* the following are all SYNCHRONOUS calls
 * TODO: make these asynchronous */

struct sysdb_cb_ctx {
    sysdb_callback_t fn;
    void *pvt;

    bool ignore_not_found;
};

static int sysdb_op_callback(struct ldb_request *req, struct ldb_reply *rep)
{
    struct sysdb_cb_ctx *cbctx;

    cbctx = talloc_get_type(req->context, struct sysdb_cb_ctx);

    if (!rep) {
        return_error(cbctx, EIO);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (rep->error != LDB_SUCCESS) {
        if (! (cbctx->ignore_not_found &&
               rep->error == LDB_ERR_NO_SUCH_OBJECT)) {
            return_error(cbctx, sysdb_error_to_errno(rep->error));
            return rep->error;
        }
    }

    talloc_free(rep);

    if (rep->type != LDB_REPLY_DONE) {
        return_error(cbctx, EINVAL);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    return_done(cbctx);
    return LDB_SUCCESS;
}

int sysdb_add_group_member(struct sysdb_req *sysreq,
                           struct ldb_dn *member_dn,
                           struct ldb_dn *group_dn,
                           sysdb_callback_t fn, void *pvt)
{
    struct sysdb_ctx *ctx;
    struct sysdb_cb_ctx *cbctx;
    struct ldb_request *req;
    struct ldb_message *msg;
    const char *dn;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    cbctx = talloc_zero(sysreq, struct sysdb_cb_ctx);
    if (!cbctx) return ENOMEM;

    cbctx->fn = fn;
    cbctx->pvt = pvt;

    /* Add the member_dn as a member of the group */
    msg = ldb_msg_new(cbctx);
    if(msg == NULL) return ENOMEM;

    msg->dn = group_dn;
    ret = ldb_msg_add_empty(msg, SYSDB_GR_MEMBER,
                            LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) return ENOMEM;

    dn = ldb_dn_get_linearized(member_dn);
    if (!dn) return EINVAL;

    ret = ldb_msg_add_fmt(msg, SYSDB_GR_MEMBER, "%s", dn);
    if (ret != LDB_SUCCESS) return EINVAL;

    ret = ldb_build_mod_req(&req, ctx->ldb, cbctx, msg,
                            NULL, cbctx, sysdb_op_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

int sysdb_remove_group_member(struct sysdb_req *sysreq,
                              struct ldb_dn *member_dn,
                              struct ldb_dn *group_dn,
                              sysdb_callback_t fn, void *pvt)
{
    struct sysdb_ctx *ctx;
    struct sysdb_cb_ctx *cbctx;
    struct ldb_request *req;
    struct ldb_message *msg;
    const char *dn;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    cbctx = talloc_zero(sysreq, struct sysdb_cb_ctx);
    if (!cbctx) return ENOMEM;

    cbctx->fn = fn;
    cbctx->pvt = pvt;

    /* Add the member_dn as a member of the group */
    msg = ldb_msg_new(cbctx);
    if(msg == NULL) return ENOMEM;

    msg->dn = group_dn;
    ret = ldb_msg_add_empty(msg, SYSDB_GR_MEMBER,
                            LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) return ENOMEM;

    dn = ldb_dn_get_linearized(member_dn);
    if (!dn) return EINVAL;

    ret = ldb_msg_add_fmt(msg, SYSDB_GR_MEMBER, "%s", dn);
    if (ret != LDB_SUCCESS) return EINVAL;

    ret = ldb_build_mod_req(&req, ctx->ldb, cbctx, msg,
                            NULL, cbctx, sysdb_op_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

int sysdb_delete_entry(struct sysdb_req *sysreq,
                       struct ldb_dn *dn,
                       sysdb_callback_t fn, void *pvt)
{
    struct sysdb_ctx *ctx;
    struct sysdb_cb_ctx *cbctx;
    struct ldb_request *req;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    cbctx = talloc_zero(sysreq, struct sysdb_cb_ctx);
    if (!cbctx) return ENOMEM;

    cbctx->fn = fn;
    cbctx->pvt = pvt;
    cbctx->ignore_not_found = true;

    ret = ldb_build_del_req(&req, ctx->ldb, cbctx, dn, NULL,
                            cbctx, sysdb_op_callback, NULL);

    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

struct delete_ctx {
    struct sysdb_req *sysreq;
    struct sysdb_cb_ctx *cbctx;

	struct ldb_result *res;
};

static int delete_callback(struct ldb_request *req, struct ldb_reply *rep)
{
    struct delete_ctx *del_ctx;
    struct sysdb_cb_ctx *cbctx;
    struct sysdb_ctx *ctx;
    struct ldb_request *delreq;
    struct ldb_result *res;
    struct ldb_dn *dn;
    int ret;

    del_ctx = talloc_get_type(req->context, struct delete_ctx);
    ctx = sysdb_req_get_ctx(del_ctx->sysreq);
    cbctx = del_ctx->cbctx;
    res = del_ctx->res;

    if (!rep) {
        return_error(cbctx, EIO);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (rep->error != LDB_SUCCESS) {
        return_error(cbctx, sysdb_error_to_errno(rep->error));
        return rep->error;
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            ret = LDB_ERR_OPERATIONS_ERROR;
            return_error(cbctx, sysdb_error_to_errno(ret));
            return ret;
        }

        res->msgs[res->count + 1] = NULL;

        res->msgs[res->count] = talloc_steal(res->msgs, rep->message);
        res->count++;

        break;

    case LDB_REPLY_DONE:

        if (res->count == 0) {
            DEBUG(7, ("Base search returned no results\n"));
            return_done(cbctx);
            break;
        }
        if (res->count > 1) {
            DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                      res->count));
            return_error(cbctx, EFAULT);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        dn = ldb_dn_copy(del_ctx, res->msgs[0]->dn);
        if (!dn) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        talloc_free(res);
        del_ctx->res = res = NULL;

        ret = ldb_build_del_req(&delreq, ctx->ldb, cbctx, dn, NULL,
                                cbctx, sysdb_op_callback, NULL);
        if (ret == LDB_SUCCESS) {
            ret = ldb_request(ctx->ldb, delreq);
        }
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, sysdb_error_to_errno(ret));
            return LDB_ERR_OPERATIONS_ERROR;
        }
        break;

    default:
        return_error(cbctx, EINVAL);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}

int sysdb_delete_user_by_uid(struct sysdb_req *sysreq,
                             const char *domain, uid_t uid,
                             sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_PW_NAME, SYSDB_PW_UIDNUM, NULL };
    struct delete_ctx *del_ctx;
    struct sysdb_ctx *ctx;
    struct ldb_dn *base_dn;
    struct ldb_request *req;
    char *filter;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    del_ctx = talloc_zero(sysreq, struct delete_ctx);
    if (!del_ctx) return ENOMEM;

    del_ctx->cbctx = talloc_zero(del_ctx, struct sysdb_cb_ctx);
    if (!del_ctx->cbctx) return ENOMEM;

    del_ctx->sysreq = sysreq;
    del_ctx->cbctx->fn = fn;
    del_ctx->cbctx->pvt = pvt;
    del_ctx->cbctx->ignore_not_found = true;

    del_ctx->res = talloc_zero(del_ctx, struct ldb_result);
    if (!del_ctx->res) return ENOMEM;

    base_dn = ldb_dn_new_fmt(del_ctx, ctx->ldb, SYSDB_TMPL_USER_BASE, domain);
    if (!base_dn) return ENOMEM;

    filter = talloc_asprintf(del_ctx, SYSDB_PWUID_FILTER, (unsigned long)uid);
    if (!filter) return ENOMEM;

    ret = ldb_build_search_req(&req, ctx->ldb, del_ctx,
                               base_dn, LDB_SCOPE_ONELEVEL,
                               filter, attrs, NULL,
                               del_ctx, delete_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

int sysdb_delete_group_by_gid(struct sysdb_req *sysreq,
                              const char *domain, gid_t gid,
                              sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_GR_NAME, SYSDB_GR_GIDNUM, NULL };
    struct delete_ctx *del_ctx;
    struct sysdb_ctx *ctx;
    struct ldb_dn *base_dn;
    struct ldb_request *req;
    char *filter;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    del_ctx = talloc_zero(sysreq, struct delete_ctx);
    if (!del_ctx) return ENOMEM;

    del_ctx->cbctx = talloc_zero(del_ctx, struct sysdb_cb_ctx);
    if (!del_ctx->cbctx) return ENOMEM;

    del_ctx->sysreq = sysreq;
    del_ctx->cbctx->fn = fn;
    del_ctx->cbctx->pvt = pvt;
    del_ctx->cbctx->ignore_not_found = true;

    del_ctx->res = talloc_zero(del_ctx, struct ldb_result);
    if (!del_ctx->res) return ENOMEM;

    base_dn = ldb_dn_new_fmt(del_ctx, ctx->ldb, SYSDB_TMPL_GROUP_BASE, domain);
    if (!base_dn) return ENOMEM;

    filter = talloc_asprintf(del_ctx, SYSDB_GRGID_FILTER, (unsigned long)gid);
    if (!filter) return ENOMEM;

    ret = ldb_build_search_req(&req, ctx->ldb, del_ctx,
                               base_dn, LDB_SCOPE_ONELEVEL,
                               filter, attrs, NULL,
                               del_ctx, delete_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

/* "sysdb_legacy_" functions
 * the set of functions named sysdb_legacy_* are used by modules
 * that only have access to strictly posix like databases where
 * user and groups names are retrieved as strings, groups can't
 * be nested and can't reference foreign sources */

struct legacy_user_ctx {
    struct sysdb_req *sysreq;
    struct sysdb_cb_ctx *cbctx;

    struct ldb_dn *dn;

    const char *domain;
    const char *name;
    const char *pwd;
    uid_t uid;
    gid_t gid;
    const char *gecos;
    const char *homedir;
    const char *shell;

	struct ldb_result *res;
};

static int legacy_user_callback(struct ldb_request *req,
                                struct ldb_reply *rep);

int sysdb_legacy_store_user(struct sysdb_req *sysreq,
                            const char *domain,
                            const char *name, const char *pwd,
                            uid_t uid, gid_t gid, const char *gecos,
                            const char *homedir, const char *shell,
                            sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_PW_NAME, NULL };
    struct legacy_user_ctx *user_ctx;
    struct sysdb_ctx *ctx;
    struct ldb_request *req;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    user_ctx = talloc(sysreq, struct legacy_user_ctx);
    if (!user_ctx) return ENOMEM;

    user_ctx->cbctx = talloc_zero(user_ctx, struct sysdb_cb_ctx);
    if (!user_ctx->cbctx) return ENOMEM;

    user_ctx->dn = sysdb_user_dn(ctx, user_ctx, domain, name);
    if (!user_ctx->dn) return ENOMEM;

    user_ctx->sysreq = sysreq;
    user_ctx->cbctx->fn = fn;
    user_ctx->cbctx->pvt = pvt;
    user_ctx->domain = domain;
    user_ctx->name = name;
    user_ctx->pwd = pwd;
    user_ctx->uid = uid;
    user_ctx->gid = gid;
    user_ctx->gecos = gecos;
    user_ctx->homedir = homedir;
    user_ctx->shell = shell;

    user_ctx->res = talloc_zero(user_ctx, struct ldb_result);
    if (!user_ctx->res) return ENOMEM;

    ret = ldb_build_search_req(&req, ctx->ldb, user_ctx,
                               user_ctx->dn, LDB_SCOPE_BASE,
                               SYSDB_PWENT_FILTER, attrs, NULL,
                               user_ctx, legacy_user_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

static int legacy_user_callback(struct ldb_request *req,
                                struct ldb_reply *rep)
{
    struct legacy_user_ctx *user_ctx;
    struct sysdb_cb_ctx *cbctx;
    struct sysdb_ctx *ctx;
    struct ldb_message *msg;
    struct ldb_request *ureq;
    struct ldb_result *res;
    int flags;
    int ret;

    user_ctx = talloc_get_type(req->context, struct legacy_user_ctx);
    ctx = sysdb_req_get_ctx(user_ctx->sysreq);
    cbctx = user_ctx->cbctx;
    res = user_ctx->res;

    if (!rep) {
        return_error(cbctx, EIO);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (rep->error != LDB_SUCCESS) {
        return_error(cbctx, sysdb_error_to_errno(rep->error));
        return rep->error;
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            ret = LDB_ERR_OPERATIONS_ERROR;
            return_error(cbctx, sysdb_error_to_errno(ret));
            return ret;
        }

        res->msgs[res->count + 1] = NULL;

        res->msgs[res->count] = talloc_steal(res->msgs, rep->message);
        res->count++;

        break;

    case LDB_REPLY_DONE:

        msg = ldb_msg_new(cbctx);
        if (!msg) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }
        msg->dn = user_ctx->dn;

        switch (res->count) {
        case 0:
            flags = LDB_FLAG_MOD_ADD;
            break;
        case 1:
            flags = LDB_FLAG_MOD_REPLACE;
            break;
        default:
            DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                      res->count));

            return_error(cbctx, EFAULT);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        talloc_free(res);
        user_ctx->res = res = NULL;

        if (flags == LDB_FLAG_MOD_ADD) {
            ret = add_string(msg, flags, "objectClass", SYSDB_USER_CLASS);
            if (ret != LDB_SUCCESS) {
                return_error(cbctx, ENOMEM);
                return LDB_ERR_OPERATIONS_ERROR;
            }

            ret = add_string(msg, flags, SYSDB_PW_NAME, user_ctx->name);
            if (ret != LDB_SUCCESS) {
                return_error(cbctx, ENOMEM);
                return LDB_ERR_OPERATIONS_ERROR;
            }
        }

        if (user_ctx->pwd && *user_ctx->pwd) {
            ret = add_string(msg, flags, SYSDB_PW_PWD, user_ctx->pwd);
        } else {
            ret = ldb_msg_add_empty(msg, SYSDB_PW_PWD,
                                     LDB_FLAG_MOD_DELETE, NULL);
        }
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (user_ctx->uid) {
            ret = add_ulong(msg, flags, SYSDB_PW_UIDNUM,
                                        (unsigned long)(user_ctx->uid));
            if (ret != LDB_SUCCESS) {
                return_error(cbctx, ENOMEM);
                return LDB_ERR_OPERATIONS_ERROR;
            }
        } else {
            DEBUG(0, ("Cached users can't have UID == 0\n"));
            return_error(cbctx, EINVAL);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (user_ctx->gid) {
            ret = add_ulong(msg, flags, SYSDB_PW_GIDNUM,
                                        (unsigned long)(user_ctx->gid));
            if (ret != LDB_SUCCESS) {
                return_error(cbctx, ENOMEM);
                return LDB_ERR_OPERATIONS_ERROR;
            }
        } else {
            DEBUG(0, ("Cached users can't have GID == 0\n"));
            return_error(cbctx, EINVAL);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (user_ctx->gecos && *user_ctx->gecos) {
            ret = add_string(msg, flags, SYSDB_PW_FULLNAME, user_ctx->gecos);
        } else {
            ret = ldb_msg_add_empty(msg, SYSDB_PW_FULLNAME,
                                     LDB_FLAG_MOD_DELETE, NULL);
        }
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (user_ctx->homedir && *user_ctx->homedir) {
            ret = add_string(msg, flags, SYSDB_PW_HOMEDIR, user_ctx->homedir);
        } else {
            ret = ldb_msg_add_empty(msg, SYSDB_PW_HOMEDIR,
                                     LDB_FLAG_MOD_DELETE, NULL);
        }
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (user_ctx->shell && *user_ctx->shell) {
            ret = add_string(msg, flags, SYSDB_PW_SHELL, user_ctx->shell);
        } else {
            ret = ldb_msg_add_empty(msg, SYSDB_PW_SHELL,
                                     LDB_FLAG_MOD_DELETE, NULL);
        }
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        /* modification time */
        ret = add_ulong(msg, flags, SYSDB_LAST_UPDATE,
                                    (unsigned long)time(NULL));
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (flags == LDB_FLAG_MOD_ADD) {
            ret = ldb_build_add_req(&ureq, ctx->ldb, cbctx, msg, NULL,
                                     cbctx, sysdb_op_callback, NULL);
        } else {
            ret = ldb_build_mod_req(&ureq, ctx->ldb, cbctx, msg, NULL,
                                     cbctx, sysdb_op_callback, NULL);
        }
        if (ret == LDB_SUCCESS) {
            ret = ldb_request(ctx->ldb, ureq);
        }
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, sysdb_error_to_errno(ret));
            return LDB_ERR_OPERATIONS_ERROR;
        }
        break;

    default:
        return_error(cbctx, EINVAL);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}



/* this function does not check that all user members are actually present */

struct legacy_group_ctx {
    struct sysdb_req *sysreq;
    struct sysdb_cb_ctx *cbctx;

    struct ldb_dn *dn;

    const char *domain;
    const char *name;
    gid_t gid;
    const char **members;

	struct ldb_result *res;
};

static int legacy_group_callback(struct ldb_request *req,
                                 struct ldb_reply *rep);

int sysdb_legacy_store_group(struct sysdb_req *sysreq,
                             const char *domain,
                             const char *name, gid_t gid,
                             const char **members,
                             sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_GR_NAME, NULL };
    struct legacy_group_ctx *group_ctx;
    struct sysdb_ctx *ctx;
    struct ldb_request *req;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    group_ctx = talloc(sysreq, struct legacy_group_ctx);
    if (!group_ctx) return ENOMEM;

    group_ctx->cbctx = talloc_zero(group_ctx, struct sysdb_cb_ctx);
    if (!group_ctx->cbctx) return ENOMEM;

    group_ctx->dn = sysdb_group_dn(ctx, group_ctx, domain, name);
    if (!group_ctx->dn) return ENOMEM;

    group_ctx->sysreq = sysreq;
    group_ctx->cbctx->fn = fn;
    group_ctx->cbctx->pvt = pvt;
    group_ctx->domain = domain;
    group_ctx->name = name;
    group_ctx->gid = gid;
    group_ctx->members = members;

    group_ctx->res = talloc_zero(group_ctx, struct ldb_result);
    if (!group_ctx->res) return ENOMEM;

    ret = ldb_build_search_req(&req, ctx->ldb, group_ctx,
                               group_ctx->dn, LDB_SCOPE_BASE,
                               SYSDB_GRENT_FILTER, attrs, NULL,
                               group_ctx, legacy_group_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

static int legacy_group_callback(struct ldb_request *req,
                                struct ldb_reply *rep)
{
    struct legacy_group_ctx *group_ctx;
    struct sysdb_cb_ctx *cbctx;
    struct sysdb_ctx *ctx;
    struct ldb_message *msg;
    struct ldb_request *greq;
    struct ldb_result *res;
    int flags;
    int i, ret;

    group_ctx = talloc_get_type(req->context, struct legacy_group_ctx);
    ctx = sysdb_req_get_ctx(group_ctx->sysreq);
    cbctx = group_ctx->cbctx;
    res = group_ctx->res;

    if (!rep) {
        return_error(cbctx, EIO);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (rep->error != LDB_SUCCESS) {
        return_error(cbctx, sysdb_error_to_errno(rep->error));
        return rep->error;
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            ret = LDB_ERR_OPERATIONS_ERROR;
            return_error(cbctx, sysdb_error_to_errno(ret));
            return ret;
        }

        res->msgs[res->count + 1] = NULL;

        res->msgs[res->count] = talloc_steal(res->msgs, rep->message);
        res->count++;

        break;

    case LDB_REPLY_DONE:

        msg = ldb_msg_new(cbctx);
        if (!msg) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }
        msg->dn = group_ctx->dn;

        switch (res->count) {
        case 0:
            flags = LDB_FLAG_MOD_ADD;
            break;
        case 1:
            flags = LDB_FLAG_MOD_REPLACE;
            break;
        default:
            DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                      res->count));

            return_error(cbctx, EFAULT);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        talloc_free(res);
        group_ctx->res = res = NULL;

        if (flags == LDB_FLAG_MOD_ADD) {
            ret = add_string(msg, flags, "objectClass", SYSDB_GROUP_CLASS);
            if (ret != LDB_SUCCESS) {
                return_error(cbctx, ENOMEM);
                return LDB_ERR_OPERATIONS_ERROR;
            }

            ret = add_string(msg, flags, SYSDB_GR_NAME, group_ctx->name);
            if (ret != LDB_SUCCESS) {
                return_error(cbctx, ENOMEM);
                return LDB_ERR_OPERATIONS_ERROR;
            }
        }

        if (group_ctx->gid) {
            ret = add_ulong(msg, flags, SYSDB_GR_GIDNUM,
                                        (unsigned long)(group_ctx->gid));
            if (ret != LDB_SUCCESS) {
                return_error(cbctx, ENOMEM);
                return LDB_ERR_OPERATIONS_ERROR;
            }
        } else {
            DEBUG(0, ("Cached groups can't have GID == 0\n"));
            return_error(cbctx, EINVAL);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        /* members */
        if (group_ctx->members && group_ctx->members[0]) {
            ret = ldb_msg_add_empty(msg, SYSDB_LEGACY_MEMBER, flags, NULL);
            if (ret != LDB_SUCCESS) {
                return_error(cbctx, ENOMEM);
                return LDB_ERR_OPERATIONS_ERROR;
            }
            for (i = 0; group_ctx->members[i]; i++) {
                ret = ldb_msg_add_string(msg, SYSDB_LEGACY_MEMBER,
                                              group_ctx->members[i]);
                if (ret != LDB_SUCCESS) {
                    return_error(cbctx, ENOMEM);
                    return LDB_ERR_OPERATIONS_ERROR;
                }
            }
        }

        /* modification time */
        ret = add_ulong(msg, flags, SYSDB_LAST_UPDATE,
                                    (unsigned long)time(NULL));
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, ENOMEM);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (flags == LDB_FLAG_MOD_ADD) {
            ret = ldb_build_add_req(&greq, ctx->ldb, cbctx, msg, NULL,
                                     cbctx, sysdb_op_callback, NULL);
        } else {
            ret = ldb_build_mod_req(&greq, ctx->ldb, cbctx, msg, NULL,
                                     cbctx, sysdb_op_callback, NULL);
        }
        if (ret == LDB_SUCCESS) {
            ret = ldb_request(ctx->ldb, greq);
        }
        if (ret != LDB_SUCCESS) {
            return_error(cbctx, sysdb_error_to_errno(ret));
            return LDB_ERR_OPERATIONS_ERROR;
        }
        break;

    default:
        return_error(cbctx, EINVAL);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}

int sysdb_legacy_add_group_member(struct sysdb_req *sysreq,
                                  const char *domain,
                                  const char *group,
                                  const char *member,
                                  sysdb_callback_t fn, void *pvt)
{
    struct sysdb_ctx *ctx;
    struct sysdb_cb_ctx *cbctx;
    struct ldb_request *req;
    struct ldb_message *msg;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    cbctx = talloc_zero(sysreq, struct sysdb_cb_ctx);
    if (!cbctx) return ENOMEM;

    cbctx->fn = fn;
    cbctx->pvt = pvt;

    /* Add the member_dn as a member of the group */
    msg = ldb_msg_new(cbctx);
    if(msg == NULL) return ENOMEM;

    msg->dn = sysdb_group_dn(ctx, cbctx, domain, group);
    if (!msg->dn) return ENOMEM;

    ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_LEGACY_MEMBER, member);
    if (ret != LDB_SUCCESS) return ENOMEM;

    ret = ldb_build_mod_req(&req, ctx->ldb, cbctx, msg,
                            NULL, cbctx, sysdb_op_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

int sysdb_legacy_remove_group_member(struct sysdb_req *sysreq,
                                     const char *domain,
                                     const char *group,
                                     const char *member,
                                     sysdb_callback_t fn, void *pvt)
{
    struct sysdb_ctx *ctx;
    struct sysdb_cb_ctx *cbctx;
    struct ldb_request *req;
    struct ldb_message *msg;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    cbctx = talloc_zero(sysreq, struct sysdb_cb_ctx);
    if (!cbctx) return ENOMEM;

    cbctx->fn = fn;
    cbctx->pvt = pvt;

    /* Add the member_dn as a member of the group */
    msg = ldb_msg_new(cbctx);
    if(msg == NULL) return ENOMEM;

    msg->dn = sysdb_group_dn(ctx, cbctx, domain, group);
    if (!msg->dn) return ENOMEM;

    ret = add_string(msg, LDB_FLAG_MOD_DELETE, SYSDB_LEGACY_MEMBER, member);
    if (ret != LDB_SUCCESS) return ENOMEM;

    ret = ldb_build_mod_req(&req, ctx->ldb, cbctx, msg,
                            NULL, cbctx, sysdb_op_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

