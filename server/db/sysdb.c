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
#include "db/sysdb.h"
#include "db/sysdb_internal.h"
#include "confdb/confdb.h"
#include <time.h>

struct sysdb_search_ctx {
    struct sysdb_ctx *dbctx;
    const char *base_dn;
    sysdb_callback_t callback;
    void *ptr;
    struct ldb_result *res;
};

static int sysdb_error_to_errno(int lerr)
{
    /* fake it up for now, requires a mapping table */
    return EIO;
}

static void request_error(struct sysdb_search_ctx *sctx, int ldb_error)
{
    sctx->callback(sctx->ptr, sysdb_error_to_errno(ldb_error), sctx->res);
}

static void request_done(struct sysdb_search_ctx *sctx)
{
    sctx->callback(sctx->ptr, EOK, sctx->res);
}

static int get_gen_callback(struct ldb_request *req,
                            struct ldb_reply *ares)
{
    struct sysdb_search_ctx *sctx;
    struct ldb_result *res;
    int n;

    sctx = talloc_get_type(req->context, struct sysdb_search_ctx);
    res = sctx->res;

    if (!ares) {
        request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (ares->error != LDB_SUCCESS) {
        request_error(sctx, ares->error);
        return ares->error;
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        res->msgs[res->count + 1] = NULL;

        res->msgs[res->count] = talloc_steal(res->msgs, ares->message);
        res->count++;
        break;

    case LDB_REPLY_REFERRAL:
        if (res->refs) {
            for (n = 0; res->refs[n]; n++) /*noop*/ ;
        } else {
            n = 0;
        }

        res->refs = talloc_realloc(res, res->refs, char *, n + 2);
        if (! res->refs) {
            request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        res->refs[n] = talloc_steal(res->refs, ares->referral);
        res->refs[n + 1] = NULL;
        break;

    case LDB_REPLY_DONE:
        res->controls = talloc_steal(res, ares->controls);

        /* this is the last message, and means the request is done */
        request_done(sctx);
        return LDB_SUCCESS;
    }

    talloc_free(ares);
    return LDB_SUCCESS;
}

static struct sysdb_search_ctx *init_src_ctx(TALLOC_CTX *mem_ctx,
                                             const char *base_dn,
                                             struct sysdb_ctx *ctx,
                                             sysdb_callback_t fn,
                                             void *ptr)
{
    struct sysdb_search_ctx *sctx;

    sctx = talloc(mem_ctx, struct sysdb_search_ctx);
    if (!sctx) {
        return NULL;
    }
    sctx->dbctx = ctx;
    sctx->base_dn = base_dn;
    sctx->callback = fn;
    sctx->ptr = ptr;
    sctx->res = talloc_zero(sctx, struct ldb_result);
    if (!sctx->res) {
        talloc_free(sctx);
        return NULL;
    }

    return sctx;
}

/* users */

static int pwd_search(struct sysdb_search_ctx *sctx,
                      struct sysdb_ctx *ctx,
                      const char *expression)
{
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_request *req;
    int ret;

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               ldb_dn_new(sctx, ctx->ldb, sctx->base_dn),
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    return EOK;
}

int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct event_context *ev,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    const char *base_dn;
    char *expression;

    if (domain) {
        base_dn = talloc_asprintf(mem_ctx, SYSDB_TMPL_USER_BASE, domain);
    } else {
        base_dn = SYSDB_BASE;
    }
    if (!base_dn) {
        return ENOMEM;
    }

    sctx = init_src_ctx(mem_ctx, base_dn, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, SYSDB_PWNAM_FILTER, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return pwd_search(sctx, ctx, expression);
}

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct event_context *ev,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   uid_t uid,
                   sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    unsigned long int filter_uid = uid;
    const char *base_dn;
    char *expression;

    if (domain) {
        base_dn = talloc_asprintf(mem_ctx, SYSDB_TMPL_USER_BASE, domain);
    } else {
        base_dn = SYSDB_BASE;
    }
    if (!base_dn) {
        return ENOMEM;
    }

    sctx = init_src_ctx(mem_ctx, base_dn, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, SYSDB_PWUID_FILTER, filter_uid);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return pwd_search(sctx, ctx, expression);
}

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct event_context *ev,
                    struct sysdb_ctx *ctx,
                    sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;

    sctx = init_src_ctx(mem_ctx, SYSDB_BASE, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    return pwd_search(sctx, ctx, SYSDB_PWENT_FILTER);
}

/* groups */

struct get_mem_ctx {
    struct sysdb_search_ctx *ret_sctx;
    struct ldb_message **grps;
    int num_grps;
};

static void get_members(void *ptr, int status, struct ldb_result *res)
{
    struct sysdb_ctx *ctx;
    struct sysdb_search_ctx *sctx;
    struct get_mem_ctx *gmctx;
    struct sysdb_search_ctx *mem_sctx;
    struct ldb_request *req;
    struct ldb_message *msg;
    struct ldb_result *ret_res;
    static const char *attrs[] = SYSDB_GRPW_ATTRS;
    const char *expression;
    int ret, i;

    sctx = talloc_get_type(ptr, struct sysdb_search_ctx);
    gmctx = talloc_get_type(sctx->ptr, struct get_mem_ctx);
    ctx = sctx->dbctx;

    if (status != LDB_SUCCESS) {
        return request_error(gmctx->ret_sctx, status);
    }

    ret_res = gmctx->ret_sctx->res;

    /* append previous search results to final (if any) */
    if (res && res->count != 0) {
        ret_res->msgs = talloc_realloc(ret_res, ret_res->msgs,
                                       struct ldb_message *,
                                       ret_res->count + res->count + 1);
        for(i = 0; i < res->count; i++) {
            ret_res->msgs[ret_res->count] = talloc_steal(ret_res, res->msgs[i]);
            ret_res->count++;
        }
        ret_res->msgs[ret_res->count] = NULL;
    }

    if (gmctx->grps[0] == NULL) {
        return request_done(gmctx->ret_sctx);
    }

    mem_sctx = init_src_ctx(gmctx, SYSDB_BASE, ctx, get_members, sctx);
    if (!mem_sctx) {
        return request_error(gmctx->ret_sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    /* fetch next group to search for members */
    gmctx->num_grps--;
    msg = gmctx->grps[gmctx->num_grps];
    gmctx->grps[gmctx->num_grps] = NULL;

    /* queue the group entry on the final result structure */
    ret_res->msgs = talloc_realloc(ret_res, ret_res->msgs,
                                   struct ldb_message *,
                                   ret_res->count + 2);
    if (!ret_res->msgs) {
        return request_error(gmctx->ret_sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    ret_res->msgs[ret_res->count + 1] = NULL;
    ret_res->msgs[ret_res->count] = talloc_steal(ret_res->msgs, msg);
    ret_res->count++;

    /* search for this group members */
    expression = talloc_asprintf(mem_sctx, SYSDB_GRNA2_FILTER,
                                 ldb_dn_get_linearized(msg->dn));
    if (!expression) {
        return request_error(gmctx->ret_sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    ret = ldb_build_search_req(&req, ctx->ldb, mem_sctx,
                               ldb_dn_new(mem_sctx, ctx->ldb, sctx->base_dn),
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               mem_sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return request_error(gmctx->ret_sctx, ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return request_error(gmctx->ret_sctx, ret);
    }
}

static int get_grp_callback(struct ldb_request *req,
                            struct ldb_reply *ares)
{
    struct sysdb_search_ctx *sctx;
    struct sysdb_ctx *ctx;
    struct ldb_result *res;
    int n;

    sctx = talloc_get_type(req->context, struct sysdb_search_ctx);
    ctx = sctx->dbctx;
    res = sctx->res;

    if (!ares) {
        request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (ares->error != LDB_SUCCESS) {
        request_error(sctx, ares->error);
        return ares->error;
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        res->msgs[res->count + 1] = NULL;

        res->msgs[res->count] = talloc_steal(res->msgs, ares->message);
        res->count++;
        break;

    case LDB_REPLY_REFERRAL:
        if (res->refs) {
            for (n = 0; res->refs[n]; n++) /*noop*/ ;
        } else {
            n = 0;
        }

        res->refs = talloc_realloc(res, res->refs, char *, n + 2);
        if (! res->refs) {
            request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        res->refs[n] = talloc_steal(res->refs, ares->referral);
        res->refs[n + 1] = NULL;
        break;

    case LDB_REPLY_DONE:
        res->controls = talloc_steal(res, ares->controls);

        /* no results, return */
        if (res->count == 0) {
            request_done(sctx);
            return LDB_SUCCESS;
        }
        if (res->count > 0) {
            struct get_mem_ctx *gmctx;

            gmctx = talloc_zero(req, struct get_mem_ctx);
            if (!gmctx) {
                request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
                return LDB_ERR_OPERATIONS_ERROR;
            }
            gmctx->ret_sctx = sctx;
            gmctx->grps = talloc_steal(gmctx, res->msgs);
            gmctx->num_grps = res->count;
            res->msgs = NULL;
            res->count = 0;

            /* re-use sctx to create a fake handler for the first call to
             * get_members() */
            sctx = init_src_ctx(gmctx, SYSDB_BASE, ctx, get_members, gmctx);

            get_members(sctx, LDB_SUCCESS, NULL);
            return LDB_SUCCESS;
        }

        /* anything else is an error */
        request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    talloc_free(ares);
    return LDB_SUCCESS;
}

static int grp_search(struct sysdb_search_ctx *sctx,
                      struct sysdb_ctx *ctx,
                      const char *expression)
{
    static const char *attrs[] = SYSDB_GRNAM_ATTRS;
    struct ldb_request *req;
    int ret;

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               ldb_dn_new(sctx, ctx->ldb, sctx->base_dn),
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               sctx, get_grp_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    return EOK;
}

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct event_context *ev,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    const char *base_dn;
    char *expression;

    if (domain) {
        base_dn = talloc_asprintf(mem_ctx, SYSDB_TMPL_GROUP_BASE, domain);
    } else {
        base_dn = SYSDB_BASE;
    }
    if (!base_dn) {
        return ENOMEM;
    }

    sctx = init_src_ctx(mem_ctx, base_dn, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, SYSDB_GRNAM_FILTER, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return grp_search(sctx, ctx, expression);
}

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct event_context *ev,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   gid_t gid,
                   sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    unsigned long int filter_gid = gid;
    const char *base_dn;
    char *expression;

    if (domain) {
        base_dn = talloc_asprintf(mem_ctx, SYSDB_TMPL_GROUP_BASE, domain);
    } else {
        base_dn = SYSDB_BASE;
    }
    if (!base_dn) {
        return ENOMEM;
    }

    sctx = init_src_ctx(mem_ctx, base_dn, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, SYSDB_GRGID_FILTER, filter_gid);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return grp_search(sctx, ctx, expression);
}

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct event_context *ev,
                    struct sysdb_ctx *ctx,
                    sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;

    sctx = init_src_ctx(mem_ctx, SYSDB_BASE, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    return grp_search(sctx, ctx, SYSDB_GRENT_FILTER);
}

static void sysdb_initgr_search(void *ptr, int status,
                                struct ldb_result *res)
{
    struct sysdb_ctx *ctx;
    struct sysdb_search_ctx *sctx;
    char *expression;
    struct ldb_request *req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *control;
    static const char *attrs[] = SYSDB_INITGR_ATTRS;
    int ret;

    sctx = talloc_get_type(ptr, struct sysdb_search_ctx);
    ctx = sctx->dbctx;

    if (res->count == 0) {
        return request_done(sctx);
    }
    if (res->count > 1) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    expression = talloc_asprintf(sctx, SYSDB_INITGR_FILTER);
    if (!expression) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    ctrl = talloc_array(sctx, struct ldb_control *, 2);
    if (!ctrl) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    ctrl[1] = NULL;
    ctrl[0] = talloc(ctrl, struct ldb_control);
    if (!ctrl[0]) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    ctrl[0]->oid = LDB_CONTROL_ASQ_OID;
    ctrl[0]->critical = 1;
    control = talloc(ctrl[0], struct ldb_asq_control);
    if (!control) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    control->request = 1;
    control->source_attribute = talloc_strdup(control, SYSDB_INITGR_ATTR);
    if (!control->source_attribute) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    control->src_attr_len = strlen(control->source_attribute);
    ctrl[0]->data = control;

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               res->msgs[0]->dn,
                               LDB_SCOPE_BASE,
                               expression, attrs, ctrl,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return request_error(sctx, ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return request_error(sctx, ret);
    }
}

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct sysdb_ctx *ctx,
                     const char *domain,
                     const char *name,
                     sysdb_callback_t fn, void *ptr)
{
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct sysdb_search_ctx *ret_sctx;
    struct sysdb_search_ctx *sctx;
    const char *base_dn;
    char *expression;
    struct ldb_request *req;
    int ret;

    if (domain) {
        base_dn = talloc_asprintf(mem_ctx, SYSDB_TMPL_USER_BASE, domain);
    } else {
        base_dn = SYSDB_BASE;
    }
    if (!base_dn) {
        return ENOMEM;
    }

    ret_sctx = init_src_ctx(mem_ctx, SYSDB_BASE, ctx, fn, ptr);
    if (!ret_sctx) {
        return ENOMEM;
    }
    sctx = init_src_ctx(ret_sctx, base_dn, ctx, sysdb_initgr_search, ret_sctx);
    if (!sctx) {
        talloc_free(sctx);
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, SYSDB_PWNAM_FILTER, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               ldb_dn_new(sctx, ctx->ldb, sctx->base_dn),
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    return LDB_SUCCESS;
}

static int sysdb_read_var(TALLOC_CTX *mem_ctx,
                          struct confdb_ctx *cdb,
                          const char *name,
                          const char *def_value,
                          char **target)
{
    int ret;
    char **values;

    ret = confdb_get_param(cdb, mem_ctx,
                           SYSDB_CONF_SECTION,
                           name, &values);
    if (ret != EOK)
        return ret;

    if (values[0])
        *target = values[0];
    else
        *target = talloc_strdup(mem_ctx, def_value);

    return EOK;
}

static int sysdb_get_db_path(TALLOC_CTX *mem_ctx,
                             struct confdb_ctx *cdb,
                             char **db_path)
{
    TALLOC_CTX *tmp_ctx;
    char *default_ldb_path;
    char *path;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx)
        return ENOMEM;

    default_ldb_path = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, SYSDB_FILE);
    if (default_ldb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sysdb_read_var(tmp_ctx, cdb, "ldbFile",
                     default_ldb_path, &path);

    *db_path = talloc_steal(mem_ctx, path);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* the following are all SYNCHRONOUS calls
 * TODO: make these asynchronous */

int sysdb_add_group_member(TALLOC_CTX *mem_ctx,
                           struct sysdb_ctx *sysdb,
                           struct ldb_dn *member_dn,
                           struct ldb_dn *group_dn)
{
    TALLOC_CTX *tmp_ctx;
    int ret, lret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    /* Add the member_dn as a member of the group */
    msg = ldb_msg_new(tmp_ctx);
    if(msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = group_dn;
    lret = ldb_msg_add_empty(msg, SYSDB_GR_MEMBER,
                             LDB_FLAG_MOD_ADD, NULL);
    if (lret != LDB_SUCCESS) {
        ret = errno;
        goto done;
    }
    lret = ldb_msg_add_fmt(msg, SYSDB_GR_MEMBER, "%s",
                           ldb_dn_get_linearized(member_dn));
    if (lret != LDB_SUCCESS) {
        ret = EINVAL;
        goto done;
    }

    lret = ldb_modify(sysdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make modify request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_remove_group_member(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              struct ldb_dn *member_dn,
                              struct ldb_dn *group_dn)
{
    TALLOC_CTX *tmp_ctx;
    int ret, lret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    /* Add the member_dn as a member of the group */
    msg = ldb_msg_new(tmp_ctx);
    if(msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = group_dn;
    lret = ldb_msg_add_empty(msg, SYSDB_GR_MEMBER,
                             LDB_FLAG_MOD_DELETE, NULL);
    if (lret != LDB_SUCCESS) {
        ret = errno;
        goto done;
    }
    lret = ldb_msg_add_fmt(msg, SYSDB_GR_MEMBER, "%s",
                           ldb_dn_get_linearized(member_dn));
    if (lret != LDB_SUCCESS) {
        ret = EINVAL;
        goto done;
    }

    lret = ldb_modify(sysdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make modify request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* "sysdb_posix_" functions
 * the set of functions named sysdb_posix_* are used by modules
 * that only have access to strictly posix like databases where
 * user and groups names are retrieved as strings, groups can't
 * be nested and can't reference foreign sources */

int sysdb_posix_store_user(TALLOC_CTX *memctx,
                           struct sysdb_ctx *sysdb,
                           const char *domain,
                           const char *name, const char *pwd,
                           uid_t uid, gid_t gid, const char *gecos,
                           const char *homedir, const char *shell)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_PW_NAME, NULL };
    struct ldb_dn *user_dn;
    struct ldb_message *msg;
    struct ldb_request *req;
	struct ldb_result *res;
    int lret, ret;
    int flags;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    user_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                                name, domain);
    if (!user_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    lret = ldb_transaction_start(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, user_dn,
                      LDB_SCOPE_BASE, attrs, SYSDB_PWENT_FILTER);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make search request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    req = NULL;

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = user_dn;

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
        ret = EIO;
        goto done;
    }

    talloc_free(res);
    res = NULL;

    if (flags == LDB_FLAG_MOD_ADD) {
        /* TODO: retrieve user objectclass list from configuration */
        lret = ldb_msg_add_empty(msg, "objectClass", flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, "objectClass", "user");
        }
        if (lret != LDB_SUCCESS) {
            ret = errno;
            goto done;
        }

        /* TODO: retrieve user name attribute from configuration */
        lret = ldb_msg_add_empty(msg, SYSDB_PW_NAME, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_NAME, name);
        }
        if (lret != LDB_SUCCESS) {
            ret = errno;
            goto done;
        }
    }

    /* TODO: retrieve attribute name mappings from configuration */

    /* pwd */
    if (pwd && *pwd) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_PWD, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_PWD, pwd);
        }
    } else {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_PWD,
                                 LDB_FLAG_MOD_DELETE, NULL);
    }
    if (lret != LDB_SUCCESS) {
        ret = errno;
        goto done;
    }

    /* uid */
    if (uid) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_UIDNUM, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_fmt(msg, SYSDB_PW_UIDNUM,
                                   "%lu", (unsigned long)uid);
        }
        if (lret != LDB_SUCCESS) {
            ret = errno;
            goto done;
        }
    } else {
        DEBUG(0, ("Cached users can't have UID == 0\n"));
        ret = EINVAL;
        goto done;
    }

    /* gid */
    if (gid) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_GIDNUM, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_fmt(msg, SYSDB_PW_GIDNUM,
                                   "%lu", (unsigned long)gid);
        }
        if (lret != LDB_SUCCESS) {
            ret = errno;
            goto done;
        }
    } else {
        DEBUG(0, ("Cached users can't have GID == 0\n"));
        ret = EINVAL;
        goto done;
    }

    /* gecos */
    if (gecos && *gecos) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_FULLNAME, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_FULLNAME, gecos);
        }
    } else {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_FULLNAME,
                                 LDB_FLAG_MOD_DELETE, NULL);
    }
    if (lret != LDB_SUCCESS) {
        ret = errno;
        goto done;
    }

    /* homedir */
    if (homedir && *homedir) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_HOMEDIR, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_HOMEDIR, homedir);
        }
    } else {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_HOMEDIR,
                                 LDB_FLAG_MOD_DELETE, NULL);
    }
    if (lret != LDB_SUCCESS) {
        ret = errno;
        goto done;
    }

    /* shell */
    if (shell && *shell) {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_SHELL, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_PW_SHELL, shell);
        }
    } else {
        lret = ldb_msg_add_empty(msg, SYSDB_PW_SHELL,
                                 LDB_FLAG_MOD_DELETE, NULL);
    }
    if (lret != LDB_SUCCESS) {
        ret = errno;
        goto done;
    }

    /* modification time */
    lret = ldb_msg_add_empty(msg, SYSDB_LAST_UPDATE, flags, NULL);
    if (lret == LDB_SUCCESS) {
        lret = ldb_msg_add_fmt(msg, SYSDB_LAST_UPDATE,
                               "%ld", (long int)time(NULL));
    }
    if (lret != LDB_SUCCESS) {
        ret = errno;
        goto done;
    }

    if (flags == LDB_FLAG_MOD_ADD) {
        lret = ldb_build_add_req(&req, sysdb->ldb, tmp_ctx, msg, NULL,
                                 NULL, ldb_op_default_callback, NULL);
    } else {
        lret = ldb_build_mod_req(&req, sysdb->ldb, tmp_ctx, msg, NULL,
                                 NULL, ldb_op_default_callback, NULL);
    }
    if (lret == LDB_SUCCESS) {
        lret = ldb_request(sysdb->ldb, req);
        if (lret == LDB_SUCCESS) {
            lret = ldb_wait(req->handle, LDB_WAIT_ALL);
        }
    }
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make modify request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    lret = ldb_transaction_commit(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        lret = ldb_transaction_cancel(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction (%d)\n", lret));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_posix_remove_user(TALLOC_CTX *memctx,
                            struct sysdb_ctx *sysdb,
                            const char *domain, const char *name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *user_dn;
    int ret;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    user_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                                SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                                name, domain);
    if (!user_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    ret = ldb_delete(sysdb->ldb, user_dn);

    if (ret != LDB_SUCCESS) {
        DEBUG(2, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_posix_remove_user_by_uid(TALLOC_CTX *memctx,
                                   struct sysdb_ctx *sysdb,
                                   const char *domain, uid_t uid)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_PW_NAME, SYSDB_PW_UIDNUM, NULL };
    struct ldb_dn *base_dn;
    struct ldb_dn *user_dn;
	struct ldb_result *res;
    int lret, ret;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_USER_BASE, domain);
    if (!base_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    lret = ldb_transaction_start(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_ONELEVEL, attrs,
                      SYSDB_PWUID_FILTER,
                      (unsigned long)uid);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make search request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(0, ("Base search returned %d results\n",
                          res->count));
        ret = EOK;
        goto done;
    }
    if (res->count > 1) {
        DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                  res->count));
        ret = EOK;
        goto done;
    }

    user_dn = ldb_dn_copy(tmp_ctx, res->msgs[0]->dn);
    if (!user_dn) {
        ret = ENOMEM;
        goto done;
    }

    talloc_free(res);
    res = NULL;

    ret = ldb_delete(sysdb->ldb, user_dn);

    if (ret != LDB_SUCCESS) {
        DEBUG(2, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    lret = ldb_transaction_commit(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction commit !! (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        lret = ldb_transaction_cancel(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction (%d)\n", lret));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

/* this function does not check that all user members are actually present,
 * the caller must verify the members list is valid and exists in the
 * database before calling this function */

int sysdb_posix_store_group(TALLOC_CTX *memctx,
                            struct sysdb_ctx *sysdb,
                            const char *domain,
                            const char *name, gid_t gid,
                            char **members)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_GR_NAME, NULL };
    struct ldb_dn *group_dn;
    struct ldb_result *res;
    struct ldb_request *req;
    struct ldb_message *msg;
    int i, ret, lret;
    int flags;

    tmp_ctx = talloc_new(memctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    group_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                           SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                           name, domain);
    if (group_dn == NULL) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    /* Start a transaction to ensure that nothing changes
     * underneath us while we're working
     */
    lret = ldb_transaction_start(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        talloc_free(tmp_ctx);
        return EIO;
    }

    /* Determine if the group already exists */
    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, group_dn,
                      LDB_SCOPE_BASE, attrs, SYSDB_GRENT_FILTER);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make search request: %s(%d)[%s]\b",
                ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    req = NULL;

    switch(res->count) {
    case 0:
        flags = LDB_FLAG_MOD_ADD;
        DEBUG(3, ("Adding new entry\n"));
        break;
    case 1:
        flags = LDB_FLAG_MOD_REPLACE;
        DEBUG(3, ("Replacing existing entry\n"));
        break;
    default:
        DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                  res->count));
        ret = EIO;
        goto done;
    }
    talloc_free(res);
    res = NULL;

    /* Set up the add/replace request */
    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = group_dn;

    if (flags == LDB_FLAG_MOD_ADD) {
        lret = ldb_msg_add_empty(msg, "objectClass", flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, "objectClass", "group");
        }
        if (lret != LDB_SUCCESS) {
            ret = errno;
            goto done;
        }

        lret = ldb_msg_add_empty(msg, SYSDB_GR_NAME, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_string(msg, SYSDB_GR_NAME, name);
        }
        if (lret != LDB_SUCCESS) {
            ret = errno;
            goto done;
        }
    }

    /* gid */
    if (gid) {
        lret = ldb_msg_add_empty(msg, SYSDB_GR_GIDNUM, flags, NULL);
        if (lret == LDB_SUCCESS) {
            lret = ldb_msg_add_fmt(msg, SYSDB_GR_GIDNUM,
                                   "%lu", (unsigned long)gid);
        }
        if (lret != LDB_SUCCESS) {
            ret = errno;
            goto done;
        }
    } else {
        DEBUG(0, ("Cached groups can't have GID == 0\n"));
        ret = EINVAL;
        goto done;
    }

    /* modification time */
    lret = ldb_msg_add_empty(msg, SYSDB_LAST_UPDATE, flags, NULL);
    if (lret == LDB_SUCCESS) {
        lret = ldb_msg_add_fmt(msg, SYSDB_LAST_UPDATE,
                               "%ld", (long int)time(NULL));
    }
    if (lret != LDB_SUCCESS) {
        ret = errno;
        goto done;
    }

    /* members */
    if (members && members[0]) {
        lret = ldb_msg_add_empty(msg, SYSDB_GR_MEMBER, flags, NULL);
        if (lret != LDB_SUCCESS) {
            ret = errno;
            goto done;
        }
        for (i = 0; members[i]; i++) {
            lret = ldb_msg_add_fmt(msg, SYSDB_GR_MEMBER,
                                   "uid=%s,"SYSDB_TMPL_USER_BASE,
                                   members[i], domain);
        }
    }

    if (flags == LDB_FLAG_MOD_ADD) {
        lret = ldb_build_add_req(&req, sysdb->ldb, tmp_ctx, msg, NULL,
                                 NULL, ldb_op_default_callback, NULL);
    } else {
        lret = ldb_build_mod_req(&req, sysdb->ldb, tmp_ctx, msg, NULL,
                                 NULL, ldb_op_default_callback, NULL);
    }
    if (lret == LDB_SUCCESS) {
        lret = ldb_request(sysdb->ldb, req);
        if (lret == LDB_SUCCESS) {
            lret = ldb_wait(req->handle, LDB_WAIT_ALL);
        }
    }
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make modify request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    lret = ldb_transaction_commit(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        lret = ldb_transaction_cancel(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction (%d)\n", lret));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

/* Wrapper around adding a user to a POSIX group */
int sysdb_posix_add_user_to_group(TALLOC_CTX *mem_ctx,
                                  struct sysdb_ctx *sysdb,
                                  const char *domain,
                                  const char *group,
                                  const char *username)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_dn *user_dn;
    struct ldb_dn *group_dn;


    if (!sysdb || !domain || !group || !username) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    user_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                             username, domain);
    if (!user_dn) {
        ret = ENOMEM;
        goto done;
    }

    group_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                              SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                              group, domain);
    if (group_dn == NULL) {
        ret = errno;
        goto done;
    }

    ret = sysdb_add_group_member(tmp_ctx, sysdb, user_dn, group_dn);

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* Wrapper around adding a user to a POSIX group */
int sysdb_posix_remove_user_from_group(TALLOC_CTX *mem_ctx,
                                       struct sysdb_ctx *sysdb,
                                       const char *domain,
                                       const char *group,
                                       const char *username)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_dn *user_dn;
    struct ldb_dn *group_dn;


    if (!sysdb || !domain || !group || !username) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    user_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                             username, domain);
    if (!user_dn) {
        ret = ENOMEM;
        goto done;
    }

    group_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                              SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                              group, domain);
    if (group_dn == NULL) {
        ret = errno;
        goto done;
    }

    ret = sysdb_remove_group_member(tmp_ctx, sysdb, user_dn, group_dn);

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_posix_remove_group(TALLOC_CTX *memctx,
                             struct sysdb_ctx *sysdb,
                             const char *domain, const char *name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *group_dn;
    int ret;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    group_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                              SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                              name, domain);
    if (!group_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    ret = ldb_delete(sysdb->ldb, group_dn);

    if (ret != LDB_SUCCESS) {
        DEBUG(2, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_posix_remove_group_by_gid(TALLOC_CTX *memctx,
                                    struct sysdb_ctx *sysdb,
                                    const char *domain, gid_t gid)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { SYSDB_GR_NAME, SYSDB_GR_GIDNUM, NULL };
    struct ldb_dn *base_dn;
    struct ldb_dn *group_dn;
    struct ldb_result *res;
    int lret, ret;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb,
                             SYSDB_TMPL_GROUP_BASE, domain);
    if (!base_dn) {
        talloc_free(tmp_ctx);
        return ENOMEM;
    }

    lret = ldb_transaction_start(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction start !? (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_ONELEVEL, attrs,
                      SYSDB_GRGID_FILTER,
                      (unsigned long)gid);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to make search request: %s(%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(0, ("Base search returned %d results\n",
                          res->count));
        ret = EOK;
        goto done;
    }
    if (res->count > 1) {
        DEBUG(0, ("Cache DB corrupted, base search returned %d results\n",
                  res->count));
        ret = EOK;
        goto done;
    }

    group_dn = ldb_dn_copy(tmp_ctx, res->msgs[0]->dn);
    if (!group_dn) {
        ret = ENOMEM;
        goto done;
    }

    talloc_free(res);
    res = NULL;

    ret = ldb_delete(sysdb->ldb, group_dn);

    if (ret != LDB_SUCCESS) {
        DEBUG(2, ("LDB Error: %s(%d)\nError Message: [%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(sysdb->ldb)));
        ret = EIO;
        goto done;
    }

    lret = ldb_transaction_commit(sysdb->ldb);
    if (lret != LDB_SUCCESS) {
        DEBUG(1, ("Failed ldb transaction commit !! (%d)\n", lret));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        lret = ldb_transaction_cancel(sysdb->ldb);
        if (lret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction (%d)\n", lret));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

static int sysdb_check_init(struct sysdb_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    const char *base_ldif;
	struct ldb_ldif *ldif;
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    char *version = NULL;
    int ret;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx)
        return ENOMEM;

    verdn = ldb_dn_new(tmp_ctx, ctx->ldb, "cn=sysdb");
    if (!verdn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmp_ctx, &res,
                     verdn, LDB_SCOPE_BASE,
                     NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    if (res->count > 1) {
        ret = EIO;
        goto done;
    }

    if (res->count == 1) {
        el = ldb_msg_find_element(res->msgs[0], "version");
        if (el) {
            if (el->num_values != 1) {
                ret = EINVAL;
                goto done;
            }
            version = talloc_strndup(tmp_ctx,
                                     (char *)(el->values[0].data),
                                     el->values[0].length);
            if (!version) {
                ret = ENOMEM;
                goto done;
            }

            if (strcmp(version, SYSDB_VERSION) == 0) {
                /* all fine, return */
                ret = EOK;
                goto done;
            }
        }

        DEBUG(0,("Unknown DB version [%s], expected [%s], aborting!\n",
                 version?version:"not found", SYSDB_VERSION));
        ret = EINVAL;
        goto done;
    }

    /* cn=sysdb does not exists, means db is empty, populate */
    base_ldif = SYSDB_BASE_LDIF;
    while ((ldif = ldb_ldif_read_string(ctx->ldb, &base_ldif))) {
        ret = ldb_add(ctx->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(0, ("Failed to inizialiaze DB (%d,[%s]), aborting!\n",
                      ret, ldb_errstring(ctx->ldb)));
            ret = EIO;
            goto done;
        }
        ldb_ldif_read_free(ctx->ldb, ldif);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_init(TALLOC_CTX *mem_ctx,
               struct event_context *ev,
               struct confdb_ctx *cdb,
               const char *alt_db_path,
               struct sysdb_ctx **dbctx)
{
    struct sysdb_ctx *ctx;
    int ret;

    ctx = talloc_zero(mem_ctx, struct sysdb_ctx);
    if (!ctx) {
        return ENOMEM;
    }

    if (!alt_db_path) {
        ret = sysdb_get_db_path(ctx, cdb, &ctx->ldb_file);
        if (ret != EOK) {
            return ret;
        }
    } else {
        ctx->ldb_file = talloc_strdup(ctx, alt_db_path);
    }
    if (ctx->ldb_file == NULL) {
        return ENOMEM;
    }

    DEBUG(3, ("DB Path is: %s\n", ctx->ldb_file));

    ctx->ldb = ldb_init(ctx, ev);
    if (!ctx->ldb) {
        talloc_free(ctx);
        return EIO;
    }

    ret = ldb_connect(ctx->ldb, ctx->ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(ctx);
        return EIO;
    }

    ret = sysdb_check_init(ctx);
    if (ret != EOK) {
        talloc_free(ctx);
        return ret;
    }

    *dbctx = ctx;

    return EOK;
}
