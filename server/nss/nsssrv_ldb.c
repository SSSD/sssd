/*
   SSSD

   NSS Responder

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

#include "ldb.h"
#include "ldb_errors.h"
#include "util/util.h"
#include "nss/nsssrv.h"
#include "nss/nsssrv_ldb.h"
#include "nss/nss_ldb.h"
#include "confdb/confdb.h"

struct nss_ldb_search_ctx {
    struct nss_ldb_ctx *nlctx;
    nss_ldb_callback_t callback;
    void *ptr;
    struct ldb_result *res;
};

static int nss_ldb_error_to_errno(int lerr)
{
    /* fake it up for now, requires a mapping table */
    return EIO;
}

static void request_error(struct nss_ldb_search_ctx *sctx, int ldb_error)
{
    sctx->callback(sctx->ptr, nss_ldb_error_to_errno(ldb_error), sctx->res);
}

static void request_done(struct nss_ldb_search_ctx *sctx)
{
    sctx->callback(sctx->ptr, EOK, sctx->res);
}

static int get_gen_callback(struct ldb_request *req,
                            struct ldb_reply *ares)
{
    struct nss_ldb_search_ctx *sctx;
    struct ldb_result *res;
    int n;

    sctx = talloc_get_type(req->context, struct nss_ldb_search_ctx);
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

static struct nss_ldb_search_ctx *init_src_ctx(TALLOC_CTX *mem_ctx,
                                               struct nss_ldb_ctx *ctx,
                                               nss_ldb_callback_t fn,
                                               void *ptr)
{
    struct nss_ldb_search_ctx *sctx;

    sctx = talloc(mem_ctx, struct nss_ldb_search_ctx);
    if (!sctx) {
        return NULL;
    }
    sctx->nlctx = ctx;
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

static int pwd_search(struct nss_ldb_search_ctx *sctx,
                     struct nss_ldb_ctx *ctx,
                     const char *expression)
{
    struct ldb_request *req;
    int ret;

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               ldb_dn_new(sctx, ctx->ldb, ctx->user_base),
                               LDB_SCOPE_SUBTREE,
                               expression, ctx->pw_attrs, NULL,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    return EOK;
}

int nss_ldb_getpwnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    char *expression;

    sctx = init_src_ctx(mem_ctx, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, ctx->pwnam_filter, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return pwd_search(sctx, ctx, expression);
}

int nss_ldb_getpwuid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     uint64_t uid,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    unsigned long long int filter_uid = uid;
    char *expression;

    sctx = init_src_ctx(mem_ctx, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, ctx->pwuid_filter, filter_uid);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return pwd_search(sctx, ctx, expression);
}

int nss_ldb_enumpwent(TALLOC_CTX *mem_ctx,
                      struct event_context *ev,
                      struct nss_ldb_ctx *ctx,
                      nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;

    sctx = init_src_ctx(mem_ctx, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    return pwd_search(sctx, ctx, ctx->pwent_filter);
}

/* groups */

struct get_mem_ctx {
    struct nss_ldb_search_ctx *ret_sctx;
    struct ldb_message **grps;
    int num_grps;
};

static void get_members(void *ptr, int status, struct ldb_result *res)
{
    struct nss_ldb_ctx *ctx;
    struct nss_ldb_search_ctx *sctx;
    struct get_mem_ctx *gmctx;
    struct nss_ldb_search_ctx *mem_sctx;
    struct ldb_request *req;
    struct ldb_message *msg;
    struct ldb_result *ret_res;
    const char *expression;
    int ret, i;

    sctx = talloc_get_type(ptr, struct nss_ldb_search_ctx);
    gmctx = talloc_get_type(sctx->ptr, struct get_mem_ctx);
    ctx = sctx->nlctx;

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

    mem_sctx = init_src_ctx(gmctx, ctx, get_members, sctx);
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
    expression = talloc_asprintf(mem_sctx, ctx->grna2_filter,
                                 ldb_dn_get_linearized(msg->dn));
    if (!expression) {
        return request_error(gmctx->ret_sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    ret = ldb_build_search_req(&req, ctx->ldb, mem_sctx,
                               ldb_dn_new(mem_sctx, ctx->ldb, ctx->user_base),
                               LDB_SCOPE_SUBTREE,
                               expression, ctx->grpw_attrs, NULL,
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
    struct nss_ldb_search_ctx *sctx;
    struct nss_ldb_ctx *ctx;
    struct ldb_result *res;
    int n;

    sctx = talloc_get_type(req->context, struct nss_ldb_search_ctx);
    ctx = sctx->nlctx;
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
            sctx = init_src_ctx(gmctx, ctx, get_members, gmctx);

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

static int grp_search(struct nss_ldb_search_ctx *sctx,
                     struct nss_ldb_ctx *ctx,
                     const char *expression)
{
    struct ldb_request *req;
    int ret;

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               ldb_dn_new(sctx, ctx->ldb, ctx->group_base),
                               LDB_SCOPE_SUBTREE,
                               expression, ctx->grnam_attrs, NULL,
                               sctx, get_grp_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    return EOK;
}

int nss_ldb_getgrnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    char *expression;

    sctx = init_src_ctx(mem_ctx, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, ctx->grnam_filter, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return grp_search(sctx, ctx, expression);
}

int nss_ldb_getgrgid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     uint64_t gid,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    unsigned long long int filter_gid = gid;
    char *expression;

    sctx = init_src_ctx(mem_ctx, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, ctx->grgid_filter, filter_gid);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return grp_search(sctx, ctx, expression);
}

int nss_ldb_enumgrent(TALLOC_CTX *mem_ctx,
                      struct event_context *ev,
                      struct nss_ldb_ctx *ctx,
                      nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;

    sctx = init_src_ctx(mem_ctx, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    return grp_search(sctx, ctx, ctx->grent_filter);
}

static void nss_ldb_initgr_search(void *ptr, int status,
                                  struct ldb_result *res)
{
    struct nss_ldb_ctx *ctx;
    struct nss_ldb_search_ctx *sctx;
    char *expression;
    struct ldb_request *req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *control;
    int ret;

    sctx = talloc_get_type(ptr, struct nss_ldb_search_ctx);
    ctx = sctx->nlctx;

    if (res->count == 0) {
        return request_done(sctx);
    }
    if (res->count > 1) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    expression = talloc_asprintf(sctx, ctx->initgr_filter);
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
    control->source_attribute = talloc_strdup(control, ctx->initgr_attr);
    if (!control->source_attribute) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    control->src_attr_len = strlen(control->source_attribute);
    ctrl[0]->data = control;

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               res->msgs[0]->dn,
                               LDB_SCOPE_BASE,
                               expression, ctx->initgr_attrs, ctrl,
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

int nss_ldb_initgroups(TALLOC_CTX *mem_ctx,
                       struct event_context *ev,
                       struct nss_ldb_ctx *ctx,
                       const char *name,
                       nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *ret_sctx;
    struct nss_ldb_search_ctx *sctx;
    char *expression;
    struct ldb_request *req;
    int ret;

    ret_sctx = init_src_ctx(mem_ctx, ctx, fn, ptr);
    if (!ret_sctx) {
        return ENOMEM;
    }
    sctx = init_src_ctx(ret_sctx, ctx, nss_ldb_initgr_search, ret_sctx);
    if (!sctx) {
        talloc_free(sctx);
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, ctx->pwnam_filter, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               ldb_dn_new(sctx, ctx->ldb, ctx->user_base),
                               LDB_SCOPE_SUBTREE,
                               expression, ctx->pw_attrs, NULL,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    return LDB_SUCCESS;
}

static int nss_ldb_read_var(TALLOC_CTX *tmp_ctx,
                            struct confdb_ctx *cdb,
                            struct nss_ldb_ctx *ctx,
                            const char *name,
                            const char *def_value,
                            const char **target)
{
    int ret;
    char *t;
    char **values;

    ret = confdb_get_param(cdb, tmp_ctx,
                           NSS_LDB_CONF_SECTION,
                           name, &values);
    if (ret != EOK)
        return ret;

    if (values[0])
        t = talloc_steal(ctx, values[0]);
    else
        t = talloc_strdup(ctx, def_value);

    *target = t;
    return EOK;
}

static int nss_ldb_read_array(TALLOC_CTX *tmp_ctx,
                              struct confdb_ctx *cdb,
                              struct nss_ldb_ctx *ctx,
                              const char *name,
                              const char **def_value,
                              const char ***target)
{
    char **values;
    const char **t;
    int i, ret;

    ret = confdb_get_param(cdb, tmp_ctx,
                           NSS_LDB_CONF_SECTION,
                           name, &values);
    if (ret != EOK)
        return ret;

    for (i = 0; values[i]; i++) /* count */ ;
    if (i == 0) {
        for (i = 0; def_value[i]; i++) /*count */ ;
    }
    if (i == 0)
        return EINVAL;

    t = talloc_array(ctx, const char *, i+1);
    if (!*target)
        return ENOMEM;

    if (values[0]) {
        for (i = 0; values[i]; i++) {
            t[i] = talloc_steal(ctx, values[i]);
        }
    } else {
        for (i = 0; def_value[i]; i++) {
            t[i] = talloc_strdup(ctx, def_value[i]);
        }
    }
    t[i] = NULL;

    *target = t;
    return EOK;
}

static int nss_ldb_read_conf(TALLOC_CTX *mem_ctx,
                      struct confdb_ctx *cdb,
                      struct nss_ldb_ctx **nlctx)
{
    struct nss_ldb_ctx *ctx;
    TALLOC_CTX *tmp_ctx;
    char *default_ldb_path;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx)
        return ENOMEM;

    ctx = talloc(mem_ctx, struct nss_ldb_ctx);
    if (!ctx) {
        ret = ENOMEM;
        goto done;
    }

    default_ldb_path = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, NSS_DEF_LDB_FILE);
    if (default_ldb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    nss_ldb_read_var(tmp_ctx, cdb, ctx, "ldbFile",
                     default_ldb_path, &ctx->ldb_file);
    DEBUG(3, ("NSS LDB Cache Path: %s\n", ctx->ldb_file));

    nss_ldb_read_var(tmp_ctx, cdb, ctx, "userBase",
                     NSS_DEF_USER_BASE, &ctx->user_base);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "groupBase",
                     NSS_DEF_GROUP_BASE, &ctx->group_base);

    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwnamFilter",
                     NSS_DEF_PWNAM_FILTER, &ctx->pwnam_filter);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwuidFilter",
                     NSS_DEF_PWUID_FILTER, &ctx->pwuid_filter);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwentFilter",
                     NSS_DEF_PWENT_FILTER, &ctx->pwent_filter);

    nss_ldb_read_var(tmp_ctx, cdb, ctx, "grnamFilter",
                     NSS_DEF_GRNAM_FILTER, &ctx->grnam_filter);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "grna2Filter",
                     NSS_DEF_GRNA2_FILTER, &ctx->grna2_filter);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "grgidFilter",
                     NSS_DEF_GRGID_FILTER, &ctx->grgid_filter);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "grentFilter",
                     NSS_DEF_GRENT_FILTER, &ctx->grent_filter);

    nss_ldb_read_var(tmp_ctx, cdb, ctx, "initgrFilter",
                     NSS_DEF_INITGR_FILTER, &ctx->initgr_filter);

    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwName",
                     NSS_DEF_PW_NAME, &ctx->pw_name);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwUidnum",
                     NSS_DEF_PW_UIDNUM, &ctx->pw_uidnum);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwGidnum",
                     NSS_DEF_PW_GIDNUM, &ctx->pw_gidnum);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwFullname",
                     NSS_DEF_PW_FULLNAME, &ctx->pw_fullname);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwHomedir",
                     NSS_DEF_PW_HOMEDIR, &ctx->pw_homedir);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "pwShell",
                     NSS_DEF_PW_SHELL, &ctx->pw_shell);

    nss_ldb_read_var(tmp_ctx, cdb, ctx, "grName",
                     NSS_DEF_GR_NAME, &ctx->gr_name);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "grGidnum",
                     NSS_DEF_GR_GIDNUM, &ctx->gr_gidnum);
    nss_ldb_read_var(tmp_ctx, cdb, ctx, "grMember",
                     NSS_DEF_GR_MEMBER, &ctx->gr_member);

    nss_ldb_read_var(tmp_ctx, cdb, ctx, "initgrAttr",
                     NSS_DEF_INITGR_ATTR,
                     &ctx->initgr_attr);

    const char *pwattrs[] = NSS_DEF_PW_ATTRS;
    nss_ldb_read_array(tmp_ctx, cdb, ctx, "pwAttrs",
                       pwattrs, &ctx->pw_attrs);
    const char *grnamattrs[] = NSS_DEF_GRNAM_ATTRS;
    nss_ldb_read_array(tmp_ctx, cdb, ctx, "grnamAttrs",
                       grnamattrs, &ctx->grnam_attrs);
    const char *grpwattrs[] = NSS_DEF_GRPW_ATTRS;
    nss_ldb_read_array(tmp_ctx, cdb, ctx, "grpwAttrs",
                       grpwattrs, &ctx->grpw_attrs);
    const char *initgrattrs[] = NSS_DEF_INITGR_ATTRS;
    nss_ldb_read_array(tmp_ctx, cdb, ctx, "initgrAttrs",
                       initgrattrs, &ctx->initgr_attrs);

    *nlctx = ctx;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int nss_ldb_init(TALLOC_CTX *mem_ctx,
                 struct event_context *ev,
                 struct confdb_ctx *cdb,
                 struct nss_ldb_ctx **nlctx)
{
    struct nss_ldb_ctx *ctx;
    int ret;

    ret = nss_ldb_read_conf(mem_ctx, cdb, &ctx);
    if (ret != EOK)
        return ret;

    ctx->ldb = ldb_init(mem_ctx, ev);
    if (!ctx->ldb) {
        talloc_free(ctx);
        return EIO;
    }

    ret = ldb_connect(ctx->ldb, ctx->ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(ctx);
        return EIO;
    }

    *nlctx = ctx;

    return EOK;
}
