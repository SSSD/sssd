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
#include "confdb/confdb.h"
#include <time.h>

struct sysdb_search_ctx;

typedef void (*gen_callback)(struct sysdb_search_ctx *);

struct sysdb_search_ctx {
    struct tevent_context *ev;
    struct sysdb_ctx *ctx;
    struct sysdb_handle *handle;

    struct sss_domain_info *domain;

    const char *expression;

    sysdb_callback_t callback;
    void *ptr;

    gen_callback gen_aux_fn;
    bool gen_conv_mpg_users;

    struct ldb_result *res;

    const char **attrs;

    int error;
};

static struct sysdb_search_ctx *init_src_ctx(TALLOC_CTX *mem_ctx,
                                             struct sss_domain_info *domain,
                                             struct sysdb_ctx *ctx,
                                             sysdb_callback_t fn,
                                             void *ptr)
{
    struct sysdb_search_ctx *sctx;

    sctx = talloc_zero(mem_ctx, struct sysdb_search_ctx);
    if (!sctx) {
        return NULL;
    }
    sctx->ctx = ctx;
    sctx->ev = ctx->ev;
    sctx->callback = fn;
    sctx->ptr = ptr;
    sctx->res = talloc_zero(sctx, struct ldb_result);
    if (!sctx->res) {
        talloc_free(sctx);
        return NULL;
    }
    sctx->domain = domain;

    return sctx;
}

static void request_ldberror(struct sysdb_search_ctx *sctx, int error)
{
    sysdb_operation_done(sctx->handle);
    sctx->callback(sctx->ptr, sysdb_error_to_errno(error), NULL);
}

static void request_error(struct sysdb_search_ctx *sctx, int error)
{
    sysdb_operation_done(sctx->handle);
    sctx->callback(sctx->ptr, error, NULL);
}

static void request_done(struct sysdb_search_ctx *sctx)
{
    sysdb_operation_done(sctx->handle);
    sctx->callback(sctx->ptr, EOK, sctx->res);
}

static int mpg_convert(struct ldb_message *msg);

static int get_gen_callback(struct ldb_request *req,
                            struct ldb_reply *rep)
{
    struct sysdb_search_ctx *sctx;
    struct ldb_result *res;
    int n, ret;

    sctx = talloc_get_type(req->context, struct sysdb_search_ctx);
    res = sctx->res;

    if (!rep) {
        request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    if (rep->error != LDB_SUCCESS) {
        request_ldberror(sctx, rep->error);
        return rep->error;
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:

        if (sctx->gen_conv_mpg_users) {
            ret = mpg_convert(rep->message);
            if (ret != EOK) {
                request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
                return LDB_ERR_OPERATIONS_ERROR;
            }
        }

        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        res->msgs[res->count + 1] = NULL;

        res->msgs[res->count] = talloc_steal(res->msgs, rep->message);
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
            request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
            return LDB_ERR_OPERATIONS_ERROR;
        }

        res->refs[n] = talloc_steal(res->refs, rep->referral);
        res->refs[n + 1] = NULL;
        break;

    case LDB_REPLY_DONE:
        res->controls = talloc_steal(res, rep->controls);

        /* check if we need to call any aux function */
        if (sctx->gen_aux_fn) {
            sctx->gen_aux_fn(sctx);
        } else {
            /* no aux functions, this means the request is done */
            request_done(sctx);
        }
        return LDB_SUCCESS;
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}

/* users */

static void user_search(struct tevent_req *treq)
{
    struct sysdb_search_ctx *sctx;
    struct ldb_request *req;
    struct ldb_dn *base_dn;
    int ret;

    sctx = tevent_req_callback_data(treq, struct sysdb_search_ctx);

    ret = sysdb_operation_recv(treq, sctx, &sctx->handle);
    if (ret) {
        return request_error(sctx, ret);
    }

    base_dn = ldb_dn_new_fmt(sctx, sctx->ctx->ldb,
                             SYSDB_TMPL_USER_BASE, sctx->domain->name);
    if (!base_dn) {
        return request_error(sctx, ENOMEM);
    }

    ret = ldb_build_search_req(&req, sctx->ctx->ldb, sctx,
                               base_dn, LDB_SCOPE_SUBTREE,
                               sctx->expression, sctx->attrs, NULL,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return request_ldberror(sctx, ret);
    }

    ret = ldb_request(sctx->ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return request_ldberror(sctx, ret);
    }
}

int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr)
{
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct sysdb_search_ctx *sctx;
    struct tevent_req *req;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    sctx->expression = talloc_asprintf(sctx, SYSDB_PWNAM_FILTER, name);
    if (!sctx->expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    sctx->attrs = attrs;

    req = sysdb_operation_send(mem_ctx, ctx->ev, ctx);
    if (!req) {
        talloc_free(sctx);
        return ENOMEM;
    }

    tevent_req_set_callback(req, user_search, sctx);

    return EOK;
}

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   uid_t uid,
                   sysdb_callback_t fn, void *ptr)
{
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct sysdb_search_ctx *sctx;
    unsigned long int filter_uid = uid;
    struct tevent_req *req;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    sctx->expression = talloc_asprintf(sctx, SYSDB_PWUID_FILTER, filter_uid);
    if (!sctx->expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    sctx->attrs = attrs;

    req = sysdb_operation_send(mem_ctx, ctx->ev, ctx);
    if (!req) {
        talloc_free(sctx);
        return ENOMEM;
    }

    tevent_req_set_callback(req, user_search, sctx);

    return EOK;
}

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    const char *expression,
                    sysdb_callback_t fn, void *ptr)
{
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct sysdb_search_ctx *sctx;
    struct tevent_req *req;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    if (expression)
        sctx->expression = expression;
    else
        sctx->expression = SYSDB_PWENT_FILTER;

    sctx->attrs = attrs;

    req = sysdb_operation_send(mem_ctx, ctx->ev, ctx);
    if (!req) {
        talloc_free(sctx);
        return ENOMEM;
    }

    tevent_req_set_callback(req, user_search, sctx);

    return EOK;
}

/* groups */

static int mpg_convert(struct ldb_message *msg)
{
    struct ldb_message_element *el;
    struct ldb_val *val;
    int i;

    el = ldb_msg_find_element(msg, "objectClass");
    if (!el) return EINVAL;

    /* see if this is a user to convert to a group */
    for (i = 0; i < el->num_values; i++) {
        val = &(el->values[i]);
        if (strncasecmp(SYSDB_USER_CLASS,
                        (char *)val->data, val->length) == 0) {
            break;
        }
    }
    /* no, leave as is */
    if (i == el->num_values) return EOK;

    /* yes, convert */
    val->data = (uint8_t *)talloc_strdup(msg, SYSDB_GROUP_CLASS);
    if (val->data == NULL) return ENOMEM;
    val->length = strlen(SYSDB_GROUP_CLASS);

    return EOK;
}

static void grp_search(struct tevent_req *treq)
{
    struct sysdb_search_ctx *sctx;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    struct ldb_request *req;
    struct ldb_dn *base_dn;
    int ret;

    sctx = tevent_req_callback_data(treq, struct sysdb_search_ctx);

    ret = sysdb_operation_recv(treq, sctx, &sctx->handle);
    if (ret) {
        return request_error(sctx, ret);
    }

    if (sctx->gen_conv_mpg_users) {
        base_dn = ldb_dn_new_fmt(sctx, sctx->ctx->ldb,
                                 SYSDB_DOM_BASE, sctx->domain->name);
    } else {
        base_dn = ldb_dn_new_fmt(sctx, sctx->ctx->ldb,
                                 SYSDB_TMPL_GROUP_BASE, sctx->domain->name);
    }
    if (!base_dn) {
        return request_error(sctx, ENOMEM);
    }

    ret = ldb_build_search_req(&req, sctx->ctx->ldb, sctx,
                               base_dn, LDB_SCOPE_SUBTREE,
                               sctx->expression, attrs, NULL,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return request_ldberror(sctx, ret);
    }

    ret = ldb_request(sctx->ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return request_ldberror(sctx, ret);
    }
}

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    struct tevent_req *req;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    if (ctx->mpg) {
        sctx->gen_conv_mpg_users = true;
        sctx->expression = talloc_asprintf(sctx, SYSDB_GRNAM_MPG_FILTER, name);
    } else {
        sctx->expression = talloc_asprintf(sctx, SYSDB_GRNAM_FILTER, name);
    }
    if (!sctx->expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    req = sysdb_operation_send(mem_ctx, ctx->ev, ctx);
    if (!req) {
        talloc_free(sctx);
        return ENOMEM;
    }

    tevent_req_set_callback(req, grp_search, sctx);

    return EOK;
}

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   gid_t gid,
                   sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    struct tevent_req *req;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    if (ctx->mpg) {
        sctx->gen_conv_mpg_users = true;
        sctx->expression = talloc_asprintf(sctx,
                                           SYSDB_GRGID_MPG_FILTER,
                                           (unsigned long int)gid);
    } else {
        sctx->expression = talloc_asprintf(sctx,
                                           SYSDB_GRGID_FILTER,
                                           (unsigned long int)gid);
    }
    if (!sctx->expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    req = sysdb_operation_send(mem_ctx, ctx->ev, ctx);
    if (!req) {
        talloc_free(sctx);
        return ENOMEM;
    }

    tevent_req_set_callback(req, grp_search, sctx);

    return EOK;
}

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    struct tevent_req *req;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    if (ctx->mpg) {
        sctx->gen_conv_mpg_users = true;
        sctx->expression = SYSDB_GRENT_MPG_FILTER;
    } else {
        sctx->expression = SYSDB_GRENT_FILTER;
    }

    req = sysdb_operation_send(mem_ctx, ctx->ev, ctx);
    if (!req) {
        talloc_free(sctx);
        return ENOMEM;
    }

    tevent_req_set_callback(req, grp_search, sctx);

    return EOK;
}

static void initgr_mem_search(struct sysdb_search_ctx *sctx)
{
    struct sysdb_ctx *ctx = sctx->ctx;
    struct ldb_result *res = sctx->res;
    struct ldb_request *req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *control;
    static const char *attrs[] = SYSDB_INITGR_ATTRS;
    int ret;

    if (res->count == 0) {
        return request_done(sctx);
    }
    if (res->count > 1) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    /* make sure we don't loop with get_gen_callback() */
    sctx->gen_aux_fn = NULL;

    sctx->expression = talloc_asprintf(sctx, SYSDB_INITGR_FILTER);
    if (!sctx->expression) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    ctrl = talloc_array(sctx, struct ldb_control *, 2);
    if (!ctrl) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    ctrl[1] = NULL;
    ctrl[0] = talloc(ctrl, struct ldb_control);
    if (!ctrl[0]) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    ctrl[0]->oid = LDB_CONTROL_ASQ_OID;
    ctrl[0]->critical = 1;
    control = talloc(ctrl[0], struct ldb_asq_control);
    if (!control) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    control->request = 1;
    control->source_attribute = talloc_strdup(control, SYSDB_INITGR_ATTR);
    if (!control->source_attribute) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    control->src_attr_len = strlen(control->source_attribute);
    ctrl[0]->data = control;

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               res->msgs[0]->dn,
                               LDB_SCOPE_BASE,
                               sctx->expression, attrs, ctrl,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return request_ldberror(sctx, ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return request_ldberror(sctx, ret);
    }
}

static void initgr_search(struct tevent_req *treq)
{
    struct sysdb_search_ctx *sctx;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_request *req;
    struct ldb_dn *base_dn;
    int ret;

    sctx = tevent_req_callback_data(treq, struct sysdb_search_ctx);

    ret = sysdb_operation_recv(treq, sctx, &sctx->handle);
    if (ret) {
        return request_error(sctx, ret);
    }

    sctx->gen_aux_fn = initgr_mem_search;

    base_dn = ldb_dn_new_fmt(sctx, sctx->ctx->ldb,
                             SYSDB_TMPL_USER_BASE, sctx->domain->name);
    if (!base_dn) {
        return request_error(sctx, ENOMEM);
    }

    ret = ldb_build_search_req(&req, sctx->ctx->ldb, sctx,
                               base_dn, LDB_SCOPE_SUBTREE,
                               sctx->expression, attrs, NULL,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return request_ldberror(sctx, ret);
    }

    ret = ldb_request(sctx->ctx->ldb, req);
    if (ret != LDB_SUCCESS) {
        return request_ldberror(sctx, ret);
    }
}

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *ctx,
                     struct sss_domain_info *domain,
                     const char *name,
                     sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    struct tevent_req *req;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    sctx->expression = talloc_asprintf(sctx, SYSDB_PWNAM_FILTER, name);
    if (!sctx->expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    req = sysdb_operation_send(mem_ctx, ctx->ev, ctx);
    if (!req) {
        talloc_free(sctx);
        return ENOMEM;
    }

    tevent_req_set_callback(req, initgr_search, sctx);

    return EOK;
}

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *ctx,
                        struct sss_domain_info *domain,
                        const char *name,
                        const char **attributes,
                        sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    struct tevent_req *req;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    sctx->expression = talloc_asprintf(sctx, SYSDB_PWNAM_FILTER, name);
    if (!sctx->expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    sctx->attrs = attributes;

    req = sysdb_operation_send(mem_ctx, ctx->ev, ctx);
    if (!req) {
        talloc_free(sctx);
        return ENOMEM;
    }

    tevent_req_set_callback(req, user_search, sctx);

    return EOK;
}
