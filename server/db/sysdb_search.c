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
    struct sysdb_ctx *ctx;
    struct sysdb_req *req;

    struct sss_domain_info *domain;

    const char *expression;

    sysdb_callback_t callback;
    void *ptr;

    gen_callback gen_aux_fn;

    struct get_mem_ctx *gmctx;

    struct ldb_result *res;

    const char **attrs;
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
    sysdb_operation_done(sctx->req);
    sctx->callback(sctx->ptr, sysdb_error_to_errno(error), NULL);
}

static void request_error(struct sysdb_search_ctx *sctx, int error)
{
    sysdb_operation_done(sctx->req);
    sctx->callback(sctx->ptr, error, NULL);
}

static void request_done(struct sysdb_search_ctx *sctx)
{
    sysdb_operation_done(sctx->req);
    sctx->callback(sctx->ptr, EOK, sctx->res);
}

static int get_gen_callback(struct ldb_request *req,
                            struct ldb_reply *rep)
{
    struct sysdb_search_ctx *sctx;
    struct ldb_result *res;
    int n;

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

static void user_search(struct sysdb_req *sysreq, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    struct ldb_request *req;
    struct ldb_dn *base_dn;
    int ret;

    sctx = talloc_get_type(ptr, struct sysdb_search_ctx);
    sctx->req = sysreq;

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

    return sysdb_operation(mem_ctx, ctx, user_search, sctx);
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

    return sysdb_operation(mem_ctx, ctx, user_search, sctx);
}

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    const char *expression,
                    sysdb_callback_t fn, void *ptr)
{
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct sysdb_search_ctx *sctx;

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

    return sysdb_operation(mem_ctx, ctx, user_search, sctx);
}

/* groups */

struct get_mem_ctx {
    struct sysdb_search_ctx *ret_sctx;
    struct ldb_message **grps;
    int num_grps;
};

static void get_members(struct sysdb_search_ctx *sctx)
{
    struct get_mem_ctx *gmctx;
    struct ldb_request *req;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    static const char *attrs[] = SYSDB_GRPW_ATTRS;
    int ret;

    gmctx = sctx->gmctx;

    if (gmctx->grps[0] == NULL) {
        return request_done(sctx);
    }

    /* fetch next group to search for members */
    gmctx->num_grps--;
    msg = gmctx->grps[gmctx->num_grps];
    gmctx->grps[gmctx->num_grps] = NULL;

    /* queue the group entry on the final result structure */
    sctx->res->msgs = talloc_realloc(sctx->res, sctx->res->msgs,
                                     struct ldb_message *,
                                     sctx->res->count + 2);
    if (!sctx->res->msgs) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    sctx->res->msgs[sctx->res->count + 1] = NULL;
    sctx->res->msgs[sctx->res->count] = talloc_steal(sctx->res->msgs, msg);
    sctx->res->count++;

    /* search for this group members */
    sctx->expression = talloc_asprintf(sctx, SYSDB_GRNA2_FILTER,
                                       ldb_dn_get_linearized(msg->dn));
    if (!sctx->expression) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    dn = ldb_dn_new_fmt(sctx, sctx->ctx->ldb,
                        SYSDB_TMPL_USER_BASE, sctx->domain->name);
    if (!dn) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    sctx->gen_aux_fn = get_members;

    ret = ldb_build_search_req(&req, sctx->ctx->ldb, sctx,
                               dn, LDB_SCOPE_SUBTREE,
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

static int get_grp_callback(struct ldb_request *req,
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

        if (sctx->domain->mpg) {
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

        /* no results, return */
        if (res->count == 0) {
            request_done(sctx);
            return LDB_SUCCESS;
        }

        if (sctx->domain->legacy) {
            request_done(sctx);
            return LDB_SUCCESS;
        }

        if (res->count > 0) {

            sctx->gmctx = talloc_zero(req, struct get_mem_ctx);
            if (!sctx->gmctx) {
                request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
                return LDB_ERR_OPERATIONS_ERROR;
            }
            sctx->gmctx->grps = res->msgs;
            sctx->gmctx->num_grps = res->count;
            res->msgs = NULL;
            res->count = 0;

            /* now get members */
            get_members(sctx);
            return LDB_SUCCESS;
        }

        /* anything else is an error */
        request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}

static void grp_search(struct sysdb_req *sysreq, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    struct ldb_request *req;
    struct ldb_dn *base_dn;
    int ret;

    sctx = talloc_get_type(ptr, struct sysdb_search_ctx);
    sctx->req = sysreq;

    if (sctx->domain->mpg) {
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
                               sctx, get_grp_callback,
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

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    if (domain->mpg) {
        sctx->expression = talloc_asprintf(sctx, SYSDB_GRNAM_MPG_FILTER, name);
    } else {
        sctx->expression = talloc_asprintf(sctx, SYSDB_GRNAM_FILTER, name);
    }
    if (!sctx->expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return sysdb_operation(mem_ctx, ctx, grp_search, sctx);
}

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   gid_t gid,
                   sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    if (domain->mpg) {
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

    return sysdb_operation(mem_ctx, ctx, grp_search, sctx);
}

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;

    if (!domain) {
        return EINVAL;
    }

    sctx = init_src_ctx(mem_ctx, domain, ctx, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    if (domain->mpg) {
        sctx->expression = SYSDB_GRENT_MPG_FILTER;
    } else {
        sctx->expression = SYSDB_GRENT_FILTER;
    }

    return sysdb_operation(mem_ctx, ctx, grp_search, sctx);
}

static void initgr_mem_legacy(struct sysdb_search_ctx *sctx)
{
    struct sysdb_ctx *ctx = sctx->ctx;
    struct ldb_result *res = sctx->res;
    struct ldb_request *req;
    struct ldb_dn *base_dn;
    static const char *attrs[] = SYSDB_INITGR_ATTRS;
    const char *userid;
    int ret;

    if (res->count == 0) {
        return request_done(sctx);
    }
    if (res->count > 1) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    /* make sure we don't loop with get_gen_callback() */
    sctx->gen_aux_fn = NULL;

    userid = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    if (!userid) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    sctx->expression = talloc_asprintf(sctx,
                                       SYSDB_INITGR_LEGACY_FILTER, userid);
    if (!sctx->expression) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    base_dn = ldb_dn_new_fmt(sctx, ctx->ldb,
                             SYSDB_TMPL_GROUP_BASE, sctx->domain->name);
    if (!base_dn) {
        return request_ldberror(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    ret = ldb_build_search_req(&req, ctx->ldb, sctx,
                               base_dn, LDB_SCOPE_SUBTREE,
                               sctx->expression, attrs, NULL,
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

static void initgr_search(struct sysdb_req *sysreq, void *ptr)
{
    struct sysdb_search_ctx *sctx;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_request *req;
    struct ldb_dn *base_dn;
    int ret;

    sctx = talloc_get_type(ptr, struct sysdb_search_ctx);
    sctx->req = sysreq;

    if (sctx->domain->legacy) {
        sctx->gen_aux_fn = initgr_mem_legacy;
    } else {
        sctx->gen_aux_fn = initgr_mem_search;
    }

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

    return sysdb_operation(mem_ctx, ctx, initgr_search, sctx);
}

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *ctx,
                        struct sss_domain_info *domain,
                        const char *name,
                        const char **attributes,
                        sysdb_callback_t fn, void *ptr)
{
    struct sysdb_search_ctx *sctx;

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

    return sysdb_operation(mem_ctx, ctx, user_search, sctx);
}
