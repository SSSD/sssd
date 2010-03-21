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

/* users */

int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmpctx;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    if (!domain) {
        return EINVAL;
    }

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                             SYSDB_TMPL_USER_BASE, domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmpctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_PWNAM_FILTER, name);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmpctx);
    return ret;
}

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   uid_t uid,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmpctx;
    unsigned long int ul_uid = uid;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    if (!domain) {
        return EINVAL;
    }

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                             SYSDB_TMPL_USER_BASE, domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmpctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_PWUID_FILTER, ul_uid);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmpctx);
    return ret;
}

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    struct ldb_result **_res)
{
    TALLOC_CTX *tmpctx;
    static const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    if (!domain) {
        return EINVAL;
    }

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                             SYSDB_TMPL_USER_BASE, domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmpctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, SYSDB_PWENT_FILTER);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmpctx);
    return ret;
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

static int mpg_res_convert(struct ldb_result *res)
{
    int ret;
    int i;

    for (i = 0; i < res->count; i++) {
        ret = mpg_convert(res->msgs[i]);
        if (ret) {
            return ret;
        }
    }
    return EOK;
}

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmpctx;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *fmt_filter;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    if (!domain) {
        return EINVAL;
    }

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    if (ctx->mpg) {
        fmt_filter = SYSDB_GRNAM_MPG_FILTER;
        base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                                 SYSDB_DOM_BASE, domain->name);
    } else {
        fmt_filter = SYSDB_GRNAM_FILTER;
        base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                                 SYSDB_TMPL_GROUP_BASE, domain->name);
    }
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmpctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, fmt_filter, name);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmpctx);
    return ret;
}

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   gid_t gid,
                   struct ldb_result **_res)
{
    TALLOC_CTX *tmpctx;
    unsigned long int ul_gid = gid;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *fmt_filter;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    if (!domain) {
        return EINVAL;
    }

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    if (ctx->mpg) {
        fmt_filter = SYSDB_GRGID_MPG_FILTER;
        base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                                 SYSDB_DOM_BASE, domain->name);
    } else {
        fmt_filter = SYSDB_GRGID_FILTER;
        base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                                 SYSDB_TMPL_GROUP_BASE, domain->name);
    }
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmpctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, fmt_filter, ul_gid);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmpctx);
    return ret;
}

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    struct ldb_result **_res)
{
    TALLOC_CTX *tmpctx;
    static const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *fmt_filter;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    if (!domain) {
        return EINVAL;
    }

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    if (ctx->mpg) {
        fmt_filter = SYSDB_GRENT_MPG_FILTER;
        base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                                 SYSDB_DOM_BASE, domain->name);
    } else {
        fmt_filter = SYSDB_GRENT_FILTER;
        base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                                 SYSDB_TMPL_GROUP_BASE, domain->name);
    }
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmpctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, fmt_filter);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = mpg_res_convert(res);
    if (ret) {
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmpctx);
    return ret;
}

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *ctx,
                     struct sss_domain_info *domain,
                     const char *name,
                     struct ldb_result **_res)
{
    TALLOC_CTX *tmpctx;
    struct ldb_result *res;
    struct ldb_dn *user_dn;
    struct ldb_request *req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *control;
    static const char *attrs[] = SYSDB_INITGR_ATTRS;
    int ret;

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sysdb_getpwnam(tmpctx, ctx, domain, name, &res);
    if (ret != EOK) {
        goto done;
    }
    if (res->count != 1) {
        ret = EIO;
        goto done;
    }

    /* no need to steal the dn, we are not freeing the result */
    user_dn = res->msgs[0]->dn;

    /* note we count on the fact that the default search callback
     * will just keep appending values. This is by design and can't
     * change so it is ok to already have a result (from the getpwnam)
     * even before we call the next search */

    ctrl = talloc_array(tmpctx, struct ldb_control *, 2);
    if (!ctrl) {
        ret = ENOMEM;
        goto done;
    }
    ctrl[1] = NULL;
    ctrl[0] = talloc(ctrl, struct ldb_control);
    if (!ctrl[0]) {
        ret = ENOMEM;
        goto done;
    }
    ctrl[0]->oid = LDB_CONTROL_ASQ_OID;
    ctrl[0]->critical = 1;
    control = talloc(ctrl[0], struct ldb_asq_control);
    if (!control) {
        ret = ENOMEM;
        goto done;
    }
    control->request = 1;
    control->source_attribute = talloc_strdup(control, SYSDB_INITGR_ATTR);
    if (!control->source_attribute) {
        ret = ENOMEM;
        goto done;
    }
    control->src_attr_len = strlen(control->source_attribute);
    ctrl[0]->data = control;

    ret = ldb_build_search_req(&req, ctx->ldb, tmpctx,
                               user_dn, LDB_SCOPE_BASE,
                               SYSDB_INITGR_FILTER, attrs, ctrl,
                               res, ldb_search_default_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret == LDB_SUCCESS) {
        ret = ldb_wait(req->handle, LDB_WAIT_ALL);
    }
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmpctx);
    return ret;
}

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *ctx,
                        struct sss_domain_info *domain,
                        const char *name,
                        const char **attributes,
                        struct ldb_result **_res)
{
    TALLOC_CTX *tmpctx;
    struct ldb_dn *base_dn;
    struct ldb_result *res;
    int ret;

    if (!domain) {
        return EINVAL;
    }

    tmpctx = talloc_new(mem_ctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmpctx, ctx->ldb,
                             SYSDB_TMPL_USER_BASE, domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmpctx, &res, base_dn,
                     LDB_SCOPE_SUBTREE, attributes,
                     SYSDB_PWNAM_FILTER, name);
    if (ret) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);

done:
    talloc_zfree(tmpctx);
    return ret;
}
