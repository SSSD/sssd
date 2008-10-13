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

struct nss_ldb_search_ctx {
    struct ldb_context *ldb;
    nss_ldb_callback_t callback;
    void *ptr;
    struct ldb_result *res;
};

static int nss_ldb_error_to_errno(int lerr)
{
    /* fake it up for now, requires a mapping table */
    return EIO;
}

static int request_error(struct nss_ldb_search_ctx *sctx, int ldb_error)
{
    sctx->callback(sctx->ptr, nss_ldb_error_to_errno(ldb_error), sctx->res);
    return ldb_error;
}

static int request_done(struct nss_ldb_search_ctx *sctx)
{
    return sctx->callback(sctx->ptr, EOK, sctx->res);
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
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return request_error(sctx, ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
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
            return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
        }

        res->refs[n] = talloc_steal(res->refs, ares->referral);
        res->refs[n + 1] = NULL;
        break;

    case LDB_REPLY_DONE:
        res->controls = talloc_steal(res, ares->controls);

        /* this is the last message, and means the request is done */
        return request_done(sctx);
    }

    talloc_free(ares);
    return LDB_SUCCESS;
}

static struct nss_ldb_search_ctx *init_sctx(TALLOC_CTX *mem_ctx,
                                            struct ldb_context *ldb,
                                            nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;

    sctx = talloc(mem_ctx, struct nss_ldb_search_ctx);
    if (!sctx) {
        return NULL;
    }
    sctx->ldb = ldb;
    sctx->callback = fn;
    sctx->ptr = ptr;
    sctx->res = talloc_zero(sctx, struct ldb_result);
    if (!sctx->res) {
        talloc_free(sctx);
        return NULL;
    }

    return sctx;
}

static int pwd_search(struct nss_ldb_search_ctx *sctx,
                     struct ldb_context *ldb,
                     const char *expression)
{
    static const char *attrs[] = NSS_PW_ATTRS;
    struct ldb_request *req;
    int ret;

    ret = ldb_build_search_req(&req, ldb, sctx,
                               ldb_dn_new(sctx, ldb, NSS_USER_BASE),
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               sctx, get_gen_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    ret = ldb_request(ldb, req);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    return EOK;
}

int nss_ldb_getpwnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct ldb_context *ldb,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    char *expression;

    sctx = init_sctx(mem_ctx, ldb, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, NSS_PWNAM_FILTER, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return pwd_search(sctx, ldb, expression);
}

int nss_ldb_getpwuid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct ldb_context *ldb,
                     uint64_t uid,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    unsigned long long int filter_uid = uid;
    char *expression;

    sctx = init_sctx(mem_ctx, ldb, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, NSS_PWUID_FILTER, filter_uid);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return pwd_search(sctx, ldb, expression);
}

int nss_ldb_enumpwent(TALLOC_CTX *mem_ctx,
                      struct event_context *ev,
                      struct ldb_context *ldb,
                      nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;

    sctx = init_sctx(mem_ctx, ldb, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    return pwd_search(sctx, ldb, NSS_PWENT_FILTER);
}



static int get_grp_callback(struct ldb_request *req,
                            struct ldb_reply *ares)
{
    struct nss_ldb_search_ctx *sctx;
    struct ldb_result *res;
    int n;

    sctx = talloc_get_type(req->context, struct nss_ldb_search_ctx);
    res = sctx->res;

    if (!ares) {
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return request_error(sctx, ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
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
            return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
        }

        res->refs[n] = talloc_steal(res->refs, ares->referral);
        res->refs[n + 1] = NULL;
        break;

    case LDB_REPLY_DONE:
        res->controls = talloc_steal(res, ares->controls);

        /* no results, return */
        if (res->count == 0) {
            return request_done(sctx);
        }
        /* 1 result, let's search for members now and append results */
        if (res->count == 1) {
            static const char *attrs[] = NSS_GRPW_ATTRS;
            struct ldb_request *ureq;
            const char *expression;
            int ret;

            expression = talloc_asprintf(sctx, NSS_GRNA2_FILTER,
                                         ldb_dn_get_linearized(res->msgs[0]->dn));
            if (!expression) {
                return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
            }

            ret = ldb_build_search_req(&ureq, sctx->ldb, sctx,
                                       ldb_dn_new(sctx, sctx->ldb, NSS_USER_BASE),
                                       LDB_SCOPE_SUBTREE,
                                       expression, attrs, NULL,
                                       sctx, get_gen_callback,
                                       NULL);
            if (ret != LDB_SUCCESS) {
                return request_error(sctx, ret);
            }

            ret = ldb_request(sctx->ldb, ureq);
            if (ret != LDB_SUCCESS) {
                return request_error(sctx, ret);
            }

            return LDB_SUCCESS;
        }

        /* anything else is an error */
        return request_error(sctx, LDB_ERR_OPERATIONS_ERROR);
    }

    talloc_free(ares);
    return LDB_SUCCESS;
}

static int grp_search(struct nss_ldb_search_ctx *sctx,
                     struct ldb_context *ldb,
                     const char *expression)
{
    static const char *attrs[] = NSS_GRNAM_ATTRS;
    struct ldb_request *req;
    int ret;

    ret = ldb_build_search_req(&req, ldb, sctx,
                               ldb_dn_new(sctx, ldb, NSS_GROUP_BASE),
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               sctx, get_grp_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    ret = ldb_request(ldb, req);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    return EOK;
}

int nss_ldb_getgrnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct ldb_context *ldb,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    char *expression;

    sctx = init_sctx(mem_ctx, ldb, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, NSS_GRNAM_FILTER, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return grp_search(sctx, ldb, expression);
}

int nss_ldb_getgrgid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct ldb_context *ldb,
                     uint64_t gid,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    unsigned long long int filter_gid = gid;
    char *expression;

    sctx = init_sctx(mem_ctx, ldb, fn, ptr);
    if (!sctx) {
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, NSS_GRGID_FILTER, filter_gid);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    return grp_search(sctx, ldb, expression);
}


int nss_ldb_init(TALLOC_CTX *mem_ctx,
                 struct event_context *ev,
                 struct ldb_context **ldbp)
{
    struct ldb_context *ldb;
    int ret;

    ldb = ldb_init(mem_ctx, ev);
    if (!ldb) {
        return EIO;
    }

    ret = ldb_connect(ldb, NSS_LDB_PATH, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(ldb);
        return EIO;
    }

    *ldbp = ldb;

    return EOK;
}
