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
    sctx->callback(sctx->ptr, ldb_error, sctx->res);
    return ldb_error;
}

static int request_done(struct nss_ldb_search_ctx *sctx)
{
    return sctx->callback(sctx->ptr, LDB_SUCCESS, sctx->res);
}

static int getpw_callback(struct ldb_request *req,
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

int nss_ldb_getpwnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct ldb_context *ldb,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    struct ldb_request *req;
    static const char *attrs[] = NSS_PW_ATTRS;
    char *expression;
    int ret;

    sctx = talloc(mem_ctx, struct nss_ldb_search_ctx);
    if (!sctx) {
        return ENOMEM;
    }
    sctx->callback = fn;
    sctx->ptr = ptr;
    sctx->res = talloc_zero(sctx, struct ldb_result);
    if (!sctx->res) {
        talloc_free(sctx);
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, NSS_PWNAM_FILTER, name);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    ret = ldb_build_search_req(&req, ldb, sctx,
                               ldb_dn_new(sctx, ldb, NSS_USER_BASE),
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               sctx, getpw_callback,
                               NULL);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);;
    }

    ret = ldb_request(ldb, req);
    if (ret != LDB_SUCCESS) {
        return nss_ldb_error_to_errno(ret);
    }

    return EOK;
}

int nss_ldb_getpwuid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct ldb_context *ldb,
                     uint64_t uid,
                     nss_ldb_callback_t fn, void *ptr)
{
    struct nss_ldb_search_ctx *sctx;
    struct ldb_request *req;
    static const char *attrs[] = NSS_PW_ATTRS;
    unsigned long long int filter_uid = uid;
    char *expression;
    int ret;

    sctx = talloc(mem_ctx, struct nss_ldb_search_ctx);
    if (!sctx) {
        return ENOMEM;
    }
    sctx->callback = fn;
    sctx->ptr = ptr;
    sctx->res = talloc_zero(sctx, struct ldb_result);
    if (!sctx->res) {
        talloc_free(sctx);
        return ENOMEM;
    }

    expression = talloc_asprintf(sctx, NSS_PWUID_FILTER, filter_uid);
    if (!expression) {
        talloc_free(sctx);
        return ENOMEM;
    }

    ret = ldb_build_search_req(&req, ldb, sctx,
                               ldb_dn_new(sctx, ldb, NSS_USER_BASE),
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               sctx, getpw_callback,
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
