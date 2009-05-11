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
#include "util/nss_sha512crypt.h"
#include <time.h>

struct sysdb_cb_ctx {
    sysdb_callback_t fn;
    void *pvt;

    bool ignore_not_found;
};

static int sysdb_ret_error(struct sysdb_cb_ctx *ctx, int ret, int lret)
{
    ctx->fn(ctx->pvt, ret, NULL);
    return lret;
};

static int sysdb_ret_done(struct sysdb_cb_ctx *ctx)
{
    ctx->fn(ctx->pvt, EOK, NULL);
    return LDB_SUCCESS;
};

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

static uint32_t get_attr_as_uint32(struct ldb_message *msg, const char *attr)
{
    const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr);
    long long int l;

    if (!v || !v->data) {
        return 0;
    }

    errno = 0;
    l = strtoll((const char *)v->data, NULL, 0);
    if (errno) {
        return (uint32_t)-1;
    }

    if (l < 0 || l > ((uint32_t)(-1))) {
        return (uint32_t)-1;
    }

    return l;
}

static int sysdb_op_callback(struct ldb_request *req, struct ldb_reply *rep)
{
    struct sysdb_cb_ctx *cbctx;
    int err;

    cbctx = talloc_get_type(req->context, struct sysdb_cb_ctx);

    if (!rep) {
        return sysdb_ret_error(cbctx, EIO, LDB_ERR_OPERATIONS_ERROR);
    }
    if (rep->error != LDB_SUCCESS) {
        if (! (cbctx->ignore_not_found &&
               rep->error == LDB_ERR_NO_SUCH_OBJECT)) {
            err = sysdb_error_to_errno(rep->error);
            return sysdb_ret_error(cbctx, err, rep->error);
        }
    }

    if (rep->type != LDB_REPLY_DONE) {
        sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
    }

    return sysdb_ret_done(cbctx);
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
    ret = ldb_msg_add_empty(msg, SYSDB_MEMBER,
                            LDB_FLAG_MOD_ADD, NULL);
    if (ret != LDB_SUCCESS) return ENOMEM;

    dn = ldb_dn_get_linearized(member_dn);
    if (!dn) return EINVAL;

    ret = ldb_msg_add_fmt(msg, SYSDB_MEMBER, "%s", dn);
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
    ret = ldb_msg_add_empty(msg, SYSDB_MEMBER,
                            LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) return ENOMEM;

    dn = ldb_dn_get_linearized(member_dn);
    if (!dn) return EINVAL;

    ret = ldb_msg_add_fmt(msg, SYSDB_MEMBER, "%s", dn);
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
    int ret, err;

    del_ctx = talloc_get_type(req->context, struct delete_ctx);
    ctx = sysdb_req_get_ctx(del_ctx->sysreq);
    cbctx = del_ctx->cbctx;
    res = del_ctx->res;

    if (!rep) {
        return sysdb_ret_error(cbctx, EIO, LDB_ERR_OPERATIONS_ERROR);
    }
    if (rep->error != LDB_SUCCESS) {
        err = sysdb_error_to_errno(rep->error);
        return sysdb_ret_error(cbctx, err, rep->error);
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:
        if (res->msgs != NULL) {
            DEBUG(1, ("More than one reply for a base search ?! "
                      "DB seems corrupted, aborting."));
            return sysdb_ret_error(cbctx, EFAULT, LDB_ERR_OPERATIONS_ERROR);
        }
        res->msgs = talloc_realloc(res, res->msgs, struct ldb_message *, 2);
        if (!res->msgs) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        res->msgs[0] = talloc_steal(res->msgs, rep->message);
        res->msgs[1] = NULL;
        res->count = 1;

        break;

    case LDB_REPLY_DONE:

        if (res->count == 0) {
            DEBUG(7, ("Base search returned no results\n"));
            return sysdb_ret_done(cbctx);
        }

        dn = ldb_dn_copy(del_ctx, res->msgs[0]->dn);
        if (!dn) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        talloc_free(res);
        del_ctx->res = res = NULL;

        ret = ldb_build_del_req(&delreq, ctx->ldb, cbctx, dn, NULL,
                                cbctx, sysdb_op_callback, NULL);
        if (ret == LDB_SUCCESS) {
            ret = ldb_request(ctx->ldb, delreq);
        }
        if (ret != LDB_SUCCESS) {
            err = sysdb_error_to_errno(ret);
            return sysdb_ret_error(cbctx, err, ret);
        }
        break;

    default:
        return sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}

int sysdb_delete_user_by_uid(struct sysdb_req *sysreq,
                             struct sss_domain_info *domain,
                             uid_t uid,
                             sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL };
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

    base_dn = ldb_dn_new_fmt(del_ctx, ctx->ldb,
                             SYSDB_TMPL_USER_BASE, domain->name);
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
                              struct sss_domain_info *domain,
                              gid_t gid,
                              sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL };
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

    base_dn = ldb_dn_new_fmt(del_ctx, ctx->ldb,
                             SYSDB_TMPL_GROUP_BASE, domain->name);
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

int sysdb_set_user_attr(struct sysdb_req *sysreq,
                        struct sss_domain_info *domain,
                        const char *name,
                        struct sysdb_attrs *attrs,
                        sysdb_callback_t fn, void *pvt)
{
    struct sysdb_ctx *ctx;
    struct sysdb_cb_ctx *cbctx;
    struct ldb_message *msg;
    struct ldb_request *req;
    int i, ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    if (attrs->num == 0) return EINVAL;

    ctx = sysdb_req_get_ctx(sysreq);

    cbctx = talloc_zero(sysreq, struct sysdb_cb_ctx);
    if (!cbctx) return ENOMEM;

    cbctx->fn = fn;
    cbctx->pvt = pvt;

    msg = ldb_msg_new(cbctx);
    if (!msg) return ENOMEM;

    msg->dn = sysdb_user_dn(ctx, msg, domain->name, name);
    if (!msg->dn) return ENOMEM;

    msg->elements = talloc_array(msg, struct ldb_message_element, attrs->num);
    if (!msg->elements) return ENOMEM;

    for (i = 0; i < attrs->num; i++) {
        msg->elements[i] = attrs->a[i];
        msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
    }

    msg->num_elements = attrs->num;

    ret = ldb_build_mod_req(&req, ctx->ldb, cbctx, msg, NULL,
                             cbctx, sysdb_op_callback, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_request(ctx->ldb, req);
    }
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    return EOK;
}

struct next_id {
    uint32_t id;
};

struct next_id_ctx {
    struct sysdb_req *sysreq;
    struct sss_domain_info *domain;
    struct sysdb_cb_ctx *cbctx;

    struct ldb_dn *base_dn;
	struct ldb_result *res;
    uint32_t tmp_id;

    enum next_step { NEXTID_SEARCH=0, NEXTID_VERIFY, NEXTID_STORE } step;

    struct next_id *result;
};

static int nextid_callback(struct ldb_request *req, struct ldb_reply *rep);

static int sysdb_get_next_available_id(struct sysdb_req *sysreq,
                                       struct sss_domain_info *domain,
                                       struct next_id *result,
                                       sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_NEXTID, NULL };
    struct sysdb_ctx *ctx;
    struct next_id_ctx *idctx;
    struct ldb_request *req;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    ctx = sysdb_req_get_ctx(sysreq);

    idctx = talloc_zero(sysreq, struct next_id_ctx);
    if (!idctx) return ENOMEM;

    idctx->sysreq = sysreq;
    idctx->domain = domain;
    idctx->result = result;

    idctx->cbctx = talloc_zero(sysreq, struct sysdb_cb_ctx);
    if (!idctx->cbctx) return ENOMEM;

    idctx->cbctx->fn = fn;
    idctx->cbctx->pvt = pvt;

    idctx->base_dn = sysdb_domain_dn(ctx, idctx, domain->name);
    if (!idctx->base_dn) return ENOMEM;

    idctx->res = talloc_zero(idctx, struct ldb_result);
    if (!idctx->res) return ENOMEM;

    ret = ldb_build_search_req(&req, ctx->ldb, idctx,
                               idctx->base_dn, LDB_SCOPE_BASE,
                               SYSDB_NEXTID_FILTER, attrs, NULL,
                               idctx, nextid_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

static int nextid_callback(struct ldb_request *req, struct ldb_reply *rep)
{
    static const char *attrs[] = { SYSDB_UIDNUM, SYSDB_GIDNUM, NULL };
    struct next_id_ctx *idctx;
    struct sysdb_cb_ctx *cbctx;
    struct sysdb_ctx *ctx;
    struct ldb_request *nreq;
    struct ldb_message *msg;
    struct ldb_result *res;
    char *filter;
    int ret, err;

    idctx = talloc_get_type(req->context, struct next_id_ctx);
    ctx = sysdb_req_get_ctx(idctx->sysreq);
    cbctx = idctx->cbctx;
    res = idctx->res;

    if (!rep) {
        return sysdb_ret_error(cbctx, EIO, LDB_ERR_OPERATIONS_ERROR);
    }
    if (rep->error != LDB_SUCCESS) {
        err = sysdb_error_to_errno(rep->error);
        return sysdb_ret_error(cbctx, err, rep->error);
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:

        if (idctx->step == NEXTID_VERIFY) {
            res->count++;
            break;
        }

        /* NEXTID_SEARCH */
        if (res->msgs != NULL) {
            DEBUG(1, ("More than one reply for a base search ?! "
                      "DB seems corrupted, aborting."));
            return sysdb_ret_error(cbctx, EFAULT, LDB_ERR_OPERATIONS_ERROR);
        }

        res->msgs = talloc_realloc(res, res->msgs, struct ldb_message *, 2);
        if (!res->msgs) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        res->msgs[0] = talloc_steal(res->msgs, rep->message);
        res->msgs[1] = NULL;
        res->count = 1;

        break;

    case LDB_REPLY_DONE:

        switch (idctx->step) {
        case NEXTID_SEARCH:
            if (res->count != 0) {
                idctx->tmp_id = get_attr_as_uint32(res->msgs[0], SYSDB_NEXTID);
                if (idctx->tmp_id == (uint32_t)(-1)) {
                    DEBUG(1, ("Invalid Next ID in domain %s\n",
                              idctx->domain->name));
                    return sysdb_ret_error(cbctx, ERANGE, LDB_ERR_OPERATIONS_ERROR);
                }
            } else {
                DEBUG(4, ("Base search returned no results, adding min id!\n"));
            }

            if (idctx->tmp_id < idctx->domain->id_min) {
                DEBUG(2, ("Initializing domain next id to id min %u\n",
                          idctx->domain->id_min));
                idctx->tmp_id = idctx->domain->id_min;
            }
            if ((idctx->domain->id_max != 0) &&
                (idctx->tmp_id > idctx->domain->id_max)) {
                DEBUG(0, ("Failed to allocate new id, out of range (%u/%u)\n",
                          idctx->tmp_id, idctx->domain->id_max));
                return sysdb_ret_error(cbctx, ERANGE, LDB_ERR_OPERATIONS_ERROR);
            }

            talloc_free(res->msgs);
            res->msgs = NULL;
            res->count = 0;

            idctx->step = NEXTID_VERIFY;
            break;

        case NEXTID_VERIFY:
            if (res->count) {
                /* actually something's using the id, try next */
                idctx->tmp_id++;
            } else {
                /* ok store new next_id */
                idctx->result->id = idctx->tmp_id;
                idctx->tmp_id++;
                idctx->step = NEXTID_STORE;
            }
            break;

        default:
            DEBUG(1, ("Invalid step, aborting.\n"));
            return sysdb_ret_error(cbctx, EFAULT, LDB_ERR_OPERATIONS_ERROR);
        }

        switch (idctx->step) {
        case NEXTID_VERIFY:
            filter = talloc_asprintf(idctx, "(|(%s=%u)(%s=%u))",
                                     SYSDB_UIDNUM, idctx->tmp_id,
                                     SYSDB_GIDNUM, idctx->tmp_id);
            if (!filter) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }
            ret = ldb_build_search_req(&nreq, ctx->ldb, idctx,
                                       idctx->base_dn, LDB_SCOPE_SUBTREE,
                                       filter, attrs, NULL,
                                       idctx, nextid_callback, NULL);
            break;

        case NEXTID_STORE:
            msg = ldb_msg_new(idctx);
            if (!msg) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }

            msg->dn = idctx->base_dn;

            ret = add_ulong(msg, LDB_FLAG_MOD_REPLACE,
                            SYSDB_NEXTID, idctx->tmp_id);
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }

            ret = ldb_build_mod_req(&nreq, ctx->ldb, idctx, msg, NULL,
                                    cbctx, sysdb_op_callback, NULL);
            break;

        default:
            DEBUG(1, ("Invalid step, aborting.\n"));
            return sysdb_ret_error(cbctx, EFAULT, LDB_ERR_OPERATIONS_ERROR);
        }

        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                      ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
            err = sysdb_error_to_errno(ret);
            return sysdb_ret_error(cbctx, err, ret);
        }

        ret = ldb_request(ctx->ldb, nreq);
        if (ret != LDB_SUCCESS) {
            err = sysdb_error_to_errno(ret);
            return sysdb_ret_error(cbctx, err, ret);
        }

        break;

    default:
        return sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}

static int check_name_callback(struct ldb_request *req, struct ldb_reply *rep);

int sysdb_check_name_unique(struct sysdb_req *sysreq,
                            struct sss_domain_info *domain,
                            TALLOC_CTX *mem_ctx, const char *name,
                            sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_NAME, NULL };
    struct sysdb_cb_ctx *cbctx;
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

    cbctx = talloc_zero(mem_ctx, struct sysdb_cb_ctx);
    if (!cbctx) return ENOMEM;

    cbctx->fn = fn;
    cbctx->pvt = pvt;

    base_dn = sysdb_domain_dn(ctx, cbctx, domain->name);
    if (!base_dn) return ENOMEM;

    filter = talloc_asprintf(cbctx, SYSDB_CHECK_FILTER, name);
    if (!filter) return ENOMEM;

    ret = ldb_build_search_req(&req, ctx->ldb, mem_ctx,
                               base_dn, LDB_SCOPE_SUBTREE,
                               filter, attrs, NULL,
                               cbctx, check_name_callback, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(ctx->ldb)));
        return sysdb_error_to_errno(ret);
    }

    ret = ldb_request(ctx->ldb, req);
    if (ret != LDB_SUCCESS) return sysdb_error_to_errno(ret);

    return EOK;
}

static int check_name_callback(struct ldb_request *req, struct ldb_reply *rep)
{
    struct sysdb_cb_ctx *cbctx;
    int err;

    cbctx = talloc_get_type(req->context, struct sysdb_cb_ctx);

    if (!rep) {
        return sysdb_ret_error(cbctx, EIO, LDB_ERR_OPERATIONS_ERROR);
    }
    if (rep->error != LDB_SUCCESS) {
        err = sysdb_error_to_errno(rep->error);
        return sysdb_ret_error(cbctx, err, rep->error);
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:

        /* one found, that means name is not available */
        /* return EEXIST */
        return sysdb_ret_error(cbctx, EEXIST, LDB_ERR_ENTRY_ALREADY_EXISTS);

    case LDB_REPLY_DONE:

        return sysdb_ret_done(cbctx);

    default:
        return sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
    }

    return LDB_SUCCESS;
}


struct user_add_ctx {
    struct sysdb_req *sysreq;
    struct sysdb_cb_ctx *cbctx;
    struct sss_domain_info *domain;

    const char *name;
    uid_t uid;
    gid_t gid;
    const char *fullname;
    const char *homedir;
    const char *shell;

    struct next_id id;
};

static void user_check_callback(void *pvt, int error, struct ldb_result *res);
static int user_add_id(struct user_add_ctx *user_ctx);
static void user_add_id_callback(void *pvt, int error, struct ldb_result *res);
static int user_add_call(struct user_add_ctx *user_ctx);

int sysdb_add_user(struct sysdb_req *sysreq,
                   struct sss_domain_info *domain,
                   const char *name,
                   uid_t uid, gid_t gid, const char *fullname,
                   const char *homedir, const char *shell,
                   sysdb_callback_t fn, void *pvt)
{
    struct user_add_ctx *user_ctx;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    if ((uid == 0 || gid == 0) && (uid != 0 || gid != 0)) {
        /* you either set both or neither, we will not guess only one */
        DEBUG(1, ("You have to either specify both uid and gid or neither"
                  " (preferred) [passed in uid=%u, gid =%u]\n", uid, gid));
        return EINVAL;
    }

    if (domain->id_max != 0 && uid != 0 &&
        (uid < domain->id_min || uid > domain->id_max)) {
        DEBUG(2, ("Supplied uid [%d] is not in the allowed range [%d-%d].\n",
                  uid, domain->id_min, domain->id_max));
        return EINVAL;
    }

    if (domain->id_max != 0 && gid != 0 &&
        (gid < domain->id_min || gid > domain->id_max)) {
        DEBUG(2, ("Supplied gid [%d] is not in the allowed range [%d-%d].\n",
                  gid, domain->id_min, domain->id_max));
        return EINVAL;
    }


    user_ctx = talloc(sysreq, struct user_add_ctx);
    if (!user_ctx) return ENOMEM;

    user_ctx->cbctx = talloc_zero(user_ctx, struct sysdb_cb_ctx);
    if (!user_ctx->cbctx) return ENOMEM;

    user_ctx->sysreq = sysreq;
    user_ctx->domain = domain;
    user_ctx->cbctx->fn = fn;
    user_ctx->cbctx->pvt = pvt;
    user_ctx->name = name;
    user_ctx->uid = uid;
    user_ctx->gid = gid;
    user_ctx->fullname = fullname;
    user_ctx->homedir = homedir;
    user_ctx->shell = shell;

    if (domain->mpg) {
        /* if the domain is mpg we need to check we do not have there are no
         * name conflicts */

        return sysdb_check_name_unique(sysreq, domain, user_ctx, name,
                                       user_check_callback, user_ctx);
    }

    return user_add_id(user_ctx);
}

static void user_check_callback(void *pvt, int error, struct ldb_result *res)
{
    struct user_add_ctx *user_ctx;
    int ret;

    user_ctx = talloc_get_type(pvt, struct user_add_ctx);
    if (error != EOK) {
        sysdb_ret_error(user_ctx->cbctx, error, LDB_ERR_OPERATIONS_ERROR);
        return;
    }

    ret = user_add_id(user_ctx);
    if (ret != EOK) {
        sysdb_ret_error(user_ctx->cbctx, ret, LDB_ERR_OPERATIONS_ERROR);
    }
}

static int user_add_id(struct user_add_ctx *user_ctx)
{
    if (user_ctx->uid == 0 && user_ctx->gid == 0) {
        /* Must generate uid/gid pair */
        return sysdb_get_next_available_id(user_ctx->sysreq,
                                           user_ctx->domain,
                                           &(user_ctx->id),
                                           user_add_id_callback, user_ctx);
    }

    return user_add_call(user_ctx);
}

static void user_add_id_callback(void *pvt, int error, struct ldb_result *res)
{
    struct user_add_ctx *user_ctx;
    int ret;

    user_ctx = talloc_get_type(pvt, struct user_add_ctx);
    if (error != EOK) {
        sysdb_ret_error(user_ctx->cbctx, error, LDB_ERR_OPERATIONS_ERROR);
        return;
    }

    /* ok id has been allocated, fill in uid and gid fields */
    user_ctx->uid = user_ctx->id.id;
    user_ctx->gid = user_ctx->id.id;

    ret = user_add_call(user_ctx);
    if (ret != EOK) {
        sysdb_ret_error(user_ctx->cbctx, ret, LDB_ERR_OPERATIONS_ERROR);
    }
}

static int user_add_call(struct user_add_ctx *user_ctx)
{
    struct sysdb_ctx *ctx;
    struct ldb_message *msg;
    struct ldb_request *req;
    int flags = LDB_FLAG_MOD_ADD;
    int ret;

    ctx = sysdb_req_get_ctx(user_ctx->sysreq);

    msg = ldb_msg_new(user_ctx);
    if (!msg) return ENOMEM;

    msg->dn = sysdb_user_dn(ctx, msg, user_ctx->domain->name, user_ctx->name);
    if (!msg->dn) return ENOMEM;

    ret = add_string(msg, flags, "objectClass", SYSDB_USER_CLASS);
    if (ret != LDB_SUCCESS) return ENOMEM;

    ret = add_string(msg, flags, SYSDB_NAME, user_ctx->name);
    if (ret != LDB_SUCCESS) return ENOMEM;

    if (user_ctx->uid) {
        ret = add_ulong(msg, flags, SYSDB_UIDNUM,
                                    (unsigned long)(user_ctx->uid));
        if (ret != LDB_SUCCESS) return ENOMEM;
    } else {
        DEBUG(0, ("Cached users can't have UID == 0\n"));
        return EINVAL;
    }

    if (user_ctx->gid) {
        ret = add_ulong(msg, flags, SYSDB_GIDNUM,
                                    (unsigned long)(user_ctx->gid));
        if (ret != LDB_SUCCESS) return ENOMEM;
    } else {
        DEBUG(0, ("Cached users can't have GID == 0\n"));
        return EINVAL;
    }

    /* We set gecos to be the same as fullname on user creation,
     * But we will not enforce coherency after that, it's up to
     * admins to decide if they want to keep it in sync if they change
     * one of the 2 */
    if (user_ctx->fullname && *user_ctx->fullname) {
        ret = add_string(msg, flags, SYSDB_FULLNAME, user_ctx->fullname);
        if (ret != LDB_SUCCESS) return ENOMEM;
        ret = add_string(msg, flags, SYSDB_GECOS, user_ctx->fullname);
        if (ret != LDB_SUCCESS) return ENOMEM;
    }

    if (user_ctx->homedir && *user_ctx->homedir) {
        ret = add_string(msg, flags, SYSDB_HOMEDIR, user_ctx->homedir);
        if (ret != LDB_SUCCESS) return ENOMEM;
    }

    if (user_ctx->shell && *user_ctx->shell) {
        ret = add_string(msg, flags, SYSDB_SHELL, user_ctx->shell);
        if (ret != LDB_SUCCESS) return ENOMEM;
    }

    /* creation time */
    ret = add_ulong(msg, flags, SYSDB_CREATE_TIME, (unsigned long)time(NULL));
    if (ret != LDB_SUCCESS) return ENOMEM;

    ret = ldb_build_add_req(&req, ctx->ldb, user_ctx, msg, NULL,
                            user_ctx->cbctx, sysdb_op_callback, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_request(ctx->ldb, req);
    }
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    return EOK;
}

struct group_add_ctx {
    struct sysdb_req *sysreq;
    struct sysdb_cb_ctx *cbctx;
    struct sss_domain_info *domain;

    const char *name;
    gid_t gid;

    struct next_id id;
};

static void group_check_callback(void *pvt, int error, struct ldb_result *res);
static int group_add_id(struct group_add_ctx *group_ctx);
static void group_add_id_callback(void *pvt, int error, struct ldb_result *res);
static int group_add_call(struct group_add_ctx *group_ctx);

int sysdb_add_group(struct sysdb_req *sysreq,
                    struct sss_domain_info *domain,
                    const char *name, gid_t gid,
                    sysdb_callback_t fn, void *pvt)
{
    struct group_add_ctx *group_ctx;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    if (domain->id_max != 0 && gid != 0 &&
        (gid < domain->id_min || gid > domain->id_max)) {
        DEBUG(2, ("Supplied gid [%d] is not in the allowed range [%d-%d].\n",
                  gid, domain->id_min, domain->id_max));
        return EINVAL;
    }

    group_ctx = talloc(sysreq, struct group_add_ctx);
    if (!group_ctx) return ENOMEM;

    group_ctx->cbctx = talloc_zero(group_ctx, struct sysdb_cb_ctx);
    if (!group_ctx->cbctx) return ENOMEM;

    group_ctx->sysreq = sysreq;
    group_ctx->domain = domain;
    group_ctx->cbctx->fn = fn;
    group_ctx->cbctx->pvt = pvt;
    group_ctx->name = name;
    group_ctx->gid = gid;

    if (domain->mpg) {
        /* if the domain is mpg we need to check we do not have there are no
         * name conflicts */

        return sysdb_check_name_unique(sysreq, domain, group_ctx, name,
                                       group_check_callback, group_ctx);
    }

    return group_add_id(group_ctx);
}

static void group_check_callback(void *pvt, int error, struct ldb_result *res)
{
    struct group_add_ctx *group_ctx;
    int ret;

    group_ctx = talloc_get_type(pvt, struct group_add_ctx);
    if (error != EOK) {
        sysdb_ret_error(group_ctx->cbctx, error, LDB_ERR_OPERATIONS_ERROR);
        return;
    }

    ret = group_add_id(group_ctx);
    if (ret != EOK) {
        sysdb_ret_error(group_ctx->cbctx, ret, LDB_ERR_OPERATIONS_ERROR);
    }
}

static int group_add_id(struct group_add_ctx *group_ctx)
{
    if (group_ctx->gid == 0) {
        /* Must generate uid/gid pair */
        return sysdb_get_next_available_id(group_ctx->sysreq,
                                           group_ctx->domain,
                                           &(group_ctx->id),
                                           group_add_id_callback, group_ctx);
    }

    return group_add_call(group_ctx);
}

static void group_add_id_callback(void *pvt, int error, struct ldb_result *res)
{
    struct group_add_ctx *group_ctx;
    int ret;

    group_ctx = talloc_get_type(pvt, struct group_add_ctx);
    if (error != EOK) {
        sysdb_ret_error(group_ctx->cbctx, error, LDB_ERR_OPERATIONS_ERROR);
        return;
    }

    /* ok id has been allocated, fill in uid and gid fields */
    group_ctx->gid = group_ctx->id.id;

    ret = group_add_call(group_ctx);
    if (ret != EOK) {
        sysdb_ret_error(group_ctx->cbctx, ret, LDB_ERR_OPERATIONS_ERROR);
    }
}

static int group_add_call(struct group_add_ctx *group_ctx)
{
    struct sysdb_ctx *ctx;
    struct ldb_message *msg;
    struct ldb_request *req;
    int flags = LDB_FLAG_MOD_ADD;
    int ret;

    ctx = sysdb_req_get_ctx(group_ctx->sysreq);

    msg = ldb_msg_new(group_ctx);
    if (!msg) return ENOMEM;

    msg->dn = sysdb_group_dn(ctx, msg, group_ctx->domain->name, group_ctx->name);
    if (!msg->dn) return ENOMEM;

    ret = add_string(msg, flags, "objectClass", SYSDB_GROUP_CLASS);
    if (ret != LDB_SUCCESS) return ENOMEM;

    ret = add_string(msg, flags, SYSDB_NAME, group_ctx->name);
    if (ret != LDB_SUCCESS) return ENOMEM;

    if (group_ctx->gid) {
        ret = add_ulong(msg, flags, SYSDB_GIDNUM,
                                    (unsigned long)(group_ctx->gid));
        if (ret != LDB_SUCCESS) return ENOMEM;
    } else {
        DEBUG(0, ("Cached groups can't have GID == 0\n"));
        return EINVAL;
    }

    /* creation time */
    ret = add_ulong(msg, flags, SYSDB_CREATE_TIME, (unsigned long)time(NULL));
    if (ret != LDB_SUCCESS) return ENOMEM;

    ret = ldb_build_add_req(&req, ctx->ldb, group_ctx, msg, NULL,
                            group_ctx->cbctx, sysdb_op_callback, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_request(ctx->ldb, req);
    }
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

    return EOK;
}

/* This function is not safe, but is included for completeness
 * It is much better to allow SSSD to internally manage the
 * group GID values. sysdb_set_group_gid() will perform no
 * validation that the new GID is unused. The only check it
 * will perform is whether the requested GID is in the range
 * of IDs allocated for the domain.
 */
int sysdb_set_group_gid(struct sysdb_req *sysreq,
                        struct sss_domain_info *domain,
                        const char *name, gid_t gid,
                        sysdb_callback_t fn, void *pvt)
{
    struct group_add_ctx *group_ctx;
    struct sysdb_ctx *sysdb;
    struct ldb_message *msg;
    struct ldb_request *req;
    int flags = LDB_FLAG_MOD_REPLACE;
    int ret;

    if (!sysdb_req_check_running(sysreq)) {
        DEBUG(2, ("Invalid request! Not running at this time.\n"));
        return EINVAL;
    }

    /* Validate that the target GID is within the domain range */
    if((gid < domain->id_min) ||
       (domain->id_max && (gid > domain->id_max))) {
        DEBUG(2, ("Invalid request. Domain ID out of range"));
        return EDOM;
    }

    group_ctx = talloc(sysreq, struct group_add_ctx);
    if (!group_ctx) return ENOMEM;

    group_ctx->cbctx = talloc_zero(group_ctx, struct sysdb_cb_ctx);
    if (!group_ctx->cbctx) return ENOMEM;

    group_ctx->sysreq = sysreq;
    group_ctx->domain = domain;
    group_ctx->cbctx->fn = fn;
    group_ctx->cbctx->pvt = pvt;
    group_ctx->name = name;
    group_ctx->gid = gid;

    sysdb = sysdb_req_get_ctx(group_ctx->sysreq);

    msg = ldb_msg_new(group_ctx);
    if (!msg) return ENOMEM;

    msg->dn = sysdb_group_dn(sysdb, msg,
                             group_ctx->domain->name,
                             group_ctx->name);
    if (!msg->dn) return ENOMEM;

    ret = add_ulong(msg, flags, SYSDB_GIDNUM,
                    (unsigned long)(group_ctx->gid));

    ret = ldb_build_mod_req(&req, sysdb->ldb, group_ctx, msg, NULL,
                            group_ctx->cbctx, sysdb_op_callback, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_request(sysdb->ldb, req);
    }
    if (ret != LDB_SUCCESS) {
        return sysdb_error_to_errno(ret);
    }

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
    struct sss_domain_info *domain;

    struct ldb_dn *dn;

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
                            struct sss_domain_info *domain,
                            const char *name, const char *pwd,
                            uid_t uid, gid_t gid, const char *gecos,
                            const char *homedir, const char *shell,
                            sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_NAME, NULL };
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

    user_ctx->dn = sysdb_user_dn(ctx, user_ctx, domain->name, name);
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
    int ret, err;

    user_ctx = talloc_get_type(req->context, struct legacy_user_ctx);
    ctx = sysdb_req_get_ctx(user_ctx->sysreq);
    cbctx = user_ctx->cbctx;
    res = user_ctx->res;

    if (!rep) {
        return sysdb_ret_error(cbctx, EIO, LDB_ERR_OPERATIONS_ERROR);
    }
    if (rep->error != LDB_SUCCESS) {
        err = sysdb_error_to_errno(rep->error);
        return sysdb_ret_error(cbctx, err, rep->error);
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        res->msgs[res->count + 1] = NULL;

        res->msgs[res->count] = talloc_steal(res->msgs, rep->message);
        res->count++;

        break;

    case LDB_REPLY_DONE:

        msg = ldb_msg_new(cbctx);
        if (!msg) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
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

            return sysdb_ret_error(cbctx, EFAULT, LDB_ERR_OPERATIONS_ERROR);
        }

        talloc_free(res);
        user_ctx->res = res = NULL;

        if (flags == LDB_FLAG_MOD_ADD) {
            ret = add_string(msg, flags, "objectClass", SYSDB_USER_CLASS);
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }

            ret = add_string(msg, flags, SYSDB_NAME, user_ctx->name);
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }
        }

        if (user_ctx->domain->legacy_passwords &&
            user_ctx->pwd && *user_ctx->pwd) {
            ret = add_string(msg, flags, SYSDB_PWD, user_ctx->pwd);
        } else {
            ret = ldb_msg_add_empty(msg, SYSDB_PWD,
                                    LDB_FLAG_MOD_DELETE, NULL);
        }
        if (ret != LDB_SUCCESS) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        if (user_ctx->uid) {
            ret = add_ulong(msg, flags, SYSDB_UIDNUM,
                                        (unsigned long)(user_ctx->uid));
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }
        } else {
            DEBUG(0, ("Cached users can't have UID == 0\n"));
            return sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
        }

        if (user_ctx->gid) {
            ret = add_ulong(msg, flags, SYSDB_GIDNUM,
                                        (unsigned long)(user_ctx->gid));
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }
        } else {
            DEBUG(0, ("Cached users can't have GID == 0\n"));
            return sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
        }

        if (user_ctx->gecos && *user_ctx->gecos) {
            ret = add_string(msg, flags, SYSDB_GECOS, user_ctx->gecos);
        } else {
            ret = ldb_msg_add_empty(msg, SYSDB_GECOS,
                                     LDB_FLAG_MOD_DELETE, NULL);
        }
        if (ret != LDB_SUCCESS) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        if (user_ctx->homedir && *user_ctx->homedir) {
            ret = add_string(msg, flags, SYSDB_HOMEDIR, user_ctx->homedir);
        } else {
            ret = ldb_msg_add_empty(msg, SYSDB_HOMEDIR,
                                     LDB_FLAG_MOD_DELETE, NULL);
        }
        if (ret != LDB_SUCCESS) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        if (user_ctx->shell && *user_ctx->shell) {
            ret = add_string(msg, flags, SYSDB_SHELL, user_ctx->shell);
        } else {
            ret = ldb_msg_add_empty(msg, SYSDB_SHELL,
                                     LDB_FLAG_MOD_DELETE, NULL);
        }
        if (ret != LDB_SUCCESS) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        /* modification time */
        ret = add_ulong(msg, flags, SYSDB_LAST_UPDATE,
                                    (unsigned long)time(NULL));
        if (ret != LDB_SUCCESS) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
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
            err = sysdb_error_to_errno(ret);
            return sysdb_ret_error(cbctx, err, ret);
        }
        break;

    default:
        return sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}



/* this function does not check that all user members are actually present */

struct legacy_group_ctx {
    struct sysdb_req *sysreq;
    struct sysdb_cb_ctx *cbctx;
    struct sss_domain_info *domain;

    struct ldb_dn *dn;

    const char *name;
    gid_t gid;
    const char **members;

	struct ldb_result *res;
};

static int legacy_group_callback(struct ldb_request *req,
                                 struct ldb_reply *rep);

int sysdb_legacy_store_group(struct sysdb_req *sysreq,
                             struct sss_domain_info *domain,
                             const char *name, gid_t gid,
                             const char **members,
                             sysdb_callback_t fn, void *pvt)
{
    static const char *attrs[] = { SYSDB_NAME, NULL };
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

    group_ctx->dn = sysdb_group_dn(ctx, group_ctx, domain->name, name);
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
    int i, ret, err;

    group_ctx = talloc_get_type(req->context, struct legacy_group_ctx);
    ctx = sysdb_req_get_ctx(group_ctx->sysreq);
    cbctx = group_ctx->cbctx;
    res = group_ctx->res;

    if (!rep) {
        return sysdb_ret_error(cbctx, EIO, LDB_ERR_OPERATIONS_ERROR);
    }
    if (rep->error != LDB_SUCCESS) {
        err = sysdb_error_to_errno(rep->error);
        return sysdb_ret_error(cbctx, err, rep->error);
    }

    switch (rep->type) {
    case LDB_REPLY_ENTRY:
        res->msgs = talloc_realloc(res, res->msgs,
                                   struct ldb_message *,
                                   res->count + 2);
        if (!res->msgs) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
        }

        res->msgs[res->count + 1] = NULL;

        res->msgs[res->count] = talloc_steal(res->msgs, rep->message);
        res->count++;

        break;

    case LDB_REPLY_DONE:

        msg = ldb_msg_new(cbctx);
        if (!msg) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
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

            return sysdb_ret_error(cbctx, EFAULT, LDB_ERR_OPERATIONS_ERROR);
        }

        talloc_free(res);
        group_ctx->res = res = NULL;

        if (flags == LDB_FLAG_MOD_ADD) {
            ret = add_string(msg, flags, "objectClass", SYSDB_GROUP_CLASS);
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }

            ret = add_string(msg, flags, SYSDB_NAME, group_ctx->name);
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }
        }

        if (group_ctx->gid) {
            ret = add_ulong(msg, flags, SYSDB_GIDNUM,
                                        (unsigned long)(group_ctx->gid));
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }
        } else {
            DEBUG(0, ("Cached groups can't have GID == 0\n"));
            return sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
        }

        /* members */
        if (group_ctx->members && group_ctx->members[0]) {
            ret = ldb_msg_add_empty(msg, SYSDB_LEGACY_MEMBER, flags, NULL);
            if (ret != LDB_SUCCESS) {
                return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
            }
            for (i = 0; group_ctx->members[i]; i++) {
                ret = ldb_msg_add_string(msg, SYSDB_LEGACY_MEMBER,
                                              group_ctx->members[i]);
                if (ret != LDB_SUCCESS) {
                    return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
                }
            }
        }

        /* modification time */
        ret = add_ulong(msg, flags, SYSDB_LAST_UPDATE,
                                    (unsigned long)time(NULL));
        if (ret != LDB_SUCCESS) {
            return sysdb_ret_error(cbctx, ENOMEM, LDB_ERR_OPERATIONS_ERROR);
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
            err = sysdb_error_to_errno(ret);
            return sysdb_ret_error(cbctx, err, ret);
        }
        break;

    default:
        return sysdb_ret_error(cbctx, EINVAL, LDB_ERR_OPERATIONS_ERROR);
    }

    talloc_free(rep);
    return LDB_SUCCESS;
}

int sysdb_legacy_add_group_member(struct sysdb_req *sysreq,
                                  struct sss_domain_info *domain,
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

    msg->dn = sysdb_group_dn(ctx, cbctx, domain->name, group);
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
                                     struct sss_domain_info *domain,
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

    msg->dn = sysdb_group_dn(ctx, cbctx, domain->name, group);
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

int sysdb_set_cached_password(struct sysdb_req *sysreq,
                              struct sss_domain_info *domain,
                              const char *user,
                              const char *password,
                              sysdb_callback_t fn, void *pvt)
{
    struct sysdb_ctx *ctx;
    struct sysdb_attrs *attrs;
    char *hash = NULL;
    char *salt;
    int ret;

    ctx = sysdb_req_get_ctx(sysreq);
    if (!ctx) return EFAULT;

    ret = s3crypt_gen_salt(sysreq, &salt);
    if (ret) {
        DEBUG(4, ("Failed to generate random salt.\n"));
        return ret;
    }

    ret = s3crypt_sha512(sysreq, password, salt, &hash);
    if (ret) {
        DEBUG(4, ("Failed to create password hash.\n"));
        return ret;
    }

    attrs = sysdb_new_attrs(sysreq);
    if (!attrs) {
        return ENOMEM;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_CACHEDPWD, hash);
    if (ret) return ret;

    /* FIXME: should we use a different attribute for chache passwords ?? */
    ret = sysdb_attrs_add_long(attrs, "lastCachedPasswordChange",
                               (long)time(NULL));
    if (ret) return ret;

    ret = sysdb_set_user_attr(sysreq, domain, user, attrs, fn, pvt);
    if (ret) return ret;

    return EOK;
}
