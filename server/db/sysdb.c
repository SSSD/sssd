/*
   SSSD

   System Database

   Copyright (C) Simo Sorce <ssorce@redhat.com> 2008

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


struct ldb_dn *sysdb_custom_subtree_dn(struct sysdb_ctx *ctx, void *memctx,
                                       const char *domain,
                                       const char *subtree_name)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                          subtree_name, domain);
}
struct ldb_dn *sysdb_custom_dn(struct sysdb_ctx *ctx, void *memctx,
                                const char *domain, const char *object_name,
                                const char *subtree_name)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_TMPL_CUSTOM, object_name,
                          subtree_name, domain);
}

struct ldb_dn *sysdb_user_dn(struct sysdb_ctx *ctx, void *memctx,
                             const char *domain, const char *name)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_TMPL_USER, name, domain);
}

struct ldb_dn *sysdb_group_dn(struct sysdb_ctx *ctx, void *memctx,
                              const char *domain, const char *name)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_TMPL_GROUP, name, domain);
}

struct ldb_dn *sysdb_domain_dn(struct sysdb_ctx *ctx, void *memctx,
                              const char *domain)
{
    return ldb_dn_new_fmt(memctx, ctx->ldb, SYSDB_DOM_BASE, domain);
}

struct ldb_context *sysdb_ctx_get_ldb(struct sysdb_ctx *ctx)
{
    return ctx->ldb;
}

struct ldb_context *sysdb_handle_get_ldb(struct sysdb_handle *handle)
{
    return handle->ctx->ldb;
}

struct sysdb_attrs *sysdb_new_attrs(TALLOC_CTX *memctx)
{
    return talloc_zero(memctx, struct sysdb_attrs);
}

static int sysdb_attrs_get_el_int(struct sysdb_attrs *attrs, const char *name,
                                  bool alloc, struct ldb_message_element **el)
{
    struct ldb_message_element *e = NULL;
    int i;

    for (i = 0; i < attrs->num; i++) {
        if (strcasecmp(name, attrs->a[i].name) == 0)
            e = &(attrs->a[i]);
    }

    if (!e && alloc) {
        e = talloc_realloc(attrs, attrs->a,
                           struct ldb_message_element, attrs->num+1);
        if (!e) return ENOMEM;
        attrs->a = e;

        e[attrs->num].name = talloc_strdup(e, name);
        if (!e[attrs->num].name) return ENOMEM;

        e[attrs->num].num_values = 0;
        e[attrs->num].values = NULL;
        e[attrs->num].flags = 0;

        e = &(attrs->a[attrs->num]);
        attrs->num++;
    }

    if (!e) {
        return ENOENT;
    }

    *el = e;

    return EOK;
}

int sysdb_attrs_get_el(struct sysdb_attrs *attrs, const char *name,
                       struct ldb_message_element **el)
{
    return sysdb_attrs_get_el_int(attrs, name, true, el);
}

int sysdb_attrs_get_string(struct sysdb_attrs *attrs, const char *name,
                           const char **string)
{
    struct ldb_message_element *el;
    int ret;

    ret = sysdb_attrs_get_el_int(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    if (el->num_values != 1) {
        return ERANGE;
    }

    *string = (const char *)el->values[0].data;
    return EOK;
}

int sysdb_attrs_add_val(struct sysdb_attrs *attrs,
                        const char *name, const struct ldb_val *val)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int ret;

    ret = sysdb_attrs_get_el(attrs, name, &el);

    vals = talloc_realloc(attrs->a, el->values,
                          struct ldb_val, el->num_values+1);
    if (!vals) return ENOMEM;

    vals[el->num_values] = ldb_val_dup(vals, val);
    if (vals[el->num_values].data == NULL &&
        vals[el->num_values].length != 0) {
        return ENOMEM;
    }

    el->values = vals;
    el->num_values++;

    return EOK;
}

int sysdb_attrs_add_string(struct sysdb_attrs *attrs,
                           const char *name, const char *str)
{
    struct ldb_val v;

    v.data = (uint8_t *)discard_const(str);
    v.length = strlen(str);

    return sysdb_attrs_add_val(attrs, name, &v);
}

int sysdb_attrs_steal_string(struct sysdb_attrs *attrs,
                             const char *name, char *str)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int ret;

    ret = sysdb_attrs_get_el(attrs, name, &el);

    vals = talloc_realloc(attrs->a, el->values,
                          struct ldb_val, el->num_values+1);
    if (!vals) return ENOMEM;
    el->values = vals;

    /* now steal and assign the string */
    talloc_steal(el->values, str);

    el->values[el->num_values].data = (uint8_t *)str;
    el->values[el->num_values].length = strlen(str);
    el->num_values++;

    return EOK;
}

int sysdb_attrs_add_long(struct sysdb_attrs *attrs,
                         const char *name, long value)
{
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%ld", value);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

int sysdb_attrs_add_uint32(struct sysdb_attrs *attrs,
                           const char *name, uint32_t value)
{
    unsigned long val = value;
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%lu", val);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

int sysdb_attrs_add_time_t(struct sysdb_attrs *attrs,
                           const char *name, time_t value)
{
    long long val = value;
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%lld", val);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

/* TODO: make a more complete and precise mapping */
int sysdb_error_to_errno(int ldberr)
{
    switch (ldberr) {
    case LDB_SUCCESS:
        return EOK;
    case LDB_ERR_OPERATIONS_ERROR:
        return EIO;
    case LDB_ERR_NO_SUCH_OBJECT:
        return ENOENT;
    case LDB_ERR_BUSY:
        return EBUSY;
    case LDB_ERR_ENTRY_ALREADY_EXISTS:
        return EEXIST;
    default:
        return EFAULT;
    }
}

/* =Internal-Operations-Queue============================================= */

static void sysdb_run_operation(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval tv, void *pvt)
{
    struct sysdb_handle *handle = talloc_get_type(pvt, struct sysdb_handle);

    tevent_req_done(handle->subreq);
}

static void sysdb_schedule_operation(struct sysdb_handle *handle)
{
    struct timeval tv = { 0, 0 };
    struct tevent_timer *te;

    te = tevent_add_timer(handle->ctx->ev, handle, tv,
                          sysdb_run_operation, handle);
    if (!te) {
        DEBUG(1, ("Failed to add critical timer to run next handle!\n"));
    }
}

static int sysdb_handle_destructor(void *mem)
{
    struct sysdb_handle *handle = talloc_get_type(mem, struct sysdb_handle);
    bool start_next = false;
    int ret;

    /* if this was the current op start next */
    if (handle->ctx->queue == handle) {
        start_next = true;
    }

    DLIST_REMOVE(handle->ctx->queue, handle);

    if (start_next && handle->ctx->queue) {
        /* run next */
        sysdb_schedule_operation(handle->ctx->queue);
    }

    if (handle->transaction_active) {
        ret = ldb_transaction_cancel(handle->ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
        }
        /* FIXME: abort() ? */
        handle->transaction_active = false;
    }

    return 0;
}

struct sysdb_get_handle_state {
    struct tevent_context *ev;
    struct sysdb_ctx *ctx;

    struct sysdb_handle *handle;
};

struct tevent_req *sysdb_get_handle_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_ctx *ctx)
{
    struct tevent_req *req;
    struct sysdb_get_handle_state *state;
    struct sysdb_handle *handle;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_get_handle_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    handle = talloc_zero(state, struct sysdb_handle);
    if (!handle) {
        talloc_zfree(req);
        return NULL;
    }

    handle->ctx = ctx;
    handle->subreq = req;

    talloc_set_destructor((TALLOC_CTX *)handle, sysdb_handle_destructor);

    DLIST_ADD_END(ctx->queue, handle, struct sysdb_handle *);

    if (ctx->queue == handle) {
        /* this is the first in the queue, schedule an immediate run */
        sysdb_schedule_operation(handle);
    }

    state->handle = handle;

    return req;
}

static int sysdb_get_handle_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                                 struct sysdb_handle **handle)
{
    struct sysdb_get_handle_state *state = tevent_req_data(req,
                                             struct sysdb_get_handle_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *handle = talloc_steal(memctx, state->handle);
    if (!*handle) return ENOMEM;

    return EOK;
}

/* =Transactions========================================================== */

struct sysdb_transaction_state {
    struct tevent_context *ev;
    struct sysdb_ctx *ctx;

    struct sysdb_handle *handle;
};

static void sysdb_transaction_done(struct tevent_req *subreq);

struct tevent_req *sysdb_transaction_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *ctx)
{
    struct tevent_req *req, *subreq;
    struct sysdb_transaction_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_transaction_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    subreq = sysdb_get_handle_send(state, ev, ctx);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, sysdb_transaction_done, req);

    return req;
}

static void sysdb_transaction_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_transaction_state *state = tevent_req_data(req,
                                         struct sysdb_transaction_state);
    int ret;

    ret = sysdb_get_handle_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    ret = ldb_transaction_start(state->ctx->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
        tevent_req_error(req, sysdb_error_to_errno(ret));
        return;
    }
    state->handle->transaction_active = true;

    tevent_req_done(req);
}

int sysdb_transaction_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                           struct sysdb_handle **handle)
{
    struct sysdb_transaction_state *state = tevent_req_data(req,
                                         struct sysdb_transaction_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *handle = talloc_steal(memctx, state->handle);
    if (!*handle) return ENOMEM;

    return EOK;
}

struct tevent_req *sysdb_transaction_commit_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_handle *handle)
{
    struct tevent_req *req;
    struct sysdb_transaction_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_transaction_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = handle->ctx;
    state->handle = handle;

    ret = ldb_transaction_commit(handle->ctx->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
        tevent_req_error(req, sysdb_error_to_errno(ret));
    }
    handle->transaction_active = false;

    /* the following may seem weird but it is actually fine.
     * _done() will not actually call the callback as it will not be set
     * until we return. But it will mark the request as done.
     * _post() will trigger the callback as it schedules after we returned
     * and actually set the callback */
    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

int sysdb_transaction_commit_recv(struct tevent_req *req)
{
    struct sysdb_transaction_state *state = tevent_req_data(req,
                                         struct sysdb_transaction_state);

    /* finally free handle
     * this will also trigger the next transaction in the queue if any */
    talloc_zfree(state->handle);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* default transaction commit receive function.
 * This function does not use the request state so it is safe to use
 * from any caller */
void sysdb_transaction_complete(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}


/* =Operations============================================================ */

struct sysdb_operation_state {
    struct tevent_context *ev;
    struct sysdb_ctx *ctx;

    struct sysdb_handle *handle;
};

static void sysdb_operation_process(struct tevent_req *subreq);

struct tevent_req *sysdb_operation_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sysdb_ctx *ctx)
{
    struct tevent_req *req, *subreq;
    struct sysdb_operation_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_operation_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    subreq = sysdb_get_handle_send(state, ev, ctx);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, sysdb_operation_process, req);

    return req;
}

static void sysdb_operation_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_operation_state *state = tevent_req_data(req,
                                         struct sysdb_operation_state);
    int ret;

    ret = sysdb_get_handle_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_operation_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                         struct sysdb_handle **handle)
{
    struct sysdb_operation_state *state = tevent_req_data(req,
                                             struct sysdb_operation_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *handle = talloc_steal(memctx, state->handle);
    if (!*handle) return ENOMEM;

    return EOK;
}

void sysdb_operation_done(struct sysdb_handle *handle)
{
    talloc_free(handle);
}

/* =Initialization======================================================== */

static int sysdb_get_db_file(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             const char *base_path, char **_ldb_file)
{
    char *ldb_file;

    /* special case for the local domain */
    if (strcasecmp(domain->provider, "local") == 0) {
        ldb_file = talloc_asprintf(mem_ctx, "%s/"LOCAL_SYSDB_FILE,
                                   base_path);
    } else {
        ldb_file = talloc_asprintf(mem_ctx, "%s/"CACHE_SYSDB_FILE,
                                   base_path, domain->name);
    }
    if (!ldb_file) {
        return ENOMEM;
    }

    *_ldb_file = ldb_file;
    return EOK;
}

/* serach all groups that have a memberUid attribute.
 * change it into a member attribute for a user of same domain.
 * remove the memberUid attribute
 * add the new member attribute
 * finally stop indexing memberUid
 * upgrade version to 0.2
 */
static int sysdb_upgrade_01(struct sysdb_ctx *ctx, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *basedn;
    struct ldb_dn *mem_dn;
    struct ldb_message *msg;
    const struct ldb_val *val;
    const char *filter = "(&(memberUid=*)(objectclass=group))";
    const char *attrs[] = { "memberUid", NULL };
    const char *mdn;
    char *domain;
    int ret, i, j;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx)
        return ENOMEM;

    basedn = ldb_dn_new(tmp_ctx, ctx->ldb, "cn=sysdb");
    if (!basedn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_SUBTREE,
                     attrs, filter);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = ldb_transaction_start(ctx->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        el = ldb_msg_find_element(res->msgs[i], "memberUid");
        if (!el) {
            DEBUG(1, ("memberUid is missing from message [%s], skipping\n",
                      ldb_dn_get_linearized(res->msgs[i]->dn)));
            continue;
        }

        /* create modification message */
        msg = ldb_msg_new(tmp_ctx);
        if (!msg) {
            ret = ENOMEM;
            goto done;
        }
        msg->dn = res->msgs[i]->dn;

        ret = ldb_msg_add_empty(msg, "memberUid", LDB_FLAG_MOD_DELETE, NULL);
        if (ret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_msg_add_empty(msg, SYSDB_MEMBER, LDB_FLAG_MOD_ADD, NULL);
        if (ret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        /* get domain name component value */
        val = ldb_dn_get_component_val(res->msgs[i]->dn, 2);
        domain = talloc_strndup(tmp_ctx, (const char *)val->data, val->length);
        if (!domain) {
            ret = ENOMEM;
            goto done;
        }

        for (j = 0; j < el->num_values; j++) {
            mem_dn = sysdb_user_dn(ctx, tmp_ctx, domain,
                                   (const char *)el->values[j].data);
            if (!mem_dn) {
                ret = ENOMEM;
                goto done;
            }

            mdn = talloc_strdup(msg, ldb_dn_get_linearized(mem_dn));
            if (!mdn) {
                ret = ENOMEM;
                goto done;
            }
            ret = ldb_msg_add_string(msg, SYSDB_MEMBER, mdn);
            if (ret != LDB_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }

            talloc_zfree(mem_dn);
        }

        /* ok now we are ready to modify the entry */
        ret = ldb_modify(ctx->ldb, msg);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        talloc_zfree(msg);
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ctx->ldb, "cn=sysdb");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_2);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    talloc_zfree(tmp_ctx);
    ret = EOK;

done:
    if (ret != EOK) {
        ret = ldb_transaction_cancel(ctx->ldb);
    } else {
        ret = ldb_transaction_commit(ctx->ldb);
    }
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

    *ver = SYSDB_VERSION_0_2;
    return ret;
}

static int sysdb_upgrade_02(struct confdb_ctx *cdb,
                            struct tevent_context *ev,
                            struct sysdb_ctx *local,
                            struct sysdb_ctx_list *list)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_ctx *ctx;
    struct ldb_message_element *el;
    struct ldb_message *msg;
    struct ldb_result *res;
    struct ldb_dn *basedn;
    const char *version;
    bool loc_trans = false;
    bool ctx_trans = false;
    int ret, i, j;

    tmp_ctx = talloc_new(list);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* first check local has the expected version for an upgrade */

    basedn = ldb_dn_new(tmp_ctx, local->ldb, "cn=sysdb");
    if (!basedn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(local->ldb, tmp_ctx, &res,
                     basedn, LDB_SCOPE_BASE,
                     NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    if (res->count != 1) {
        ret = EIO;
        goto done;
    }

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

        if (strcmp(version, SYSDB_VERSION_0_2) != 0) {
            DEBUG(0,("Wrong DB version [%s],"
                     " expected [%s] for this upgrade!\n",
                     version, SYSDB_VERSION));
            ret = EINVAL;
            goto done;
        }
    }
    talloc_zfree(res);

    DEBUG(0, ("UPGRADING DB TO VERSION %s\n", SYSDB_VERSION_0_3));

    /* ldb uses posix locks,
     * posix is stupid and kills all locks when you close *any* file
     * descriptor associated to the same file.
     * Therefore we must close and reopen the ldb file here */

    /* == Backup and reopen ldb == */

    /* close */
    talloc_zfree(local->ldb);

    /* backup*/
    ret = backup_file(local->ldb_file, 0);
    if (ret != EOK) {
        return ret;
    }

    /* reopen */
    local->ldb = ldb_init(local, ev);
    if (!local->ldb) {
        return EIO;
    }

    ret = ldb_set_debug(local->ldb, ldb_debug_messages, NULL);
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

    ret = ldb_connect(local->ldb, local->ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

    /* open a transaction */
    ret = ldb_transaction_start(local->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
        return EIO;
    }
    loc_trans = true;

    /* == Upgrade contents == */

    for (i = 0; i < list->num_dbs; i++) {
        struct ldb_dn *domain_dn;
        struct ldb_dn *users_dn;
        struct ldb_dn *groups_dn;

        ctx = list->dbs[i];

        /* skip local */
        if (list->dbs[i] == local) continue;

        ret = ldb_transaction_start(ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to start ldb transaction! (%d)\n", ret));
            ret = EIO;
            goto done;
        }
        ctx_trans = true;

        /* search all entries for this domain in local,
         * copy them all in the new database,
         * then remove them from local */

        domain_dn = ldb_dn_new_fmt(tmp_ctx, ctx->ldb,
                                   SYSDB_DOM_BASE, ctx->domain->name);
        if (!domain_dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(local->ldb, tmp_ctx, &res,
                         domain_dn, LDB_SCOPE_SUBTREE,
                         NULL, NULL);
        if (ret != LDB_SUCCESS) {
            ret = EIO;
            goto done;
        }

        users_dn = ldb_dn_new_fmt(tmp_ctx, ctx->ldb,
                                 SYSDB_TMPL_USER_BASE, ctx->domain->name);
        if (!users_dn) {
            ret = ENOMEM;
            goto done;
        }
        groups_dn = ldb_dn_new_fmt(tmp_ctx, ctx->ldb,
                                   SYSDB_TMPL_GROUP_BASE, ctx->domain->name);
        if (!groups_dn) {
            ret = ENOMEM;
            goto done;
        }

        for (j = 0; j < res->count; j++) {

            msg = res->msgs[j];

            /* skip pre-created congtainers */
            if ((ldb_dn_compare(msg->dn, domain_dn) == 0) ||
                (ldb_dn_compare(msg->dn, users_dn) == 0) ||
                (ldb_dn_compare(msg->dn, groups_dn) == 0)) {
                continue;
            }

            ret = ldb_add(ctx->ldb, msg);
            if (ret != LDB_SUCCESS) {
                DEBUG(0, ("WARNING: Could not add entry %s,"
                          " to new ldb file! (%d [%s])\n",
                          ldb_dn_get_linearized(msg->dn),
                          ret, ldb_errstring(ctx->ldb)));
            }

            ret = ldb_delete(local->ldb, msg->dn);
            if (ret != LDB_SUCCESS) {
                DEBUG(0, ("WARNING: Could not remove entry %s,"
                          " from old ldb file! (%d [%s])\n",
                          ldb_dn_get_linearized(msg->dn),
                          ret, ldb_errstring(local->ldb)));
            }
        }

        /* now remove the basic containers from local */
        /* these were optional so debug at level 9 in case
         * of failure just for tracing */
        ret = ldb_delete(local->ldb, groups_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(msg->dn),
                      ret, ldb_errstring(local->ldb)));
        }
        ret = ldb_delete(local->ldb, users_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(msg->dn),
                      ret, ldb_errstring(local->ldb)));
        }
        ret = ldb_delete(local->ldb, domain_dn);
        if (ret != LDB_SUCCESS) {
            DEBUG(9, ("WARNING: Could not remove entry %s,"
                      " from old ldb file! (%d [%s])\n",
                      ldb_dn_get_linearized(msg->dn),
                      ret, ldb_errstring(local->ldb)));
        }

        ret = ldb_transaction_commit(ctx->ldb);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
            ret = EIO;
            goto done;
        }
        ctx_trans = false;

        talloc_zfree(domain_dn);
        talloc_zfree(groups_dn);
        talloc_zfree(users_dn);
        talloc_zfree(res);
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, local->ldb, "cn=sysdb");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_3);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(local->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_transaction_commit(local->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to commit ldb transaction! (%d)\n", ret));
        ret = EIO;
        goto done;
    }
    loc_trans = false;

    ret = EOK;

done:
    if (ret != EOK) {
        if (ctx_trans) {
            ret = ldb_transaction_cancel(ctx->ldb);
            if (ret != LDB_SUCCESS) {
                DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
            }
        }
        if (loc_trans) {
            ret = ldb_transaction_cancel(local->ldb);
            if (ret != LDB_SUCCESS) {
                DEBUG(1, ("Failed to cancel ldb transaction! (%d)\n", ret));
            }
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static int sysdb_upgrade_03(struct sysdb_ctx *ctx, const char **ver)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = ldb_transaction_start(ctx->ldb);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    /* Make this database case-sensitive */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ctx->ldb, "@ATTRIBUTES");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "name", LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    /* conversion done, upgrade version number */
    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new(tmp_ctx, ctx->ldb, "cn=sysdb");
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, "version", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "version", SYSDB_VERSION_0_4);
    if (ret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_modify(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);

    if (ret != EOK) {
        ret = ldb_transaction_cancel(ctx->ldb);
    } else {
        ret = ldb_transaction_commit(ctx->ldb);
    }
    if (ret != LDB_SUCCESS) {
        ret = EIO;
    }

    *ver = SYSDB_VERSION_0_4;
    return ret;
}

static int sysdb_domain_init_internal(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sss_domain_info *domain,
                                      const char *db_path,
                                      bool allow_upgrade,
                                      struct sysdb_ctx **_ctx,
                                      bool *need_02_upgrade)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sysdb_ctx *ctx;
    const char *base_ldif;
    struct ldb_ldif *ldif;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    const char *version = NULL;
    int ret;

    ctx = talloc_zero(mem_ctx, struct sysdb_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->ev = ev;
    ctx->domain = domain;

    /* The local provider s the only true MPG,
     * for the other domains, the provider actually unrolls MPGs */
    if (strcasecmp(domain->provider, "local") == 0) {
        ctx->mpg = true;
    }

    ret = sysdb_get_db_file(ctx, domain, db_path, &ctx->ldb_file);
    if (ret != EOK) {
        return ret;
    }
    DEBUG(5, ("DB File for %s: %s\n", domain->name, ctx->ldb_file));

    ctx->ldb = ldb_init(ctx, ev);
    if (!ctx->ldb) {
        return EIO;
    }

    ret = ldb_set_debug(ctx->ldb, ldb_debug_messages, NULL);
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

#ifdef SYSDB_TEST
    ldb_set_modules_dir(ctx->ldb, "./.libs");
#endif

    ret = ldb_connect(ctx->ldb, ctx->ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

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

            if (!allow_upgrade) {
                DEBUG(0, ("Wrong DB version (got %s expected %s)\n",
                          version, SYSDB_VERSION));
                ret = EINVAL;
                goto done;
            }

            if (strcmp(version, SYSDB_VERSION_0_1) == 0) {
                /* convert database */
                ret = sysdb_upgrade_01(ctx, &version);
                if (ret != EOK) goto done;
            }

            if (strcmp(version, SYSDB_VERSION_0_2) == 0) {
                /* if this is not local we have a big problem */
                if (strcasecmp(domain->provider, "local") != 0) {
                    DEBUG(0, ("Fatal: providers other than 'local'"
                              " shouldn't present v0.2, db corrupted?\n"));
                    ret = EFAULT;
                    goto done;
                }

                /* need to convert database to split files */
                /* this need to be done later when all domains are set up */
                if (need_02_upgrade) {
                    *need_02_upgrade = true;
                } else {
                    DEBUG(0, ("DB file seem to need an upgrade,"
                              " but upgrade flag is not provided,"
                              " db corrupted?\n"));
                    ret = EFAULT;
                    goto done;
                }

                ret = EOK;
                goto done;
            }

            if (strcmp(version, SYSDB_VERSION_0_3) == 0) {
                ret = sysdb_upgrade_03(ctx, &version);
                goto done;
            }

        }

        DEBUG(0,("Unknown DB version [%s], expected [%s] for domain %s!\n",
                 version?version:"not found", SYSDB_VERSION, domain->name));
        ret = EINVAL;
        goto done;
    }

    /* cn=sysdb does not exists, means db is empty, populate */

    base_ldif = SYSDB_BASE_LDIF;
    while ((ldif = ldb_ldif_read_string(ctx->ldb, &base_ldif))) {
        ret = ldb_add(ctx->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(0, ("Failed to initialize DB (%d, [%s]) for domain %s!",
                      ret, ldb_errstring(ctx->ldb), domain->name));
            ret = EIO;
            goto done;
        }
        ldb_ldif_read_free(ctx->ldb, ldif);
    }

    /* == create base domain object == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ctx->ldb, SYSDB_DOM_BASE, domain->name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_fmt(msg, "cn", "%s", domain->name);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Failed to initialize DB (%d, [%s]) for domain %s!",
                  ret, ldb_errstring(ctx->ldb), domain->name));
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    /* == create Users tree == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ctx->ldb,
                             SYSDB_TMPL_USER_BASE, domain->name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_fmt(msg, "cn", "Users");
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Failed to initialize DB (%d, [%s]) for domain %s!",
                  ret, ldb_errstring(ctx->ldb), domain->name));
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    /* == create Groups tree == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ctx->ldb,
                             SYSDB_TMPL_GROUP_BASE, domain->name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_fmt(msg, "cn", "Groups");
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Failed to initialize DB (%d, [%s]) for domain %s!",
                  ret, ldb_errstring(ctx->ldb), domain->name));
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    ret = EOK;

done:
    if (ret == EOK) {
        *_ctx = ctx;
    }
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_init(TALLOC_CTX *mem_ctx,
               struct tevent_context *ev,
               struct confdb_ctx *cdb,
               const char *alt_db_path,
               bool allow_upgrade,
               struct sysdb_ctx_list **_ctx_list)
{
    struct sysdb_ctx_list *ctx_list;
    struct sss_domain_info *domains, *dom;
    struct sysdb_ctx *ctx;
    bool upgrade_02 = false;
    int ret;

    if (!ev) return EINVAL;

    ctx_list = talloc_zero(mem_ctx, struct sysdb_ctx_list);
    if (!ctx_list) {
        return ENOMEM;
    }

    if (alt_db_path) {
        ctx_list->db_path = talloc_strdup(ctx_list, alt_db_path);
    } else {
        ctx_list->db_path = talloc_strdup(ctx_list, DB_PATH);
    }
    if (!ctx_list->db_path) {
        talloc_zfree(ctx_list);
        return ENOMEM;
    }

    /* open a db for each backend */
    ret = confdb_get_domains(cdb, &domains);
    if (ret != EOK) {
        talloc_zfree(ctx_list);
        return ret;
    }

    for (dom = domains; dom; dom = dom->next) {

        ctx_list->dbs = talloc_realloc(ctx_list, ctx_list->dbs,
                                       struct sysdb_ctx *,
                                       ctx_list->num_dbs + 1);
        if (!ctx_list->dbs) {
            talloc_zfree(ctx_list);
            return ENOMEM;
        }

        ret = sysdb_domain_init_internal(ctx_list, ev, dom,
                                         ctx_list->db_path,
                                         allow_upgrade,
                                         &ctx, &upgrade_02);
        if (ret != EOK) {
            talloc_zfree(ctx_list);
            return ret;
        }

        ctx_list->dbs[ctx_list->num_dbs] = ctx;
        ctx_list->num_dbs++;
    }
    if (ctx_list->num_dbs == 0) {
        /* what? .. */
        talloc_zfree(ctx_list);
        return ENOENT;
    }

    if (upgrade_02) {
        ret = confdb_get_domain(cdb, "local", &dom);
        if (ret != EOK) {
            talloc_zfree(ctx_list);
            return ret;
        }
        ret = sysdb_get_ctx_from_list(ctx_list, dom, &ctx);
        if (ret != EOK) {
            talloc_zfree(ctx_list);
            return ret;
        }

        ret = sysdb_upgrade_02(cdb, ev, ctx, ctx_list);
        if (ret != EOK) {
            DEBUG(0, ("FATAL: Upgrade form db version %d failed!\n",
                      SYSDB_VERSION_0_2));
            DEBUG(0, ("You can find a backup of the database here: %s\n",
                      backup_file));
            talloc_zfree(ctx_list);
            return ret;
        }
    }

    *_ctx_list = ctx_list;

    return EOK;
}

int sysdb_domain_init(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct sss_domain_info *domain,
                      const char *db_path,
                      struct sysdb_ctx **_ctx)
{
    return sysdb_domain_init_internal(mem_ctx, ev, domain,
                                      db_path, false, _ctx, NULL);
}

int sysdb_get_ctx_from_list(struct sysdb_ctx_list *ctx_list,
                            struct sss_domain_info *domain,
                            struct sysdb_ctx **ctx)
{
    int i;

    for (i = 0; i < ctx_list->num_dbs; i++) {
        if (ctx_list->dbs[i]->domain == domain) {
            *ctx = ctx_list->dbs[i];
            return EOK;
        }
        if (strcasecmp(ctx_list->dbs[i]->domain->name, domain->name) == 0) {
            *ctx = ctx_list->dbs[i];
            return EOK;
        }
    }
    /* definitely not found */
    return ENOENT;
}


int compare_ldb_dn_comp_num(const void *m1, const void *m2)
{
    struct ldb_message *msg1 = talloc_get_type(*(void **) discard_const(m1),
                                               struct ldb_message);
    struct ldb_message *msg2 = talloc_get_type(*(void **) discard_const(m2),
                                               struct ldb_message);

    return ldb_dn_get_comp_num(msg2->dn) - ldb_dn_get_comp_num(msg1->dn);
}

int sysdb_attrs_replace_name(struct sysdb_attrs *attrs, const char *oldname,
                             const char *newname)
{
    struct ldb_message_element *e = NULL;
    int i;
    const char *dummy;

    if (attrs == NULL || oldname == NULL || newname == NULL) return EINVAL;

    for (i = 0; i < attrs->num; i++) {
        if (strcasecmp(oldname, attrs->a[i].name) == 0) {
            e = &(attrs->a[i]);
        }
        if (strcasecmp(newname, attrs->a[i].name) == 0) {
            DEBUG(3, ("New attribute name [%s] already exists.\n", newname));
            return EEXIST;
        }
    }

    if (e != NULL) {
        dummy = talloc_strdup(attrs, newname);
        if (dummy == NULL) {
            DEBUG(1, ("talloc_strdup failed.\n"));
            return ENOMEM;
        }

        talloc_free(discard_const(e->name));
        e->name = dummy;
    }

    return EOK;
}
