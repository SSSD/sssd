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

static int add_string(struct ldb_message *msg, int flags,
                      const char *attr, const char *value)
{
    int ret;

    ret = ldb_msg_add_empty(msg, attr, flags, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_msg_add_string(msg, attr, value);
        if (ret == LDB_SUCCESS) return EOK;
    }
    return ENOMEM;
}

static int add_ulong(struct ldb_message *msg, int flags,
                     const char *attr, unsigned long value)
{
    int ret;

    ret = ldb_msg_add_empty(msg, attr, flags, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_msg_add_fmt(msg, attr, "%lu", value);
        if (ret == LDB_SUCCESS) return EOK;
    }
    return ENOMEM;
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

#define ERROR_OUT(v, r, l) do { v = r; goto l; } while(0);

/* =LDB-Request-(tevent_req-style)======================================== */

struct sldb_request_state {
    struct tevent_context *ev;
    struct ldb_context *ldbctx;
    struct ldb_request *ldbreq;
    struct ldb_reply *ldbreply;
};

static void sldb_request_wakeup(struct tevent_req *subreq);
static int sldb_request_callback(struct ldb_request *ldbreq,
                                 struct ldb_reply *ldbreply);

static struct tevent_req *sldb_request_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct ldb_context *ldbctx,
                                            struct ldb_request *ldbreq)
{
    struct tevent_req *req, *subreq;
    struct sldb_request_state *state;
    struct timeval tv = { 0, 0 };

    req = tevent_req_create(mem_ctx, &state, struct sldb_request_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ldbctx = ldbctx;
    state->ldbreq = ldbreq;
    state->ldbreply = NULL;

    subreq = tevent_wakeup_send(state, ev, tv);
    if (!subreq) {
        DEBUG(1, ("Failed to add critical timer to run next ldb operation!\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sldb_request_wakeup, req);

    return req;
}

static void sldb_request_wakeup(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sldb_request_state *state = tevent_req_data(req,
                                                  struct sldb_request_state);
    int ret;

    if (!tevent_wakeup_recv(subreq)) return;
    talloc_zfree(subreq);

    state->ldbreq->callback = sldb_request_callback;
    state->ldbreq->context = req;

    ret = ldb_request(state->ldbctx, state->ldbreq);
    if (ret != LDB_SUCCESS) {
        tevent_req_error(req, sysdb_error_to_errno(ret));
    }
}

static int sldb_request_callback(struct ldb_request *ldbreq,
                                  struct ldb_reply *ldbreply)
{
    struct tevent_req *req = talloc_get_type(ldbreq->context,
                                                  struct tevent_req);
    struct sldb_request_state *state = tevent_req_data(req,
                                                  struct sldb_request_state);
    int err;

    if (!ldbreply) {
        ERROR_OUT(err, EIO, fail);
    }

    state->ldbreply = talloc_steal(state, ldbreply);

    if (ldbreply->error != LDB_SUCCESS) {
        ERROR_OUT(err, sysdb_error_to_errno(ldbreply->error), fail);
    }

    if (ldbreply->type == LDB_REPLY_DONE) {
        tevent_req_done(req);
        return EOK;
    }

    tevent_req_notify_callback(req);
    return EOK;

fail:
    tevent_req_error(req, err);
    return EOK;
}

static int sldb_request_recv(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             struct ldb_reply **ldbreply)
{
    struct sldb_request_state *state = tevent_req_data(req,
                                                  struct sldb_request_state);
    enum tevent_req_state tstate;
    uint64_t err = 0;

    if (state->ldbreply) {
        *ldbreply = talloc_move(mem_ctx, &state->ldbreply);
    }

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err != 0) return err;
        if (tstate == TEVENT_REQ_IN_PROGRESS) return EOK;
        return EIO;
    }

    return EOK;
}

/* =Standard-Sysdb-Operations-utility-functions=========================== */

struct sysdb_op_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;

    bool ignore_not_found;

    struct ldb_reply *ldbreply;
};

static void sysdb_op_default_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_op_state *state = tevent_req_data(req,
                                                  struct sysdb_op_state);
    int ret;

    ret = sldb_request_recv(subreq, state, &state->ldbreply);
    talloc_zfree(subreq);
    if (ret) {
        if (state->ignore_not_found && ret == ENOENT) {
            goto done;
        }
        tevent_req_error(req, ret);
        return;
    }

    if (state->ldbreply->type != LDB_REPLY_DONE) {
        tevent_req_error(req, EIO);
        return;
    }

done:
    tevent_req_done(req);
}

static int sysdb_op_default_recv(struct tevent_req *req)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    return EOK;
}


/* =Remove-Entry-From-Sysdb=============================================== */

struct tevent_req *sysdb_delete_entry_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_handle *handle,
                                           struct ldb_dn *dn)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_request *ldbreq;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = true;
    state->ldbreply = NULL;

    ret = ldb_build_del_req(&ldbreq, handle->ctx->ldb, state, dn,
                            NULL, NULL, NULL, NULL);

    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("LDB Error: %s(%d)\nError Message: [%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(handle->ctx->ldb)));
        ERROR_OUT(ret, sysdb_error_to_errno(ret), fail);
    }

    subreq = sldb_request_send(state, ev, handle->ctx->ldb, ldbreq);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_op_default_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

int sysdb_delete_entry_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Search-Entry========================================================== */

static void sysdb_search_entry_done(struct tevent_req *subreq);

struct tevent_req *sysdb_search_entry_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_handle *handle,
                                           struct ldb_dn *base_dn,
                                           int scope,
                                           const char *filter,
                                           const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_request *ldbreq;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    ret = ldb_build_search_req(&ldbreq, handle->ctx->ldb, state,
                               base_dn, scope, filter, attrs,
                               NULL, NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(handle->ctx->ldb)));
        ERROR_OUT(ret, sysdb_error_to_errno(ret), fail);
    }

    subreq = sldb_request_send(state, ev, handle->ctx->ldb, ldbreq);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_search_entry_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_search_entry_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_op_state *state = tevent_req_data(req,
                                                  struct sysdb_op_state);
    struct ldb_reply *ldbreply;
    int ret;

    ret = sldb_request_recv(subreq, state, &ldbreply);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    switch (ldbreply->type) {
    case LDB_REPLY_ENTRY:
        if (state->ldbreply) {
            DEBUG(1, ("More than one reply for a base search ?! "
                      "DB seems corrupted, aborting."));
            tevent_req_error(req, EFAULT);
            return;
        }

        /* save the entry so that it can be retrieved by the caller */
        state->ldbreply = ldbreply;

        /* just return, wait for a LDB_REPLY_DONE entry */
        return;

    case LDB_REPLY_DONE:
        if (!state->ldbreply) {
            talloc_zfree(ldbreply);
            tevent_req_error(req, ENOENT);
            return;
        }
        talloc_zfree(ldbreply);
        return tevent_req_done(req);

    default:
        /* unexpected stuff */
        talloc_zfree(ldbreply);
        tevent_req_error(req, EIO);
        return;
    }
}

int sysdb_search_entry_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct ldb_message **msg)
{
    struct sysdb_op_state *state = tevent_req_data(req,
                                                   struct sysdb_op_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    *msg = talloc_move(mem_ctx, &state->ldbreply->message);

    return EOK;
}


/* =Search-User-by-[UID/NAME]============================================= */

struct sysdb_search_user_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;

    struct ldb_dn *basedn;
    const char **attrs;
    const char *filter;
    int scope;

    struct ldb_message *msg;
};

static void sysdb_search_user_cont(struct tevent_req *subreq);
static void sysdb_search_user_done(struct tevent_req *subreq);

struct tevent_req *sysdb_search_user_by_name_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_ctx *sysdb,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  const char *name,
                                                  const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_search_user_state *state;
    static const char *def_attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL };
    int ret;

    if (!sysdb && !handle) return NULL;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_search_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->msg = NULL;

    state->attrs = attrs ? attrs : def_attrs;
    state->filter = NULL;
    state->scope = LDB_SCOPE_BASE;

    if (!sysdb) sysdb = handle->ctx;

    state->basedn = sysdb_user_dn(sysdb, state, domain->name, name);
    if (!state->basedn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    if (!handle) {
        subreq = sysdb_operation_send(state, state->ev, sysdb);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_search_user_cont, req);
    }
    else {
        subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                         state->basedn, state->scope,
                                         state->filter, state->attrs);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_search_user_done, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

struct tevent_req *sysdb_search_user_by_uid_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_ctx *sysdb,
                                                 struct sysdb_handle *handle,
                                                 struct sss_domain_info *domain,
                                                 uid_t uid,
                                                 const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_search_user_state *state;
    static const char *def_attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL };
    int ret;

    if (!sysdb && !handle) return NULL;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_search_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->msg = NULL;
    state->attrs = attrs ? attrs : def_attrs;

    if (!sysdb) sysdb = handle->ctx;

    state->basedn = ldb_dn_new_fmt(state, sysdb->ldb,
                                   SYSDB_TMPL_USER_BASE, domain->name);
    if (!state->basedn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    state->filter = talloc_asprintf(state, SYSDB_PWUID_FILTER,
                                    (unsigned long)uid);
    if (!state->filter) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    state->scope = LDB_SCOPE_ONELEVEL;

    if (!handle) {
        subreq = sysdb_operation_send(state, state->ev, sysdb);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_search_user_cont, req);
    }
    else {
        subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                         state->basedn, state->scope,
                                         state->filter, state->attrs);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_search_user_done, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_search_user_cont(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_search_user_state *state = tevent_req_data(req,
                                            struct sysdb_search_user_state);
    int ret;

    ret = sysdb_operation_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                     state->basedn, state->scope,
                                     state->filter, state->attrs);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_search_user_done, req);
}

static void sysdb_search_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_search_user_state *state = tevent_req_data(req,
                                            struct sysdb_search_user_state);
    int ret;

    ret = sysdb_search_entry_recv(subreq, state, &state->msg);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_search_user_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           struct ldb_message **msg)
{
    struct sysdb_search_user_state *state = tevent_req_data(req,
                                              struct sysdb_search_user_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    *msg = talloc_move(mem_ctx, &state->msg);

    return EOK;
}


/* =Delete-User-by-UID==================================================== */

static void sysdb_delete_user_by_uid_found(struct tevent_req *subreq);
static void sysdb_delete_user_by_uid_done(struct tevent_req *subreq);

struct tevent_req *sysdb_delete_user_by_uid_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_handle *handle,
                                                 struct sss_domain_info *domain,
                                                 uid_t uid)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = true;
    state->ldbreply = NULL;

    subreq = sysdb_search_user_by_uid_send(state, ev, NULL, handle,
                                           domain, uid, NULL);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sysdb_delete_user_by_uid_found, req);

    return req;
}

static void sysdb_delete_user_by_uid_found(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_op_state *state = tevent_req_data(req,
                                                  struct sysdb_op_state);
    struct ldb_message *msg;
    int ret;

    ret = sysdb_search_user_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret) {
        if (state->ignore_not_found && ret == ENOENT) {
            return tevent_req_done(req);
        }
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_delete_entry_send(state, state->ev, state->handle, msg->dn);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_delete_user_by_uid_done, req);
}

static void sysdb_delete_user_by_uid_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_delete_user_by_uid_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Search-Group-by-[GID/NAME]============================================ */

struct sysdb_search_group_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;

    struct ldb_dn *basedn;
    const char **attrs;
    const char *filter;
    int scope;

    struct ldb_message *msg;
};

static void sysdb_search_group_cont(struct tevent_req *subreq);
static void sysdb_search_group_done(struct tevent_req *subreq);

struct tevent_req *sysdb_search_group_by_name_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct sysdb_ctx *sysdb,
                                                   struct sysdb_handle *handle,
                                                   struct sss_domain_info *domain,
                                                   const char *name,
                                                   const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_search_group_state *state;
    static const char *def_attrs[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL };
    int ret;

    if (!sysdb && !handle) return NULL;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_search_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->msg = NULL;

    state->attrs = attrs ? attrs : def_attrs;
    state->filter = NULL;
    state->scope = LDB_SCOPE_BASE;

    if (!sysdb) sysdb = handle->ctx;

    state->basedn = sysdb_group_dn(sysdb, state, domain->name, name);
    if (!state->basedn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    if (!handle) {
        subreq = sysdb_operation_send(state, state->ev, sysdb);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_search_group_cont, req);
    }
    else {
        subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                         state->basedn, state->scope,
                                         state->filter, state->attrs);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_search_group_done, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

struct tevent_req *sysdb_search_group_by_gid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_ctx *sysdb,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  gid_t gid,
                                                  const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_search_group_state *state;
    static const char *def_attrs[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL };
    int ret;

    if (!sysdb && !handle) return NULL;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_search_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->msg = NULL;
    state->attrs = attrs ? attrs : def_attrs;

    if (!sysdb) sysdb = handle->ctx;

    state->basedn = ldb_dn_new_fmt(state, sysdb->ldb,
                                   SYSDB_TMPL_GROUP_BASE, domain->name);
    if (!state->basedn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    state->filter = talloc_asprintf(state, SYSDB_GRGID_FILTER,
                                    (unsigned long)gid);
    if (!state->filter) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    state->scope = LDB_SCOPE_ONELEVEL;

    if (!handle) {
        subreq = sysdb_operation_send(state, state->ev, sysdb);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_search_group_cont, req);
    }
    else {
        subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                         state->basedn, state->scope,
                                         state->filter, state->attrs);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_search_group_done, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_search_group_cont(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_search_group_state *state = tevent_req_data(req,
                                            struct sysdb_search_group_state);
    int ret;

    ret = sysdb_operation_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                     state->basedn, state->scope,
                                     state->filter, state->attrs);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_search_group_done, req);
}

static void sysdb_search_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_search_group_state *state = tevent_req_data(req,
                                             struct sysdb_search_group_state);
    int ret;

    ret = sysdb_search_entry_recv(subreq, state, &state->msg);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_search_group_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                             struct ldb_message **msg)
{
    struct sysdb_search_group_state *state = tevent_req_data(req,
                                             struct sysdb_search_group_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    *msg = talloc_move(mem_ctx, &state->msg);

    return EOK;
}


/* =Delete-Group-by-GID=================================================== */

static void sysdb_delete_group_by_gid_found(struct tevent_req *subreq);
static void sysdb_delete_group_by_gid_done(struct tevent_req *subreq);

struct tevent_req *sysdb_delete_group_by_gid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  gid_t gid)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = true;
    state->ldbreply = NULL;

    subreq = sysdb_search_group_by_gid_send(state, ev, NULL, handle,
                                            domain, gid, NULL);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sysdb_delete_group_by_gid_found, req);

    return req;
}

static void sysdb_delete_group_by_gid_found(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_op_state *state = tevent_req_data(req,
                                                  struct sysdb_op_state);
    struct ldb_message *msg;
    int ret;

    ret = sysdb_search_group_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret) {
        if (state->ignore_not_found && ret == ENOENT) {
            return tevent_req_done(req);
        }
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_delete_entry_send(state, state->ev, state->handle, msg->dn);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_delete_group_by_gid_done, req);
}

static void sysdb_delete_group_by_gid_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_delete_group_by_gid_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Replace-Attributes-On-Entry=========================================== */

struct tevent_req *sysdb_set_entry_attr_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct ldb_dn *entry_dn,
                                             struct sysdb_attrs *attrs,
                                             int mod_op)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_request *ldbreq;
    struct ldb_message *msg;
    int i, ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    if (!entry_dn) {
        ERROR_OUT(ret, EINVAL, fail);
    }

    if (attrs->num == 0) {
        ERROR_OUT(ret, EINVAL, fail);
    }

    msg = ldb_msg_new(state);
    if (!msg) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    msg->dn = entry_dn;

    msg->elements = talloc_array(msg, struct ldb_message_element, attrs->num);
    if (!msg->elements) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    for (i = 0; i < attrs->num; i++) {
        msg->elements[i] = attrs->a[i];
        msg->elements[i].flags = mod_op;
    }

    msg->num_elements = attrs->num;

    ret = ldb_build_mod_req(&ldbreq, handle->ctx->ldb, state, msg,
                           NULL, NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(handle->ctx->ldb)));
        ERROR_OUT(ret, sysdb_error_to_errno(ret), fail);
    }

    subreq = sldb_request_send(state, ev, handle->ctx->ldb, ldbreq);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_op_default_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

int sysdb_set_entry_attr_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Replace-Attributes-On-User============================================ */

static void sysdb_set_user_attr_done(struct tevent_req *subreq);

struct tevent_req *sysdb_set_user_attr_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sysdb_handle *handle,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            struct sysdb_attrs *attrs,
                                            int mod_op)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_dn *dn;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    dn = sysdb_user_dn(handle->ctx, state, domain->name, name);
    if (!dn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    subreq = sysdb_set_entry_attr_send(state, ev, handle, dn, attrs, mod_op);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_set_user_attr_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_set_user_attr_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_set_entry_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_set_user_attr_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Replace-Attributes-On-Group=========================================== */

static void sysdb_set_group_attr_done(struct tevent_req *subreq);

struct tevent_req *sysdb_set_group_attr_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             struct sysdb_attrs *attrs,
                                             int mod_op)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_dn *dn;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    dn = sysdb_group_dn(handle->ctx, state, domain->name, name);
    if (!dn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    subreq = sysdb_set_entry_attr_send(state, ev, handle, dn, attrs, mod_op);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_set_group_attr_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_set_group_attr_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_set_entry_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_set_group_attr_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Get-New-ID============================================================ */

struct sysdb_get_new_id_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;

    struct ldb_dn *base_dn;
    struct ldb_message *base;

    struct ldb_message **v_msgs;
    int v_count;

    uint32_t new_id;
};

static void sysdb_get_new_id_base(struct tevent_req *subreq);
static void sysdb_get_new_id_verify(struct tevent_req *subreq);
static void sysdb_get_new_id_done(struct tevent_req *subreq);

struct tevent_req *sysdb_get_new_id_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain)
{
    struct tevent_req *req, *subreq;
    struct sysdb_get_new_id_state *state;
    static const char *attrs[] = { SYSDB_NEXTID, NULL };
    struct ldb_request *ldbreq;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_get_new_id_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->base = NULL;
    state->v_msgs = NULL;
    state->v_count = 0;
    state->new_id = 0;

    state->base_dn = sysdb_domain_dn(handle->ctx, state, domain->name);
    if (!state->base_dn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    ret = ldb_build_search_req(&ldbreq, handle->ctx->ldb, state,
                               state->base_dn, LDB_SCOPE_BASE,
                               SYSDB_NEXTID_FILTER, attrs,
                               NULL, NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(handle->ctx->ldb)));
        ERROR_OUT(ret, sysdb_error_to_errno(ret), fail);
    }

    subreq = sldb_request_send(state, ev, handle->ctx->ldb, ldbreq);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_get_new_id_base, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_get_new_id_base(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                 struct tevent_req);
    struct sysdb_get_new_id_state *state = tevent_req_data(req,
                                                 struct sysdb_get_new_id_state);
    static const char *attrs[] = { SYSDB_UIDNUM, SYSDB_GIDNUM, NULL };
    struct ldb_reply *ldbreply;
    struct ldb_request *ldbreq;
    char *filter;
    int ret;

    ret = sldb_request_recv(subreq, state, &ldbreply);
    if (ret) {
        talloc_zfree(subreq);
        tevent_req_error(req, ret);
        return;
    }

    switch (ldbreply->type) {
    case LDB_REPLY_ENTRY:
        if (state->base) {
            DEBUG(1, ("More than one reply for a base search ?! "
                      "DB seems corrupted, aborting."));
            tevent_req_error(req, EFAULT);
            return;
        }

        state->base = talloc_move(state, &ldbreply->message);
        if (!state->base) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        /* just return, wait for a LDB_REPLY_DONE entry */
        talloc_zfree(ldbreply);
        return;

    case LDB_REPLY_DONE:
        break;

    default:
        /* unexpected stuff */
        tevent_req_error(req, EIO);
        talloc_zfree(ldbreply);
        return;
    }

    talloc_zfree(subreq);

    if (state->base) {
        state->new_id = get_attr_as_uint32(state->base, SYSDB_NEXTID);
        if (state->new_id == (uint32_t)(-1)) {
            DEBUG(1, ("Invalid Next ID in domain %s\n", state->domain->name));
            tevent_req_error(req, ERANGE);
            return;
        }

        if (state->new_id < state->domain->id_min) {
            state->new_id = state->domain->id_min;
        }

        if ((state->domain->id_max != 0) &&
            (state->new_id > state->domain->id_max)) {
            DEBUG(0, ("Failed to allocate new id, out of range (%u/%u)\n",
                      state->new_id, state->domain->id_max));
            tevent_req_error(req, ERANGE);
            return;
        }

    } else {
        /* looks like the domain is not initialized yet, use min_id */
        state->new_id = state->domain->id_min;
    }

    /* verify the id is actually really free.
     * search all entries with id >= new_id and < max_id */
    filter = talloc_asprintf(state,
                             "(|(&(%s>=%u)(%s<=%u))(&(%s>=%u)(%s<=%u)))",
                             SYSDB_UIDNUM, state->new_id,
                             SYSDB_UIDNUM, state->domain->id_max,
                             SYSDB_GIDNUM, state->new_id,
                             SYSDB_GIDNUM, state->domain->id_max);
    if (!filter) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = ldb_build_search_req(&ldbreq, state->handle->ctx->ldb, state,
                               state->base_dn, LDB_SCOPE_SUBTREE,
                               filter, attrs,
                               NULL, NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build search request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret,
                  ldb_errstring(state->handle->ctx->ldb)));
        tevent_req_error(req, sysdb_error_to_errno(ret));
        return;
    }

    subreq = sldb_request_send(state, state->ev,
                               state->handle->ctx->ldb, ldbreq);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_get_new_id_verify, req);

    return;
}

static void sysdb_get_new_id_verify(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_get_new_id_state *state = tevent_req_data(req,
                                                 struct sysdb_get_new_id_state);
    struct ldb_reply *ldbreply;
    struct ldb_request *ldbreq;
    struct ldb_message *msg;
    int ret, i;

    ret = sldb_request_recv(subreq, state, &ldbreply);
    if (ret) {
        talloc_zfree(subreq);
        tevent_req_error(req, ret);
        return;
    }

    switch (ldbreply->type) {
    case LDB_REPLY_ENTRY:
        state->v_msgs = talloc_realloc(state, state->v_msgs,
                                       struct ldb_message *,
                                       state->v_count + 2);
        if (!state->v_msgs) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        state->v_msgs[state->v_count] = talloc_move(state, &ldbreply->message);
        if (!state->v_msgs[state->v_count]) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        state->v_count++;

        /* just return, wait for a LDB_REPLY_DONE entry */
        talloc_zfree(ldbreply);
        return;

    case LDB_REPLY_DONE:
        break;

    default:
        /* unexpected stuff */
        tevent_req_error(req, EIO);
        talloc_zfree(ldbreply);
        return;
    }

    talloc_zfree(subreq);

    /* if anything was found, find the maximum and increment past it */
    if (state->v_count) {
        uint32_t id;

        for (i = 0; i < state->v_count; i++) {
            id = get_attr_as_uint32(state->v_msgs[i], SYSDB_UIDNUM);
            if (id != (uint32_t)(-1)) {
                if (id > state->new_id) state->new_id = id;
            }
            id = get_attr_as_uint32(state->v_msgs[i], SYSDB_GIDNUM);
            if (id != (uint32_t)(-1)) {
                if (id > state->new_id) state->new_id = id;
            }
        }

        state->new_id++;

        /* check again we are not falling out of range */
        if ((state->domain->id_max != 0) &&
            (state->new_id > state->domain->id_max)) {
            DEBUG(0, ("Failed to allocate new id, out of range (%u/%u)\n",
                      state->new_id, state->domain->id_max));
            tevent_req_error(req, ERANGE);
            return;
        }

        talloc_zfree(state->v_msgs);
        state->v_count = 0;
    }

    /* finally store the new next id */
    msg = ldb_msg_new(state);
    if (!msg) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    msg->dn = state->base_dn;

    ret = add_ulong(msg, LDB_FLAG_MOD_REPLACE,
                    SYSDB_NEXTID, state->new_id + 1);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    ret = ldb_build_mod_req(&ldbreq, state->handle->ctx->ldb, state, msg,
                            NULL, NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret,
                  ldb_errstring(state->handle->ctx->ldb)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sldb_request_send(state, state->ev,
                               state->handle->ctx->ldb, ldbreq);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_get_new_id_done, req);
}

static void sysdb_get_new_id_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_get_new_id_state *state = tevent_req_data(req,
                                                 struct sysdb_get_new_id_state);
    struct ldb_reply *ldbreply;
    int ret;

    ret = sldb_request_recv(subreq, state, &ldbreply);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (ldbreply->type != LDB_REPLY_DONE) {
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

int sysdb_get_new_id_recv(struct tevent_req *req, uint32_t *id)
{
    struct sysdb_get_new_id_state *state = tevent_req_data(req,
                                                 struct sysdb_get_new_id_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    *id = state->new_id;

    return EOK;
}


/* =Add-Basic-User-NO-CHECKS============================================== */

struct tevent_req *sysdb_add_basic_user_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             uid_t uid, gid_t gid,
                                             const char *gecos,
                                             const char *homedir,
                                             const char *shell)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_request *ldbreq;
    struct ldb_message *msg;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    msg = ldb_msg_new(state);
    if (!msg) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    /* user dn */
    msg->dn = sysdb_user_dn(handle->ctx, msg, domain->name, name);
    if (!msg->dn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    ret = add_string(msg, LDB_FLAG_MOD_ADD, "objectClass", SYSDB_USER_CLASS);
    if (ret) goto fail;

    ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_NAME, name);
    if (ret) goto fail;

    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_UIDNUM, (unsigned long)uid);
    if (ret) goto fail;

    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_GIDNUM, (unsigned long)gid);
    if (ret) goto fail;

    /* We set gecos to be the same as fullname on user creation,
     * But we will not enforce coherency after that, it's up to
     * admins to decide if they want to keep it in sync if they change
     * one of the 2 */
    if (gecos && *gecos) {
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_FULLNAME, gecos);
        if (ret) goto fail;
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_GECOS, gecos);
        if (ret) goto fail;
    }

    if (homedir && *homedir) {
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_HOMEDIR, homedir);
        if (ret) goto fail;
    }

    if (shell && *shell) {
        ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_SHELL, shell);
        if (ret) goto fail;
    }

    /* creation time */
    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_CREATE_TIME,
                    (unsigned long)time(NULL));
    if (ret) goto fail;


    ret = ldb_build_add_req(&ldbreq, handle->ctx->ldb, state, msg,
                            NULL, NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(handle->ctx->ldb)));
        ERROR_OUT(ret, sysdb_error_to_errno(ret), fail);
    }

    subreq = sldb_request_send(state, ev, handle->ctx->ldb, ldbreq);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_op_default_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

int sysdb_add_basic_user_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Add-User-Function===================================================== */

struct sysdb_add_user_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;

    const char *name;
    uid_t uid;
    gid_t gid;
    const char *gecos;
    const char *homedir;
    const char *shell;
    struct sysdb_attrs *attrs;
};

static void sysdb_add_user_group_check(struct tevent_req *subreq);
static void sysdb_add_user_uid_check(struct tevent_req *subreq);
static void sysdb_add_user_basic_done(struct tevent_req *subreq);
static void sysdb_add_user_get_id_done(struct tevent_req *subreq);
static void sysdb_add_user_set_id_done(struct tevent_req *subreq);
static void sysdb_add_user_set_attrs_done(struct tevent_req *subreq);

struct tevent_req *sysdb_add_user_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sysdb_handle *handle,
                                       struct sss_domain_info *domain,
                                       const char *name,
                                       uid_t uid, gid_t gid,
                                       const char *gecos,
                                       const char *homedir,
                                       const char *shell,
                                       struct sysdb_attrs *attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_add_user_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_add_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->name = name;
    state->uid = uid;
    state->gid = gid;
    state->gecos = gecos;
    state->homedir = homedir;
    state->shell = shell;
    state->attrs = attrs;

    if (domain->mpg) {
        if (gid != 0) {
            DEBUG(0, ("Cannot add user with arbitrary GID in MPG domain!\n"));
            ERROR_OUT(ret, EINVAL, fail);
        }
        state->gid = state->uid;
    }

    if (domain->id_max != 0 && uid != 0 &&
        (uid < domain->id_min || uid > domain->id_max)) {
        DEBUG(2, ("Supplied uid [%d] is not in the allowed range [%d-%d].\n",
                  uid, domain->id_min, domain->id_max));
        ERROR_OUT(ret, EINVAL, fail);
    }

    if (domain->id_max != 0 && gid != 0 &&
        (gid < domain->id_min || gid > domain->id_max)) {
        DEBUG(2, ("Supplied gid [%d] is not in the allowed range [%d-%d].\n",
                  gid, domain->id_min, domain->id_max));
        ERROR_OUT(ret, EINVAL, fail);
    }

    if (domain->mpg) {
        /* In MPG domains you can't have groups with the same name as users,
         * search if a group with the same name exists.
         * Don't worry about users, if we try to add a user with the same
         * name the operation will fail */

        subreq = sysdb_search_group_by_name_send(state, ev, NULL, handle,
                                                 domain, name, NULL);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_add_user_group_check, req);
        return req;
    }

    /* check no other user with the same uid exist */
    if (state->uid != 0) {
        subreq = sysdb_search_user_by_uid_send(state, ev, NULL, handle,
                                               domain, uid, NULL);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_add_user_uid_check, req);
        return req;
    }

    /* try to add the user */
    subreq = sysdb_add_basic_user_send(state, ev, handle,
                                       domain, name, uid, gid,
                                       gecos, homedir, shell);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_add_user_basic_done, req);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_add_user_group_check(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_user_state *state = tevent_req_data(req,
                                            struct sysdb_add_user_state);
    struct ldb_message *msg;
    int ret;

    /* We can succeed only if we get an ENOENT error, which means no groups
     * with the same name exist.
     * If any other error is returned fail as well. */
    ret = sysdb_search_group_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret != ENOENT) {
        if (ret == EOK) ret = EEXIST;
        tevent_req_error(req, ret);
        return;
    }

    /* check no other user with the same uid exist */
    if (state->uid != 0) {
        subreq = sysdb_search_user_by_uid_send(state, state->ev,
                                               NULL, state->handle,
                                               state->domain, state->uid,
                                               NULL);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_user_uid_check, req);
        return;
    }

    /* try to add the user */
    subreq = sysdb_add_basic_user_send(state, state->ev, state->handle,
                                       state->domain, state->name,
                                       state->uid, state->gid,
                                       state->gecos,
                                       state->homedir,
                                       state->shell);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_add_user_basic_done, req);
}

static void sysdb_add_user_uid_check(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_user_state *state = tevent_req_data(req,
                                            struct sysdb_add_user_state);
    struct ldb_message *msg;
    int ret;

    /* We can succeed only if we get an ENOENT error, which means no user
     * with the same uid exist.
     * If any other error is returned fail as well. */
    ret = sysdb_search_user_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret != ENOENT) {
        if (ret == EOK) ret = EEXIST;
        tevent_req_error(req, ret);
        return;
    }

    /* try to add the user */
    subreq = sysdb_add_basic_user_send(state, state->ev, state->handle,
                                       state->domain, state->name,
                                       state->uid, state->gid,
                                       state->gecos,
                                       state->homedir,
                                       state->shell);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_add_user_basic_done, req);
}

static void sysdb_add_user_basic_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_user_state *state = tevent_req_data(req,
                                            struct sysdb_add_user_state);
    int ret;

    ret = sysdb_add_basic_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->uid == 0) {
        subreq = sysdb_get_new_id_send(state,
                                       state->ev, state->handle,
                                       state->domain);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_user_get_id_done, req);
        return;
    }

    if (state->attrs) {
        subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                          state->domain, state->name,
                                          state->attrs, SYSDB_MOD_ADD);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_user_set_attrs_done, req);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_add_user_get_id_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_user_state *state = tevent_req_data(req,
                                            struct sysdb_add_user_state);
    struct sysdb_attrs *id_attrs;
    uint32_t id;
    int ret;

    ret = sysdb_get_new_id_recv(subreq, &id);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->uid == 0) {
        id_attrs = sysdb_new_attrs(state);
        if (!id_attrs) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        ret = sysdb_attrs_add_uint32(id_attrs, SYSDB_UIDNUM, id);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
        if (state->domain->mpg) {
            ret = sysdb_attrs_add_uint32(id_attrs, SYSDB_GIDNUM, id);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
        }

        subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                          state->domain, state->name,
                                          id_attrs, SYSDB_MOD_REP);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_user_set_id_done, req);
        return;
    }

    if (state->attrs) {
        subreq = sysdb_set_user_attr_send(state, state->ev,
                                          state->handle, state->domain,
                                          state->name, state->attrs,
                                          SYSDB_MOD_REP);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_user_set_attrs_done, req);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_add_user_set_id_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_user_state *state = tevent_req_data(req,
                                            struct sysdb_add_user_state);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->attrs) {
        subreq = sysdb_set_user_attr_send(state, state->ev,
                                          state->handle, state->domain,
                                          state->name, state->attrs,
                                          SYSDB_MOD_REP);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_user_set_attrs_done, req);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_add_user_set_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_add_user_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Add-Basic-Group-NO-CHECKS============================================= */

struct tevent_req *sysdb_add_basic_group_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct sysdb_handle *handle,
                                              struct sss_domain_info *domain,
                                              const char *name, gid_t gid)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_request *ldbreq;
    struct ldb_message *msg;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    msg = ldb_msg_new(state);
    if (!msg) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    /* user dn */
    msg->dn = sysdb_group_dn(handle->ctx, msg, domain->name, name);
    if (!msg->dn) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    ret = add_string(msg, LDB_FLAG_MOD_ADD, "objectClass", SYSDB_GROUP_CLASS);
    if (ret) goto fail;

    ret = add_string(msg, LDB_FLAG_MOD_ADD, SYSDB_NAME, name);
    if (ret) goto fail;

    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_GIDNUM, (unsigned long)gid);
    if (ret) goto fail;

    /* creation time */
    ret = add_ulong(msg, LDB_FLAG_MOD_ADD, SYSDB_CREATE_TIME,
                    (unsigned long)time(NULL));
    if (ret) goto fail;


    ret = ldb_build_add_req(&ldbreq, handle->ctx->ldb, state, msg,
                            NULL, NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(handle->ctx->ldb)));
        ERROR_OUT(ret, sysdb_error_to_errno(ret), fail);
    }

    subreq = sldb_request_send(state, ev, handle->ctx->ldb, ldbreq);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_op_default_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

int sysdb_add_basic_group_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Add-Group-Function==================================================== */

struct sysdb_add_group_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;

    const char *name;
    gid_t gid;
    struct sysdb_attrs *attrs;
};

static void sysdb_add_group_user_check(struct tevent_req *subreq);
static void sysdb_add_group_gid_check(struct tevent_req *subreq);
static void sysdb_add_group_basic_done(struct tevent_req *subreq);
static void sysdb_add_group_get_id_done(struct tevent_req *subreq);
static void sysdb_add_group_set_id_done(struct tevent_req *subreq);
static void sysdb_add_group_set_attrs_done(struct tevent_req *subreq);

struct tevent_req *sysdb_add_group_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sysdb_handle *handle,
                                        struct sss_domain_info *domain,
                                        const char *name, gid_t gid,
                                        struct sysdb_attrs *attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_add_group_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_add_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->name = name;
    state->gid = gid;
    state->attrs = attrs;

    if (domain->id_max != 0 && gid != 0 &&
        (gid < domain->id_min || gid > domain->id_max)) {
        DEBUG(2, ("Supplied gid [%d] is not in the allowed range [%d-%d].\n",
                  gid, domain->id_min, domain->id_max));
        ERROR_OUT(ret, EINVAL, fail);
    }

    if (domain->mpg) {
        /* In MPG domains you can't have groups with the same name as users,
         * search if a group with the same name exists.
         * Don't worry about users, if we try to add a user with the same
         * name the operation will fail */

        subreq = sysdb_search_user_by_name_send(state, ev, NULL, handle,
                                                domain, name, NULL);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_add_group_user_check, req);
        return req;
    }

    /* check no other groups with the same gid exist */
    if (state->gid != 0) {
        subreq = sysdb_search_group_by_gid_send(state, ev, NULL, handle,
                                                domain, gid, NULL);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_add_group_gid_check, req);
        return req;
    }

    /* try to add the group */
    subreq = sysdb_add_basic_group_send(state, ev, handle,
                                        domain, name, gid);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_add_group_basic_done, req);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_add_group_user_check(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_group_state *state = tevent_req_data(req,
                                           struct sysdb_add_group_state);
    struct ldb_message *msg;
    int ret;

    /* We can succeed only if we get an ENOENT error, which means no users
     * with the same name exist.
     * If any other error is returned fail as well. */
    ret = sysdb_search_user_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret != ENOENT) {
        if (ret == EOK) ret = EEXIST;
        tevent_req_error(req, ret);
        return;
    }

    /* check no other group with the same gid exist */
    if (state->gid != 0) {
        subreq = sysdb_search_group_by_gid_send(state, state->ev,
                                                NULL, state->handle,
                                                state->domain, state->gid,
                                                NULL);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_group_gid_check, req);
        return;
    }

    /* try to add the group */
    subreq = sysdb_add_basic_group_send(state, state->ev,
                                        state->handle, state->domain,
                                        state->name, state->gid);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_add_group_basic_done, req);
}

static void sysdb_add_group_gid_check(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_group_state *state = tevent_req_data(req,
                                           struct sysdb_add_group_state);
    struct ldb_message *msg;
    int ret;

    /* We can succeed only if we get an ENOENT error, which means no group
     * with the same gid exist.
     * If any other error is returned fail as well. */
    ret = sysdb_search_group_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret != ENOENT) {
        if (ret == EOK) ret = EEXIST;
        tevent_req_error(req, ret);
        return;
    }

    /* try to add the group */
    subreq = sysdb_add_basic_group_send(state, state->ev,
                                        state->handle, state->domain,
                                        state->name, state->gid);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_add_group_basic_done, req);
}

static void sysdb_add_group_basic_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_group_state *state = tevent_req_data(req,
                                           struct sysdb_add_group_state);
    int ret;

    ret = sysdb_add_basic_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->gid == 0) {
        subreq = sysdb_get_new_id_send(state,
                                       state->ev, state->handle,
                                       state->domain);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_group_get_id_done, req);
        return;
    }

    if (state->attrs) {
        subreq = sysdb_set_group_attr_send(state, state->ev,
                                           state->handle, state->domain,
                                           state->name, state->attrs,
                                           SYSDB_MOD_ADD);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_group_set_attrs_done, req);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_add_group_get_id_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_group_state *state = tevent_req_data(req,
                                           struct sysdb_add_group_state);
    struct sysdb_attrs *id_attrs;
    uint32_t id;
    int ret;

    ret = sysdb_get_new_id_recv(subreq, &id);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->gid == 0) {
        id_attrs = sysdb_new_attrs(state);
        if (!id_attrs) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        ret = sysdb_attrs_add_uint32(id_attrs, SYSDB_GIDNUM, id);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }

        subreq = sysdb_set_group_attr_send(state, state->ev, state->handle,
                                           state->domain, state->name,
                                           id_attrs, SYSDB_MOD_REP);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_group_set_id_done, req);
        return;
    }

    if (state->attrs) {
        subreq = sysdb_set_group_attr_send(state, state->ev,
                                           state->handle, state->domain,
                                           state->name, state->attrs,
                                           SYSDB_MOD_ADD);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_group_set_attrs_done, req);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_add_group_set_id_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_group_state *state = tevent_req_data(req,
                                           struct sysdb_add_group_state);
    int ret;

    ret = sysdb_set_group_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->attrs) {
        subreq = sysdb_set_group_attr_send(state, state->ev,
                                           state->handle, state->domain,
                                           state->name, state->attrs,
                                           SYSDB_MOD_ADD);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_group_set_attrs_done, req);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_add_group_set_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_set_group_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_add_group_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Add-Or-Remove-Group-Memeber=========================================== */

/* mod_op must be either SYSDB_MOD_ADD or SYSDB_MOD_DEL */
struct tevent_req *sysdb_mod_group_member_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct ldb_dn *member_dn,
                                               struct ldb_dn *group_dn,
                                               int mod_op)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_request *ldbreq;
    struct ldb_message *msg;
    const char *dn;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    msg = ldb_msg_new(state);
    if (!msg) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    msg->dn = group_dn;
    ret = ldb_msg_add_empty(msg, SYSDB_MEMBER, mod_op, NULL);
    if (ret != LDB_SUCCESS) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    dn = ldb_dn_get_linearized(member_dn);
    if (!dn) {
        ERROR_OUT(ret, EINVAL, fail);
    }

    ret = ldb_msg_add_fmt(msg, SYSDB_MEMBER, "%s", dn);
    if (ret != LDB_SUCCESS) {
        ERROR_OUT(ret, EINVAL, fail);
    }

    ret = ldb_build_mod_req(&ldbreq, handle->ctx->ldb, state, msg,
                            NULL, NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build modify request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(handle->ctx->ldb)));
        ERROR_OUT(ret, sysdb_error_to_errno(ret), fail);
    }

    subreq = sldb_request_send(state, ev, handle->ctx->ldb, ldbreq);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_op_default_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

int sysdb_mod_group_member_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Store-Users-(Native/Legacy)-(replaces-existing-data)================== */

/* if one of the basic attributes is empty ("") as opposed to NULL,
 * this will just remove it */

struct sysdb_store_user_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;

    const char *name;
    uid_t uid;
    gid_t gid;
    const char *gecos;
    const char *homedir;
    const char *shell;
    struct sysdb_attrs *attrs;
};

static void sysdb_store_user_check(struct tevent_req *subreq);
static void sysdb_store_user_add_done(struct tevent_req *subreq);
static void sysdb_store_user_attr_done(struct tevent_req *subreq);

struct tevent_req *sysdb_store_user_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain,
                                         const char *name,
                                         const char *pwd,
                                         uid_t uid, gid_t gid,
                                         const char *gecos,
                                         const char *homedir,
                                         const char *shell)
{
    struct tevent_req *req, *subreq;
    struct sysdb_store_user_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_store_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->name = name;
    state->uid = uid;
    state->gid = gid;
    state->gecos = gecos;
    state->homedir = homedir;
    state->shell = shell;
    state->attrs = NULL;

    if (pwd && (domain->legacy_passwords || !*pwd)) {
        ret = sysdb_attrs_add_string(state->attrs, SYSDB_PWD, pwd);
        if (ret) goto fail;
    }

    subreq = sysdb_search_user_by_name_send(state, ev, NULL, handle,
                                            domain, name, NULL);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_store_user_check, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_store_user_check(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_store_user_state *state = tevent_req_data(req,
                                               struct sysdb_store_user_state);
    struct ldb_message *msg;
    int ret;

    ret = sysdb_search_user_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT) {
        /* users doesn't exist, turn into adding a user */
        subreq = sysdb_add_user_send(state, state->ev, state->handle,
                                     state->domain, state->name,
                                     state->uid, state->gid,
                                     state->gecos, state->homedir,
                                     state->shell, state->attrs);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_store_user_add_done, req);
        return;
    }

    /* the user exists, let's just replace attributes when set */
    if (!state->attrs) {
        state->attrs = sysdb_new_attrs(state);
        if (!state->attrs) {
            tevent_req_error(req, ENOMEM);
            return;
        }
    }

    if (state->uid) {
        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_UIDNUM, state->uid);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->gid) {
        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_GIDNUM, state->gid);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->uid && !state->gid && state->domain->mpg) {
        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_GIDNUM, state->uid);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->gecos) {
        ret = sysdb_attrs_add_string(state->attrs, SYSDB_GECOS, state->gecos);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->homedir) {
        ret = sysdb_attrs_add_string(state->attrs,
                                     SYSDB_HOMEDIR, state->homedir);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->shell) {
        ret = sysdb_attrs_add_string(state->attrs, SYSDB_SHELL, state->shell);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_LAST_UPDATE, time(NULL));
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_user_attr_send(state, state->ev,
                                      state->handle, state->domain,
                                      state->name, state->attrs,
                                      SYSDB_MOD_REP);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_store_user_attr_done, req);
}

static void sysdb_store_user_add_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_add_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_store_user_attr_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_store_user_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Store-Group-(Native/Legacy)-(replaces-existing-data)================== */

/* this function does not check that all user members are actually present */

struct sysdb_store_group_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;

    const char *name;
    gid_t gid;
    const char **members;

    struct sysdb_attrs *attrs;
};

static void sysdb_store_group_check(struct tevent_req *subreq);
static void sysdb_store_group_add_done(struct tevent_req *subreq);
static void sysdb_store_group_attr_done(struct tevent_req *subreq);

struct tevent_req *sysdb_store_group_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_handle *handle,
                                          struct sss_domain_info *domain,
                                          const char *name,
                                          gid_t gid,
                                          const char **members)
{
    struct tevent_req *req, *subreq;
    struct sysdb_store_group_state *state;
    int ret, i;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_store_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->name = name;
    state->gid = gid;
    state->members = members;
    state->attrs = NULL;

    if (state->members) {
        state->attrs = sysdb_new_attrs(state);
        if (!state->attrs) {
            ERROR_OUT(ret, ENOMEM, fail);
        }

        for (i = 0; state->members[i]; i++) {
            if (domain->legacy) {
/*
                const char *member;

                member = talloc_asprintf(state, SYSDB_TMPL_USER,
                                         domain->name, state->members[i]);
                if (!member) {
                    ERROR_OUT(ret, ENOMEM, fail);
                }
*/
                ret = sysdb_attrs_add_string(state->attrs, SYSDB_LEGACY_MEMBER,
                                             state->members[i]);
                if (ret) goto fail;
            } else {
                ret = sysdb_attrs_add_string(state->attrs, SYSDB_MEMBER,
                                             state->members[i]);
                if (ret) goto fail;
            }
        }

        state->members = NULL;
    }

    subreq = sysdb_search_group_by_name_send(state, ev, NULL, handle,
                                             domain, name, NULL);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_store_group_check, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_store_group_check(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_store_group_state *state = tevent_req_data(req,
                                               struct sysdb_store_group_state);
    struct ldb_message *msg;
    int ret;

    ret = sysdb_search_group_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT) {
        /* groups doesn't exist, turn into adding a group */
        subreq = sysdb_add_group_send(state, state->ev, state->handle,
                                     state->domain, state->name,
                                     state->gid, state->attrs);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_store_group_add_done, req);
        return;
    }

    /* the group exists, let's just replace attributes when set */
    if (!state->attrs) {
        state->attrs = sysdb_new_attrs(state);
        if (!state->attrs) {
            tevent_req_error(req, ENOMEM);
            return;
        }
    }

    if (state->gid) {
        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_GIDNUM, state->gid);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }
    }

    /* FIXME: handle non legacy groups */

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_LAST_UPDATE, time(NULL));
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_group_attr_send(state, state->ev,
                                      state->handle, state->domain,
                                      state->name, state->attrs,
                                      SYSDB_MOD_REP);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_store_group_attr_done, req);
}

static void sysdb_store_group_add_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_add_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_store_group_attr_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_set_group_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_store_group_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Add-User-to-Group(Native/Legacy)====================================== */

static void sysdb_add_group_member_done(struct tevent_req *subreq);
static void sysdb_add_group_member_l_done(struct tevent_req *subreq);

struct tevent_req *sysdb_add_group_member_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct sss_domain_info *domain,
                                               const char *group,
                                               const char *user)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_dn *group_dn, *user_dn;
    struct sysdb_attrs *attrs;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    if (domain->legacy) {
        attrs = sysdb_new_attrs(state);
        if (!attrs) {
            ERROR_OUT(ret, ENOMEM, fail);
        }

        ret = sysdb_attrs_add_string(attrs, SYSDB_LEGACY_MEMBER, user);
        if (ret) goto fail;

        subreq = sysdb_set_group_attr_send(state, ev, handle,
                                           domain, group, attrs,
                                           SYSDB_MOD_ADD);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_add_group_member_l_done, req);

    } else {
        group_dn = sysdb_group_dn(handle->ctx, state, domain->name, group);
        if (!group_dn) {
            ERROR_OUT(ret, ENOMEM, fail);
        }

        user_dn = sysdb_user_dn(handle->ctx, state, domain->name, user);
        if (!user_dn) {
            ERROR_OUT(ret, ENOMEM, fail);
        }

        subreq = sysdb_mod_group_member_send(state, ev, handle,
                                             user_dn, group_dn,
                                             SYSDB_MOD_ADD);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_add_group_member_done, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_add_group_member_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_mod_group_member_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_add_group_member_l_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_set_group_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_add_group_member_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Remove-member-from-Group(Native/Legacy)=============================== */

static void sysdb_remove_group_member_done(struct tevent_req *subreq);
static void sysdb_remove_group_member_l_done(struct tevent_req *subreq);

struct tevent_req *sysdb_remove_group_member_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  const char *group,
                                                  const char *user)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_dn *group_dn, *user_dn;
    struct sysdb_attrs *attrs;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

    if (domain->legacy) {
        attrs = sysdb_new_attrs(state);
        if (!attrs) {
            ERROR_OUT(ret, ENOMEM, fail);
        }

        ret = sysdb_attrs_add_string(attrs, SYSDB_LEGACY_MEMBER, user);
        if (ret) goto fail;

        subreq = sysdb_set_group_attr_send(state, ev, handle,
                                           domain, group, attrs,
                                           SYSDB_MOD_DEL);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_remove_group_member_l_done, req);

    } else {
        group_dn = sysdb_group_dn(handle->ctx, state, domain->name, group);
        if (!group_dn) {
            ERROR_OUT(ret, ENOMEM, fail);
        }

        user_dn = sysdb_user_dn(handle->ctx, state, domain->name, user);
        if (!user_dn) {
            ERROR_OUT(ret, ENOMEM, fail);
        }

        subreq = sysdb_mod_group_member_send(state, ev, handle,
                                             user_dn, group_dn,
                                             SYSDB_MOD_DEL);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_remove_group_member_done, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_remove_group_member_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_mod_group_member_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void sysdb_remove_group_member_l_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_set_group_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_remove_group_member_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Password-Caching====================================================== */

struct sysdb_cache_pw_state {
    struct tevent_context *ev;
    struct sss_domain_info *domain;

    const char *username;
    struct sysdb_attrs *attrs;

    struct sysdb_handle *handle;
    bool commit;
};

static void sysdb_cache_password_trans(struct tevent_req *subreq);
static void sysdb_cache_password_done(struct tevent_req *subreq);

struct tevent_req *sysdb_cache_password_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_ctx *sysdb,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *username,
                                             const char *password)
{
    struct tevent_req *req, *subreq;
    struct sysdb_cache_pw_state *state;
    char *hash = NULL;
    char *salt;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_cache_pw_state);
    if (!req) return NULL;

    state->ev = ev;
    state->domain = domain;
    state->username = username;

    ret = s3crypt_gen_salt(state, &salt);
    if (ret) {
        DEBUG(4, ("Failed to generate random salt.\n"));
        goto fail;
    }

    ret = s3crypt_sha512(state, password, salt, &hash);
    if (ret) {
        DEBUG(4, ("Failed to create password hash.\n"));
        goto fail;
    }

    state->attrs = sysdb_new_attrs(state);
    if (!state->attrs) {
        ERROR_OUT(ret, ENOMEM, fail);
    }

    ret = sysdb_attrs_add_string(state->attrs, SYSDB_CACHEDPWD, hash);
    if (ret) goto fail;

    /* FIXME: should we use a different attribute for chache passwords ?? */
    ret = sysdb_attrs_add_long(state->attrs, "lastCachedPasswordChange",
                               (long)time(NULL));
    if (ret) goto fail;

    state->handle = NULL;

    if (handle) {
        state->handle = handle;
        state->commit = false;

        subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                          state->domain, state->username,
                                          state->attrs, SYSDB_MOD_REP);
        if (!subreq) {
            ERROR_OUT(ret, ENOMEM, fail);
        }
        tevent_req_set_callback(subreq, sysdb_cache_password_done, req);
    } else {
        state->commit = true;

        subreq = sysdb_transaction_send(state, state->ev, sysdb);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, sysdb_cache_password_trans, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_cache_password_trans(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_cache_pw_state *state = tevent_req_data(req,
                                                  struct sysdb_cache_pw_state);
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                      state->domain, state->username,
                                      state->attrs, SYSDB_MOD_REP);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_cache_password_done, req);
}

static void sysdb_cache_password_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_cache_pw_state *state = tevent_req_data(req,
                                                  struct sysdb_cache_pw_state);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->commit) {
        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
        return;
    }

    tevent_req_done(req);
}

int sysdb_cache_password_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}

