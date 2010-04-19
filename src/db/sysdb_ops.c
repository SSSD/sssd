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
#include "util/sha512crypt.h"
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
        int err = sysdb_error_to_errno(ret);
        DEBUG(6, ("Error: %d (%s)\n", err, strerror(err)));
        tevent_req_error(req, err);
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
        DEBUG(6, ("Error: Missing ldbreply\n"));
        ERROR_OUT(err, EIO, fail);
    }

    state->ldbreply = talloc_steal(state, ldbreply);

    if (ldbreply->error != LDB_SUCCESS) {
        DEBUG(6, ("LDB Error: %d (%s)\n",
                  ldbreply->error, ldb_errstring(state->ldbctx)));
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
        switch (tstate) {
        case TEVENT_REQ_USER_ERROR:
            return err;
        case TEVENT_REQ_IN_PROGRESS:
             return EOK;
        default:
            return EIO;
        }
    }

    return EOK;
}

/* =Standard-Sysdb-Operations-utility-functions=========================== */

struct sysdb_op_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;

    bool ignore_not_found;

    struct ldb_reply *ldbreply;
    size_t msgs_count;
    struct ldb_message **msgs;
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    if (state->ldbreply->type != LDB_REPLY_DONE) {
        DEBUG(6, ("Error: %d (%s)\n", EIO, strerror(EIO)));
        tevent_req_error(req, EIO);
        return;
    }

done:
    tevent_req_done(req);
}

static int sysdb_op_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* =Remove-Entry-From-Sysdb=============================================== */

struct tevent_req *sysdb_delete_entry_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_handle *handle,
                                           struct ldb_dn *dn,
                                           bool ignore_not_found)
{
    struct tevent_req *req, *subreq;
    struct sysdb_op_state *state;
    struct ldb_request *ldbreq;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = ignore_not_found;
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

int sysdb_delete_entry_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Remove-Subentries-From-Sysdb=============================================== */

struct sysdb_delete_recursive_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;

    bool ignore_not_found;

    struct ldb_reply *ldbreply;
    size_t msgs_count;
    struct ldb_message **msgs;
    size_t current_item;
};

static void sysdb_delete_search_done(struct tevent_req *subreq);
static void sysdb_delete_recursive_prepare_op(struct tevent_req *req);
static void sysdb_delete_recursive_op_done(struct tevent_req *req);

struct tevent_req *sysdb_delete_recursive_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct ldb_dn *dn,
                                               bool ignore_not_found)
{
    struct tevent_req *req, *subreq;
    struct sysdb_delete_recursive_state *state;
    int ret;
    const char **no_attrs;

    req = tevent_req_create(mem_ctx, &state,
                            struct sysdb_delete_recursive_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = ignore_not_found;
    state->ldbreply = NULL;
    state->msgs_count = 0;
    state->msgs = NULL;
    state->current_item = 0;

    no_attrs = talloc_array(state, const char *, 1);
    if (no_attrs == NULL) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    no_attrs[0] = NULL;

    subreq = sysdb_search_entry_send(state, ev, handle, dn, LDB_SCOPE_SUBTREE,
                                     "(distinguishedName=*)", no_attrs);

    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_delete_search_done, req);

    return req;

fail:
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_delete_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_delete_recursive_state *state = tevent_req_data(req,
                                           struct sysdb_delete_recursive_state);
    int ret;

    ret = sysdb_search_entry_recv(subreq, state, &state->msgs_count,
                                  &state->msgs);
    talloc_zfree(subreq);
    if (ret) {
        if (state->ignore_not_found && ret == ENOENT) {
            tevent_req_done(req);
            return;
        }
        DEBUG(6, ("Search error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }
    DEBUG(9, ("Found [%d] items to delete.\n", state->msgs_count));

    qsort(state->msgs, state->msgs_count, sizeof(struct ldb_message *),
          compare_ldb_dn_comp_num);

    state->current_item = 0;
    sysdb_delete_recursive_prepare_op(req);
}

static void sysdb_delete_recursive_prepare_op(struct tevent_req *req)
{
    struct sysdb_delete_recursive_state *state = tevent_req_data(req,
                                           struct sysdb_delete_recursive_state);
    struct tevent_req *subreq;
    int ret;
    struct ldb_request *ldbreq;

    if (state->current_item < state->msgs_count) {
        DEBUG(9 ,("Trying to delete [%s].\n",
                  ldb_dn_canonical_string(state,
                                        state->msgs[state->current_item]->dn)));
        ret = ldb_build_del_req(&ldbreq, state->handle->ctx->ldb, state,
                                state->msgs[state->current_item]->dn, NULL,
                                NULL, NULL, NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(1, ("LDB Error: %s(%d)\nError Message: [%s]\n",
                      ldb_strerror(ret), ret,
                      ldb_errstring(state->handle->ctx->ldb)));
            ret = sysdb_error_to_errno(ret);
            goto fail;
        }

        subreq = sldb_request_send(state, state->ev, state->handle->ctx->ldb,
                                   ldbreq);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        state->current_item++;
        tevent_req_set_callback(subreq, sysdb_delete_recursive_op_done, req);
        return;
    }

    tevent_req_done(req);
    return;

fail:
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
    tevent_req_error(req, ret);
}

static void sysdb_delete_recursive_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    int ret;

    ret = sysdb_op_default_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(6, ("Delete error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    sysdb_delete_recursive_prepare_op(req);
}

int sysdb_delete_recursive_recv(struct tevent_req *req)
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
    state->msgs_count = 0;
    state->msgs = NULL;

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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    struct ldb_message **dummy;
    int ret;

    ret = sldb_request_recv(subreq, state, &ldbreply);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    switch (ldbreply->type) {
    case LDB_REPLY_ENTRY:
        dummy = talloc_realloc(state, state->msgs,
                                     struct ldb_message *,
                                     state->msgs_count + 2);
        if (dummy == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        state->msgs = dummy;

        state->msgs[state->msgs_count + 1] = NULL;

        state->msgs[state->msgs_count] = talloc_steal(state->msgs,
                                                      ldbreply->message);
        state->msgs_count++;

        talloc_zfree(ldbreply);
        return;

    case LDB_REPLY_DONE:
        talloc_zfree(subreq);
        talloc_zfree(ldbreply);
        if (state->msgs_count == 0) {
            DEBUG(6, ("Error: Entry not Found!\n"));
            tevent_req_error(req, ENOENT);
            return;
        }
        return tevent_req_done(req);

    default:
        /* unexpected stuff */
        talloc_zfree(ldbreply);
        DEBUG(6, ("Error: Unknown error!\n"));
        tevent_req_error(req, EIO);
        return;
    }
}

int sysdb_search_entry_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            size_t *msgs_count,
                            struct ldb_message ***msgs)
{
    struct sysdb_op_state *state = tevent_req_data(req,
                                                   struct sysdb_op_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *msgs_count = state->msgs_count;
    *msgs = talloc_move(mem_ctx, &state->msgs);

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

    size_t msgs_count;
    struct ldb_message **msgs;
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
    state->msgs_count = 0;
    state->msgs = NULL;

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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    state->msgs_count = 0;
    state->msgs = NULL;
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                     state->basedn, state->scope,
                                     state->filter, state->attrs);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
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

    ret = sysdb_search_entry_recv(subreq, state, &state->msgs_count,
                                  &state->msgs);
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

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->msgs_count > 1) {
        DEBUG(1, ("More than one result found.\n"));
        return EFAULT;
    }

    *msg = talloc_move(mem_ctx, &state->msgs[0]);

    return EOK;
}


/* =Search-Group-by-[GID/NAME]============================================ */

struct sysdb_search_group_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;

    struct ldb_dn *basedn;
    const char **attrs;
    const char *filter;
    int scope;

    size_t msgs_count;
    struct ldb_message **msgs;
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
    state->msgs_count = 0;
    state->msgs = NULL;

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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    state->msgs_count = 0;
    state->msgs = NULL;
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                     state->basedn, state->scope,
                                     state->filter, state->attrs);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
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

    ret = sysdb_search_entry_recv(subreq, state, &state->msgs_count,
                                  &state->msgs);
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

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->msgs_count > 1) {
        DEBUG(1, ("More than one result found.\n"));
        return EFAULT;
    }

    *msg = talloc_move(mem_ctx, &state->msgs[0]);

    return EOK;
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    switch (ldbreply->type) {
    case LDB_REPLY_ENTRY:
        if (state->base) {
            DEBUG(1, ("More than one reply for a base search ?! "
                      "DB seems corrupted, aborting.\n"));
            tevent_req_error(req, EFAULT);
            return;
        }

        state->base = talloc_move(state, &ldbreply->message);
        if (!state->base) {
            DEBUG(6, ("Error: Out of memory!\n"));
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
        DEBUG(6, ("Error: Unknown error\n"));
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
    if (state->domain->id_max) {
        filter = talloc_asprintf(state,
                                 "(|(&(%s>=%u)(%s<=%u))(&(%s>=%u)(%s<=%u)))",
                                 SYSDB_UIDNUM, state->new_id,
                                 SYSDB_UIDNUM, state->domain->id_max,
                                 SYSDB_GIDNUM, state->new_id,
                                 SYSDB_GIDNUM, state->domain->id_max);
    }
    else {
        filter = talloc_asprintf(state,
                                 "(|(%s>=%u)(%s>=%u))",
                                 SYSDB_UIDNUM, state->new_id,
                                 SYSDB_GIDNUM, state->new_id);
    }
    if (!filter) {
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    switch (ldbreply->type) {
    case LDB_REPLY_ENTRY:
        state->v_msgs = talloc_realloc(state, state->v_msgs,
                                       struct ldb_message *,
                                       state->v_count + 2);
        if (!state->v_msgs) {
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }

        state->v_msgs[state->v_count] = talloc_move(state, &ldbreply->message);
        if (!state->v_msgs[state->v_count]) {
            DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: Unknown error\n"));
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
        DEBUG(6, ("Error: Out of memory\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    msg->dn = state->base_dn;

    ret = add_ulong(msg, LDB_FLAG_MOD_REPLACE,
                    SYSDB_NEXTID, state->new_id + 1);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    if (ldbreply->type != LDB_REPLY_DONE) {
        DEBUG(6, ("Error: %d (%s)\n", EIO, strerror(EIO)));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

int sysdb_get_new_id_recv(struct tevent_req *req, uint32_t *id)
{
    struct sysdb_get_new_id_state *state = tevent_req_data(req,
                                                 struct sysdb_get_new_id_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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

    int cache_timeout;
};

static void sysdb_add_user_group_check(struct tevent_req *subreq);
static void sysdb_add_user_uid_check(struct tevent_req *subreq);
static void sysdb_add_user_basic_done(struct tevent_req *subreq);
static void sysdb_add_user_get_id_done(struct tevent_req *subreq);
static void sysdb_add_user_set_id_done(struct tevent_req *subreq);
static void sysdb_add_user_set_attrs(struct tevent_req *req);
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
                                       struct sysdb_attrs *attrs,
                                       int cache_timeout)
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
    state->cache_timeout = cache_timeout;

    if (handle->ctx->mpg) {
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
        ERROR_OUT(ret, ERANGE, fail);
    }

    if (domain->id_max != 0 && gid != 0 &&
        (gid < domain->id_min || gid > domain->id_max)) {
        DEBUG(2, ("Supplied gid [%d] is not in the allowed range [%d-%d].\n",
                  gid, domain->id_min, domain->id_max));
        ERROR_OUT(ret, ERANGE, fail);
    }

    if (handle->ctx->mpg) {
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
            DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    if (state->uid == 0) {
        subreq = sysdb_get_new_id_send(state,
                                       state->ev, state->handle,
                                       state->domain);
        if (!subreq) {
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_user_get_id_done, req);
        return;
    }

    sysdb_add_user_set_attrs(req);
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
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }
        ret = sysdb_attrs_add_uint32(id_attrs, SYSDB_UIDNUM, id);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
        if (state->handle->ctx->mpg) {
            ret = sysdb_attrs_add_uint32(id_attrs, SYSDB_GIDNUM, id);
            if (ret) {
                DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
                tevent_req_error(req, ret);
                return;
            }
        }

        subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                          state->domain, state->name,
                                          id_attrs, SYSDB_MOD_REP);
        if (!subreq) {
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_user_set_id_done, req);
        return;
    }

    sysdb_add_user_set_attrs(req);
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
    }

    tevent_req_done(req);
}

static void sysdb_add_user_set_attrs(struct tevent_req *req)
{
    struct sysdb_add_user_state *state = tevent_req_data(req,
                                            struct sysdb_add_user_state);
    struct tevent_req *subreq;
    time_t now = time(NULL);
    int ret;

    if (!state->attrs) {
        state->attrs = sysdb_new_attrs(state);
        if (!state->attrs) {
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_CACHE_EXPIRE,
                                 ((state->cache_timeout) ?
                                  (now + state->cache_timeout) : 0));
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_user_attr_send(state, state->ev,
                                      state->handle, state->domain,
                                      state->name, state->attrs,
                                      SYSDB_MOD_REP);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_add_user_set_attrs_done, req);
}

static void sysdb_add_user_set_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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

    int cache_timeout;
};

static void sysdb_add_group_user_check(struct tevent_req *subreq);
static void sysdb_add_group_gid_check(struct tevent_req *subreq);
static void sysdb_add_group_basic_done(struct tevent_req *subreq);
static void sysdb_add_group_get_id_done(struct tevent_req *subreq);
static void sysdb_add_group_set_attrs(struct tevent_req *req);
static void sysdb_add_group_set_attrs_done(struct tevent_req *subreq);

struct tevent_req *sysdb_add_group_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sysdb_handle *handle,
                                        struct sss_domain_info *domain,
                                        const char *name, gid_t gid,
                                        struct sysdb_attrs *attrs,
                                        int cache_timeout)
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
    state->cache_timeout = cache_timeout;

    if (domain->id_max != 0 && gid != 0 &&
        (gid < domain->id_min || gid > domain->id_max)) {
        DEBUG(2, ("Supplied gid [%d] is not in the allowed range [%d-%d].\n",
                  gid, domain->id_min, domain->id_max));
        ERROR_OUT(ret, ERANGE, fail);
    }

    if (handle->ctx->mpg) {
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
            DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    if (state->gid == 0) {
        subreq = sysdb_get_new_id_send(state,
                                       state->ev, state->handle,
                                       state->domain);
        if (!subreq) {
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sysdb_add_group_get_id_done, req);
        return;
    }

    sysdb_add_group_set_attrs(req);
}

static void sysdb_add_group_get_id_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_add_group_state *state = tevent_req_data(req,
                                           struct sysdb_add_group_state);
    uint32_t id;
    int ret;

    ret = sysdb_get_new_id_recv(subreq, &id);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->gid == 0) {
        if (!state->attrs) {
            state->attrs = sysdb_new_attrs(state);
            if (!state->attrs) {
                DEBUG(6, ("Error: Out of memory\n"));
                tevent_req_error(req, ENOMEM);
                return;
            }
        }

        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_GIDNUM, id);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    sysdb_add_group_set_attrs(req);
}

static void sysdb_add_group_set_attrs(struct tevent_req *req)
{
    struct sysdb_add_group_state *state = tevent_req_data(req,
                                           struct sysdb_add_group_state);
    struct tevent_req *subreq;
    time_t now = time(NULL);
    int ret;

    if (!state->attrs) {
        state->attrs = sysdb_new_attrs(state);
        if (!state->attrs) {
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_CACHE_EXPIRE,
                                 ((state->cache_timeout) ?
                                  (now + state->cache_timeout) : 0));
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_group_attr_send(state, state->ev,
                                       state->handle, state->domain,
                                       state->name, state->attrs,
                                       SYSDB_MOD_REP);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_add_group_set_attrs_done, req);
}

static void sysdb_add_group_set_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_set_group_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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

    uint64_t cache_timeout;
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
                                         const char *shell,
                                         struct sysdb_attrs *attrs,
                                         uint64_t cache_timeout)
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
    state->attrs = attrs;
    state->cache_timeout = cache_timeout;

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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    time_t now = time(NULL);
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
                                     state->shell, state->attrs,
                                     state->cache_timeout);
        if (!subreq) {
            DEBUG(6, ("Error: Out of memory\n"));
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
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }
    }

    if (state->uid) {
        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_UIDNUM, state->uid);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->gid) {
        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_GIDNUM, state->gid);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->uid && !state->gid && state->handle->ctx->mpg) {
        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_GIDNUM, state->uid);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->gecos) {
        ret = sysdb_attrs_add_string(state->attrs, SYSDB_GECOS, state->gecos);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->homedir) {
        ret = sysdb_attrs_add_string(state->attrs,
                                     SYSDB_HOMEDIR, state->homedir);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    if (state->shell) {
        ret = sysdb_attrs_add_string(state->attrs, SYSDB_SHELL, state->shell);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_CACHE_EXPIRE,
                                 ((state->cache_timeout) ?
                                  (now + state->cache_timeout) : 0));
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_user_attr_send(state, state->ev,
                                      state->handle, state->domain,
                                      state->name, state->attrs,
                                      SYSDB_MOD_REP);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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

    struct sysdb_attrs *attrs;

    uint64_t cache_timeout;
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
                                          struct sysdb_attrs *attrs,
                                          uint64_t cache_timeout)
{
    struct tevent_req *req, *subreq;
    struct sysdb_store_group_state *state;
    static const char *src_attrs[] = { SYSDB_NAME, SYSDB_GIDNUM,
                                       SYSDB_ORIG_MODSTAMP, NULL };
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_store_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->name = name;
    state->gid = gid;
    state->attrs = attrs;
    state->cache_timeout = cache_timeout;

    subreq = sysdb_search_group_by_name_send(state, ev, NULL, handle,
                                             domain, name, src_attrs);
    if (!subreq) {
        ERROR_OUT(ret, ENOMEM, fail);
    }
    tevent_req_set_callback(subreq, sysdb_store_group_check, req);

    return req;

fail:
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    time_t now = time(NULL);
    bool new_group = false;
    int ret;

    ret = sysdb_search_group_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }
    if (ret == ENOENT) {
        new_group = true;
    }

    /* FIXME: use the remote modification timestamp to know if the
     * group needs any update */

    if (new_group) {
        /* group doesn't exist, turn into adding a group */
        subreq = sysdb_add_group_send(state, state->ev, state->handle,
                                      state->domain, state->name,
                                      state->gid, state->attrs,
                                      state->cache_timeout);
        if (!subreq) {
            DEBUG(6, ("Error: Out of memory\n"));
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
            DEBUG(6, ("Error: Out of memory\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }
    }

    if (state->gid) {
        ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_GIDNUM, state->gid);
        if (ret) {
            DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_attrs_add_time_t(state->attrs, SYSDB_CACHE_EXPIRE,
                                 ((state->cache_timeout) ?
                                  (now + state->cache_timeout) : 0));
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_group_attr_send(state, state->ev,
                                       state->handle, state->domain,
                                       state->name, state->attrs,
                                       SYSDB_MOD_REP);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

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

    return req;

fail:
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_op_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->ignore_not_found = false;
    state->ldbreply = NULL;

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

    return req;

fail:
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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

    ret = sysdb_attrs_add_uint32(state->attrs, SYSDB_FAILED_LOGIN_ATTEMPTS, 0U);
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
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                      state->domain, state->username,
                                      state->attrs, SYSDB_MOD_REP);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
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
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    if (state->commit) {
        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            DEBUG(6, ("Error: Out of memory\n"));
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

/* = sysdb_check_handle ================== */
struct sysdb_check_handle_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
};

static void sysdb_check_handle_done(struct tevent_req *subreq);

struct tevent_req *sysdb_check_handle_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_ctx *sysdb,
                                           struct sysdb_handle *handle)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sysdb_check_handle_state *state;

    if (sysdb == NULL && handle == NULL) {
        DEBUG(1, ("Sysdb context not available.\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct sysdb_check_handle_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;

    if (handle != NULL) {
        state->handle = talloc_memdup(state, handle, sizeof(struct sysdb_handle));
        if (state->handle == NULL) {
            DEBUG(1, ("talloc_memdup failed.\n"));
            tevent_req_error(req, ENOMEM);
        } else {
            tevent_req_done(req);
        }
        tevent_req_post(req, ev);
        return req;
    }

    state->handle = NULL;

    subreq = sysdb_operation_send(state, state->ev, sysdb);
    if (!subreq) {
        DEBUG(1, ("sysdb_operation_send failed.\n"));
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, ev);
        return req;
    }
    tevent_req_set_callback(subreq, sysdb_check_handle_done, req);

    return req;
}

static void sysdb_check_handle_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_check_handle_state *state = tevent_req_data(req,
                                             struct sysdb_check_handle_state);
    int ret;

    ret = sysdb_operation_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

int sysdb_check_handle_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                            struct sysdb_handle **handle)
{
    struct sysdb_check_handle_state *state = tevent_req_data(req,
                                             struct sysdb_check_handle_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *handle = talloc_move(memctx, &state->handle);

    return EOK;

}

/* =Custom Search================== */
struct sysdb_search_custom_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;

    struct ldb_dn *basedn;
    const char **attrs;
    const char *filter;
    int scope;
    bool expect_not_more_than_one;

    size_t msgs_count;
    struct ldb_message **msgs;
};

static void sysdb_search_custom_check_handle_done(struct tevent_req *subreq);
static void sysdb_search_custom_done(struct tevent_req *subreq);

struct tevent_req *sysdb_search_custom_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sysdb_ctx *sysdb,
                                            struct sysdb_handle *handle,
                                            struct sss_domain_info *domain,
                                            const char *filter,
                                            const char *subtree_name,
                                            const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_search_custom_state *state;
    int ret;

    if (sysdb == NULL && handle == NULL) return NULL;

    if (filter == NULL || subtree_name == NULL) return NULL;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_search_custom_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->handle = handle;
    state->attrs = attrs;
    state->filter = filter;
    state->scope = LDB_SCOPE_SUBTREE;
    state->expect_not_more_than_one = false;
    state->msgs_count = 0;
    state->msgs = NULL;

    if (sysdb == NULL) {
        sysdb = handle->ctx;
    }
    state->basedn = sysdb_custom_subtree_dn(sysdb, state, domain->name,
                                            subtree_name);
    if (state->basedn == NULL) {
        DEBUG(1, ("sysdb_custom_subtree_dn failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    if (!ldb_dn_validate(state->basedn)) {
        DEBUG(1, ("Failed to create DN.\n"));
        ret = EINVAL;
        goto fail;
    }

    subreq = sysdb_check_handle_send(state, state->ev, sysdb, state->handle);
    if (!subreq) {
        DEBUG(1, ("sysdb_check_handle_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_search_custom_check_handle_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

struct tevent_req *sysdb_search_custom_by_name_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct sysdb_ctx *sysdb,
                                                    struct sysdb_handle *handle,
                                                    struct sss_domain_info *domain,
                                                    const char *object_name,
                                                    const char *subtree_name,
                                                    const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_search_custom_state *state;
    int ret;

    if (sysdb == NULL && handle == NULL) return NULL;

    if (object_name == NULL || subtree_name == NULL) return NULL;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_search_custom_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->handle = handle;
    state->attrs = attrs;
    state->filter = NULL;
    state->scope = LDB_SCOPE_BASE;
    state->expect_not_more_than_one = true;
    state->msgs_count = 0;
    state->msgs = NULL;

    if (sysdb == NULL) {
        sysdb = handle->ctx;
    }
    state->basedn = sysdb_custom_dn(sysdb, state, domain->name, object_name,
                                     subtree_name);
    if (state->basedn == NULL) {
        DEBUG(1, ("sysdb_custom_dn failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    if (!ldb_dn_validate(state->basedn)) {
        DEBUG(1, ("Failed to create DN.\n"));
        ret = EINVAL;
        goto fail;
    }

    subreq = sysdb_check_handle_send(state, state->ev, sysdb, state->handle);
    if (!subreq) {
        DEBUG(1, ("sysdb_check_handle_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_search_custom_check_handle_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_search_custom_check_handle_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_search_custom_state *state = tevent_req_data(req,
                                            struct sysdb_search_custom_state);
    int ret;

    ret = sysdb_check_handle_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                     state->basedn, state->scope,
                                     state->filter, state->attrs);
    if (!subreq) {
        DEBUG(1, ("sysdb_search_entry_send failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_search_custom_done, req);
    return;
}

static void sysdb_search_custom_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_search_custom_state *state = tevent_req_data(req,
                                            struct sysdb_search_custom_state);
    int ret;

    ret = sysdb_search_entry_recv(subreq, state, &state->msgs_count,
                                  &state->msgs);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->expect_not_more_than_one && state->msgs_count > 1) {
        DEBUG(1, ("More than one result found.\n"));
        tevent_req_error(req, EFAULT);
        return;
    }

    tevent_req_done(req);
}

int sysdb_search_custom_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              size_t *msgs_count,
                              struct ldb_message ***msgs)
{
    struct sysdb_search_custom_state *state = tevent_req_data(req,
                                              struct sysdb_search_custom_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *msgs_count = state->msgs_count;
    *msgs = talloc_move(mem_ctx, &state->msgs);

    return EOK;
}


/* =Custom Store (replaces-existing-data)================== */

struct sysdb_store_custom_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;

    const char *object_name;
    const char *subtree_name;
    struct ldb_dn *dn;
    struct sysdb_attrs *attrs;
    struct ldb_message *msg;
};

static void sysdb_store_custom_check_done(struct tevent_req *subreq);
static void sysdb_store_custom_done(struct tevent_req *subreq);

struct tevent_req *sysdb_store_custom_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain,
                                         const char *object_name,
                                         const char *subtree_name,
                                         struct sysdb_attrs *attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_store_custom_state *state;
    int ret;
    const char **search_attrs;

    if (object_name == NULL || subtree_name == NULL) return NULL;

    if (handle == NULL) {
        DEBUG(1, ("Sysdb context not available.\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct sysdb_store_custom_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->object_name = object_name;
    state->subtree_name = subtree_name;
    state->attrs = attrs;
    state->msg = NULL;
    state->dn = sysdb_custom_dn(handle->ctx, state, domain->name, object_name,
                                 subtree_name);
    if (state->dn == NULL) {
        DEBUG(1, ("sysdb_custom_dn failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    search_attrs = talloc_array(state, const char *, 2);
    if (search_attrs == NULL) {
        DEBUG(1, ("talloc_array failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    search_attrs[0] = "*";
    search_attrs[1] = NULL;

    subreq = sysdb_search_custom_by_name_send(state, state->ev, NULL,
                                              state->handle,
                                              state->domain,
                                              state->object_name,
                                              state->subtree_name,
                                              search_attrs);
    if (!subreq) {
        DEBUG(1, ("sysdb_search_custom_by_name_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_store_custom_check_done, req);

    return req;
fail:
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_store_custom_check_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_store_custom_state *state = tevent_req_data(req,
                                            struct sysdb_store_custom_state);
    int ret;
    int i;
    size_t resp_count = 0;
    struct ldb_message **resp;
    struct ldb_message *msg;
    struct ldb_request *ldbreq;
    struct ldb_message_element *el;
    bool add_object = false;

    ret = sysdb_search_custom_recv(subreq, state, &resp_count, &resp);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT) {
       add_object = true;
    }

    msg = ldb_msg_new(state);
    if (msg == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    msg->dn = state->dn;

    msg->elements = talloc_array(msg, struct ldb_message_element,
                                 state->attrs->num);
    if (!msg->elements) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    for (i = 0; i < state->attrs->num; i++) {
        msg->elements[i] = state->attrs->a[i];
        if (add_object) {
            msg->elements[i].flags = LDB_FLAG_MOD_ADD;
        } else {
            el = ldb_msg_find_element(resp[0], state->attrs->a[i].name);
            if (el == NULL) {
                msg->elements[i].flags = LDB_FLAG_MOD_ADD;
            } else {
                msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
            }
        }
    }
    msg->num_elements = state->attrs->num;

    if (add_object) {
        ret = ldb_build_add_req(&ldbreq, state->handle->ctx->ldb, state, msg,
                                NULL, NULL, NULL, NULL);
    } else {
        ret = ldb_build_mod_req(&ldbreq, state->handle->ctx->ldb, state, msg,
                                NULL, NULL, NULL, NULL);
    }
    if (ret != LDB_SUCCESS) {
        DEBUG(1, ("Failed to build request: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret,
                  ldb_errstring(state->handle->ctx->ldb)));
        tevent_req_error(req, sysdb_error_to_errno(ret));
        return;
    }

    subreq = sldb_request_send(state, state->ev, state->handle->ctx->ldb,
                               ldbreq);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_store_custom_done, req);
    return;
}

static void sysdb_store_custom_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_op_default_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

int sysdb_store_custom_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* = Custom Delete======================================= */

struct sysdb_delete_custom_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;

    const char *object_name;
    const char *subtree_name;
    struct ldb_dn *dn;
};
static void sysdb_delete_custom_done(struct tevent_req *subreq);

struct tevent_req *sysdb_delete_custom_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *object_name,
                                             const char *subtree_name)
{
    struct tevent_req *req, *subreq;
    struct sysdb_delete_custom_state *state;
    int ret;

    if (object_name == NULL || subtree_name == NULL) return NULL;

    if (handle == NULL) {
        DEBUG(1, ("Sysdb context not available.\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct sysdb_store_custom_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->object_name = object_name;
    state->subtree_name = subtree_name;
    state->dn = sysdb_custom_dn(handle->ctx, state, domain->name, object_name,
                                 subtree_name);
    if (state->dn == NULL) {
        DEBUG(1, ("sysdb_custom_dn failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    subreq = sysdb_delete_entry_send(state, state->ev, state->handle,
                                     state->dn, true);
    if (!subreq) {
        DEBUG(1, ("sysdb_delete_entry_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_delete_custom_done, req);

    return req;
fail:
    DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sysdb_delete_custom_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

int sysdb_delete_custom_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* = ASQ search request ======================================== */
struct sysdb_asq_search_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;
    struct ldb_dn *base_dn;
    const char *asq_attribute;
    const char **attrs;
    const char *expression;

    int msgs_count;
    struct ldb_message **msgs;
};

void sysdb_asq_search_check_handle_done(struct tevent_req *subreq);
static void sysdb_asq_search_done(struct tevent_req *subreq);

struct tevent_req *sysdb_asq_search_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_ctx *sysdb,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain,
                                         struct ldb_dn *base_dn,
                                         const char *expression,
                                         const char *asq_attribute,
                                         const char **attrs)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sysdb_asq_search_state *state;
    int ret;

    if (sysdb == NULL && handle == NULL) {
        DEBUG(1, ("Sysdb context not available.\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct sysdb_asq_search_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->sysdb = (sysdb == NULL) ? handle->ctx : sysdb;
    state->handle = handle;
    state->domain = domain;
    state->base_dn = base_dn;
    state->expression = expression;
    state->asq_attribute = asq_attribute;
    state->attrs = attrs;

    state->msgs_count = 0;
    state->msgs = NULL;

    subreq = sysdb_check_handle_send(state, state->ev, state->sysdb,
                                     state->handle);
    if (!subreq) {
        DEBUG(1, ("sysdb_check_handle_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_asq_search_check_handle_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

void sysdb_asq_search_check_handle_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_asq_search_state *state = tevent_req_data(req,
                                            struct sysdb_asq_search_state);
    struct ldb_request *ldb_req;
    struct ldb_control **ctrl;
    struct ldb_asq_control *asq_control;
    int ret;

    ret = sysdb_check_handle_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ctrl = talloc_array(state, struct ldb_control *, 2);
    if (ctrl == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ctrl[0] = talloc(ctrl, struct ldb_control);
    if (ctrl[0] == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    ctrl[1] = NULL;

    ctrl[0]->oid = LDB_CONTROL_ASQ_OID;
    ctrl[0]->critical = 1;

    asq_control = talloc(ctrl[0], struct ldb_asq_control);
    if (asq_control == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    asq_control->request = 1;
    asq_control->source_attribute = talloc_strdup(asq_control,
                                                  state->asq_attribute);
    if (asq_control->source_attribute == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    asq_control->src_attr_len = strlen(asq_control->source_attribute);
    ctrl[0]->data = asq_control;

    ret = ldb_build_search_req(&ldb_req, state->handle->ctx->ldb, state,
            state->base_dn, LDB_SCOPE_BASE,
            state->expression, state->attrs, ctrl,
            NULL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto fail;
    }

    subreq = sldb_request_send(state, state->ev, state->handle->ctx->ldb,
                               ldb_req);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, sysdb_asq_search_done, req);
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void sysdb_asq_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_asq_search_state *state = tevent_req_data(req,
                                                 struct sysdb_asq_search_state);
    struct ldb_reply *ldbreply;
    int ret;

    ret = sldb_request_recv(subreq, state, &ldbreply);
    /* DO NOT free the subreq here, the subrequest search is not
     * finished until we get an ldbreply of type LDB_REPLY_DONE */
    if (ret != EOK) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    switch (ldbreply->type) {
        case LDB_REPLY_ENTRY:
            state->msgs = talloc_realloc(state, state->msgs,
                                         struct ldb_message *,
                                         state->msgs_count + 2);
            if (state->msgs == NULL) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            state->msgs[state->msgs_count + 1] = NULL;

            state->msgs[state->msgs_count] = talloc_steal(state->msgs,
                                                          ldbreply->message);
            state->msgs_count++;

            talloc_zfree(ldbreply);
            return;

        case LDB_REPLY_DONE:
            /* now it is safe to free the subrequest, the search is complete */
            talloc_zfree(subreq);
            break;

        default:
            DEBUG(1, ("Unknown ldb reply type [%d].\n", ldbreply->type));
            tevent_req_error(req, EINVAL);
            return;
    }

    tevent_req_done(req);
}

int sysdb_asq_search_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                          size_t *msgs_count, struct ldb_message ***msgs)
{
    struct sysdb_asq_search_state *state = tevent_req_data(req,
                                              struct sysdb_asq_search_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *msgs_count = state->msgs_count;
    *msgs = talloc_move(mem_ctx, &state->msgs);

    return EOK;
}

/* =Search-Users-with-Custom-Filter====================================== */

struct sysdb_search_users_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;
    const char *sub_filter;
    const char **attrs;

    struct ldb_message **msgs;
    size_t msgs_count;
};

void sysdb_search_users_check_handle(struct tevent_req *subreq);
static void sysdb_search_users_done(struct tevent_req *subreq);

struct tevent_req *sysdb_search_users_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_ctx *sysdb,
                                           struct sysdb_handle *handle,
                                           struct sss_domain_info *domain,
                                           const char *sub_filter,
                                           const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_search_users_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_search_users_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->sub_filter = sub_filter;
    state->attrs = attrs;

    state->msgs_count = 0;
    state->msgs = NULL;

    subreq = sysdb_check_handle_send(state, ev, sysdb, handle);
    if (!subreq) {
        DEBUG(1, ("sysdb_check_handle_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_search_users_check_handle, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

void sysdb_search_users_check_handle(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_search_users_state *state = tevent_req_data(req,
                                            struct sysdb_search_users_state);
    struct ldb_dn *basedn;
    char *filter;
    int ret;

    ret = sysdb_check_handle_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    basedn = ldb_dn_new_fmt(state, state->handle->ctx->ldb,
                            SYSDB_TMPL_USER_BASE, state->domain->name);
    if (!basedn) {
        DEBUG(2, ("Failed to build base dn\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    filter = talloc_asprintf(state, "(&(%s)%s)",
                             SYSDB_UC, state->sub_filter);
    if (!filter) {
        DEBUG(2, ("Failed to build filter\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    DEBUG(6, ("Search users with filter: %s\n", filter));

    subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                     basedn, LDB_SCOPE_SUBTREE,
                                     filter, state->attrs);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_search_users_done, req);
}

static void sysdb_search_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_search_users_state *state = tevent_req_data(req,
                                            struct sysdb_search_users_state);
    int ret;

    ret = sysdb_search_entry_recv(subreq, state,
                                  &state->msgs_count, &state->msgs);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_search_users_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            size_t *msgs_count, struct ldb_message ***msgs)
{
    struct sysdb_search_users_state *state = tevent_req_data(req,
                                            struct sysdb_search_users_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *msgs_count = state->msgs_count;
    *msgs = talloc_move(mem_ctx, &state->msgs);

    return EOK;
}

/* =Delete-User-by-Name-OR-uid============================================ */

struct sysdb_delete_user_state {
    struct tevent_context *ev;
    struct sss_domain_info *domain;

    const char *name;
    uid_t uid;

    struct sysdb_handle *handle;
};

void sysdb_delete_user_check_handle(struct tevent_req *subreq);
static void sysdb_delete_user_found(struct tevent_req *subreq);
static void sysdb_delete_user_done(struct tevent_req *subreq);

struct tevent_req *sysdb_delete_user_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *sysdb,
                                          struct sysdb_handle *handle,
                                          struct sss_domain_info *domain,
                                          const char *name, uid_t uid)
{
    struct tevent_req *req, *subreq;
    struct sysdb_delete_user_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_delete_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->name = name;
    state->uid = uid;

    subreq = sysdb_check_handle_send(state, ev, sysdb, handle);
    if (!subreq) {
        DEBUG(1, ("sysdb_check_handle_send failed.\n"));
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, ev);
        return req;
    }
    tevent_req_set_callback(subreq, sysdb_delete_user_check_handle, req);

    return req;
}

void sysdb_delete_user_check_handle(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_delete_user_state *state = tevent_req_data(req,
                                            struct sysdb_delete_user_state);
    static const char *attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL };
    int ret;

    ret = sysdb_check_handle_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->name) {
        subreq = sysdb_search_user_by_name_send(state, state->ev, NULL,
                                                state->handle, state->domain,
                                                state->name, attrs);
    } else {
        subreq = sysdb_search_user_by_uid_send(state, state->ev, NULL,
                                               state->handle, state->domain,
                                               state->uid, NULL);
    }

    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_delete_user_found, req);
}

static void sysdb_delete_user_found(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_delete_user_state *state = tevent_req_data(req,
                                            struct sysdb_delete_user_state);
    struct ldb_message *msg;
    int ret;

    ret = sysdb_search_user_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->name && state->uid) {
        /* verify name/gid match */
        const char *name;
        uint64_t uid;

        name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
        if (name == NULL || uid == 0) {
            DEBUG(2, ("Attribute is missing but this should never happen!\n"));
            tevent_req_error(req, EFAULT);
            return;
        }
        if (strcmp(state->name, name) || state->uid != uid) {
            /* this is not the entry we are looking for */
            tevent_req_error(req, EINVAL);
            return;
        }
    }

    subreq = sysdb_delete_entry_send(state, state->ev,
                                     state->handle, msg->dn, false);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_delete_user_done, req);
}

static void sysdb_delete_user_done(struct tevent_req *subreq)
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

int sysdb_delete_user_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}


/* =Search-Groups-with-Custom-Filter===================================== */

struct sysdb_search_groups_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;
    const char *sub_filter;
    const char **attrs;

    struct ldb_message **msgs;
    size_t msgs_count;
};

void sysdb_search_groups_check_handle(struct tevent_req *subreq);
static void sysdb_search_groups_done(struct tevent_req *subreq);

struct tevent_req *sysdb_search_groups_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sysdb_ctx *sysdb,
                                            struct sysdb_handle *handle,
                                            struct sss_domain_info *domain,
                                            const char *sub_filter,
                                            const char **attrs)
{
    struct tevent_req *req, *subreq;
    struct sysdb_search_groups_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_search_groups_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->sub_filter = sub_filter;
    state->attrs = attrs;

    state->msgs_count = 0;
    state->msgs = NULL;

    subreq = sysdb_check_handle_send(state, ev, sysdb, handle);
    if (!subreq) {
        DEBUG(1, ("sysdb_check_handle_send failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sysdb_search_groups_check_handle, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

void sysdb_search_groups_check_handle(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_search_groups_state *state = tevent_req_data(req,
                                            struct sysdb_search_groups_state);
    struct ldb_dn *basedn;
    char *filter;
    int ret;

    ret = sysdb_check_handle_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    basedn = ldb_dn_new_fmt(state, state->handle->ctx->ldb,
                            SYSDB_TMPL_GROUP_BASE, state->domain->name);
    if (!basedn) {
        DEBUG(2, ("Failed to build base dn\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    filter = talloc_asprintf(state, "(&(%s)%s)",
                             SYSDB_GC, state->sub_filter);
    if (!filter) {
        DEBUG(2, ("Failed to build filter\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    DEBUG(6, ("Search groups with filter: %s\n", filter));

    subreq = sysdb_search_entry_send(state, state->ev, state->handle,
                                     basedn, LDB_SCOPE_SUBTREE,
                                     filter, state->attrs);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_search_groups_done, req);
}

static void sysdb_search_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_search_groups_state *state = tevent_req_data(req,
                                            struct sysdb_search_groups_state);
    int ret;

    ret = sysdb_search_entry_recv(subreq, state,
                                  &state->msgs_count, &state->msgs);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sysdb_search_groups_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            size_t *msgs_count, struct ldb_message ***msgs)
{
    struct sysdb_search_groups_state *state = tevent_req_data(req,
                                            struct sysdb_search_groups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *msgs_count = state->msgs_count;
    *msgs = talloc_move(mem_ctx, &state->msgs);

    return EOK;
}

/* =Delete-Group-by-Name-OR-gid=========================================== */

struct sysdb_delete_group_state {
    struct tevent_context *ev;
    struct sss_domain_info *domain;

    const char *name;
    gid_t gid;

    struct sysdb_handle *handle;
};

void sysdb_delete_group_check_handle(struct tevent_req *subreq);
static void sysdb_delete_group_found(struct tevent_req *subreq);
static void sysdb_delete_group_done(struct tevent_req *subreq);

struct tevent_req *sysdb_delete_group_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *sysdb,
                                          struct sysdb_handle *handle,
                                          struct sss_domain_info *domain,
                                          const char *name, gid_t gid)
{
    struct tevent_req *req, *subreq;
    struct sysdb_delete_group_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sysdb_delete_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->domain = domain;
    state->name = name;
    state->gid = gid;

    subreq = sysdb_check_handle_send(state, ev, sysdb, handle);
    if (!subreq) {
        DEBUG(1, ("sysdb_check_handle_send failed.\n"));
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, ev);
        return req;
    }
    tevent_req_set_callback(subreq, sysdb_delete_group_check_handle, req);

    return req;
}

void sysdb_delete_group_check_handle(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sysdb_delete_group_state *state = tevent_req_data(req,
                                           struct sysdb_delete_group_state);
    static const char *attrs[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL };
    int ret;

    ret = sysdb_check_handle_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->name) {
        subreq = sysdb_search_group_by_name_send(state, state->ev, NULL,
                                                 state->handle, state->domain,
                                                 state->name, attrs);
    } else {
        subreq = sysdb_search_group_by_gid_send(state, state->ev, NULL,
                                                state->handle, state->domain,
                                                state->gid, NULL);
    }

    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_delete_group_found, req);
}

static void sysdb_delete_group_found(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct sysdb_delete_group_state *state = tevent_req_data(req,
                                           struct sysdb_delete_group_state);
    struct ldb_message *msg;
    int ret;

    ret = sysdb_search_group_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->name && state->gid) {
        /* verify name/gid match */
        const char *name;
        uint64_t gid;

        name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
        if (name == NULL || gid == 0) {
            DEBUG(2, ("Attribute is missing but this should never happen!\n"));
            tevent_req_error(req, EFAULT);
            return;
        }
        if (strcmp(state->name, name) || state->gid != gid) {
            /* this is not the entry we are looking for */
            tevent_req_error(req, EINVAL);
            return;
        }
    }

    subreq = sysdb_delete_entry_send(state, state->ev,
                                     state->handle, msg->dn, false);
    if (!subreq) {
        DEBUG(6, ("Error: Out of memory\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_delete_group_done, req);
}

static void sysdb_delete_group_done(struct tevent_req *subreq)
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

int sysdb_delete_group_recv(struct tevent_req *req)
{
    return sysdb_op_default_recv(req);
}

/* ========= Authentication against cached password ============ */

struct sysdb_cache_auth_state {
    struct tevent_context *ev;
    const char *name;
    const uint8_t *authtok;
    size_t authtok_size;
    struct sss_domain_info *domain;
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *cdb;
    bool just_check;
    struct sysdb_attrs *update_attrs;
    bool authentication_successful;
    struct sysdb_handle *handle;
    time_t expire_date;
    time_t delayed_until;
};

errno_t check_failed_login_attempts(TALLOC_CTX *mem_ctx, struct confdb_ctx *cdb,
                                    struct ldb_message *ldb_msg,
                                    uint32_t *failed_login_attempts,
                                    time_t *delayed_until)
{
    int ret;
    int allowed_failed_login_attempts;
    int failed_login_delay;
    time_t last_failed_login;
    time_t end;

    *delayed_until = -1;
    *failed_login_attempts = ldb_msg_find_attr_as_uint(ldb_msg,
                                                SYSDB_FAILED_LOGIN_ATTEMPTS, 0);
    last_failed_login = (time_t) ldb_msg_find_attr_as_int64(ldb_msg,
                                                    SYSDB_LAST_FAILED_LOGIN, 0);
    ret = confdb_get_int(cdb, mem_ctx, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_FAILED_LOGIN_ATTEMPTS,
                         CONFDB_DEFAULT_PAM_FAILED_LOGIN_ATTEMPTS,
                         &allowed_failed_login_attempts);
    if (ret != EOK) {
        DEBUG(1, ("Failed to read the number of allowed failed login "
                  "attempts.\n"));
        return EIO;
    }
    ret = confdb_get_int(cdb, mem_ctx, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_FAILED_LOGIN_DELAY,
                         CONFDB_DEFAULT_PAM_FAILED_LOGIN_DELAY,
                         &failed_login_delay);
    if (ret != EOK) {
        DEBUG(1, ("Failed to read the failed login delay.\n"));
        return EIO;
    }
    DEBUG(9, ("Failed login attempts [%d], allowed failed login attempts [%d], "
              "failed login delay [%d].\n", *failed_login_attempts,
              allowed_failed_login_attempts, failed_login_delay));

    if (allowed_failed_login_attempts) {
        if (*failed_login_attempts >= allowed_failed_login_attempts) {
            if (failed_login_delay) {
                end = last_failed_login + (failed_login_delay * 60);
                if (end < time(NULL)) {
                    DEBUG(7, ("failed_login_delay has passed, "
                              "resetting failed_login_attempts.\n"));
                    *failed_login_attempts = 0;
                } else {
                    DEBUG(7, ("login delayed until %lld.\n", (long long) end));
                    *delayed_until = end;
                    return EACCES;
                }
            } else {
                DEBUG(4, ("Too many failed logins.\n"));
                return EACCES;
            }
        }
    }

    return EOK;
}

static void sysdb_cache_auth_get_attrs_done(struct tevent_req *subreq);
static void sysdb_cache_auth_transaction_start_done(struct tevent_req *subreq);
static void sysdb_cache_auth_attr_update_done(struct tevent_req *subreq);
static void sysdb_cache_auth_done(struct tevent_req *subreq);

struct tevent_req *sysdb_cache_auth_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_ctx *sysdb,
                                         struct sss_domain_info *domain,
                                         const char *name,
                                         const uint8_t *authtok,
                                         size_t authtok_size,
                                         struct confdb_ctx *cdb,
                                         bool just_check)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sysdb_cache_auth_state *state;

    if (name == NULL || *name == '\0') {
        DEBUG(1, ("Missing user name.\n"));
        return NULL;
    }

    if (cdb == NULL) {
        DEBUG(1, ("Missing config db context.\n"));
        return NULL;
    }

    if (sysdb == NULL) {
        DEBUG(1, ("Missing sysdb db context.\n"));
        return NULL;
    }

    if (!domain->cache_credentials) {
        DEBUG(3, ("Cached credentials not available.\n"));
        return NULL;
    }

    static const char *attrs[] = {SYSDB_NAME,
                                  SYSDB_CACHEDPWD,
                                  SYSDB_DISABLED,
                                  SYSDB_LAST_LOGIN,
                                  SYSDB_LAST_ONLINE_AUTH,
                                  "lastCachedPasswordChange",
                                  "accountExpires",
                                  SYSDB_FAILED_LOGIN_ATTEMPTS,
                                  SYSDB_LAST_FAILED_LOGIN,
                                  NULL};

    req = tevent_req_create(mem_ctx, &state, struct sysdb_cache_auth_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->name = name;
    state->authtok = authtok;
    state->authtok_size = authtok_size;
    state->domain = domain;
    state->sysdb = sysdb;
    state->cdb = cdb;
    state->just_check = just_check;
    state->update_attrs = NULL;
    state->authentication_successful = false;
    state->handle = NULL;
    state->expire_date = -1;
    state->delayed_until = -1;

    subreq = sysdb_search_user_by_name_send(state, ev, sysdb, NULL, domain,
                                            name, attrs);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_search_user_by_name_send failed.\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sysdb_cache_auth_get_attrs_done, req);

    return req;
}

static void sysdb_cache_auth_get_attrs_done(struct tevent_req *subreq)
{
    struct ldb_message *ldb_msg;
    const char *userhash;
    char *comphash;
    char *password = NULL;
    int i;
    int ret;
    uint64_t lastLogin = 0;
    int cred_expiration;
    uint32_t failed_login_attempts = 0;

    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    struct sysdb_cache_auth_state *state = tevent_req_data(req,
                                                 struct sysdb_cache_auth_state);

    ret = sysdb_search_user_recv(subreq, state, &ldb_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_search_user_by_name_send failed [%d][%s].\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ENOENT);
        return;
    }

    /* Check offline_auth_cache_timeout */
    lastLogin = ldb_msg_find_attr_as_uint64(ldb_msg,
                                            SYSDB_LAST_ONLINE_AUTH,
                                            0);

    ret = confdb_get_int(state->cdb, state, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_CRED_TIMEOUT, 0, &cred_expiration);
    if (ret != EOK) {
        DEBUG(1, ("Failed to read expiration time of offline credentials.\n"));
        ret = EACCES;
        goto done;
    }
    DEBUG(9, ("Offline credentials expiration is [%d] days.\n",
              cred_expiration));

    if (cred_expiration) {
        state->expire_date = lastLogin + (cred_expiration * 86400);
        if (state->expire_date < time(NULL)) {
            DEBUG(4, ("Cached user entry is too old.\n"));
            state->expire_date = 0;
            ret = EACCES;
            goto done;
        }
    } else {
        state->expire_date = 0;
    }

    ret = check_failed_login_attempts(state, state->cdb, ldb_msg,
                                      &failed_login_attempts,
                                      &state->delayed_until);
    if (ret != EOK) {
        goto done;
    }

    /* TODO: verify user account (disabled, expired ...) */

    password = talloc_strndup(state, (const char *) state->authtok,
                              state->authtok_size);
    if (password == NULL) {
        DEBUG(1, ("talloc_strndup failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    userhash = ldb_msg_find_attr_as_string(ldb_msg, SYSDB_CACHEDPWD, NULL);
    if (userhash == NULL || *userhash == '\0') {
        DEBUG(4, ("Cached credentials not available.\n"));
        ret = ENOENT;
        goto done;
    }

    ret = s3crypt_sha512(state, password, userhash, &comphash);
    if (ret) {
        DEBUG(4, ("Failed to create password hash.\n"));
        ret = EFAULT;
        goto done;
    }

    state->update_attrs = sysdb_new_attrs(state);
    if (state->update_attrs == NULL) {
        DEBUG(1, ("sysdb_new_attrs failed.\n"));
        goto done;
    }

    if (strcmp(userhash, comphash) == 0) {
        /* TODO: probable good point for audit logging */
        DEBUG(4, ("Hashes do match!\n"));
        state->authentication_successful = true;

        if (state->just_check) {
            ret = EOK;
            goto done;
        }

        ret = sysdb_attrs_add_time_t(state->update_attrs, SYSDB_LAST_LOGIN,
                                     time(NULL));
        if (ret != EOK) {
            DEBUG(3, ("sysdb_attrs_add_time_t failed, "
                      "but authentication is successful.\n"));
            ret = EOK;
            goto done;
        }

        ret = sysdb_attrs_add_uint32(state->update_attrs,
                                     SYSDB_FAILED_LOGIN_ATTEMPTS, 0U);
        if (ret != EOK) {
            DEBUG(3, ("sysdb_attrs_add_uint32 failed, "
                      "but authentication is successful.\n"));
            ret = EOK;
            goto done;
        }


    } else {
        DEBUG(4, ("Authentication failed.\n"));
        state->authentication_successful = false;

        ret = sysdb_attrs_add_time_t(state->update_attrs,
                                     SYSDB_LAST_FAILED_LOGIN,
                                     time(NULL));
        if (ret != EOK) {
            DEBUG(3, ("sysdb_attrs_add_time_t failed\n."));
            ret = EINVAL;
            goto done;
        }

        ret = sysdb_attrs_add_uint32(state->update_attrs,
                                     SYSDB_FAILED_LOGIN_ATTEMPTS,
                                     ++failed_login_attempts);
        if (ret != EOK) {
            DEBUG(3, ("sysdb_attrs_add_uint32 failed.\n"));
            ret = EINVAL;
            goto done;
        }
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_transaction_send failed.\n"));
        goto done;
    }
    tevent_req_set_callback(subreq, sysdb_cache_auth_transaction_start_done,
                            req);
    return;

done:
    if (password) for (i = 0; password[i]; i++) password[i] = 0;
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    return;
}

static void sysdb_cache_auth_transaction_start_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    struct sysdb_cache_auth_state *state = tevent_req_data(req,
                                                 struct sysdb_cache_auth_state);

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_transaction_send failed [%d][%s].\n",
                  ret, strerror(ret)));
        goto done;
    }


    subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                      state->domain, state->name,
                                      state->update_attrs,
                                      LDB_FLAG_MOD_REPLACE);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_set_user_attr_send failed.\n"));
        goto done;
    }
    tevent_req_set_callback(subreq, sysdb_cache_auth_attr_update_done,
                            req);
    return;

done:
    if (state->authentication_successful) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, EINVAL);
    }
    return;
}

static void sysdb_cache_auth_attr_update_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    struct sysdb_cache_auth_state *state = tevent_req_data(req,
                                                 struct sysdb_cache_auth_state);

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_set_user_attr request failed [%d][%s].\n",
                  ret, strerror(ret)));
        goto done;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (subreq == NULL) {
        DEBUG(1, ("sysdb_transaction_commit_send failed.\n"));
        goto done;
    }
    tevent_req_set_callback(subreq, sysdb_cache_auth_done, req);
    return;

done:
    if (state->authentication_successful) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, EINVAL);
    }
    return;
}

static void sysdb_cache_auth_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    struct sysdb_cache_auth_state *state = tevent_req_data(req,
                                                 struct sysdb_cache_auth_state);

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_transaction_commit_send failed [%d][%s].\n",
                  ret, strerror(ret)));
    }

    if (state->authentication_successful) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, EINVAL);
    }
    return;
}

int sysdb_cache_auth_recv(struct tevent_req *req, time_t *expire_date,
                          time_t *delayed_until) {
    struct sysdb_cache_auth_state *state = tevent_req_data(req,
                                                 struct sysdb_cache_auth_state);
    *expire_date = state->expire_date;
    *delayed_until = state->delayed_until;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return (state->authentication_successful ? EOK : EINVAL);
}
