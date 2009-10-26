/*
    SSSD

    LDAP Identity Backend Module

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2008 Red Hat

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

#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/dp_backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"

static int build_attrs_from_map(TALLOC_CTX *memctx,
                                struct sdap_id_map *map,
                                size_t size,
                                const char ***_attrs)
{
    char **attrs;
    int i, j;

    attrs = talloc_array(memctx, char *, size + 1);
    if (!attrs) return ENOMEM;

    /* first attribute is "objectclass" not the specifc one */
    attrs[0] = talloc_strdup(memctx, "objectClass");
    if (!attrs[0]) return ENOMEM;

    /* add the others */
    for (i = j = 1; i < size; i++) {
        if (map[i].name) {
            attrs[j] = map[i].name;
            j++;
        }
    }
    attrs[j] = NULL;

    *_attrs = (const char **)attrs;

    return EOK;
}


/* =Connection-handling-functions========================================= */

static bool connected(struct sdap_id_ctx *ctx)
{
    if (ctx->gsh) {
        return ctx->gsh->connected;
    }

    return false;
}

static void mark_offline(struct sdap_id_ctx *ctx)
{
    if (ctx->gsh) {
        /* make sure we mark the connection as gone when we go offline so that
         * we do not try to reuse a bad connection by mistale later */
        talloc_zfree(ctx->gsh);
    }

    be_mark_offline(ctx->be);
}

/* =Users-Related-Functions-(by-name,by-uid)============================== */

struct users_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;

    char *filter;
    const char **attrs;
};

static void users_get_connect_done(struct tevent_req *subreq);
static void users_get_op_done(struct tevent_req *subreq);

static struct tevent_req *users_get_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_id_ctx *ctx,
                                         const char *name,
                                         int filter_type,
                                         int attrs_type)
{
    struct tevent_req *req, *subreq;
    struct users_get_state *state;
    const char *attr_name;
    int ret;

    req = tevent_req_create(memctx, &state, struct users_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    switch(filter_type) {
    case BE_FILTER_NAME:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_NAME].name;
        break;
    case BE_FILTER_IDNUM:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_UID].name;
        break;
    default:
        ret = EINVAL;
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                                    attr_name, name,
                                    ctx->opts->user_map[SDAP_OC_USER].name);
    if (!state->filter) {
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->user_map,
                               SDAP_OPTS_USER, &state->attrs);
    if (ret != EOK) goto fail;

    if (!connected(ctx)) {

        if (ctx->gsh) talloc_zfree(ctx->gsh);

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_cli_connect_send(state, ev, ctx->opts);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, users_get_connect_done, req);

        return req;
    }

    subreq = sdap_get_users_send(state, state->ev,
                                 state->ctx->be->domain,
                                 state->ctx->be->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, users_get_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void users_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct users_get_state *state = tevent_req_data(req,
                                                     struct users_get_state);
    int ret;

    ret = sdap_cli_connect_recv(subreq, state->ctx, &state->ctx->gsh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_users_send(state, state->ev,
                                 state->ctx->be->domain,
                                 state->ctx->be->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, users_get_op_done, req);
}

static void users_get_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_users_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void users_get_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    struct sdap_id_ctx *ctx;
    enum tevent_req_state tstate;
    uint64_t err;
    int dp_err = DP_ERR_OK;
    const char *error = NULL;
    int ret = EOK;

    if (tevent_req_is_error(req, &tstate, &err)) {
        ret = err;
    }

    if (ret) {
        dp_err = DP_ERR_FATAL;
        error = "Enum Users Failed";

        if (ret == ETIMEDOUT) {
            dp_err = DP_ERR_TIMEOUT;
        }
        if (ret == ETIMEDOUT || ret == EFAULT) {
            ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data,
                                  struct sdap_id_ctx);
            mark_offline(ctx);
        }
    }

    sdap_handler_done(breq, dp_err, ret, error);
}

/* =Groups-Related-Functions-(by-name,by-uid)============================= */

struct groups_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;

    char *filter;
    const char **attrs;
};

static void groups_get_connect_done(struct tevent_req *subreq);
static void groups_get_op_done(struct tevent_req *subreq);

static struct tevent_req *groups_get_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          const char *name,
                                          int filter_type,
                                          int attrs_type)
{
    struct tevent_req *req, *subreq;
    struct groups_get_state *state;
    const char *attr_name;
    int ret;

    req = tevent_req_create(memctx, &state, struct groups_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    switch(filter_type) {
    case BE_FILTER_NAME:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_NAME].name;
        break;
    case BE_FILTER_IDNUM:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_GID].name;
        break;
    default:
        ret = EINVAL;
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                                    attr_name, name,
                                    ctx->opts->group_map[SDAP_OC_GROUP].name);
    if (!state->filter) {
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->group_map,
                               SDAP_OPTS_GROUP, &state->attrs);
    if (ret != EOK) goto fail;

    if (!connected(ctx)) {

        if (ctx->gsh) talloc_zfree(ctx->gsh);

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_cli_connect_send(state, ev, ctx->opts);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, groups_get_connect_done, req);

        return req;
    }

    subreq = sdap_get_groups_send(state, state->ev,
                                 state->ctx->be->domain,
                                 state->ctx->be->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, groups_get_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void groups_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);
    int ret;

    ret = sdap_cli_connect_recv(subreq, state->ctx, &state->ctx->gsh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_groups_send(state, state->ev,
                                  state->ctx->be->domain,
                                  state->ctx->be->sysdb,
                                  state->ctx->opts, state->ctx->gsh,
                                  state->attrs, state->filter);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, groups_get_op_done, req);
}

static void groups_get_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_groups_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void groups_get_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    struct sdap_id_ctx *ctx;
    enum tevent_req_state tstate;
    uint64_t err;
    int dp_err = DP_ERR_OK;
    const char *error = NULL;
    int ret = EOK;

    if (tevent_req_is_error(req, &tstate, &err)) {
        ret = err;
    }

    if (ret) {
        dp_err = DP_ERR_FATAL;
        error = "Enum Groups Failed";

        if (ret == ETIMEDOUT) {
            dp_err = DP_ERR_TIMEOUT;
        }
        if (ret == ETIMEDOUT || ret == EFAULT) {
            ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data,
                                  struct sdap_id_ctx);
            mark_offline(ctx);
        }
    }

    return sdap_handler_done(breq, dp_err, ret, error);
}

/* =Get-Groups-for-User================================================== */

struct groups_by_user_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    const char *name;
    const char **attrs;
};

static void groups_by_user_connect_done(struct tevent_req *subreq);
static void groups_by_user_op_done(struct tevent_req *subreq);

static struct tevent_req *groups_by_user_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sdap_id_ctx *ctx,
                                              const char *name)
{
    struct tevent_req *req, *subreq;
    struct groups_by_user_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct groups_by_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->name = name;

    ret = build_attrs_from_map(state, ctx->opts->group_map,
                               SDAP_OPTS_GROUP, &state->attrs);
    if (ret != EOK) goto fail;

    if (!connected(ctx)) {

        if (ctx->gsh) talloc_zfree(ctx->gsh);

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_cli_connect_send(state, ev, ctx->opts);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, groups_by_user_connect_done, req);

        return req;
    }

    subreq = sdap_get_initgr_send(state, state->ev,
                                  state->ctx->be->domain,
                                  state->ctx->be->sysdb,
                                  state->ctx->opts, state->ctx->gsh,
                                  state->name, state->attrs);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, groups_by_user_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void groups_by_user_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_by_user_state *state = tevent_req_data(req,
                                                     struct groups_by_user_state);
    int ret;

    ret = sdap_cli_connect_recv(subreq, state->ctx, &state->ctx->gsh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_initgr_send(state, state->ev,
                                  state->ctx->be->domain,
                                  state->ctx->be->sysdb,
                                  state->ctx->opts, state->ctx->gsh,
                                  state->name, state->attrs);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, groups_by_user_op_done, req);
}

static void groups_by_user_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_initgr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void groups_by_user_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    struct sdap_id_ctx *ctx;
    enum tevent_req_state tstate;
    uint64_t err;
    int dp_err = DP_ERR_OK;
    const char *error = NULL;
    int ret = EOK;

    if (tevent_req_is_error(req, &tstate, &err)) {
        ret = err;
    }

    if (ret) {
        dp_err = DP_ERR_FATAL;
        error = "Init Groups Failed";

        if (ret == ETIMEDOUT) {
            dp_err = DP_ERR_TIMEOUT;
        }
        if (ret == ETIMEDOUT || ret == EFAULT) {
            ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data,
                                  struct sdap_id_ctx);
            mark_offline(ctx);
        }
    }

    return sdap_handler_done(breq, dp_err, ret, error);
}



/* =Get-Account-Info-Call================================================= */

/* FIXME: embed this function in sssd_be and only call out
 * specific functions from modules ? */
void sdap_account_info_handler(struct be_req *breq)
{
    struct sdap_id_ctx *ctx;
    struct be_acct_req *ar;
    struct tevent_req *req;
    const char *err = "Unknown Error";
    int ret = EOK;

    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data, struct sdap_id_ctx);

    if (be_is_offline(ctx->be)) {
        return sdap_handler_done(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    ar = talloc_get_type(breq->req_data, struct be_acct_req);

    switch (ar->entry_type) {
    case BE_REQ_USER: /* user */

        /* skip enumerations on demand */
        if (strcmp(ar->filter_value, "*") == 0) {
            return sdap_handler_done(breq, DP_ERR_OK, EOK, "Success");
        }

        req = users_get_send(breq, breq->be_ctx->ev, ctx,
                             ar->filter_value,
                             ar->filter_type,
                             ar->attr_type);
        if (!req) {
            return sdap_handler_done(breq, DP_ERR_FATAL, ENOMEM, "Out of memory");
        }

        tevent_req_set_callback(req, users_get_done, breq);

        break;

    case BE_REQ_GROUP: /* group */

        if (strcmp(ar->filter_value, "*") == 0) {
            return sdap_handler_done(breq, DP_ERR_OK, EOK, "Success");
        }

        /* skip enumerations on demand */
        req = groups_get_send(breq, breq->be_ctx->ev, ctx,
                              ar->filter_value,
                              ar->filter_type,
                              ar->attr_type);
        if (!req) {
            return sdap_handler_done(breq, DP_ERR_FATAL, ENOMEM, "Out of memory");
        }

        tevent_req_set_callback(req, groups_get_done, breq);

        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            err = "Invalid filter type";
            break;
        }
        if (ar->attr_type != BE_ATTR_CORE) {
            ret = EINVAL;
            err = "Invalid attr type";
            break;
        }
        if (strchr(ar->filter_value, '*')) {
            ret = EINVAL;
            err = "Invalid filter value";
            break;
        }
        req = groups_by_user_send(breq, breq->be_ctx->ev, ctx,
                                  ar->filter_value);
        if (!req) ret = ENOMEM;
        /* tevent_req_set_callback(req, groups_by_user_done, breq); */

        tevent_req_set_callback(req, groups_by_user_done, breq);

        break;

    default: /*fail*/
        ret = EINVAL;
        err = "Invalid request type";
    }

    if (ret != EOK) return sdap_handler_done(breq, DP_ERR_FATAL, ret, err);
}


/* ==Enumeration-Task===================================================== */

static struct tevent_req *ldap_id_enumerate_send(struct tevent_context *ev,
                                                 struct sdap_id_ctx *ctx);
static void ldap_id_enumerate_reschedule(struct tevent_req *req);
static void ldap_id_enumerate_set_timer(struct sdap_id_ctx *ctx,
                                        struct timeval tv);

static void ldap_id_enumerate_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt);

static void ldap_id_enumerate(struct tevent_context *ev,
                              struct tevent_timer *tt,
                              struct timeval tv, void *pvt)
{
    struct sdap_id_ctx *ctx = talloc_get_type(pvt, struct sdap_id_ctx);
    struct tevent_timer *timeout;
    struct tevent_req *req;
    int ert;

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        /* schedule starting from now, not the last run */
        ldap_id_enumerate_set_timer(ctx, tevent_timeval_current());
        return;
    }

    ctx->last_run = tv;

    req = ldap_id_enumerate_send(ev, ctx);
    if (!req) {
        DEBUG(1, ("Failed to schedule enumeration, retrying later!\n"));
        /* schedule starting from now, not the last run */
        ldap_id_enumerate_set_timer(ctx, tevent_timeval_current());
        return;
    }
    tevent_req_set_callback(req, ldap_id_enumerate_reschedule, ctx);

    /* if enumeration takes so long, either we try to enumerate too
     * frequently, or something went seriously wrong */
    tv = tevent_timeval_current();
    ert = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    tv = tevent_timeval_add(&tv, ert, 0);
    timeout = tevent_add_timer(ctx->be->ev, req, tv,
                               ldap_id_enumerate_timeout, req);
    return;
}

static void ldap_id_enumerate_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    int ert;

    ert = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    DEBUG(1, ("Enumeration timed out! Timeout too small? (%ds)!\n", ert));
    ldap_id_enumerate_set_timer(ctx, tevent_timeval_current());

    talloc_zfree(req);
}

static void ldap_id_enumerate_reschedule(struct tevent_req *req)
{
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    struct timeval tv;
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        /* On error schedule starting from now, not the last run */
        tv = tevent_timeval_current();
    } else {
        tv = ctx->last_run;
    }
    talloc_zfree(req);

    ldap_id_enumerate_set_timer(ctx, ctx->last_run);
}

static void ldap_id_enumerate_set_timer(struct sdap_id_ctx *ctx,
                                        struct timeval tv)
{
    struct tevent_timer *enum_task;
    int ert;

    ert = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    tv = tevent_timeval_add(&tv, ert, 0);
    enum_task = tevent_add_timer(ctx->be->ev, ctx, tv, ldap_id_enumerate, ctx);
    if (!enum_task) {
        DEBUG(0, ("FATAL: failed to setup enumeration task!\n"));
        /* shutdown! */
        exit(1);
    }
}



struct global_enum_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
};

static struct tevent_req *enum_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx);
static void ldap_id_enum_users_done(struct tevent_req *subreq);
static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx);
static void ldap_id_enum_groups_done(struct tevent_req *subreq);

static struct tevent_req *ldap_id_enumerate_send(struct tevent_context *ev,
                                                 struct sdap_id_ctx *ctx)
{
    struct global_enum_state *state;
    struct tevent_req *req, *subreq;

    req = tevent_req_create(ctx, &state, struct global_enum_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    subreq = enum_users_send(state, ev, ctx);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, ldap_id_enum_users_done, req);

    return req;
}

static void ldap_id_enum_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    enum tevent_req_state tstate;
    uint64_t err = 0;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        goto fail;
    }
    talloc_zfree(subreq);

    subreq = enum_groups_send(state, state->ev, state->ctx);
    if (!subreq) {
        goto fail;
    }
    tevent_req_set_callback(subreq, ldap_id_enum_groups_done, req);

    return;

fail:
    if (err) {
        DEBUG(9, ("User enumeration failed with: (%d)[%s]\n",
                  (int)err, strerror(err)));

        mark_offline(state->ctx);
    }

    DEBUG(1, ("Failed to enumerate users, retrying later!\n"));
    tevent_req_done(req);
}

static void ldap_id_enum_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        goto fail;
    }
    talloc_zfree(subreq);

    tevent_req_done(req);
    return;

fail:
    /* always go offline on failures */
    mark_offline(state->ctx);
    DEBUG(1, ("Failed to enumerate groups (%d [%s]), retrying later!\n",
              (int)err, strerror(err)));
    tevent_req_done(req);
}


/* ==User-Enumeration===================================================== */

struct enum_users_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;

    char *filter;
    const char **attrs;
};

static void enum_users_connect_done(struct tevent_req *subreq);
static void enum_users_op_done(struct tevent_req *subreq);

static struct tevent_req *enum_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx)
{
    struct tevent_req *req, *subreq;
    struct enum_users_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct enum_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    if (ctx->max_user_timestamp) {
        state->filter = talloc_asprintf(state,
                               "(&(%s=*)(objectclass=%s)(%s>=%s)(!(%s=%s)))",
                               ctx->opts->user_map[SDAP_AT_USER_NAME].name,
                               ctx->opts->user_map[SDAP_OC_USER].name,
                               ctx->opts->user_map[SDAP_AT_USER_MODSTAMP].name,
                               ctx->max_user_timestamp,
                               ctx->opts->user_map[SDAP_AT_USER_MODSTAMP].name,
                               ctx->max_user_timestamp);
    } else {
        state->filter = talloc_asprintf(state,
                               "(&(%s=*)(objectclass=%s))",
                               ctx->opts->user_map[SDAP_AT_USER_NAME].name,
                               ctx->opts->user_map[SDAP_OC_USER].name);
    }
    if (!state->filter) {
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->user_map,
                               SDAP_OPTS_USER, &state->attrs);
    if (ret != EOK) goto fail;

    if (!connected(ctx)) {

        if (ctx->gsh) talloc_zfree(ctx->gsh);

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_cli_connect_send(state, ev, ctx->opts);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, enum_users_connect_done, req);

        return req;
    }

    subreq = sdap_get_users_send(state, state->ev,
                                 state->ctx->be->domain,
                                 state->ctx->be->sysdb,
                                 state->ctx->opts,
                                 state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, enum_users_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void enum_users_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct enum_users_state *state = tevent_req_data(req,
                                                     struct enum_users_state);
    int ret;

    ret = sdap_cli_connect_recv(subreq, state->ctx, &state->ctx->gsh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_users_send(state, state->ev,
                                 state->ctx->be->domain,
                                 state->ctx->be->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, enum_users_op_done, req);
}

static void enum_users_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct enum_users_state *state = tevent_req_data(req,
                                                     struct enum_users_state);
    char *timestamp;
    int ret;

    ret = sdap_get_users_recv(subreq, state, &timestamp);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (timestamp) {
        talloc_zfree(state->ctx->max_user_timestamp);
        state->ctx->max_user_timestamp = talloc_steal(state->ctx, timestamp);
    }

    DEBUG(4, ("Users higher timestamp: [%s]\n",
              state->ctx->max_user_timestamp));

    tevent_req_done(req);
}

/* =Group-Enumeration===================================================== */

struct enum_groups_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;

    char *filter;
    const char **attrs;
};

static void enum_groups_connect_done(struct tevent_req *subreq);
static void enum_groups_op_done(struct tevent_req *subreq);

static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx)
{
    struct tevent_req *req, *subreq;
    struct enum_groups_state *state;
    const char *attr_name;
    int ret;

    req = tevent_req_create(memctx, &state, struct enum_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    attr_name = ctx->opts->group_map[SDAP_AT_GROUP_NAME].name;

    if (ctx->max_group_timestamp) {
        state->filter = talloc_asprintf(state,
                              "(&(%s=*)(objectclass=%s)(%s>=%s)(!(%s=%s)))",
                              ctx->opts->group_map[SDAP_AT_GROUP_NAME].name,
                              ctx->opts->group_map[SDAP_OC_GROUP].name,
                              ctx->opts->group_map[SDAP_AT_GROUP_MODSTAMP].name,
                              ctx->max_group_timestamp,
                              ctx->opts->group_map[SDAP_AT_GROUP_MODSTAMP].name,
                              ctx->max_group_timestamp);
    } else {
        state->filter = talloc_asprintf(state,
                              "(&(%s=*)(objectclass=%s))",
                              ctx->opts->group_map[SDAP_AT_GROUP_NAME].name,
                              ctx->opts->group_map[SDAP_OC_GROUP].name);
    }
    if (!state->filter) {
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->group_map,
                               SDAP_OPTS_GROUP, &state->attrs);
    if (ret != EOK) goto fail;

    if (!connected(ctx)) {

        if (ctx->gsh) talloc_zfree(ctx->gsh);

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_cli_connect_send(state, ev, ctx->opts);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, enum_groups_connect_done, req);

        return req;
    }

    subreq = sdap_get_groups_send(state, state->ev,
                                 state->ctx->be->domain,
                                 state->ctx->be->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, enum_groups_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void enum_groups_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct enum_groups_state *state = tevent_req_data(req,
                                                 struct enum_groups_state);
    int ret;

    ret = sdap_cli_connect_recv(subreq, state->ctx, &state->ctx->gsh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_groups_send(state, state->ev,
                                  state->ctx->be->domain,
                                  state->ctx->be->sysdb,
                                  state->ctx->opts, state->ctx->gsh,
                                  state->attrs, state->filter);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, enum_groups_op_done, req);
}

static void enum_groups_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct enum_groups_state *state = tevent_req_data(req,
                                                 struct enum_groups_state);
    char *timestamp;
    int ret;

    ret = sdap_get_groups_recv(subreq, state, &timestamp);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (timestamp) {
        talloc_zfree(state->ctx->max_group_timestamp);
        state->ctx->max_group_timestamp = talloc_steal(state->ctx, timestamp);
    }

    DEBUG(4, ("Groups higher timestamp: [%s]\n",
              state->ctx->max_group_timestamp));

    tevent_req_done(req);
}

int sdap_id_setup_tasks(struct sdap_id_ctx *ctx)
{
    struct tevent_timer *enum_task;
    int ret = EOK;

    /* set up enumeration task */
    if (ctx->be->domain->enumerate) {
        /* run the first one in a couple of seconds so that we have time to
         * finish initializations first*/
        ctx->last_run = tevent_timeval_current_ofs(2, 0);
        enum_task = tevent_add_timer(ctx->be->ev, ctx, ctx->last_run,
                                     ldap_id_enumerate, ctx);
        if (!enum_task) {
            DEBUG(0, ("FATAL: failed to setup enumeration task!\n"));
            ret = EFAULT;
        }
    }

    return ret;
}

