/*
    SSSD

    LDAP Identity Enumeration

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"

extern struct tevent_req *ldap_id_cleanup_send(TALLOC_CTX *memctx,
                                               struct tevent_context *ev,
                                               struct sdap_id_ctx *ctx);

/* ==Enumeration-Task===================================================== */

static struct tevent_req *ldap_id_enumerate_send(struct tevent_context *ev,
                                                 struct sdap_id_ctx *ctx);

static void ldap_id_enumerate_reschedule(struct tevent_req *req);

static void ldap_id_enumerate_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt);

static void ldap_id_enumerate_timer(struct tevent_context *ev,
                                    struct tevent_timer *tt,
                                    struct timeval tv, void *pvt)
{
    struct sdap_id_ctx *ctx = talloc_get_type(pvt, struct sdap_id_ctx);
    struct tevent_timer *timeout;
    struct tevent_req *req;
    int delay;
    errno_t ret;

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ldap_id_enumerate_set_timer(ctx, tv);
        return;
    }

    req = ldap_id_enumerate_send(ev, ctx);
    if (!req) {
        DEBUG(1, ("Failed to schedule enumeration, retrying later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = ldap_id_enumerate_set_timer(ctx, tv);
        if (ret != EOK) {
            DEBUG(1, ("Error setting up enumerate timer\n"));
        }
        return;
    }
    tevent_req_set_callback(req, ldap_id_enumerate_reschedule, ctx);

    /* if enumeration takes so long, either we try to enumerate too
     * frequently, or something went seriously wrong */
    delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    tv = tevent_timeval_current_ofs(delay, 0);
    timeout = tevent_add_timer(ctx->be->ev, req, tv,
                               ldap_id_enumerate_timeout, req);
    if (timeout == NULL) {
        /* If we can't guarantee a timeout, we
         * need to cancel the request, to avoid
         * the possibility of starting another
         * concurrently
         */
        talloc_zfree(req);

        DEBUG(1, ("Failed to schedule enumeration, retrying later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = ldap_id_enumerate_set_timer(ctx, tv);
        if (ret != EOK) {
            DEBUG(1, ("Error setting up enumerate timer\n"));
        }
        return;
    }
    return;
}

static void ldap_id_enumerate_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    int delay;

    delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    DEBUG(1, ("Enumeration timed out! Timeout too small? (%ds)!\n", delay));

    tv = tevent_timeval_current_ofs(delay, 0);
    ldap_id_enumerate_set_timer(ctx, tv);

    talloc_zfree(req);
}

static void ldap_id_enumerate_reschedule(struct tevent_req *req)
{
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    enum tevent_req_state tstate;
    uint64_t err;
    struct timeval tv;
    int delay;

    if (tevent_req_is_error(req, &tstate, &err)) {
        /* On error schedule starting from now, not the last run */
        tv = tevent_timeval_current();
    } else {
        tv = ctx->last_enum;
    }
    talloc_zfree(req);

    delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    tv = tevent_timeval_add(&tv, delay, 0);
    ldap_id_enumerate_set_timer(ctx, tv);
}



int ldap_id_enumerate_set_timer(struct sdap_id_ctx *ctx, struct timeval tv)
{
    struct tevent_timer *enum_task;

    DEBUG(6, ("Scheduling next enumeration at %ld.%ld\n",
              (long)tv.tv_sec, (long)tv.tv_usec));

    enum_task = tevent_add_timer(ctx->be->ev, ctx,
                                 tv, ldap_id_enumerate_timer, ctx);
    if (!enum_task) {
        DEBUG(0, ("FATAL: failed to setup enumeration task!\n"));
        return EFAULT;
    }

    return EOK;
}

#define MAX_ENUM_RESTARTS 3

struct global_enum_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;

    bool purge;
    int restarts;
};

static struct tevent_req *enum_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          bool purge);
static void ldap_id_enum_users_done(struct tevent_req *subreq);
static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          bool purge);
static void ldap_id_enum_groups_done(struct tevent_req *subreq);
static void ldap_id_enum_cleanup_done(struct tevent_req *subreq);
static int ldap_id_enum_users_restart(struct tevent_req *req);
static int ldap_id_enum_groups_restart(struct tevent_req *req);

static struct tevent_req *ldap_id_enumerate_send(struct tevent_context *ev,
                                                 struct sdap_id_ctx *ctx)
{
    struct global_enum_state *state;
    struct tevent_req *req, *subreq;
    int t;

    req = tevent_req_create(ctx, &state, struct global_enum_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->restarts = 0;

    ctx->last_enum = tevent_timeval_current();

    t = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    if ((ctx->last_purge.tv_sec + t) < ctx->last_enum.tv_sec) {
        state->purge = true;
    } else {
        state->purge = false;
    }

    subreq = enum_users_send(state, ev, ctx, state->purge);
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
    int ret;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        if (tstate != TEVENT_REQ_USER_ERROR) {
            err = EIO;
        }
        if (err != ENOENT) {
            goto fail;
        }
    }
    talloc_zfree(subreq);

    subreq = enum_groups_send(state, state->ev, state->ctx, state->purge);
    if (!subreq) {
        goto fail;
    }
    tevent_req_set_callback(subreq, ldap_id_enum_groups_done, req);

    return;

fail:
    if (err) {
        DEBUG(9, ("User enumeration failed with: (%d)[%s]\n",
                  (int)err, strerror(err)));

        if (sdap_check_gssapi_reconnect(state->ctx)) {
            if (state->ctx->gsh) {
                state->ctx->gsh->connected = false;
            }
            ret = ldap_id_enum_users_restart(req);
            if (ret == EOK) return;
        }
        sdap_mark_offline(state->ctx);
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
    uint64_t err = 0;
    int ret;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        if (tstate != TEVENT_REQ_USER_ERROR) {
            err = EIO;
        }
        if (err != ENOENT) {
            goto fail;
        }
    }
    talloc_zfree(subreq);

    if (state->purge) {

        subreq = ldap_id_cleanup_send(state, state->ev, state->ctx);
        if (!subreq) {
            goto fail;
        }
        tevent_req_set_callback(subreq, ldap_id_enum_cleanup_done, req);

        return;
    }

    tevent_req_done(req);
    return;

fail:
    /* check if credentials are expired otherwise go offline on failures */
    if (sdap_check_gssapi_reconnect(state->ctx)) {
        if (state->ctx->gsh) {
            state->ctx->gsh->connected = false;
        }
        ret = ldap_id_enum_groups_restart(req);
        if (ret == EOK) return;
    }
    sdap_mark_offline(state->ctx);
    DEBUG(1, ("Failed to enumerate groups (%d [%s]), retrying later!\n",
              (int)err, strerror(err)));
    tevent_req_done(req);
}

static void ldap_id_enum_cleanup_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    talloc_zfree(subreq);
    tevent_req_done(req);
}

static void ldap_id_enum_users_immediate(struct tevent_context *ctx,
                                         struct tevent_immediate *im,
                                         void *private_data)
{
    struct tevent_req *req = talloc_get_type(private_data,
                                             struct tevent_req);
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    struct tevent_req *subreq;

    subreq = enum_users_send(state, state->ev, state->ctx, state->purge);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ldap_id_enum_users_done, req);
}

static int ldap_id_enum_users_restart(struct tevent_req *req)
{
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    struct tevent_immediate *im;

    state->restarts++;
    if (state->restarts < MAX_ENUM_RESTARTS) {
        return ELOOP;
    }

    im = tevent_create_immediate(req);
    if (!im) {
        return ENOMEM;
    }

    /* schedule a completely new event to avoid deep recursions */
    tevent_schedule_immediate(im, state->ev,
                              ldap_id_enum_users_immediate, req);

    return EOK;
}

static void ldap_id_enum_groups_immediate(struct tevent_context *ctx,
                                          struct tevent_immediate *im,
                                          void *private_data)
{
    struct tevent_req *req = talloc_get_type(private_data,
                                             struct tevent_req);
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    struct tevent_req *subreq;

    subreq = enum_groups_send(state, state->ev, state->ctx, state->purge);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ldap_id_enum_groups_done, req);
}

static int ldap_id_enum_groups_restart(struct tevent_req *req)
{
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    struct tevent_immediate *im;

    state->restarts++;
    if (state->restarts < MAX_ENUM_RESTARTS) {
        return ELOOP;
    }

    im = tevent_create_immediate(req);
    if (!im) {
        return ENOMEM;
    }

    /* schedule a completely new event to avoid deep recursions */
    tevent_schedule_immediate(im, state->ev,
                              ldap_id_enum_groups_immediate, req);

    return EOK;
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
                                          struct sdap_id_ctx *ctx,
                                          bool purge)
{
    struct tevent_req *req, *subreq;
    struct enum_users_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct enum_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    if (ctx->max_user_timestamp && !purge) {

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

    if (!sdap_connected(ctx)) {

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_cli_connect_send(state, ev, ctx->opts,
                                       ctx->be, ctx->service,
                                       &ctx->rootDSE);
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

    ret = sdap_cli_connect_recv(subreq, state->ctx,
                                &state->ctx->gsh, &state->ctx->rootDSE);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ENOTSUP) {
            DEBUG(0, ("Authentication mechanism not Supported by server"));
        }
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
                                          struct sdap_id_ctx *ctx,
                                          bool purge)
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

    if (ctx->max_group_timestamp && !purge) {

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

    if (!sdap_connected(ctx)) {

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_cli_connect_send(state, ev, ctx->opts,
                                       ctx->be, ctx->service,
                                       &ctx->rootDSE);
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

    ret = sdap_cli_connect_recv(subreq, state->ctx,
                                &state->ctx->gsh, &state->ctx->rootDSE);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ENOTSUP) {
            DEBUG(0, ("Authentication mechanism not Supported by server"));
        }
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

