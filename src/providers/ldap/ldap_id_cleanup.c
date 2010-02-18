/*
    SSSD

    LDAP Identity Cleanup Functions

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

/* ==Cleanup-Task========================================================= */

struct tevent_req *ldap_id_cleanup_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sdap_id_ctx *ctx);
static void ldap_id_cleanup_reschedule(struct tevent_req *req);

static void ldap_id_cleanup_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt);

static void ldap_id_cleanup_timer(struct tevent_context *ev,
                                  struct tevent_timer *tt,
                                  struct timeval tv, void *pvt)
{
    struct sdap_id_ctx *ctx = talloc_get_type(pvt, struct sdap_id_ctx);
    struct tevent_timer *timeout;
    struct tevent_req *req;
    int delay;

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ldap_id_cleanup_set_timer(ctx, tv);
        return;
    }

    req = ldap_id_cleanup_send(ctx, ev, ctx);
    if (!req) {
        DEBUG(1, ("Failed to schedule cleanup, retrying later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ldap_id_cleanup_set_timer(ctx, tv);
        return;
    }
    tevent_req_set_callback(req, ldap_id_cleanup_reschedule, ctx);

    /* if cleanup takes so long, either we try to cleanup too
     * frequently, or something went seriously wrong */
    delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    tv = tevent_timeval_current_ofs(delay, 0);
    timeout = tevent_add_timer(ctx->be->ev, req, tv,
                               ldap_id_cleanup_timeout, req);
    return;
}

static void ldap_id_cleanup_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    int delay;

    delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    DEBUG(1, ("Cleanup timed out! Timeout too small? (%ds)!\n", delay));

    tv = tevent_timeval_current_ofs(delay, 0);
    ldap_id_enumerate_set_timer(ctx, tv);

    talloc_zfree(req);
}

static void ldap_id_cleanup_reschedule(struct tevent_req *req)
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
        tv = ctx->last_purge;
    }
    talloc_zfree(req);

    delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    tv = tevent_timeval_add(&tv, delay, 0);
    ldap_id_enumerate_set_timer(ctx, tv);
}



int ldap_id_cleanup_set_timer(struct sdap_id_ctx *ctx, struct timeval tv)
{
    struct tevent_timer *cleanup_task;

    DEBUG(6, ("Scheduling next cleanup at %ld.%ld\n",
              (long)tv.tv_sec, (long)tv.tv_usec));

    cleanup_task = tevent_add_timer(ctx->be->ev, ctx,
                                    tv, ldap_id_cleanup_timer, ctx);
    if (!cleanup_task) {
        DEBUG(0, ("FATAL: failed to setup cleanup task!\n"));
        return EFAULT;
    }

    return EOK;
}



struct global_cleanup_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
};

static struct tevent_req *cleanup_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx);
static void ldap_id_cleanup_users_done(struct tevent_req *subreq);
static struct tevent_req *cleanup_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx);
static void ldap_id_cleanup_groups_done(struct tevent_req *subreq);

struct tevent_req *ldap_id_cleanup_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sdap_id_ctx *ctx)
{
    struct global_cleanup_state *state;
    struct tevent_req *req, *subreq;

    req = tevent_req_create(memctx, &state, struct global_cleanup_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    subreq = cleanup_users_send(state, ev, ctx);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, ldap_id_cleanup_users_done, req);

    ctx->last_purge = tevent_timeval_current();

    return req;
}

static void ldap_id_cleanup_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_cleanup_state *state = tevent_req_data(req,
                                                 struct global_cleanup_state);
    enum tevent_req_state tstate;
    uint64_t err = 0;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        if (tstate != TEVENT_REQ_USER_ERROR) {
            err = EIO;
        }
        if (err != ENOENT) {
            goto fail;
        }
    }
    talloc_zfree(subreq);

    subreq = cleanup_groups_send(state, state->ev, state->ctx);
    if (!subreq) {
        goto fail;
    }
    tevent_req_set_callback(subreq, ldap_id_cleanup_groups_done, req);

    return;

fail:
    if (err) {
        DEBUG(9, ("User cleanup failed with: (%d)[%s]\n",
                  (int)err, strerror(err)));

        if (sdap_check_gssapi_reconnect(state->ctx)) {
            talloc_zfree(state->ctx->gsh);
            subreq = cleanup_users_send(state, state->ev, state->ctx);
            if (subreq != NULL) {
                tevent_req_set_callback(subreq, ldap_id_cleanup_users_done, req);
                return;
            }
        }
        sdap_mark_offline(state->ctx);
    }

    DEBUG(1, ("Failed to cleanup users, retrying later!\n"));
    tevent_req_done(req);
}

static void ldap_id_cleanup_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_cleanup_state *state = tevent_req_data(req,
                                                 struct global_cleanup_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        if (tstate != TEVENT_REQ_USER_ERROR) {
            err = EIO;
        }
        if (err != ENOENT) {
            goto fail;
        }
    }
    talloc_zfree(subreq);

    tevent_req_done(req);
    return;

fail:
    /* check if credentials are expired otherwise go offline on failures */
    if (sdap_check_gssapi_reconnect(state->ctx)) {
        talloc_zfree(state->ctx->gsh);
        subreq = cleanup_groups_send(state, state->ev, state->ctx);
        if (subreq != NULL) {
            tevent_req_set_callback(subreq, ldap_id_cleanup_groups_done, req);
            return;
        }
    }
    sdap_mark_offline(state->ctx);
    DEBUG(1, ("Failed to cleanup groups (%d [%s]), retrying later!\n",
              (int)err, strerror(err)));
    tevent_req_done(req);
}


/* ==User-Cleanup-Process================================================= */

struct cleanup_users_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    struct sysdb_handle *handle;

    struct ldb_message **msgs;
    size_t count;
    int cur;
};

static void cleanup_users_process(struct tevent_req *subreq);
static void cleanup_users_update(struct tevent_req *req);
static void cleanup_users_up_done(struct tevent_req *subreq);

static struct tevent_req *cleanup_users_send(TALLOC_CTX *memctx,
                                             struct tevent_context *ev,
                                             struct sdap_id_ctx *ctx)
{
    struct tevent_req *req, *subreq;
    struct cleanup_users_state *state;
    static const char *attrs[] = { SYSDB_NAME, NULL };
    time_t now = time(NULL);
    char *subfilter;

    req = tevent_req_create(memctx, &state, struct cleanup_users_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = ctx->be->sysdb;
    state->domain = ctx->be->domain;
    state->msgs = NULL;
    state->count = 0;
    state->cur = 0;

    subfilter = talloc_asprintf(state, "(&(!(%s=0))(%s<=%ld))",
                                SYSDB_CACHE_EXPIRE,
                                SYSDB_CACHE_EXPIRE, (long)now);
    if (!subfilter) {
        DEBUG(2, ("Failed to build filter\n"));
        talloc_zfree(req);
        return NULL;
    }

    subreq = sysdb_search_users_send(state, state->ev,
                                     state->sysdb, NULL,
                                     state->domain, subfilter, attrs);
    if (!subreq) {
        DEBUG(2, ("Failed to send entry search\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, cleanup_users_process, req);

    return req;
}

static void cleanup_users_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct cleanup_users_state *state = tevent_req_data(req,
                                               struct cleanup_users_state);
    int ret;

    ret = sysdb_search_users_recv(subreq, state, &state->count, &state->msgs);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ENOENT) {
            tevent_req_done(req);
            return;
        }
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(4, ("Found %d expired user entries!\n", state->count));

    if (state->count == 0) {
        tevent_req_done(req);
    }

    cleanup_users_update(req);
}

static void cleanup_users_update(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct cleanup_users_state *state = tevent_req_data(req,
                                               struct cleanup_users_state);
    const char *str;

    str = ldb_msg_find_attr_as_string(state->msgs[state->cur],
                                      SYSDB_NAME, NULL);
    if (!str) {
        DEBUG(2, ("Entry %s has no Name Attribute ?!?\n",
                  ldb_dn_get_linearized(state->msgs[state->cur]->dn)));
        tevent_req_error(req, EFAULT);
        return;
    }

    subreq = users_get_send(state, state->ev, state->ctx,
                            str, BE_FILTER_NAME, BE_ATTR_CORE);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, cleanup_users_up_done, req);
}

static void cleanup_users_up_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct cleanup_users_state *state = tevent_req_data(req,
                                               struct cleanup_users_state);
    int ret;

    ret = users_get_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("User check returned: %d(%s)\n",
                  ret, strerror(ret)));
    }

    /* if the entry doesn't need to be purged, remove it from the list */
    if (ret != ENOENT) {
        talloc_zfree(state->msgs[state->cur]);
    }

    state->cur++;
    if (state->cur < state->count) {
        cleanup_users_update(req);
        return;
    }

    tevent_req_done(req);
}

/* ==Group-Cleanup-Process================================================ */

struct cleanup_groups_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    struct sysdb_handle *handle;

    struct ldb_message **msgs;
    size_t count;
    int cur;
};

static void cleanup_groups_process(struct tevent_req *subreq);
static void cleanup_groups_update(struct tevent_req *req);
static void cleanup_groups_up_done(struct tevent_req *subreq);

static struct tevent_req *cleanup_groups_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sdap_id_ctx *ctx)
{
    struct tevent_req *req, *subreq;
    struct cleanup_groups_state *state;
    static const char *attrs[] = { SYSDB_NAME, NULL };
    time_t now = time(NULL);
    char *subfilter;

    req = tevent_req_create(memctx, &state, struct cleanup_groups_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->ctx = ctx;
    state->sysdb = ctx->be->sysdb;
    state->domain = ctx->be->domain;
    state->msgs = NULL;
    state->count = 0;
    state->cur = 0;

    subfilter = talloc_asprintf(state, "(&(!(%s=0))(%s<=%ld))",
                                SYSDB_CACHE_EXPIRE,
                                SYSDB_CACHE_EXPIRE, (long)now);
    if (!subfilter) {
        DEBUG(2, ("Failed to build filter\n"));
        talloc_zfree(req);
        return NULL;
    }

    subreq = sysdb_search_groups_send(state, state->ev,
                                      state->sysdb, NULL,
                                      state->domain, subfilter, attrs);
    if (!subreq) {
        DEBUG(2, ("Failed to send entry search\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, cleanup_groups_process, req);

    return req;
}

static void cleanup_groups_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct cleanup_groups_state *state = tevent_req_data(req,
                                               struct cleanup_groups_state);
    int ret;

    ret = sysdb_search_groups_recv(subreq, state, &state->count, &state->msgs);
    talloc_zfree(subreq);
    if (ret) {
        if (ret == ENOENT) {
            tevent_req_done(req);
            return;
        }
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(4, ("Found %d expired group entries!\n", state->count));

    if (state->count == 0) {
        tevent_req_done(req);
    }

    cleanup_groups_update(req);
}

static void cleanup_groups_update(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct cleanup_groups_state *state = tevent_req_data(req,
                                               struct cleanup_groups_state);
    const char *str;

    str = ldb_msg_find_attr_as_string(state->msgs[state->cur],
                                      SYSDB_NAME, NULL);
    if (!str) {
        DEBUG(2, ("Entry %s has no Name Attribute ?!?\n",
                  ldb_dn_get_linearized(state->msgs[state->cur]->dn)));
        tevent_req_error(req, EFAULT);
        return;
    }

    subreq = groups_get_send(state, state->ev, state->ctx,
                             str, BE_FILTER_NAME, BE_ATTR_CORE);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, cleanup_groups_up_done, req);
}

static void cleanup_groups_up_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct cleanup_groups_state *state = tevent_req_data(req,
                                               struct cleanup_groups_state);
    int ret;

    ret = groups_get_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("User check returned: %d(%s)\n",
                  ret, strerror(ret)));
    }

    state->cur++;
    if (state->cur < state->count) {
        cleanup_groups_update(req);
        return;
    }

    tevent_req_done(req);
}

