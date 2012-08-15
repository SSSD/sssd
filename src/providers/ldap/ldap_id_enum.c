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

static int ldap_id_enumerate_retry(struct tevent_req *req);
static void ldap_id_enumerate_connect_done(struct tevent_req *req);

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
    errno_t ret;

    if (tevent_req_is_error(req, &tstate, &err)) {
        /* On error schedule starting from now, not the last run */
        tv = tevent_timeval_current();
    } else {
        tv = ctx->last_enum;

        /* Ok, we've completed an enumeration. Save this to the
         * sysdb so we can postpone starting up the enumeration
         * process on the next SSSD service restart (to avoid
         * slowing down system boot-up
         */
        ret = sysdb_set_enumerated(ctx->be->sysdb, true);
        if (ret != EOK) {
            DEBUG(1, ("Could not mark domain as having enumerated.\n"));
            /* This error is non-fatal, so continue */
        }
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
    struct sdap_id_op *op;

    bool purge;
};

static struct tevent_req *enum_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_id_op *op,
                                          bool purge);
static void ldap_id_enum_users_done(struct tevent_req *subreq);
static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_id_op *op,
                                          bool purge);
static void ldap_id_enum_groups_done(struct tevent_req *subreq);
static void ldap_id_enum_services_done(struct tevent_req *subreq);
static void ldap_id_enum_cleanup_done(struct tevent_req *subreq);

struct tevent_req *ldap_id_enumerate_send(struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx)
{
    struct global_enum_state *state;
    struct tevent_req *req;
    int t;

    req = tevent_req_create(ctx, &state, struct global_enum_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->op = sdap_id_op_create(state, state->ctx->conn_cache);
    if (!state->op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
        talloc_zfree(req);
        return NULL;
    }

    ctx->last_enum = tevent_timeval_current();

    t = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    if ((ctx->last_purge.tv_sec + t) < ctx->last_enum.tv_sec) {
        state->purge = true;
    } else {
        state->purge = false;
    }

    int ret = ldap_id_enumerate_retry(req);
    if (ret != EOK) {
        DEBUG(2, ("ldap_id_enumerate_retry failed\n"));
        talloc_zfree(req);
        return NULL;
    }

    return req;
}

static int ldap_id_enumerate_retry(struct tevent_req *req)
{
    struct global_enum_state *state = tevent_req_data(req,
                                                      struct global_enum_state);
    struct tevent_req *subreq;
    int ret;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, ldap_id_enumerate_connect_done, req);
    return EOK;
}

static void ldap_id_enumerate_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            tevent_req_done(req);
        } else {
            DEBUG(9, ("User enumeration failed to connect to LDAP server: (%d)[%s]\n",
                      ret, strerror(ret)));
            tevent_req_error(req, ret);
        }

        return;
    }

    subreq = enum_users_send(state, state->ev,
                             state->ctx, state->op,
                             state->purge);
    if(!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ldap_id_enum_users_done, req);
}

static void ldap_id_enum_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    enum tevent_req_state tstate;
    uint64_t err = 0;
    int ret, dp_error = DP_ERR_FATAL;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        if (tstate != TEVENT_REQ_USER_ERROR) {
            err = EIO;
        }

        if (err == ENOENT) {
            err = EOK;
        }
    }
    talloc_zfree(subreq);

    if (err != EOK) {
        /* We call sdap_id_op_done only on error
         * as the connection is reused by groups enumeration */
        ret = sdap_id_op_done(state->op, (int)err, &dp_error);
        if (dp_error == DP_ERR_OK) {
            /* retry */
            ret = ldap_id_enumerate_retry(req);
            if (ret == EOK) {
                return;
            }

            dp_error = DP_ERR_FATAL;
        }

        if (dp_error == DP_ERR_OFFLINE) {
            tevent_req_done(req);
        } else {
            DEBUG(9, ("User enumeration failed with: (%d)[%s]\n",
                      ret, strerror(ret)));
            tevent_req_error(req, ret);
        }
        return;
    }

    subreq = enum_groups_send(state, state->ev, state->ctx, state->op, state->purge);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ldap_id_enum_groups_done, req);
}

static void ldap_id_enum_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);
    enum tevent_req_state tstate;
    uint64_t err = 0;
    int ret, dp_error = DP_ERR_FATAL;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        if (tstate != TEVENT_REQ_USER_ERROR) {
            err = EIO;
        }

        if (err == ENOENT) {
            err = EOK;
        }
    }
    talloc_zfree(subreq);

    if (err != EOK) {
        /* We call sdap_id_op_done only on error
         * as the connection is reused by services enumeration */
        ret = sdap_id_op_done(state->op, (int)err, &dp_error);
        if (dp_error == DP_ERR_OK && ret != EOK) {
            /* retry */
            ret = ldap_id_enumerate_retry(req);
            if (ret == EOK) {
                return;
            }

            dp_error = DP_ERR_FATAL;
        }

        if (ret != EOK) {
            if (dp_error == DP_ERR_OFFLINE) {
                tevent_req_done(req);
            } else {
                DEBUG(9, ("Group enumeration failed with: (%d)[%s]\n",
                          ret, strerror(ret)));
                tevent_req_error(req, ret);
            }

            return;
        }
    }

    subreq = enum_services_send(state, state->ev, state->ctx,
                                state->op, state->purge);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ldap_id_enum_services_done, req);
}

static void ldap_id_enum_services_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct global_enum_state *state = tevent_req_data(req,
                                                 struct global_enum_state);

    ret = enum_services_recv(subreq);
    talloc_zfree(subreq);
    if (ret == ENOENT) ret = EOK;

    /* All enumerations are complete, so conclude the
     * id_op
     */
    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ldap_id_enumerate_retry(req);
        if (ret == EOK) {
            return;
        }

        dp_error = DP_ERR_FATAL;
    }

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Service enumeration failed with: (%d)[%s]\n",
                   ret, strerror(ret)));
            tevent_req_error(req, ret);
        }

        return;
    }

    if (state->purge) {

        subreq = ldap_id_cleanup_send(state, state->ev, state->ctx);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        tevent_req_set_callback(subreq, ldap_id_enum_cleanup_done, req);
        return;
    }

    tevent_req_done(req);
}

static void ldap_id_enum_cleanup_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    talloc_zfree(subreq);
    tevent_req_done(req);
}

/* ==User-Enumeration===================================================== */

struct enum_users_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;

    char *filter;
    const char **attrs;
};

static void enum_users_op_done(struct tevent_req *subreq);

static struct tevent_req *enum_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_id_op *op,
                                          bool purge)
{
    struct tevent_req *req, *subreq;
    struct enum_users_state *state;
    int ret;
    bool use_mapping;

    req = tevent_req_create(memctx, &state, struct enum_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->op = op;

    use_mapping = dp_opt_get_bool(ctx->opts->basic, SDAP_ID_MAPPING);

    /* We always want to filter on objectclass and an available name */
    state->filter = talloc_asprintf(state,
                                    "(&(objectclass=%s)(%s=*)",
                                    ctx->opts->user_map[SDAP_OC_USER].name,
                                    ctx->opts->user_map[SDAP_AT_USER_NAME].name);
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to build base filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    if (use_mapping) {
        /* If we're ID-mapping, check for the objectSID as well */
        state->filter = talloc_asprintf_append_buffer(
                state->filter, "(%s=*)",
                ctx->opts->user_map[SDAP_AT_USER_OBJECTSID].name);
    } else {
        /* We're not ID-mapping, so make sure to only get entries
         * that have UID and GID
         */
        state->filter = talloc_asprintf_append_buffer(
                state->filter, "(%s=*)(%s=*)",
                ctx->opts->user_map[SDAP_AT_USER_UID].name,
                ctx->opts->user_map[SDAP_AT_USER_GID].name);
    }
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to build base filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    if (ctx->srv_opts && ctx->srv_opts->max_user_value && !purge) {
        /* If we have lastUSN available and we're not doing a full
         * refresh, limit to changes with a higher entryUSN value.
         */
        state->filter = talloc_asprintf_append_buffer(
                state->filter,
                "(%s>=%s)(!(%s=%s))",
                ctx->opts->user_map[SDAP_AT_USER_USN].name,
                ctx->srv_opts->max_user_value,
                ctx->opts->user_map[SDAP_AT_USER_USN].name,
                ctx->srv_opts->max_user_value);

        if (!state->filter) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Failed to build base filter\n"));
            ret = ENOMEM;
            goto fail;
        }
    }

    /* Terminate the search filter */
    state->filter = talloc_asprintf_append_buffer(state->filter, ")");
    if (!state->filter) {
        DEBUG(2, ("Failed to build base filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->user_map, SDAP_OPTS_USER,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) goto fail;

    /* TODO: restrict the enumerations to using a single
     * search base at a time.
     */

    subreq = sdap_get_users_send(state, state->ev,
                                 state->ctx->be->domain,
                                 state->ctx->be->sysdb,
                                 state->ctx->opts,
                                 state->ctx->opts->user_search_bases,
                                 sdap_id_op_handle(state->op),
                                 state->attrs, state->filter,
                                 dp_opt_get_int(state->ctx->opts->basic,
                                                SDAP_ENUM_SEARCH_TIMEOUT),
                                 true);
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

static void enum_users_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct enum_users_state *state = tevent_req_data(req,
                                                     struct enum_users_state);
    char *usn_value;
    char *endptr = NULL;
    unsigned usn_number;
    int ret;

    ret = sdap_get_users_recv(subreq, state, &usn_value);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (usn_value) {
        talloc_zfree(state->ctx->srv_opts->max_user_value);
        state->ctx->srv_opts->max_user_value = talloc_steal(state->ctx, usn_value);

        usn_number = strtoul(usn_value, &endptr, 10);
        if ((endptr == NULL || (*endptr == '\0' && endptr != usn_value))
            && (usn_number > state->ctx->srv_opts->last_usn)) {
            state->ctx->srv_opts->last_usn = usn_number;
        }
    }

    DEBUG(4, ("Users higher USN value: [%s]\n",
              state->ctx->srv_opts->max_user_value));

    tevent_req_done(req);
}

/* =Group-Enumeration===================================================== */

struct enum_groups_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;

    char *filter;
    const char **attrs;
};

static void enum_groups_op_done(struct tevent_req *subreq);

static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_id_op *op,
                                          bool purge)
{
    struct tevent_req *req, *subreq;
    struct enum_groups_state *state;
    int ret;
    bool use_mapping;

    req = tevent_req_create(memctx, &state, struct enum_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->op = op;

    use_mapping = dp_opt_get_bool(ctx->opts->basic, SDAP_ID_MAPPING);

    /* We always want to filter on objectclass and an available name */
    state->filter = talloc_asprintf(state,
                                    "(&(objectclass=%s)(%s=*)",
                                    ctx->opts->group_map[SDAP_OC_GROUP].name,
                                    ctx->opts->group_map[SDAP_AT_GROUP_NAME].name);
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to build base filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    if (use_mapping) {
        /* If we're ID-mapping, check for the objectSID as well */
        state->filter = talloc_asprintf_append_buffer(
                state->filter, "(%s=*)",
                ctx->opts->group_map[SDAP_AT_GROUP_OBJECTSID].name);
    } else {
        /* We're not ID-mapping, so make sure to only get entries
         * that have a non-zero GID.
         */
        state->filter = talloc_asprintf_append_buffer(
                state->filter, "(&(%s=*)(!(%s=0)))",
                ctx->opts->group_map[SDAP_AT_GROUP_GID].name,
                ctx->opts->group_map[SDAP_AT_GROUP_GID].name);
    }
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to build base filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    if (ctx->srv_opts && ctx->srv_opts->max_group_value && !purge) {
        state->filter = talloc_asprintf_append_buffer(
                state->filter,
                "(%s>=%s)(!(%s=%s))",
                ctx->opts->group_map[SDAP_AT_GROUP_USN].name,
                ctx->srv_opts->max_group_value,
                ctx->opts->group_map[SDAP_AT_GROUP_USN].name,
                ctx->srv_opts->max_group_value);
        if (!state->filter) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Failed to build base filter\n"));
            ret = ENOMEM;
            goto fail;
        }
    }

    /* Terminate the search filter */
    state->filter = talloc_asprintf_append_buffer(state->filter, ")");
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to build base filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->group_map, SDAP_OPTS_GROUP,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) goto fail;

    /* TODO: restrict the enumerations to using a single
     * search base at a time.
     */

    subreq = sdap_get_groups_send(state, state->ev,
                                 state->ctx->be->domain,
                                 state->ctx->be->sysdb,
                                 state->ctx->opts,
                                 state->ctx->opts->group_search_bases,
                                 sdap_id_op_handle(state->op),
                                 state->attrs, state->filter,
                                 dp_opt_get_int(state->ctx->opts->basic,
                                                SDAP_ENUM_SEARCH_TIMEOUT),
                                 true);
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

static void enum_groups_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct enum_groups_state *state = tevent_req_data(req,
                                                 struct enum_groups_state);
    char *usn_value;
    char *endptr = NULL;
    unsigned usn_number;
    int ret;

    ret = sdap_get_groups_recv(subreq, state, &usn_value);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (usn_value) {
        talloc_zfree(state->ctx->srv_opts->max_group_value);
        state->ctx->srv_opts->max_group_value =
                                        talloc_steal(state->ctx, usn_value);
        usn_number = strtoul(usn_value, &endptr, 10);
        if ((endptr == NULL || (*endptr == '\0' && endptr != usn_value))
            && (usn_number > state->ctx->srv_opts->last_usn)) {
            state->ctx->srv_opts->last_usn = usn_number;
        }
    }

    DEBUG(4, ("Groups higher USN value: [%s]\n",
              state->ctx->srv_opts->max_group_value));

    tevent_req_done(req);
}

