/*
    SSSD

    LDAP Enumeration Module

    Authors:
        Simo Sorce <ssorce@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_enum.h"
#include "providers/ldap/sdap_idmap.h"

static struct tevent_req *enum_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_domain *sdom,
                                          struct sdap_id_op *op,
                                          bool purge);
static errno_t enum_users_recv(struct tevent_req *req);

static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_domain *sdom,
                                          struct sdap_id_op *op,
                                          bool purge);
static errno_t enum_groups_recv(struct tevent_req *req);

/* ==Enumeration-Request==================================================== */
struct sdap_dom_enum_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *op;

    bool purge;
};

static errno_t sdap_dom_enum_retry(struct tevent_req *req);
static void sdap_dom_enum_conn_done(struct tevent_req *subreq);
static void sdap_dom_enum_users_done(struct tevent_req *subreq);
static void sdap_dom_enum_groups_done(struct tevent_req *subreq);
static void sdap_dom_enum_services_done(struct tevent_req *subreq);

struct tevent_req *
sdap_dom_enum_send(TALLOC_CTX *memctx,
                   struct tevent_context *ev,
                   struct sdap_id_ctx *ctx,
                   struct sdap_domain *sdom,
                   struct sdap_id_conn_ctx *conn)
{
    struct tevent_req *req;
    struct sdap_dom_enum_state *state;
    int t;
    errno_t ret;

    req = tevent_req_create(ctx, &state, struct sdap_dom_enum_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->op = sdap_id_op_create(state, state->ctx->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sdap_id_op_create failed\n"));
        ret = EIO;
        goto fail;
    }

    sdom->last_enum = tevent_timeval_current();

    t = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
    if ((sdom->last_purge.tv_sec + t) < sdom->last_enum.tv_sec) {
        state->purge = true;
    }

    ret = sdap_dom_enum_retry(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("ldap_id_enumerate_retry failed\n"));
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t sdap_dom_enum_retry(struct tevent_req *req)
{
    struct sdap_dom_enum_state *state = tevent_req_data(req,
                                                   struct sdap_dom_enum_state);
    struct tevent_req *subreq;
    errno_t ret;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sdap_id_op_connect_send failed: %d\n", ret));
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_dom_enum_conn_done, req);
    return EOK;
}

static void sdap_dom_enum_conn_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_state *state = tevent_req_data(req,
                                                   struct sdap_dom_enum_state);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("Backend is marked offline, retry later!\n"));
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Domain enumeration failed to connect to " \
                   "LDAP server: (%d)[%s]\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
        }
        return;
    }

    subreq = enum_users_send(state, state->ev,
                             state->ctx, state->sdom,
                             state->op, state->purge);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_dom_enum_users_done, req);
}

static void sdap_dom_enum_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_state *state = tevent_req_data(req,
                                                   struct sdap_dom_enum_state);
    uint64_t err = 0;
    int ret, dp_error = DP_ERR_FATAL;

    err = enum_users_recv(subreq);
    talloc_zfree(subreq);
    if (err != EOK && err != ENOENT) {
        /* We call sdap_id_op_done only on error
         * as the connection is reused by groups enumeration */
        ret = sdap_id_op_done(state->op, (int)err, &dp_error);
        if (dp_error == DP_ERR_OK) {
            /* retry */
            ret = sdap_dom_enum_retry(req);
            if (ret == EOK) {
                return;
            }

            dp_error = DP_ERR_FATAL;
        }

        if (dp_error == DP_ERR_OFFLINE) {
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("User enumeration failed with: (%d)[%s]\n",
                   ret, strerror(ret)));
            tevent_req_error(req, ret);
        }
        return;
    }

    subreq = enum_groups_send(state, state->ev, state->ctx,
                              state->sdom,
                              state->op, state->purge);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_dom_enum_groups_done, req);
}

static void sdap_dom_enum_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_state *state = tevent_req_data(req,
                                                   struct sdap_dom_enum_state);
    uint64_t err = 0;
    int ret, dp_error = DP_ERR_FATAL;

    err = enum_groups_recv(subreq);
    talloc_zfree(subreq);
    if (err != EOK && err != ENOENT) {
        /* We call sdap_id_op_done only on error
         * as the connection is reused by services enumeration */
        ret = sdap_id_op_done(state->op, (int)err, &dp_error);
        if (dp_error == DP_ERR_OK && ret != EOK) {
            /* retry */
            ret = sdap_dom_enum_retry(req);
            if (ret == EOK) {
                return;
            }

            dp_error = DP_ERR_FATAL;
        }

        if (ret != EOK) {
            if (dp_error == DP_ERR_OFFLINE) {
                tevent_req_done(req);
            } else {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("Group enumeration failed with: (%d)[%s]\n",
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
    tevent_req_set_callback(subreq, sdap_dom_enum_services_done, req);
}

static void sdap_dom_enum_services_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_state *state = tevent_req_data(req,
                                                   struct sdap_dom_enum_state);

    ret = enum_services_recv(subreq);
    talloc_zfree(subreq);
    if (ret == ENOENT) ret = EOK;

    /* All enumerations are complete, so conclude the
     * id_op
     */
    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = sdap_dom_enum_retry(req);
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

    /* Ok, we've completed an enumeration. Save this to the
     * sysdb so we can postpone starting up the enumeration
     * process on the next SSSD service restart (to avoid
     * slowing down system boot-up
     */
    ret = sysdb_set_enumerated(state->sdom->dom, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not mark domain as having enumerated.\n"));
        /* This error is non-fatal, so continue */
    }

    if (state->purge) {
        ret = ldap_id_cleanup(state->ctx->opts, state->sdom);
        if (ret != EOK) {
            /* Not fatal, worst case we'll have stale entries that would be
             * removed on a subsequent online lookup
             */
            DEBUG(SSSDBG_MINOR_FAILURE, ("Cleanup failed: %d\n", ret));
        }
    }

    tevent_req_done(req);
}

errno_t sdap_dom_enum_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==User-Enumeration===================================================== */
struct enum_users_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_op *op;

    char *filter;
    const char **attrs;
};

static void enum_users_done(struct tevent_req *subreq);

static struct tevent_req *enum_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_domain *sdom,
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
    state->sdom = sdom;
    state->ctx = ctx;
    state->op = op;

    use_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                        ctx->opts->idmap_ctx,
                                                        sdom->dom->name,
                                                        sdom->dom->domain_id);

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
                                 state->sdom->dom,
                                 state->sdom->dom->sysdb,
                                 state->ctx->opts,
                                 state->sdom->user_search_bases,
                                 sdap_id_op_handle(state->op),
                                 state->attrs, state->filter,
                                 dp_opt_get_int(state->ctx->opts->basic,
                                                SDAP_ENUM_SEARCH_TIMEOUT),
                                 true);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, enum_users_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void enum_users_done(struct tevent_req *subreq)
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
        state->ctx->srv_opts->max_user_value =
                                        talloc_steal(state->ctx, usn_value);

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

static errno_t enum_users_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* =Group-Enumeration===================================================== */
struct enum_groups_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_op *op;

    char *filter;
    const char **attrs;
};

static void enum_groups_done(struct tevent_req *subreq);

static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_domain *sdom,
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
    state->sdom = sdom;
    state->ctx = ctx;
    state->op = op;

    use_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                        ctx->opts->idmap_ctx,
                                                        sdom->dom->name,
                                                        sdom->dom->domain_id);

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
                                  state->sdom,
                                  state->ctx->opts,
                                  sdap_id_op_handle(state->op),
                                  state->attrs, state->filter,
                                  dp_opt_get_int(state->ctx->opts->basic,
                                                 SDAP_ENUM_SEARCH_TIMEOUT),
                                  true);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, enum_groups_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void enum_groups_done(struct tevent_req *subreq)
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

static errno_t enum_groups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
