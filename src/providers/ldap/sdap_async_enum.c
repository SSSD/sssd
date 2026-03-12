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
                                          struct sss_failover_ldap_connection *conn,
                                          bool purge);
static errno_t enum_users_recv(struct tevent_req *req);

static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_domain *sdom,
                                          struct sss_failover_ldap_connection *conn,
                                          bool purge);
static errno_t enum_groups_recv(struct tevent_req *req);

/* ==Enumeration-Request-with-connections=================================== */
struct sdap_dom_enum_ex_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;

    struct sss_failover_ldap_connection *conn;
    struct sss_failover_ldap_connection *group_conn;
    struct sss_failover_ldap_connection *svc_conn;

    bool purge;
};

static void sdap_dom_enum_ex_get_users(struct tevent_req *subreq);
static void sdap_dom_enum_ex_users_done(struct tevent_req *subreq);
static void sdap_dom_enum_ex_get_groups(struct tevent_req *subreq);
static void sdap_dom_enum_ex_groups_done(struct tevent_req *subreq);
static void sdap_dom_enum_ex_get_svcs(struct tevent_req *subreq);
static void sdap_dom_enum_ex_svcs_done(struct tevent_req *subreq);

struct tevent_req *
sdap_dom_enum_ex_send(TALLOC_CTX *memctx,
                      struct tevent_context *ev,
                      struct sdap_id_ctx *ctx,
                      struct sdap_domain *sdom)
{
    struct tevent_req *req;
    struct sdap_dom_enum_ex_state *state;
    int t;
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct sdap_dom_enum_ex_state);
    if (req == NULL) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sdom = sdom;
    ctx->last_enum = tevent_timeval_current();

    t = dp_opt_get_int(ctx->opts->basic, SDAP_PURGE_CACHE_TIMEOUT);
    if ((ctx->last_purge.tv_sec + t) < ctx->last_enum.tv_sec) {
        state->purge = true;
    }

    ret = sss_failover_transaction_send(state, ev, ctx->fctx, req,
                                        sdap_dom_enum_ex_get_users);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_failover_transaction_send failed\n");
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_dom_enum_ex_get_users(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_ex_state *state = tevent_req_data(req,
                                                struct sdap_dom_enum_ex_state);

    state->conn = sss_failover_transaction_connected_recv(state, subreq,
                                        struct sss_failover_ldap_connection);
    talloc_zfree(subreq);

    if (state->conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: No connection?\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    subreq = enum_users_send(state, state->ev,
                             state->ctx, state->sdom,
                             state->conn, state->purge);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_dom_enum_ex_users_done, req);
}

static void sdap_dom_enum_ex_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_ex_state *state = tevent_req_data(req,
                                                struct sdap_dom_enum_ex_state);
    errno_t ret;

    ret = enum_users_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        /* Non-recoverable error */
        DEBUG(SSSDBG_OP_FAILURE,
              "User enumeration failed: %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = sss_failover_transaction_send(state, state->ev, state->ctx->fctx, req,
                                        sdap_dom_enum_ex_get_groups);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Continues to sdap_dom_enum_ex_get_groups */
}

static void sdap_dom_enum_ex_get_groups(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_ex_state *state = tevent_req_data(req,
                                                struct sdap_dom_enum_ex_state);

    state->group_conn = sss_failover_transaction_connected_recv(state, subreq,
                                        struct sss_failover_ldap_connection);
    talloc_zfree(subreq);

    if (state->group_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: No connection?\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    subreq = enum_groups_send(state, state->ev, state->ctx,
                              state->sdom,
                              state->group_conn, state->purge);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_dom_enum_ex_groups_done, req);
}

static void sdap_dom_enum_ex_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_ex_state *state = tevent_req_data(req,
                                                struct sdap_dom_enum_ex_state);
    int ret;

    ret = enum_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        /* Non-recoverable error */
        DEBUG(SSSDBG_OP_FAILURE,
              "Group enumeration failed: %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = sss_failover_transaction_send(state, state->ev, state->ctx->fctx, req,
                                        sdap_dom_enum_ex_get_svcs);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
}

static void sdap_dom_enum_ex_get_svcs(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_ex_state *state = tevent_req_data(req,
                                                struct sdap_dom_enum_ex_state);

    state->svc_conn = sss_failover_transaction_connected_recv(state, subreq,
                                           struct sss_failover_ldap_connection);
    talloc_zfree(subreq);

    if (state->svc_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: No connection?\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    subreq = enum_services_send(state, state->ev, state->ctx,
                                state->svc_conn, state->purge);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_dom_enum_ex_svcs_done, req);
}

static void sdap_dom_enum_ex_svcs_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_enum_ex_state *state = tevent_req_data(req,
                                                struct sdap_dom_enum_ex_state);
    int ret;

    ret = enum_services_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        /* Non-recoverable error */
        DEBUG(SSSDBG_OP_FAILURE,
              "Service enumeration failed: %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* Ok, we've completed an enumeration. Save this to the
     * sysdb so we can postpone starting up the enumeration
     * process on the next SSSD service restart (to avoid
     * slowing down system boot-up
     */
    ret = sysdb_set_enumerated(state->sdom->dom, SYSDB_HAS_ENUMERATED_ID,
                               true);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not mark domain as having enumerated.\n");
        /* This error is non-fatal, so continue */
    }

    if (state->purge) {
        ret = ldap_id_cleanup(state->ctx, state->sdom);
        if (ret != EOK) {
            /* Not fatal, worst case we'll have stale entries that would be
             * removed on a subsequent online lookup
             */
            DEBUG(SSSDBG_MINOR_FAILURE, "Cleanup failed: [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
    }

    tevent_req_done(req);
}

errno_t sdap_dom_enum_ex_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==Enumeration-Request==================================================== */
struct tevent_req *
sdap_dom_enum_send(TALLOC_CTX *memctx,
                   struct tevent_context *ev,
                   struct sdap_id_ctx *ctx,
                   struct sdap_domain *sdom)
{
    return sdap_dom_enum_ex_send(memctx, ev, ctx, sdom);
}

errno_t sdap_dom_enum_recv(struct tevent_req *req)
{
    return sdap_dom_enum_ex_recv(req);
}

/* ==User-Enumeration===================================================== */
struct enum_users_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sss_failover_ldap_connection *conn;

    char *filter;
    const char **attrs;
};

static void enum_users_done(struct tevent_req *subreq);

static struct tevent_req *enum_users_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_domain *sdom,
                                          struct sss_failover_ldap_connection *conn,
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
    state->conn = conn;

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
              "Failed to build base filter\n");
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
              "Failed to build base filter\n");
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
                  "Failed to build base filter\n");
            ret = ENOMEM;
            goto fail;
        }
    }

    /* Terminate the search filter */
    state->filter = talloc_asprintf_append_buffer(state->filter, ")");
    if (!state->filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build base filter\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = build_attrs_from_map(state, ctx->opts->user_map,
                               ctx->opts->user_map_cnt,
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
                                 state->conn->sh,
                                 state->attrs, state->filter,
                                 dp_opt_get_int(state->ctx->opts->basic,
                                                SDAP_ENUM_SEARCH_TIMEOUT),
                                 SDAP_LOOKUP_ENUMERATE, NULL);
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
        errno = 0;
        usn_number = strtoul(usn_value, &endptr, 10);
        if (!errno && endptr && (*endptr == '\0') && (endptr != usn_value)
            && (usn_number > state->ctx->srv_opts->last_usn)) {
            state->ctx->srv_opts->last_usn = usn_number;
        }
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Users higher USN value: [%s]\n",
              state->ctx->srv_opts->max_user_value);

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
    struct sss_failover_ldap_connection *conn;

    char *filter;
    const char **attrs;
};

static void enum_groups_done(struct tevent_req *subreq);

static struct tevent_req *enum_groups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_domain *sdom,
                                          struct sss_failover_ldap_connection *conn,
                                          bool purge)
{
    struct tevent_req *req, *subreq;
    struct enum_groups_state *state;
    int ret;
    bool use_mapping;
    bool non_posix = false;
    char *oc_list;

    req = tevent_req_create(memctx, &state, struct enum_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->sdom = sdom;
    state->ctx = ctx;
    state->conn = conn;

    if (sdom->dom->type == DOM_TYPE_APPLICATION) {
        non_posix = true;
    }

    use_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                        ctx->opts->idmap_ctx,
                                                        sdom->dom->name,
                                                        sdom->dom->domain_id);

    /* We always want to filter on objectclass and an available name */
    oc_list = sdap_make_oc_list(state, ctx->opts->group_map);
    if (oc_list == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create objectClass list.\n");
        ret = ENOMEM;
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s)(%s=*)", oc_list,
                               ctx->opts->group_map[SDAP_AT_GROUP_NAME].name);
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to build base filter\n");
        ret = ENOMEM;
        goto fail;
    }

    if (!non_posix && use_mapping) {
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
              "Failed to build base filter\n");
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
                  "Failed to build base filter\n");
            ret = ENOMEM;
            goto fail;
        }
    }

    /* Terminate the search filter */
    state->filter = talloc_asprintf_append_buffer(state->filter, ")");
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to build base filter\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = build_attrs_from_map(state, ctx->opts->group_map, SDAP_OPTS_GROUP,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) goto fail;

    /* TODO: restrict the enumerations to using a single
     * search base at a time.
     */

    subreq = sdap_get_groups_send(state, state->ev,
                                  state->sdom,
                                  state->ctx->opts,
                                  state->conn->sh,
                                  state->attrs, state->filter,
                                  dp_opt_get_int(state->ctx->opts->basic,
                                                 SDAP_ENUM_SEARCH_TIMEOUT),
                                  SDAP_LOOKUP_ENUMERATE, false);
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
        errno = 0;
        usn_number = strtoul(usn_value, &endptr, 10);
        if (!errno && endptr && (*endptr == '\0') && (endptr != usn_value)
            && (usn_number > state->ctx->srv_opts->last_usn)) {
            state->ctx->srv_opts->last_usn = usn_number;
        }
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Groups higher USN value: [%s]\n",
              state->ctx->srv_opts->max_group_value);

    tevent_req_done(req);
}

static errno_t enum_groups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
