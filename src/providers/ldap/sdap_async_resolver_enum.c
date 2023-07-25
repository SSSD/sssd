/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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

#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/ldap_resolver_enum.h"
#include "providers/ldap/sdap_async_resolver_enum.h"

static errno_t sdap_dom_resolver_enum_retry(struct tevent_req *req,
                                            struct sdap_id_op *op,
                                            tevent_req_fn tcb);
static bool sdap_dom_resolver_enum_connected(struct tevent_req *subreq);
static void sdap_dom_resolver_enum_get_iphost(struct tevent_req *subreq);
static void sdap_dom_resolver_enum_iphost_done(struct tevent_req *subreq);
static void sdap_dom_resolver_enum_get_ipnetwork(struct tevent_req *subreq);
static void sdap_dom_resolver_enum_ipnetwork_done(struct tevent_req *subreq);

struct sdap_dom_resolver_enum_state {
    struct tevent_context *ev;
    struct sdap_resolver_ctx *resolver_ctx;
    struct sdap_id_ctx *id_ctx;
    struct sdap_domain *sdom;

    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *iphost_op;
    struct sdap_id_op *ipnetwork_op;

    bool purge;
};

struct tevent_req *
sdap_dom_resolver_enum_send(TALLOC_CTX *memctx,
                            struct tevent_context *ev,
                            struct sdap_resolver_ctx *resolver_ctx,
                            struct sdap_id_ctx *id_ctx,
                            struct sdap_domain *sdom,
                            struct sdap_id_conn_ctx *conn)
{
    struct tevent_req *req;
    struct sdap_dom_resolver_enum_state *state;
    int t;
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct sdap_dom_resolver_enum_state);
    if (req == NULL) return NULL;

    state->ev = ev;
    state->resolver_ctx = resolver_ctx;
    state->id_ctx = id_ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->resolver_ctx->last_enum = tevent_timeval_current();

    t = dp_opt_get_int(resolver_ctx->id_ctx->opts->basic, SDAP_PURGE_CACHE_TIMEOUT);
    if ((state->resolver_ctx->last_purge.tv_sec + t) < state->resolver_ctx->last_enum.tv_sec) {
        state->purge = true;
    }

    state->iphost_op = sdap_id_op_create(state, conn->conn_cache);
    if (state->iphost_op == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_create failed for iphosts\n");
        ret = EIO;
        goto fail;
    }

    ret = sdap_dom_resolver_enum_retry(req, state->iphost_op,
                                       sdap_dom_resolver_enum_get_iphost);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_dom_enum_retry failed\n");
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t
sdap_dom_resolver_enum_retry(struct tevent_req *req,
                             struct sdap_id_op *op,
                             tevent_req_fn tcb)
{
    struct sdap_dom_resolver_enum_state *state;
    struct tevent_req *subreq;
    errno_t ret;

    state = tevent_req_data(req, struct sdap_dom_resolver_enum_state);
    subreq = sdap_id_op_connect_send(op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_id_op_connect_send failed: %d\n", ret);
        return ret;
    }

    tevent_req_set_callback(subreq, tcb, req);
    return EOK;
}

static bool sdap_dom_resolver_enum_connected(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Backend is marked offline, retry later!\n");
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Domain enumeration failed to connect to " \
                   "LDAP server: (%d)[%s]\n", ret, strerror(ret));
            tevent_req_error(req, ret);
        }
        return false;
    }

    return true;
}

static void sdap_dom_resolver_enum_get_iphost(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_resolver_enum_state *state;

    state = tevent_req_data(req, struct sdap_dom_resolver_enum_state);

    if (sdap_dom_resolver_enum_connected(subreq) == false) {
        return;
    }

    subreq = enum_iphosts_send(state, state->ev,
                               state->id_ctx,
                               state->iphost_op,
                               state->purge);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_dom_resolver_enum_iphost_done, req);
}

static void sdap_dom_resolver_enum_iphost_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_resolver_enum_state *state;
    errno_t ret;
    int dp_error;

    state = tevent_req_data(req, struct sdap_dom_resolver_enum_state);

    ret = enum_iphosts_recv(subreq);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->iphost_op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = sdap_dom_resolver_enum_retry(req, state->iphost_op,
                                           sdap_dom_resolver_enum_get_iphost);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        return;
    } else if (dp_error == DP_ERR_OFFLINE) {
        DEBUG(SSSDBG_TRACE_FUNC, "Backend is offline, retrying later\n");
        tevent_req_done(req);
        return;
    } else if (ret != EOK && ret != ENOENT) {
        /* Non-recoverable error */
        DEBUG(SSSDBG_OP_FAILURE,
              "IP hosts enumeration failed: %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->ipnetwork_op = sdap_id_op_create(state, state->conn->conn_cache);
    if (state->ipnetwork_op == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sdap_id_op_create failed for IP networks\n");
        tevent_req_error(req, EIO);
        return;
    }

    ret = sdap_dom_resolver_enum_retry(req, state->ipnetwork_op,
                                       sdap_dom_resolver_enum_get_ipnetwork);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Continues to sdap_dom_resolver_enum_get_ipnetwork */
}

static void sdap_dom_resolver_enum_get_ipnetwork(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_resolver_enum_state *state;

    state = tevent_req_data(req, struct sdap_dom_resolver_enum_state);

    if (sdap_dom_resolver_enum_connected(subreq) == false) {
        return;
    }

    subreq = enum_ipnetworks_send(state, state->ev,
                                  state->id_ctx,
                                  state->ipnetwork_op,
                                  state->purge);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_dom_resolver_enum_ipnetwork_done, req);
}

static void sdap_dom_resolver_enum_ipnetwork_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_resolver_enum_state *state;
    errno_t ret;
    int dp_error;

    state = tevent_req_data(req, struct sdap_dom_resolver_enum_state);

    ret = enum_ipnetworks_recv(subreq);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->ipnetwork_op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = sdap_dom_resolver_enum_retry(req, state->ipnetwork_op,
                                        sdap_dom_resolver_enum_get_ipnetwork);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        return;
    } else if (dp_error == DP_ERR_OFFLINE) {
        DEBUG(SSSDBG_TRACE_FUNC, "Backend is offline, retrying later\n");
        tevent_req_done(req);
        return;
    } else if (ret != EOK && ret != ENOENT) {
        /* Non-recoverable error */
        DEBUG(SSSDBG_OP_FAILURE,
              "IP networks enumeration failed: %d: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* Ok, we've completed an enumeration. Save this to the
     * sysdb so we can postpone starting up the enumeration
     * process on the next SSSD service restart (to avoid
     * slowing down system boot-up
     */
    ret = sysdb_set_enumerated(state->sdom->dom, SYSDB_HAS_ENUMERATED_RESOLVER,
                               true);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not mark domain as having enumerated.\n");
        /* This error is non-fatal, so continue */
    }

    if (state->purge) {
        ret = ldap_resolver_cleanup(state->resolver_ctx);
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

errno_t sdap_dom_resolver_enum_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
