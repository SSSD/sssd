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

static void sdap_dom_resolver_enum_get_iphost(struct tevent_req *subreq);
static void sdap_dom_resolver_enum_iphost_done(struct tevent_req *subreq);
static void sdap_dom_resolver_enum_get_ipnetwork(struct tevent_req *subreq);
static void sdap_dom_resolver_enum_ipnetwork_done(struct tevent_req *subreq);

struct sdap_dom_resolver_enum_state {
    struct tevent_context *ev;
    struct sdap_resolver_ctx *resolver_ctx;
    struct sdap_id_ctx *id_ctx;
    struct sdap_domain *sdom;

    struct sss_failover_ldap_connection *iphost_conn;
    struct sss_failover_ldap_connection *ipnetwork_conn;

    bool purge;
};

struct tevent_req *
sdap_dom_resolver_enum_send(TALLOC_CTX *memctx,
                            struct tevent_context *ev,
                            struct sdap_resolver_ctx *resolver_ctx,
                            struct sdap_id_ctx *id_ctx,
                            struct sdap_domain *sdom)
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
    state->resolver_ctx->last_enum = tevent_timeval_current();

    t = dp_opt_get_int(resolver_ctx->id_ctx->opts->basic, SDAP_PURGE_CACHE_TIMEOUT);
    if ((state->resolver_ctx->last_purge.tv_sec + t) < state->resolver_ctx->last_enum.tv_sec) {
        state->purge = true;
    }

    ret = sss_failover_transaction_send(state, ev, id_ctx->fctx, req,
                                        sdap_dom_resolver_enum_get_iphost);
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

static void sdap_dom_resolver_enum_get_iphost(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dom_resolver_enum_state *state;

    state = tevent_req_data(req, struct sdap_dom_resolver_enum_state);

    state->iphost_conn = sss_failover_transaction_connected_recv(state, subreq,
                                             struct sss_failover_ldap_connection);
    talloc_zfree(subreq);

    if (state->iphost_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: No connection?\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    subreq = enum_iphosts_send(state, state->ev,
                               state->id_ctx,
                               state->iphost_conn,
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

    state = tevent_req_data(req, struct sdap_dom_resolver_enum_state);

    ret = enum_iphosts_recv(subreq);
    talloc_zfree(subreq);

    ret = sss_failover_transaction_send(state, state->ev, state->id_ctx->fctx, req,
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

    state->ipnetwork_conn = sss_failover_transaction_connected_recv(state, subreq,
                                                   struct sss_failover_ldap_connection);
    talloc_zfree(subreq);

    if (state->ipnetwork_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: No connection?\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    subreq = enum_ipnetworks_send(state, state->ev,
                                  state->id_ctx,
                                  state->ipnetwork_conn,
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

    state = tevent_req_data(req, struct sdap_dom_resolver_enum_state);

    ret = enum_ipnetworks_recv(subreq);
    talloc_zfree(subreq);

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
