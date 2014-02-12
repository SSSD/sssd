/*
    SSSD

    LDAP Identity Backend Module - Netgroup support

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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


struct ldap_netgroup_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_op *op;
    struct sdap_id_conn_ctx *conn;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *name;
    int timeout;

    char *filter;
    const char **attrs;

    size_t count;
    struct sysdb_attrs **netgroups;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
};

static int ldap_netgroup_get_retry(struct tevent_req *req);
static void ldap_netgroup_get_connect_done(struct tevent_req *subreq);
static void ldap_netgroup_get_done(struct tevent_req *subreq);

struct tevent_req *ldap_netgroup_get_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct sdap_domain *sdom,
                                          struct sdap_id_conn_ctx *conn,
                                          const char *name,
                                          bool noexist_delete)
{
    struct tevent_req *req;
    struct ldap_netgroup_get_state *state;
    char *clean_name;
    int ret;

    req = tevent_req_create(memctx, &state, struct ldap_netgroup_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->dp_error = DP_ERR_FATAL;
    state->noexist_delete = noexist_delete;

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;
    state->name = name;
    state->timeout = dp_opt_get_int(ctx->opts->basic, SDAP_SEARCH_TIMEOUT);

    ret = sss_filter_sanitize(state, name, &clean_name);
    if (ret != EOK) {
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                            ctx->opts->netgroup_map[SDAP_AT_NETGROUP_NAME].name,
                            clean_name,
                            ctx->opts->netgroup_map[SDAP_OC_NETGROUP].name);
    if (!state->filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto fail;
    }
    talloc_zfree(clean_name);

    ret = build_attrs_from_map(state, ctx->opts->netgroup_map, SDAP_OPTS_NETGROUP,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) goto fail;

    ret = ldap_netgroup_get_retry(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static int ldap_netgroup_get_retry(struct tevent_req *req)
{
    struct ldap_netgroup_get_state *state = tevent_req_data(req,
                                                    struct ldap_netgroup_get_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, ldap_netgroup_get_connect_done, req);
    return EOK;
}

static void ldap_netgroup_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ldap_netgroup_get_state *state = tevent_req_data(req,
                                                    struct ldap_netgroup_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_netgroups_send(state, state->ev,
                                     state->domain, state->sysdb,
                                     state->ctx->opts,
                                     state->sdom->netgroup_search_bases,
                                     sdap_id_op_handle(state->op),
                                     state->attrs, state->filter,
                                     state->timeout);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ldap_netgroup_get_done, req);

    return;
}

static void ldap_netgroup_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ldap_netgroup_get_state *state = tevent_req_data(req,
                                                    struct ldap_netgroup_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_get_netgroups_recv(subreq, state, NULL, &state->count,
                                  &state->netgroups);
    talloc_zfree(subreq);
    ret = sdap_id_op_done(state->op, ret, &dp_error);

    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ldap_netgroup_get_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        return;
    }
    state->sdap_ret = ret;

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == EOK && state->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one netgroup with the name [%s].\n",
                  state->name);
        tevent_req_error(req, EINVAL);
        return;
    }

    if (ret == ENOENT && state->noexist_delete == true) {
        ret = sysdb_delete_netgroup(state->domain, state->name);
        if (ret != EOK && ret != ENOENT) {
            tevent_req_error(req, ret);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;
}

int ldap_netgroup_get_recv(struct tevent_req *req, int *dp_error_out, int *sdap_ret)
{
    struct ldap_netgroup_get_state *state = tevent_req_data(req,
                                                    struct ldap_netgroup_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
