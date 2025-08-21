/*
    SSSD

    LDAP Identity Backend Module - subid ranges support

    Copyright (C) 2021 Red Hat

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

#include "db/sysdb_subid.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_ops.h"

static int subid_ranges_get_retry(struct tevent_req *req);
static void subid_ranges_get_connect_done(struct tevent_req *subreq);
static void subid_ranges_resolve_owner(struct tevent_req *req);
static void subid_ranges_get_search(struct tevent_req *req);
static void subid_ranges_get_done(struct tevent_req *subreq);


struct subid_ranges_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *op;
    struct sss_domain_info *domain;

    char *filter;
    char *owner_name;
    char *owner_dn;
    const char **attrs;

    int dp_error;
    int sdap_ret;
};

struct tevent_req *subid_ranges_get_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_id_ctx *ctx,
                                         struct sdap_domain *sdom,
                                         struct sdap_id_conn_ctx *conn,
                                         const char *filter_value)
{
    struct tevent_req *req;
    struct subid_ranges_get_state *state;
    int ret;

    DEBUG(SSSDBG_TRACE_ALL, "Handling request for subid ranges of '%s'\n", filter_value);

    req = tevent_req_create(memctx, &state, struct subid_ranges_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->dp_error = DP_ERR_FATAL;
    state->owner_name = talloc_strdup(state, filter_value);
    if (!state->owner_name) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed\n");
        ret = ENOMEM;
        goto done;
    }

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    state->domain = sdom->dom;

    ret = subid_ranges_get_retry(req);
    if (ret != EOK) {
        goto done;
    }

    return req;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    return tevent_req_post(req, ev);
}

static int subid_ranges_get_retry(struct tevent_req *req)
{
    struct subid_ranges_get_state *state = tevent_req_data(req,
                                                    struct subid_ranges_get_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, subid_ranges_get_connect_done, req);
    return EOK;
}

static void subid_ranges_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct subid_ranges_get_state *state = tevent_req_data(req,
                                                     struct subid_ranges_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subid_ranges_resolve_owner(req);
}

static void subid_ranges_resolve_owner(struct tevent_req *req)
{
    struct subid_ranges_get_state *state = tevent_req_data(req,
                                                     struct subid_ranges_get_state);
    const char *attrs[] = {SYSDB_DN, SYSDB_CACHE_EXPIRE, NULL};
    struct ldb_result *res = NULL;
    int ret;
    time_t expire;
    const char *dn = NULL;

    DEBUG(SSSDBG_TRACE_ALL, "Resolving '%s'\n", state->owner_name);

    /* First let's check local cache - this is the most probable case */
    ret = sysdb_get_user_attr(req, state->domain, state->owner_name, attrs, &res);
    DEBUG(SSSDBG_TRACE_ALL, "cache search: ret = %d, res = %p, count = %d\n",
          ret, res, (res ? res->count : -1));
    if (ret == EOK) {
        if ((res == NULL) || (res->count != 1)) {
            ret = EINVAL;
            goto done;
        }
        expire = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_CACHE_EXPIRE, 0);
        if (expire < time(NULL)) { /* expired */
            DEBUG(SSSDBG_TRACE_ALL,
                  "'%s' user object found in the cache, but expired\n",
                  state->owner_name);
            ret = ENOENT;
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "'%s' user object found in the cache\n",
                  state->owner_name);
            dn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_DN, NULL);
            if (dn == NULL) {
                ret = EINVAL;
                goto done;
            }
            state->owner_dn = talloc_strdup(state, dn);
            if (state->owner_dn == NULL) {
                ret = ENOMEM;
                goto done;
            }
            subid_ranges_get_search(req);
        }
    }

    if (ret == ENOENT) {
        /* Not cached or expired: issue network search */
        /* TODO */
        DEBUG(SSSDBG_TRACE_ALL, "'%s' needs to be looked up online\n",
              state->owner_name);
        ret = EFAULT;
    }

done:
    talloc_free(res);
    if (ret != EOK) {
        tevent_req_error(req, EINVAL);
    }
}

static void subid_ranges_get_search(struct tevent_req *req)
{
    struct subid_ranges_get_state *state = tevent_req_data(req,
                                                     struct subid_ranges_get_state);
    struct tevent_req *subreq = NULL;
    const char **attrs;
    int ret;

    ret = build_attrs_from_map(state, state->ctx->opts->subid_map,
                               SDAP_OPTS_SUBID_RANGE, NULL, &attrs, NULL);
    if (ret != EOK) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    state->filter = talloc_asprintf(state,
                                    "(&(%s=%s)(%s=%s))",
                                    SYSDB_OBJECTCLASS,
                                    state->ctx->opts->subid_map[SDAP_OC_SUBID_RANGE].name,
                                    state->ctx->opts->subid_map[SDAP_AT_SUBID_RANGE_OWNER].name,
                                    state->owner_dn);
    if (state->filter == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = sdap_search_bases_send(state, state->ev, state->ctx->opts,
                                    sdap_id_op_handle(state->op),
                                    state->sdom->subid_ranges_search_bases,
                                    state->ctx->opts->subid_map,
                                    false, /* allow_paging */
                                    dp_opt_get_int(state->ctx->opts->basic,
                                                   SDAP_SEARCH_TIMEOUT),
                                    state->filter,
                                    attrs,
                                    NULL);
    talloc_free(attrs);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, subid_ranges_get_done, req);
}

static void subid_ranges_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct subid_ranges_get_state *state = tevent_req_data(req,
                                                     struct subid_ranges_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    struct sysdb_attrs **results;
    size_t num_results;

    ret = sdap_search_bases_recv(subreq, state, &num_results, &results);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = subid_ranges_get_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        return;
    }
    state->sdap_ret = ret;

    if (ret && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve subid ranges.\n");
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (num_results == 0 || !results) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No such user '%s' or user doesn't have subid range\n",
              state->owner_name);
        sysdb_delete_subid_range(state->domain, state->owner_name);
    } else {
        if (num_results > 1) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Multiple subid ranges, only first will be processed\n");
        }

        /* store range */
        sysdb_store_subid_range(state->domain, state->owner_name,
                                state->domain->user_timeout,
                                results[0]);
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

int subid_ranges_get_recv(struct tevent_req *req, int *dp_error_out,
                          int *sdap_ret)
{
    struct subid_ranges_get_state *state = tevent_req_data(req,
                                                    struct subid_ranges_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
