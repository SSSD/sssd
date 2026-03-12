/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2020 SUSE LINUX GmbH, Nuernberg, Germany.

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
#include "db/sysdb_ipnetworks.h"

struct sdap_ipnetwork_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *id_ctx;
    struct sdap_domain *sdom;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct sss_failover_ldap_connection *conn;

    uint32_t filter_type;
    const char *filter_value;

    char *filter;
    const char **attrs;

    bool noexist_delete;
};

static void
sdap_ipnetwork_get_connect_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_ipnetwork_get_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sdap_id_ctx *id_ctx,
                        struct sdap_domain *sdom,
                        uint32_t filter_type,
                        const char *filter_value,
                        bool noexist_delete)
{
    struct tevent_req *req;
    struct sdap_ipnetwork_get_state *state;
    const char *attr_name;
    char *clean_filter_value;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_ipnetwork_get_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->id_ctx = id_ctx;
    state->sdom = sdom;
    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;
    state->filter_value = filter_value;
    state->filter_type = filter_type;
    state->noexist_delete = noexist_delete;

    switch(filter_type) {
    case BE_FILTER_NAME:
        attr_name = id_ctx->opts->ipnetwork_map[SDAP_AT_IPNETWORK_NAME].name;
        break;
    case BE_FILTER_ADDR:
        attr_name = id_ctx->opts->ipnetwork_map[SDAP_AT_IPNETWORK_NUMBER].name;
        break;
    default:
        ret = EINVAL;
        goto fail;
    }

    ret = sss_filter_sanitize(state, filter_value, &clean_filter_value);
    if (ret != EOK) {
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(objectclass=%s)(%s=%s))",
                        id_ctx->opts->ipnetwork_map[SDAP_OC_IPNETWORK].name,
                        attr_name, clean_filter_value);
    talloc_zfree(clean_filter_value);
    if (state->filter == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to build the base filter\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = build_attrs_from_map(state, id_ctx->opts->ipnetwork_map,
            SDAP_OPTS_IPNETWORK, NULL, &state->attrs, NULL);
    if (ret != EOK) {
        goto fail;
    }
    ret = sss_failover_transaction_send(state, ev, id_ctx->fctx, req,
                                        sdap_ipnetwork_get_connect_done);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
sdap_ipnetwork_get_done(struct tevent_req *subreq);

static void
sdap_ipnetwork_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_ipnetwork_get_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ipnetwork_get_state);

    state->conn = sss_failover_transaction_connected_recv(state, subreq,
                                        struct sss_failover_ldap_connection);
    talloc_zfree(subreq);

    if (state->conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: No connection?\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    subreq = sdap_get_ipnetwork_send(state, state->ev,
                                     state->domain, state->sysdb,
                                     state->id_ctx->opts,
                                     state->sdom->ipnetwork_search_bases,
                                     state->conn->sh,
                                     state->attrs, state->filter,
                                     dp_opt_get_int(state->id_ctx->opts->basic,
                                                    SDAP_SEARCH_TIMEOUT),
                                     false);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_ipnetwork_get_done, req);
}

static void
sdap_ipnetwork_get_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_ipnetwork_get_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ipnetwork_get_state);

    ret = sdap_get_ipnetwork_recv(NULL, subreq, NULL);
    talloc_zfree(subreq);

    if (ret == ENOENT && state->noexist_delete == true) {
        /* Ensure that this entry is removed from the sysdb */
        switch (state->filter_type) {
            case BE_FILTER_NAME:
                ret = sysdb_ipnetwork_delete(state->domain,
                                             state->filter_value,
                                             NULL);
                if (ret != EOK) {
                    tevent_req_error(req, ret);
                    return;
                }
                break;

            case BE_FILTER_ADDR:
                ret = sysdb_ipnetwork_delete(state->domain, NULL,
                                             state->filter_value);
                if (ret != EOK) {
                    tevent_req_error(req, ret);
                    return;
                }
                break;

            default:
                tevent_req_error(req, EINVAL);
                return;
        }
    }

    tevent_req_done(req);
}

static errno_t
sdap_ipnetwork_get_recv(struct tevent_req *req)
{

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_ipnetwork_handler_state {
    struct dp_reply_std reply;
};

static void
sdap_ipnetwork_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_ipnetwork_handler_send(TALLOC_CTX *mem_ctx,
                            struct sdap_resolver_ctx *resolver_ctx,
                            struct dp_resolver_data *resolver_data,
                            struct dp_req_params *params)
{
    struct sdap_ipnetwork_handler_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ipnetwork_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (resolver_data->filter_type == BE_FILTER_ENUM) {
        DEBUG(SSSDBG_TRACE_LIBS, "Skipping enumeration on demand\n");
        ret = EOK;
        goto immediately;
    }

    subreq = sdap_ipnetwork_get_send(state, params->ev,
                                     resolver_ctx->id_ctx,
                                     resolver_ctx->id_ctx->opts->sdom,
                                     resolver_data->filter_type,
                                     resolver_data->filter_value,
                                     true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_ipnetwork_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void
sdap_ipnetwork_handler_done(struct tevent_req *subreq)
{
    struct sdap_ipnetwork_handler_state *state;
    struct tevent_req *req;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ipnetwork_handler_state);

    ret = sdap_ipnetwork_get_recv(subreq);
    talloc_zfree(subreq);

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, dp_error, ret, NULL);
    tevent_req_done(req);
}

errno_t
sdap_ipnetwork_handler_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            struct dp_reply_std *data)
{
    struct sdap_ipnetwork_handler_state *state;

    state = tevent_req_data(req, struct sdap_ipnetwork_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
