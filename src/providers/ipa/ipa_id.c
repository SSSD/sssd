/*
    SSSD

    IPA Identity Backend Module

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include "providers/ipa/ipa_id.h"

static const char *ipa_account_info_error_text(int ret, int *dp_error,
                                               const char *default_text)
{
    switch (*dp_error) {
    case DP_ERR_OK:
        if (ret == EOK) {
            return NULL;
        }
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Bug: dp_error is OK on failed request\n");
        *dp_error = DP_ERR_FATAL;
        break;
    case DP_ERR_OFFLINE:
        return "Offline";
    case DP_ERR_FATAL:
        if (ret == ENOMEM) {
            return "Out of memory";
        }
        break;
    default:
        break;
    }

    return default_text;
}

static struct tevent_req *ipa_id_get_netgroup_send(TALLOC_CTX *memctx,
                                                   struct tevent_context *ev,
                                                   struct ipa_id_ctx *ipa_ctx,
                                                   const char *name);
static int ipa_id_get_netgroup_recv(struct tevent_req *req, int *dp_error);

static void ipa_account_info_done(struct tevent_req *req);

void ipa_account_info_handler(struct be_req *breq)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(breq);
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_id_ctx *ctx;
    struct be_acct_req *ar;
    struct tevent_req *req = NULL;

    ipa_ctx = talloc_get_type(be_ctx->bet_info[BET_ID].pvt_bet_data,
                              struct ipa_id_ctx);
    ctx = ipa_ctx->sdap_id_ctx;

    if (be_is_offline(ctx->be)) {
        return sdap_handler_done(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    ar = talloc_get_type(be_req_get_data(breq), struct be_acct_req);

    if (strcasecmp(ar->domain, be_ctx->domain->name) != 0) {
        /* if domain names do not match, this is a subdomain case
         * subdomain lookups are handled differently on the server
         * and the client
         */
        if (dp_opt_get_bool(ipa_ctx->ipa_options->basic, IPA_SERVER_MODE)) {
            req = ipa_get_ad_acct_send(breq, be_ctx->ev, ipa_ctx, breq, ar);
        } else {
            req = ipa_get_subdom_acct_send(breq, be_ctx->ev, ctx, ar);
        }
    } else if ((ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_NETGROUP) {
        /* netgroups are handled by a separate request function */
        if (ar->filter_type != BE_FILTER_NAME) {
            return sdap_handler_done(breq, DP_ERR_FATAL,
                                     EINVAL, "Invalid filter type");
        }
        req = ipa_id_get_netgroup_send(breq, be_ctx->ev,
                                       ipa_ctx, ar->filter_value);
    } else {
        /* any account request is handled by sdap,
         * any invalid request is caught there. */
        return sdap_handle_account_info(breq, ctx, ctx->conn);
    }

    if (!req) {
        return sdap_handler_done(breq, DP_ERR_FATAL,
                                 ENOMEM, "Out of memory");
    }
    tevent_req_set_callback(req, ipa_account_info_done, breq);
}

static void ipa_account_info_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    struct be_ctx *be_ctx = be_req_get_be_ctx(breq);
    struct ipa_id_ctx *ipa_ctx;
    struct be_acct_req *ar = talloc_get_type(be_req_get_data(breq),
                                             struct be_acct_req);
    const char *error_text;
    int ret, dp_error;

    ipa_ctx = talloc_get_type(be_ctx->bet_info[BET_ID].pvt_bet_data,
                              struct ipa_id_ctx);

    if ((ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_NETGROUP) {
        ret = ipa_id_get_netgroup_recv(req, &dp_error);
    } else {
        if (dp_opt_get_bool(ipa_ctx->ipa_options->basic, IPA_SERVER_MODE)) {
            ret = ipa_get_ad_acct_recv(req, &dp_error);
        } else {
            ret = ipa_get_subdom_acct_recv(req, &dp_error);
        }
    }
    talloc_zfree(req);

    error_text = ipa_account_info_error_text(ret, &dp_error,
                                             "Account info lookup failed");
    sdap_handler_done(breq, dp_error, ret, error_text);
}


/* Request for netgroups
 * - first start here and then go to ipa_netgroups.c
 */
struct ipa_id_get_netgroup_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *name;
    int timeout;

    char *filter;
    const char **attrs;

    size_t count;
    struct sysdb_attrs **netgroups;

    int dp_error;
};

static void ipa_id_get_netgroup_connected(struct tevent_req *subreq);
static void ipa_id_get_netgroup_done(struct tevent_req *subreq);

static struct tevent_req *ipa_id_get_netgroup_send(TALLOC_CTX *memctx,
                                                   struct tevent_context *ev,
                                                   struct ipa_id_ctx *ipa_ctx,
                                                   const char *name)
{
    struct tevent_req *req;
    struct ipa_id_get_netgroup_state *state;
    struct tevent_req *subreq;
    struct sdap_id_ctx *ctx;
    char *clean_name;
    int ret;

    ctx = ipa_ctx->sdap_id_ctx;

    req = tevent_req_create(memctx, &state, struct ipa_id_get_netgroup_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ipa_ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, ctx->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    state->sysdb = ctx->be->domain->sysdb;
    state->domain = ctx->be->domain;
    state->name = name;
    state->timeout = dp_opt_get_int(ctx->opts->basic, SDAP_SEARCH_TIMEOUT);

    ret = sss_filter_sanitize(state, name, &clean_name);
    if (ret != EOK) {
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                            ctx->opts->netgroup_map[IPA_AT_NETGROUP_NAME].name,
                            clean_name,
                            ctx->opts->netgroup_map[IPA_OC_NETGROUP].name);
    if (!state->filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto fail;
    }
    talloc_zfree(clean_name);

    ret = build_attrs_from_map(state, ctx->opts->netgroup_map,
                               IPA_OPTS_NETGROUP, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) goto fail;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_id_get_netgroup_connected, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_id_get_netgroup_connected(struct tevent_req *subreq)
{
    struct tevent_req *req =
                    tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_id_get_netgroup_state *state =
                    tevent_req_data(req, struct ipa_id_get_netgroup_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    struct sdap_id_ctx *sdap_ctx = state->ctx->sdap_id_ctx;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subreq = ipa_get_netgroups_send(state, state->ev, state->sysdb,
                                    state->domain, sdap_ctx->opts,
                                    state->ctx->ipa_options,
                                    sdap_id_op_handle(state->op),
                                    state->attrs, state->filter,
                                    state->timeout);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ipa_id_get_netgroup_done, req);

    return;
}

static void ipa_id_get_netgroup_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
                    tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_id_get_netgroup_state *state =
                    tevent_req_data(req, struct ipa_id_get_netgroup_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = ipa_get_netgroups_recv(subreq, state,
                                 &state->count, &state->netgroups);
    talloc_zfree(subreq);
    ret = sdap_id_op_done(state->op, ret, &dp_error);

    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        subreq = sdap_id_op_connect_send(state->op, state, &ret);
        if (!subreq) {
            tevent_req_error(req, ret);
            return;
        }
        tevent_req_set_callback(subreq, ipa_id_get_netgroup_connected, req);
        return;
    }

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

    if (ret == ENOENT) {
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

static int ipa_id_get_netgroup_recv(struct tevent_req *req, int *dp_error)
{
    struct ipa_id_get_netgroup_state *state =
                    tevent_req_data(req, struct ipa_id_get_netgroup_state);

    if (dp_error) {
        *dp_error = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


void ipa_check_online(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct ipa_id_ctx *ipa_ctx;

    ipa_ctx = talloc_get_type(be_ctx->bet_info[BET_ID].pvt_bet_data,
                              struct ipa_id_ctx);

    return sdap_do_online_check(be_req, ipa_ctx->sdap_id_ctx);
}
