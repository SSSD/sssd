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

struct ipa_netgroup_get_state {
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

struct tevent_req *ipa_netgroup_get_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct ipa_id_ctx *ctx,
                                     const char *name);
static int ipa_netgroup_get_retry(struct tevent_req *req);
static void ipa_netgroup_get_connect_done(struct tevent_req *subreq);
static void ipa_netgroup_get_done(struct tevent_req *subreq);
static void ipa_account_info_netgroups_done(struct tevent_req *req);

void ipa_account_info_handler(struct be_req *breq)
{
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_id_ctx *ctx;
    struct be_acct_req *ar;
    struct tevent_req *req;
    const char *err = "Unknown Error";
    int ret = EOK;

    ipa_ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data, struct ipa_id_ctx);
    ctx = ipa_ctx->sdap_id_ctx;

    if (be_is_offline(ctx->be)) {
        return sdap_handler_done(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    ar = talloc_get_type(breq->req_data, struct be_acct_req);

    switch (ar->entry_type & 0xFFF) {
    case BE_REQ_USER: /* user */
    case BE_REQ_GROUP: /* group */
    case BE_REQ_INITGROUPS: /* init groups for user */
    case BE_REQ_SERVICES: /* Services. Not natively supported by IPA */
        return sdap_handle_account_info(breq, ctx);

    case BE_REQ_NETGROUP:
        if (ar->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            err = "Invalid filter type";
            break;
        }

        req = ipa_netgroup_get_send(breq, breq->be_ctx->ev, ipa_ctx, ar->filter_value);
        if (!req) {
            return sdap_handler_done(breq, DP_ERR_FATAL, ENOMEM, "Out of memory");
        }

        tevent_req_set_callback(req, ipa_account_info_netgroups_done, breq);
        break;

    default: /*fail*/
        ret = EINVAL;
        err = "Invalid request type";
    }

    if (ret != EOK) return sdap_handler_done(breq, DP_ERR_FATAL, ret, err);
}

static void ipa_account_info_complete(struct be_req *breq, int dp_error,
                                       int ret, const char *default_error_text)
{
    const char* error_text;

    if (dp_error == DP_ERR_OK) {
        if (ret == EOK) {
            error_text = NULL;
        } else {
            DEBUG(1, ("Bug: dp_error is OK on failed request"));
            dp_error = DP_ERR_FATAL;
            error_text = default_error_text;
        }
    } else if (dp_error == DP_ERR_OFFLINE) {
        error_text = "Offline";
    } else if (dp_error == DP_ERR_FATAL && ret == ENOMEM) {
        error_text = "Out of memory";
    } else {
        error_text = default_error_text;
    }

    sdap_handler_done(breq, dp_error, ret, error_text);
}

/* Request for netgroups
 * - first start here and then go to ipa_netgroups.c
 */
struct tevent_req *ipa_netgroup_get_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct ipa_id_ctx *ipa_ctx,
                                     const char *name)
{
    struct tevent_req *req;
    struct ipa_netgroup_get_state *state;
    struct sdap_id_ctx *ctx;
    char *clean_name;
    int ret;

    ctx = ipa_ctx->sdap_id_ctx;

    req = tevent_req_create(memctx, &state, struct ipa_netgroup_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ipa_ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, ctx->conn_cache);
    if (!state->op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->sysdb = ctx->be->sysdb;
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
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto fail;
    }
    talloc_zfree(clean_name);

    ret = build_attrs_from_map(state, ctx->opts->netgroup_map,
                               IPA_OPTS_NETGROUP, &state->attrs);
    if (ret != EOK) goto fail;

    ret = ipa_netgroup_get_retry(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static int ipa_netgroup_get_retry(struct tevent_req *req)
{
    struct ipa_netgroup_get_state *state = tevent_req_data(req,
                                                    struct ipa_netgroup_get_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, ipa_netgroup_get_connect_done, req);
    return EOK;
}

static void ipa_netgroup_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_netgroup_get_state *state = tevent_req_data(req,
                                                    struct ipa_netgroup_get_state);
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
    tevent_req_set_callback(subreq, ipa_netgroup_get_done, req);

    return;
}

static void ipa_netgroup_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_netgroup_get_state *state = tevent_req_data(req,
                                                    struct ipa_netgroup_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = ipa_get_netgroups_recv(subreq, state, &state->count, &state->netgroups);
    talloc_zfree(subreq);
    ret = sdap_id_op_done(state->op, ret, &dp_error);

    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ipa_netgroup_get_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        return;
    }

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == EOK && state->count > 1) {
        DEBUG(1, ("Found more than one netgroup with the name [%s].\n",
                  state->name));
        tevent_req_error(req, EINVAL);
        return;
    }

    if (ret == ENOENT) {
        ret = sysdb_delete_netgroup(state->sysdb, state->name);
        if (ret != EOK && ret != ENOENT) {
            tevent_req_error(req, ret);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;
}

int ipa_netgroup_get_recv(struct tevent_req *req, int *dp_error_out)
{
    struct ipa_netgroup_get_state *state = tevent_req_data(req,
                                                    struct ipa_netgroup_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void ipa_account_info_netgroups_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    int ret, dp_error;

    ret = ipa_netgroup_get_recv(req, &dp_error);
    talloc_zfree(req);

    ipa_account_info_complete(breq, dp_error, ret, "Netgroup lookup failed");
}

void ipa_check_online(struct be_req *be_req)
{
    struct ipa_id_ctx *ipa_ctx;

    ipa_ctx = talloc_get_type(be_req->be_ctx->bet_info[BET_ID].pvt_bet_data,
                              struct ipa_id_ctx);

    return sdap_do_online_check(be_req, ipa_ctx->sdap_id_ctx);
}
