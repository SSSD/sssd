/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "db/sysdb_ssh.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_hostid.h"
#include "providers/ipa/ipa_hosts.h"

struct hosts_get_state {
    struct tevent_context *ev;
    struct ipa_hostid_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    const char *name;
    const char *alias;
    const char **attrs;

    size_t count;
    struct sysdb_attrs **hosts;
    int dp_error;
};

struct tevent_req *
hosts_get_send(TALLOC_CTX *memctx,
               struct tevent_context *ev,
               struct ipa_hostid_ctx *hostid_ctx,
               const char *name,
               const char *alias,
               int attrs_type);
static errno_t
hosts_get_recv(struct tevent_req *req,
               int *dp_error_out);

static void
ipa_host_info_hosts_done(struct tevent_req *req);

void
ipa_host_info_handler(struct be_req *breq)
{
    struct ipa_hostid_ctx *hostid_ctx;
    struct sdap_id_ctx *ctx;
    struct be_acct_req *ar;
    struct tevent_req *req;
    int dp_error = DP_ERR_FATAL;
    errno_t ret = EOK;
    const char *err = "Unknown Error";

    hostid_ctx = talloc_get_type(breq->be_ctx->bet_info[BET_HOSTID].pvt_bet_data, struct ipa_hostid_ctx);
    ctx = hostid_ctx->sdap_id_ctx;

    if (be_is_offline(ctx->be)) {
        dp_error = DP_ERR_OFFLINE;
        ret = EAGAIN;
        err = "Offline";
        goto done;
    }

    ar = talloc_get_type(breq->req_data, struct be_acct_req);

    if (ar->filter_type != BE_FILTER_NAME) {
        ret = EINVAL;
        err = "Invalid filter type";
        goto done;
    }

    req = hosts_get_send(breq, breq->be_ctx->ev, hostid_ctx,
                         ar->filter_value, ar->extra_value,
                         ar->attr_type);
    if (!req) {
        ret = ENOMEM;
        err = "Out of memory";
        goto done;
    }

    tevent_req_set_callback(req, ipa_host_info_hosts_done, breq);

    ret = EOK;

done:
    if (ret != EOK) return sdap_handler_done(breq, dp_error, ret, err);
}

static void
ipa_host_info_complete(struct be_req *breq, int dp_error,
                            errno_t ret, const char *default_error_text)
{
    const char* error_text;

    if (dp_error == DP_ERR_OK) {
        if (ret == EOK) {
            error_text = NULL;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Bug: dp_error is OK on failed request"));
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

static void
ipa_host_info_hosts_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    int ret, dp_error;

    ret = hosts_get_recv(req, &dp_error);
    talloc_zfree(req);

    ipa_host_info_complete(breq, dp_error, ret, "Host lookup failed");
}

static errno_t
hosts_get_retry(struct tevent_req *req);
static void
hosts_get_connect_done(struct tevent_req *subreq);
static void
hosts_get_done(struct tevent_req *subreq);

struct tevent_req *
hosts_get_send(TALLOC_CTX *memctx,
               struct tevent_context *ev,
               struct ipa_hostid_ctx *hostid_ctx,
               const char *name,
               const char *alias,
               int attrs_type)
{
    struct tevent_req *req;
    struct hosts_get_state *state;
    struct sdap_id_ctx *ctx;
    errno_t ret;

    ctx = hostid_ctx->sdap_id_ctx;

    req = tevent_req_create(memctx, &state, struct hosts_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = hostid_ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, ctx->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->sysdb = ctx->be->sysdb;
    state->domain = ctx->be->domain;
    state->name = name;
    state->alias = alias;

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->host_map,
                               IPA_OPTS_HOST, &state->attrs);
    if (ret != EOK) goto fail;

    ret = hosts_get_retry(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t
hosts_get_retry(struct tevent_req *req)
{
    struct hosts_get_state *state = tevent_req_data(req,
                                                    struct hosts_get_state);
    struct tevent_req *subreq;
    errno_t ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, hosts_get_connect_done, req);
    return EOK;
}

static void
hosts_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hosts_get_state *state = tevent_req_data(req,
                                                    struct hosts_get_state);
    int dp_error = DP_ERR_FATAL;
    errno_t ret;
    struct sdap_id_ctx *ctx = state->ctx->sdap_id_ctx;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subreq = ipa_host_info_send(state, state->ev, state->sysdb,
                                sdap_id_op_handle(state->op),
                                ctx->opts, state->name,
                                state->attrs, ctx->opts->host_map,
                                IPA_OPTS_HOST, false,
                                state->ctx->host_search_bases);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, hosts_get_done, req);
}

static void
hosts_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct hosts_get_state *state = tevent_req_data(req,
                                                    struct hosts_get_state);
    int dp_error = DP_ERR_FATAL;
    errno_t ret;

    ret = ipa_host_info_recv(subreq, state,
                             &state->count, &state->hosts,
                             NULL, NULL);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = hosts_get_retry(req);
        if (ret != EOK) {
            goto done;
        }
        return;
    }

    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    if (state->count == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("No host with name [%s] found.\n", state->name));
        ret = EINVAL;
        goto done;
    }

    if (state->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Found more than one host with name [%s].\n", state->name));
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_store_ssh_host(state->sysdb, state->name, state->alias,
                               state->hosts[0]);
    if (ret != EOK) {
        goto done;
    }

    dp_error = DP_ERR_OK;

done:
    state->dp_error = dp_error;
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static errno_t
hosts_get_recv(struct tevent_req *req,
               int *dp_error_out)
{
    struct hosts_get_state *state = tevent_req_data(req,
                                                    struct hosts_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
