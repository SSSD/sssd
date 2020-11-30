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
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_hostid.h"

struct hosts_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *id_ctx;
    struct sdap_id_op *op;
    struct sss_domain_info *domain;
    const char *name;
    const char *alias;

    size_t count;
    struct sysdb_attrs **hosts;
    int dp_error;
};

static errno_t
hosts_get_retry(struct tevent_req *req);
static void
hosts_get_connect_done(struct tevent_req *subreq);
static void
hosts_get_done(struct tevent_req *subreq);

struct tevent_req *
hosts_get_send(TALLOC_CTX *memctx,
               struct tevent_context *ev,
               struct sdap_id_ctx *id_ctx,
               const char *name,
               const char *alias)
{
    struct tevent_req *req;
    struct hosts_get_state *state;
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct hosts_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->id_ctx = id_ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, id_ctx->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    state->domain = id_ctx->be->domain;
    state->name = name;
    state->alias = alias;

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

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_host_info_send(state, state->ev,
                                 sdap_id_op_handle(state->op),
                                 state->id_ctx->opts, state->name,
                                 state->id_ctx->opts->host_map,
                                 state->id_ctx->opts->sdom->host_search_bases);
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
    struct sysdb_attrs *attrs;
    time_t now = time(NULL);

    ret = sdap_host_info_recv(subreq, state,
                              &state->count, &state->hosts);
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
        DEBUG(SSSDBG_FUNC_DATA,
              "No host with name [%s] found.\n", state->name);

        ret = sysdb_delete_ssh_host(state->domain, state->name);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }

        ret = EINVAL;
        goto done;
    }

    if (state->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one host with name [%s].\n", state->name);
        ret = EINVAL;
        goto done;
    }

    attrs = sysdb_new_attrs(state);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    /* we are interested only in the host keys */
    ret = sysdb_attrs_copy_values(state->hosts[0], attrs, SYSDB_SSH_PUBKEY);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_store_ssh_host(state->domain, state->name, state->alias,
                               state->domain->ssh_host_timeout, now, attrs);
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

struct sdap_hostid_handler_state {
    struct dp_reply_std reply;
};

static void sdap_hostid_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_hostid_handler_send(TALLOC_CTX *mem_ctx,
                         struct sdap_id_ctx *id_ctx,
                         struct dp_hostid_data *data,
                         struct dp_req_params *params)
{
    struct sdap_hostid_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_hostid_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    subreq = hosts_get_send(state, params->ev, id_ctx,
                            data->name, data->alias);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request\n");
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_hostid_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void sdap_hostid_handler_done(struct tevent_req *subreq)
{
    struct sdap_hostid_handler_state *state;
    struct tevent_req *req;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_hostid_handler_state);

    ret = hosts_get_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, dp_error, ret, NULL);
    tevent_req_done(req);
}

errno_t
sdap_hostid_handler_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct dp_reply_std *data)
{
    struct sdap_hostid_handler_state *state = NULL;

    state = tevent_req_data(req, struct sdap_hostid_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}

errno_t sdap_hostid_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         struct sdap_id_ctx *id_ctx,
                         struct dp_method *dp_methods)
{
    (void)be_ctx;

    dp_set_method(dp_methods, DPM_HOSTID_HANDLER,
                  sdap_hostid_handler_send, sdap_hostid_handler_recv, id_ctx,
                  struct sdap_id_ctx, struct dp_hostid_data, struct dp_reply_std);

    return EOK;
}
