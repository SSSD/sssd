/*
    SSSD

    LDAP handler for autofs

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <errno.h>
#include <tevent.h>

#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_autofs.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/backend.h"
#include "providers/data_provider.h"
#include "db/sysdb_autofs.h"
#include "util/util.h"

static void
sdap_autofs_invalidate_maps(struct sdap_id_ctx *id_ctx,
                            const char *mapname)
{
    const char *master_map;
    errno_t ret;

    master_map = dp_opt_get_string(id_ctx->opts->basic,
                                   SDAP_AUTOFS_MAP_MASTER_NAME);
    if (strcmp(master_map, mapname) == 0) {
        DEBUG(SSSDBG_FUNC_DATA, "Refresh of automount master map triggered: "
              "%s\n", mapname);

        ret = sysdb_invalidate_autofs_maps(id_ctx->be->domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not invalidate autofs maps, "
                  "backend might return stale entries\n");
        }
    }
}

struct sdap_autofs_enumerate_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    const char *map_name;

    int dp_error;
};

static errno_t
sdap_autofs_enumerate_retry(struct tevent_req *req);
static void
sdap_autofs_enumerate_connect_done(struct tevent_req *subreq);
static void
sdap_autofs_enumerate_done(struct tevent_req *req);

static struct tevent_req *
sdap_autofs_enumerate_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sdap_id_ctx *ctx,
                           const char *map_name)
{
    struct tevent_req *req;
    struct sdap_autofs_enumerate_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_autofs_enumerate_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dp_error = DP_ERR_FATAL;
    state->map_name = map_name;

    state->op = sdap_id_op_create(state, state->ctx->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = sdap_autofs_enumerate_retry(req);
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
sdap_autofs_enumerate_retry(struct tevent_req *req)
{
    struct sdap_autofs_enumerate_state *state =
                tevent_req_data(req, struct sdap_autofs_enumerate_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_autofs_enumerate_connect_done, req);
    return EOK;
}

static void
sdap_autofs_enumerate_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_autofs_enumerate_state *state =
                tevent_req_data(req, struct sdap_autofs_enumerate_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_autofs_setautomntent_send(state, state->ev,
                                            state->ctx->be->domain,
                                            state->ctx->be->domain->sysdb,
                                            sdap_id_op_handle(state->op),
                                            state->op,
                                            state->ctx->opts,
                                            state->map_name);
    if (!subreq) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sdap_autofs_setautomntent_send failed\n");
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_autofs_enumerate_done, req);

}

static void
sdap_autofs_enumerate_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_autofs_enumerate_state *state =
        tevent_req_data(req, struct sdap_autofs_enumerate_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_autofs_setautomntent_recv(subreq);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = sdap_autofs_enumerate_retry(req);
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

    if (ret == ENOENT) {
        ret = sysdb_delete_autofsmap(state->ctx->be->domain, state->map_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Cannot delete autofs map %s [%d]: %s\n",
                 state->map_name, ret, strerror(ret));
            tevent_req_error(req, ret);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

static errno_t
sdap_autofs_enumerate_recv(struct tevent_req *req, int *dp_error_out)
{
    struct sdap_autofs_enumerate_state *state =
        tevent_req_data(req, struct sdap_autofs_enumerate_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_autofs_enumerate_handler_state {
    int dummy;
};

static void sdap_autofs_enumerate_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_autofs_enumerate_handler_send(TALLOC_CTX *mem_ctx,
                                   struct sdap_id_ctx *id_ctx,
                                   struct dp_autofs_data *data,
                                   struct dp_req_params *params)
{
    struct sdap_autofs_enumerate_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_autofs_enumerate_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Requested refresh for: %s\n", data->mapname);

    sdap_autofs_invalidate_maps(id_ctx, data->mapname);

    subreq = sdap_autofs_enumerate_send(mem_ctx, params->ev,
                                      id_ctx, data->mapname);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request for %s.\n",
              data->mapname);
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_autofs_enumerate_handler_done, req);

    ret = EAGAIN;

immediately:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, params->ev);
    }

    return req;
}

static void sdap_autofs_enumerate_handler_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_autofs_enumerate_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    ret = dp_error_to_ret(ret, dp_error);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sdap_autofs_enumerate_handler_recv(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *req,
                                   dp_no_output *_no_output)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_autofs_get_map_handler_state {
    int dummy;
};

static void sdap_autofs_get_map_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_autofs_get_map_handler_send(TALLOC_CTX *mem_ctx,
                                 struct sdap_id_ctx *id_ctx,
                                 struct dp_autofs_data *data,
                                 struct dp_req_params *params)
{
    struct sdap_autofs_get_map_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_autofs_get_map_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Requested refresh for: %s\n", data->mapname);

    sdap_autofs_invalidate_maps(id_ctx, data->mapname);

    subreq = sdap_autofs_get_map_send(mem_ctx, id_ctx, data->mapname);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request for %s.\n",
              data->mapname);
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_autofs_get_map_handler_done, req);

    ret = EAGAIN;

immediately:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, params->ev);
    }

    return req;
}

static void sdap_autofs_get_map_handler_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_autofs_get_map_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    ret = dp_error_to_ret(ret, dp_error);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sdap_autofs_get_map_handler_recv(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *req,
                                   dp_no_output *_no_output)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_autofs_get_entry_handler_state {
    int dummy;
};

static void sdap_autofs_get_entry_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_autofs_get_entry_handler_send(TALLOC_CTX *mem_ctx,
                                 struct sdap_id_ctx *id_ctx,
                                 struct dp_autofs_data *data,
                                 struct dp_req_params *params)
{
    struct sdap_autofs_get_entry_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_autofs_get_entry_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Requested refresh for: %s:%s\n",
          data->mapname, data->entryname);

    subreq = sdap_autofs_get_entry_send(mem_ctx, id_ctx,
                                        data->mapname, data->entryname);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request for %s:%s.\n",
              data->mapname, data->entryname);
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_autofs_get_entry_handler_done, req);

    ret = EAGAIN;

immediately:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, params->ev);
    }

    return req;
}

static void sdap_autofs_get_entry_handler_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_autofs_get_entry_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    ret = dp_error_to_ret(ret, dp_error);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sdap_autofs_get_entry_handler_recv(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *req,
                                   dp_no_output *_no_output)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t sdap_autofs_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         struct sdap_id_ctx *id_ctx,
                         struct dp_method *dp_methods)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing autofs LDAP back end\n");

    ret = ldap_get_autofs_options(id_ctx, sysdb_ctx_get_ldb(be_ctx->domain->sysdb),
                                  be_ctx->cdb, be_ctx->conf_path, id_ctx->opts);
    if (ret != EOK) {
        return ret;
    }

    dp_set_method(dp_methods, DPM_AUTOFS_ENUMERATE,
                  sdap_autofs_enumerate_handler_send, sdap_autofs_enumerate_handler_recv, id_ctx,
                  struct sdap_id_ctx, struct dp_autofs_data, dp_no_output);

    dp_set_method(dp_methods, DPM_AUTOFS_GET_MAP,
                  sdap_autofs_get_map_handler_send, sdap_autofs_get_map_handler_recv, id_ctx,
                  struct sdap_id_ctx, struct dp_autofs_data, dp_no_output);

    dp_set_method(dp_methods, DPM_AUTOFS_GET_ENTRY,
                  sdap_autofs_get_entry_handler_send, sdap_autofs_get_entry_handler_recv, id_ctx,
                  struct sdap_id_ctx, struct dp_autofs_data, dp_no_output);

    return EOK;
}
