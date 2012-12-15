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
#include "providers/dp_backend.h"
#include "db/sysdb_autofs.h"
#include "util/util.h"

static void
sdap_autofs_shutdown(struct be_req *req)
{
    sdap_handler_done(req, DP_ERR_OK, EOK, NULL);
}

void sdap_autofs_handler(struct be_req *be_req);

/* Autofs Handler */
struct bet_ops sdap_autofs_ops = {
    .handler = sdap_autofs_handler,
    .finalize = sdap_autofs_shutdown
};

int sdap_autofs_init(struct be_ctx *be_ctx,
                     struct sdap_id_ctx *id_ctx,
                     struct bet_ops **ops,
                     void **pvt_data)
{
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Initializing autofs LDAP back end\n"));

    *ops = &sdap_autofs_ops;
    *pvt_data = id_ctx;

    ret = ldap_get_autofs_options(id_ctx, be_ctx->cdb,
                                  be_ctx->conf_path, id_ctx->opts);
    if (ret != EOK) {
        return ret;
    }

    return ret;
}

static struct tevent_req *
sdap_autofs_get_map_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sdap_id_ctx *ctx,
                         const char *map_name);

static void sdap_autofs_handler_done(struct tevent_req *req);

void sdap_autofs_handler(struct be_req *be_req)
{
    struct sdap_id_ctx *id_ctx;
    struct be_autofs_req *autofs_req;
    struct tevent_req *req;
    int ret = EOK;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("sdap autofs handler called\n"));

    id_ctx = talloc_get_type(be_req->be_ctx->bet_info[BET_AUTOFS].pvt_bet_data,
                             struct sdap_id_ctx);

    if (be_is_offline(id_ctx->be)) {
        return sdap_handler_done(be_req, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    autofs_req = talloc_get_type(be_req->req_data, struct be_autofs_req);

    DEBUG(SSSDBG_FUNC_DATA, ("Requested refresh for: %s\n",
          autofs_req->mapname ? autofs_req->mapname : "<ALL>\n"));

    if (autofs_req->invalidate) {
        ret = sysdb_invalidate_autofs_maps(id_ctx->be->sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Could not invalidate autofs maps, "
                  "backend might return stale entries\n"));
        }
    }

    req = sdap_autofs_get_map_send(be_req, be_req->be_ctx->ev,
                                   id_ctx, autofs_req->mapname);
    if (!req) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, sdap_autofs_handler_done, be_req);

    return;
fail:
    be_req->fn(be_req, DP_ERR_FATAL, ret, NULL);
}

struct autofs_get_map_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    const char *map_name;

    int dp_error;
};

static errno_t
sdap_autofs_get_map_retry(struct tevent_req *req);
static void
sdap_autofs_get_map_connect_done(struct tevent_req *subreq);
static void
sdap_autofs_get_map_done(struct tevent_req *req);

static struct tevent_req *
sdap_autofs_get_map_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sdap_id_ctx *ctx,
                         const char *map_name)
{
    struct tevent_req *req;
    struct autofs_get_map_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct autofs_get_map_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dp_error = DP_ERR_FATAL;
    state->map_name = map_name;

    state->op = sdap_id_op_create(state, state->ctx->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    ret = sdap_autofs_get_map_retry(req);
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
sdap_autofs_get_map_retry(struct tevent_req *req)
{
    struct autofs_get_map_state *state =
                tevent_req_data(req, struct autofs_get_map_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_autofs_get_map_connect_done, req);
    return EOK;
}

static void
sdap_autofs_get_map_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct autofs_get_map_state *state =
                tevent_req_data(req, struct autofs_get_map_state);
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
                                            state->ctx->be->sysdb,
                                            sdap_id_op_handle(state->op),
                                            state->op,
                                            state->ctx->opts,
                                            state->map_name);
    if (!subreq) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sdap_autofs_setautomntent_send failed\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_autofs_get_map_done, req);

}

static void
sdap_autofs_get_map_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct autofs_get_map_state *state =
        tevent_req_data(req, struct autofs_get_map_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_autofs_setautomntent_recv(subreq);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = sdap_autofs_get_map_retry(req);
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
        ret = sysdb_delete_autofsmap(state->ctx->be->sysdb, state->map_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                ("Cannot delete autofs map %s [%d]: %s\n",
                 state->map_name, ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

static errno_t
sdap_autofs_get_map_recv(struct tevent_req *req, int *dp_error_out)
{
    struct autofs_get_map_state *state =
        tevent_req_data(req, struct autofs_get_map_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void
sdap_autofs_handler_done(struct tevent_req *req)
{
    struct be_req *be_req =
        tevent_req_callback_data(req, struct be_req);
    int dperr;
    errno_t ret;

    ret = sdap_autofs_get_map_recv(req, &dperr);
    sdap_handler_done(be_req, dperr, ret, strerror(ret));
}

