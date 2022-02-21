/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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
#include <talloc.h>
#include <tevent.h>
#include "util/util.h"
#include "providers/backend.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/ldap_common.h"

struct sdap_online_check_state {
    struct sdap_id_ctx *id_ctx;
    struct be_ctx *be_ctx;
};

static void sdap_online_check_connect_done(struct tevent_req *subreq);
static void sdap_online_check_reinit_done(struct tevent_req *subreq);

static struct tevent_req *sdap_online_check_send(TALLOC_CTX *mem_ctx,
                                                 struct sdap_id_ctx *id_ctx)
{
    struct sdap_online_check_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    struct be_ctx *be_ctx;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_online_check_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->id_ctx = id_ctx;
    state->be_ctx = be_ctx = id_ctx->be;

    subreq = sdap_cli_connect_send(state, be_ctx->ev, id_ctx->opts, be_ctx,
                                   id_ctx->conn->service, false,
                                   CON_TLS_DFL, false);
    if (subreq == NULL) {
        ret = ENOMEM;
        tevent_req_error(req, ret);
        tevent_req_post(req, be_ctx->ev);
    } else {
        tevent_req_set_callback(subreq, sdap_online_check_connect_done, req);
    }

    return req;
}

static void sdap_online_check_connect_done(struct tevent_req *subreq)
{
    struct sdap_online_check_state *state;
    struct sdap_server_opts *srv_opts;
    struct sdap_id_ctx *id_ctx;
    struct tevent_req *req;
    bool can_retry;
    bool reinit = false;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_online_check_state);

    id_ctx = state->id_ctx;

    ret = sdap_cli_connect_recv(subreq, state, &can_retry, NULL, &srv_opts);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (can_retry == false) {
            ret = ERR_OFFLINE;
        }

        goto done;
    } else {
        if (id_ctx->srv_opts == NULL) {
            srv_opts->max_user_value = 0;
            srv_opts->max_group_value = 0;
            srv_opts->max_service_value = 0;
            srv_opts->max_sudo_value = 0;
            srv_opts->max_iphost_value = 0;
            srv_opts->max_ipnetwork_value = 0;
        } else if (strcmp(srv_opts->server_id, id_ctx->srv_opts->server_id) == 0
                   && srv_opts->supports_usn
                   && id_ctx->srv_opts->last_usn > srv_opts->last_usn) {
            id_ctx->srv_opts->max_user_value = 0;
            id_ctx->srv_opts->max_group_value = 0;
            id_ctx->srv_opts->max_service_value = 0;
            id_ctx->srv_opts->max_sudo_value = 0;
            id_ctx->srv_opts->max_iphost_value = 0;
            id_ctx->srv_opts->max_ipnetwork_value = 0;
            id_ctx->srv_opts->last_usn = srv_opts->last_usn;

            reinit = true;
        }

        sdap_steal_server_opts(id_ctx, &srv_opts);
    }

    if (reinit) {
        DEBUG(SSSDBG_TRACE_FUNC, "Server reinitialization detected. "
              "Cleaning cache.\n");
        subreq = sdap_reinit_cleanup_send(state, state->be_ctx, id_ctx);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to perform reinitialization "
                  "clean up.\n");
            /* not fatal */
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_online_check_reinit_done, req);
        return;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void sdap_online_check_reinit_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_reinit_cleanup_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to perform reinitialization "
              "clean up [%d]: %s\n", ret, strerror(ret));
        /* not fatal */
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Reinitialization clean up completed\n");
    }

    tevent_req_done(req);
}

static errno_t sdap_online_check_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_online_check_handler_state {
    struct dp_reply_std reply;
};

static void sdap_online_check_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_online_check_handler_send(TALLOC_CTX *mem_ctx,
                               struct sdap_id_ctx *id_ctx,
                               void *data,
                               struct dp_req_params *params)
{
    struct sdap_online_check_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_online_check_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    subreq = sdap_online_check_send(state, id_ctx);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_online_check_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void sdap_online_check_handler_done(struct tevent_req *subreq)
{
    struct sdap_online_check_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_online_check_handler_state);

    ret = sdap_online_check_recv(subreq);
    talloc_zfree(subreq);

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);
    tevent_req_done(req);
}

errno_t sdap_online_check_handler_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       struct dp_reply_std *data)
{
    struct sdap_online_check_handler_state *state = NULL;

    state = tevent_req_data(req, struct sdap_online_check_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
