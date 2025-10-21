/*
    SSSD

    minimal Identity Backend Module

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2025 Red Hat

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
#include "providers/minimal/minimal_id.h"

struct minimal_handle_acct_req_state {
    struct dp_id_data *ar;
    const char *err;
    int dp_error;
    int minimal_ret;
    int sdap_ret;
};

static void minimal_handle_acct_req_done(struct tevent_req *subreq);

static struct tevent_req *
minimal_handle_acct_req_send(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             struct dp_id_data *ar,
                             struct sdap_id_ctx *id_ctx,
                             struct sdap_domain *sdom,
                             struct sdap_id_conn_ctx *conn,
                             bool noexist_delete)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct minimal_handle_acct_req_state *state;
    errno_t ret;


    req = tevent_req_create(mem_ctx, &state,
                            struct minimal_handle_acct_req_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create() failed.\n");
        return NULL;
    }
    state->ar = ar;

    if (ar == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing input.\n");
        ret = EINVAL;
        goto done;
    }

    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_SERVICES:
        DEBUG(SSSDBG_TRACE_FUNC, "Executing BE_REQ_SERVICES request\n");
        subreq = services_get_send(state, be_ctx->ev, id_ctx,
                                   sdom, conn,
                                   ar->filter_value,
                                   ar->extra_value,
                                   ar->filter_type,
                                   noexist_delete);
        break;
    default: /*fail*/
        ret = EINVAL;
        state->err = "Invalid request type";
        DEBUG(SSSDBG_OP_FAILURE,
              "Unexpected request type: 0x%X [%s:%s] in %s\n",
              ar->entry_type, ar->filter_value,
              ar->extra_value?ar->extra_value:"-",
              ar->domain);
        goto done;
    }

    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, minimal_handle_acct_req_done, req);
    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, be_ctx->ev);
    return req;
}

static void minimal_handle_acct_req_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct minimal_handle_acct_req_state *state;
    errno_t ret;
    const char *err = "Invalid request type";

    state = tevent_req_data(req, struct minimal_handle_acct_req_state);

    switch (state->ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_SERVICES:
        err = "Service lookup failed";
        ret = services_get_recv(subreq, &state->dp_error, &state->sdap_ret);
        break;
    default: /* fail */
        ret = EINVAL;
        break;
    }
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->err = err;
        tevent_req_error(req, ret);
        return;
    }

    state->err = "Success";
    tevent_req_done(req);
}

static errno_t
minimal_handle_acct_req_recv(struct tevent_req *req,
                          int *_dp_error, const char **_err,
                          int *minimal_ret)
{
    struct minimal_handle_acct_req_state *state;

    state = tevent_req_data(req, struct minimal_handle_acct_req_state);

    if (_dp_error) {
        *_dp_error = state->dp_error;
    }

    if (_err) {
        *_err = state->err;
    }

    if (minimal_ret) {
        *minimal_ret = state->minimal_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct minimal_account_info_handler_state {
    struct dp_reply_std reply;
};

static void minimal_account_info_handler_done(struct tevent_req *subreq);

struct tevent_req *
minimal_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                  struct sdap_id_ctx *id_ctx,
                                  struct dp_id_data *data,
                                  struct dp_req_params *params)
{
    struct minimal_account_info_handler_state *state;
    struct tevent_req *subreq = NULL;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct minimal_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    subreq = minimal_handle_acct_req_send(state, params->be_ctx, data, id_ctx,
                                          id_ctx->opts->sdom, id_ctx->conn, true);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "minimal_handle_acct_req_send() failed.\n");
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, minimal_account_info_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void minimal_account_info_handler_done(struct tevent_req *subreq)
{
    struct minimal_account_info_handler_state *state;
    struct tevent_req *req;
    const char *error_msg = NULL;
    int dp_error = DP_ERR_FATAL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct minimal_account_info_handler_state);

    ret = minimal_handle_acct_req_recv(subreq, &dp_error, &error_msg, NULL);
    talloc_zfree(subreq);

    dp_reply_std_set(&state->reply, dp_error, ret, error_msg);
    tevent_req_done(req);
}

errno_t minimal_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data)
{
    struct minimal_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct minimal_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
