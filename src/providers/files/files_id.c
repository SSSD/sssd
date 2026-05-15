/*
    SSSD

    files_id.c - Identity operaions on the files provider

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

#include "providers/data_provider/dp.h"
#include "providers/files/files_private.h"

struct files_account_info_handler_state {
    struct dp_reply_std reply;

    struct files_id_ctx *id_ctx;
    struct dp_id_data *data;
};

void handle_certmap(struct tevent_req *req)
{
    struct files_account_info_handler_state *state;
    int ret;

    state = tevent_req_data(req, struct files_account_info_handler_state);

    ret = files_map_cert_to_user(state->id_ctx, state->data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "files_map_cert_to_user failed\n");
    }

    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    return;
}

struct tevent_req *
files_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                struct files_id_ctx *id_ctx,
                                struct dp_id_data *data,
                                struct dp_req_params *params)
{
    struct files_account_info_handler_state *state;
    struct tevent_req *req;
    struct tevent_req **update_req = NULL;
    bool needs_update;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct files_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }
    state->id_ctx = id_ctx;

    switch (data->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER:
        if (data->filter_type != BE_FILTER_ENUM) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected user filter type: %d\n", data->filter_type);
            ret = EINVAL;
            goto immediate;
        }
        update_req = &id_ctx->users_req;
        needs_update = (id_ctx->refresh_ctx != NULL);
        break;
    case BE_REQ_GROUP:
        if (data->filter_type != BE_FILTER_ENUM) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected group filter type: %d\n", data->filter_type);
            ret = EINVAL;
            goto immediate;
        }
        update_req = &id_ctx->groups_req;
        needs_update = (id_ctx->refresh_ctx != NULL);
        break;
    case BE_REQ_INITGROUPS:
        if (data->filter_type != BE_FILTER_NAME) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected initgr filter type: %d\n", data->filter_type);
            ret = EINVAL;
            goto immediate;
        }
        if (strcmp(data->filter_value, DP_REQ_OPT_FILES_INITGR) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected initgr filter value: %d\n", data->filter_type);
            ret = EINVAL;
            goto immediate;
        }
        update_req = &id_ctx->initgroups_req;
        needs_update = (id_ctx->refresh_ctx != NULL);
        break;
    case BE_REQ_BY_CERT:
        if (data->filter_type != BE_FILTER_CERT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected filter type for lookup by cert: %d\n",
                  data->filter_type);
            ret = EINVAL;
            goto immediate;
        }

        if (id_ctx->sss_certmap_ctx == NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "Certificate mapping not configured.\n");
            ret = EOK;
            goto immediate;
        }

        /* Refresh is running, we have to wait until it is done */
        if (id_ctx->refresh_ctx != NULL) {
            state->data = data;

            ret = sf_add_certmap_req(id_ctx->refresh_ctx, req);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to add request certmap request list.\n");
                goto immediate;
            }

            return req;
        }

        /* No refresh is running, we have reply immediately */
        ret = files_map_cert_to_user(id_ctx, data);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "files_map_cert_to_user failed\n");
        }
        goto immediate;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected entry type: %d\n", data->entry_type & BE_REQ_TYPE_MASK);
        ret = EINVAL;
        goto immediate;
    }

    if (needs_update == false) {
        DEBUG(SSSDBG_TRACE_LIBS, "The files domain no longer needs an update\n");
        ret = EOK;
        goto immediate;
    }

    if (*update_req != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Received a concurrent update!\n");
        ret = EAGAIN;
        goto immediate;
    }

    /* id_ctx now must mark the requests as updated when the inotify-induced
     * update finishes
     */
    *update_req = req;
    return req;

immediate:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, params->ev);
    return req;
}

static void finish_update_req(struct tevent_req **update_req,
                              errno_t ret)
{
    if (*update_req == NULL) {
        return;
    }

    if (ret != EOK) {
        tevent_req_error(*update_req, ret);
    } else {
        tevent_req_done(*update_req);
    }
    *update_req = NULL;
}

void files_account_info_finished(struct files_id_ctx *id_ctx,
                                 int req_type,
                                 errno_t ret)
{
        finish_update_req(&id_ctx->users_req, ret);
        finish_update_req(&id_ctx->groups_req, ret);
        finish_update_req(&id_ctx->initgroups_req, ret);
}

errno_t files_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        struct dp_reply_std *data)
{
    struct files_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct files_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;
    return EOK;
}
