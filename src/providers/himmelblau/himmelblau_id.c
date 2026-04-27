/*
    SSSD

    Himmelblau Provider - Identity handler

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#include "config.h"

#include "providers/himmelblau/himmelblau_common.h"
#include "providers/backend.h"

struct himmelblau_account_info_state {
    struct himmelblau_id_ctx *id_ctx;
    struct dp_reply_std reply;
    struct dp_id_data *data;
};

struct tevent_req *
himmelblau_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                    struct himmelblau_id_ctx *id_ctx,
                                    struct dp_id_data *data,
                                    struct dp_req_params *params)
{
    struct tevent_req *req;
    struct himmelblau_account_info_state *state;

    req = tevent_req_create(mem_ctx, &state,
                           struct himmelblau_account_info_state);
    if (req == NULL) {
        return NULL;
    }

    state->id_ctx = id_ctx;
    state->data = data;

    DEBUG(SSSDBG_TRACE_FUNC,
          "himmelblau account info handler called for filter type [%d], "
          "value [%s]\n",
          data->filter_type, data->filter_value);

    /* TODO: Future implementation will:
     * 1. Query Microsoft Graph API for user/group information
     * 2. Cache results in sysdb
     * 3. Return DP_ERR_OK with user data
     */

    /* Stub: return not found */
    dp_reply_std_set(&state->reply, DP_ERR_OK, ENOENT,
                     "himmelblau provider stub - not implemented");

    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

errno_t
himmelblau_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct dp_reply_std *data)
{
    struct himmelblau_account_info_state *state;
    state = tevent_req_data(req, struct himmelblau_account_info_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;
    return EOK;
}
