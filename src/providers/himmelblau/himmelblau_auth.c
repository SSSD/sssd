/*
    SSSD

    Himmelblau Provider - Authentication handler

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

#include <security/pam_modules.h>

#include "providers/himmelblau/himmelblau_common.h"
#include "providers/backend.h"

struct himmelblau_pam_handler_state {
    struct pam_data *pd;
    struct himmelblau_auth_ctx *auth_ctx;
};

struct tevent_req *
himmelblau_pam_handler_send(TALLOC_CTX *mem_ctx,
                           struct himmelblau_auth_ctx *auth_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params)
{
    struct tevent_req *req;
    struct himmelblau_pam_handler_state *state;

    req = tevent_req_create(mem_ctx, &state,
                           struct himmelblau_pam_handler_state);
    if (req == NULL) {
        return NULL;
    }

    state->pd = pd;
    state->auth_ctx = auth_ctx;

    DEBUG(SSSDBG_TRACE_FUNC,
          "himmelblau auth handler called for user [%s], command [%d]\n",
          pd->user, pd->cmd);

    /* Only handle authenticate command for now */
    if (pd->cmd != SSS_PAM_AUTHENTICATE) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "himmelblau does not handle PAM command %d\n", pd->cmd);
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "himmelblau auth stub - returning unavailable for user [%s]\n",
          pd->user);

    /* TODO: Future implementation will:
     * 1. Check if device is joined (read from device_storage_path)
     * 2. If not joined: initiate device join flow
     * 3. Perform authentication using device credentials
     * 4. Return PAM_SUCCESS or appropriate error
     */

    /* Stub: return service unavailable */
    pd->pam_status = PAM_AUTHINFO_UNAVAIL;

immediately:
    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

errno_t
himmelblau_pam_handler_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct pam_data **_data)
{
    struct himmelblau_pam_handler_state *state;
    state = tevent_req_data(req, struct himmelblau_pam_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);
    return EOK;
}
