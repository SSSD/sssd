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

#include <security/pam_modules.h>
#include <talloc.h>
#include "config.h"
#include "providers/data_provider/dp.h"
#include "providers/backend.h"
#include "util/util.h"

struct dp_access_permit_handler_state {
    struct pam_data *pd;
};

struct tevent_req *
dp_access_permit_handler_send(TALLOC_CTX *mem_ctx,
                              void *data,
                              struct pam_data *pd,
                              struct dp_req_params *params)
{
    struct dp_access_permit_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct dp_access_permit_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    DEBUG(SSSDBG_TRACE_ALL, "Access permit, returning PAM_SUCCESS.\n");
    state->pd->pam_status = PAM_SUCCESS;

    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

errno_t
dp_access_permit_handler_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              struct pam_data **_data)
{
    struct dp_access_permit_handler_state *state = NULL;

    state = tevent_req_data(req, struct dp_access_permit_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}

struct dp_access_deny_handler_state {
    struct pam_data *pd;
};

struct tevent_req *
dp_access_deny_handler_send(TALLOC_CTX *mem_ctx,
                            void *data,
                            struct pam_data *pd,
                            struct dp_req_params *params)
{
    struct dp_access_deny_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct dp_access_deny_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    DEBUG(SSSDBG_TRACE_ALL, "Access deny, returning PAM_PERM_DENIED.\n");
    state->pd->pam_status = PAM_PERM_DENIED;

    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

errno_t
dp_access_deny_handler_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            struct pam_data **_data)
{
    struct dp_access_deny_handler_state *state = NULL;

    state = tevent_req_data(req, struct dp_access_deny_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
