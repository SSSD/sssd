/*
    SSSD

    files_auth.c - PAM operations on the files provider

    Copyright (C) 2018 Red Hat

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

#include "providers/data_provider/dp.h"
#include "providers/data_provider.h"
#include "providers/files/files_private.h"
#include "util/cert.h"

struct files_auth_ctx {
    struct pam_data *pd;
};

struct tevent_req *
files_auth_handler_send(TALLOC_CTX *mem_ctx,
                        void *unused,
                        struct pam_data *pd,
                        struct dp_req_params *params)
{
    struct files_auth_ctx *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct files_auth_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;

    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

errno_t files_auth_handler_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                struct pam_data **_data)
{
    struct files_auth_ctx *state = NULL;

    state = tevent_req_data(req, struct files_auth_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
