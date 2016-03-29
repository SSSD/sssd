/*
    SSSD

    ldap_access.c

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2013 Red Hat

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
#include "src/util/util.h"
#include "src/providers/data_provider.h"
#include "src/providers/backend.h"
#include "src/providers/ldap/sdap_access.h"
#include "providers/ldap/ldap_common.h"

struct sdap_pam_access_handler_state {
    struct pam_data *pd;
};

static void sdap_pam_access_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_pam_access_handler_send(TALLOC_CTX *mem_ctx,
                           struct sdap_access_ctx *access_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params)
{
    struct sdap_pam_access_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_pam_access_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;

    subreq = sdap_access_send(state, params->ev, params->be_ctx,
                              params->domain, access_ctx,
                              access_ctx->id_ctx->conn, pd);
    if (subreq == NULL) {
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_pam_access_handler_done, req);

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void sdap_pam_access_handler_done(struct tevent_req *subreq)
{
    struct sdap_pam_access_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_pam_access_handler_state);

    ret = sdap_access_recv(subreq);
    talloc_free(subreq);
    switch (ret) {
    case EOK:
    case ERR_PASSWORD_EXPIRED_WARN:
        state->pd->pam_status = PAM_SUCCESS;
        break;
    case ERR_ACCOUNT_EXPIRED:
        state->pd->pam_status = PAM_ACCT_EXPIRED;
        break;
    case ERR_ACCESS_DENIED:
    case ERR_PASSWORD_EXPIRED:
    case ERR_PASSWORD_EXPIRED_REJECT:
        state->pd->pam_status = PAM_PERM_DENIED;
        break;
    case ERR_PASSWORD_EXPIRED_RENEW:
        state->pd->pam_status = PAM_NEW_AUTHTOK_REQD;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Error retrieving access check result.\n");
        state->pd->pam_status = PAM_SYSTEM_ERR;
        break;
    }

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
sdap_pam_access_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data)
{
    struct sdap_pam_access_handler_state *state = NULL;

    state = tevent_req_data(req, struct sdap_pam_access_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
