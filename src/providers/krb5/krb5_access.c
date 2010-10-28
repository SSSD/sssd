/*
    SSSD

    Kerberos 5 Backend Module - access control

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "util/util.h"
#include "providers/krb5/krb5_auth.h"

struct krb5_access_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;

    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    const char *upn;

    bool access_allowed;
};

struct tevent_req *krb5_access_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct be_ctx *be_ctx,
                                    struct pam_data *pd,
                                    struct krb5_ctx *krb5_ctx)
{
    struct krb5_access_state *state;
    struct tevent_req *req;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct krb5_access_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->pd = pd;
    state->krb5_ctx = krb5_ctx;
    state->upn = NULL;
    state->access_allowed = false;

    if (pd->cmd != SSS_PAM_ACCT_MGMT) {
        DEBUG(1, ("Unexpected pam task.\n"));
        ret = EINVAL;
        goto done;
    }

    state->access_allowed = true;
    ret = EOK;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, state->ev);
    return req;
}

int krb5_access_recv(struct tevent_req *req, bool *access_allowed)
{
    struct krb5_access_state *state = tevent_req_data(req,
                                                      struct krb5_access_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *access_allowed = state->access_allowed;

    return EOK;
}
