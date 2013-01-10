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
#include "src/providers/dp_backend.h"
#include "src/providers/ldap/sdap_access.h"

static void sdap_access_reply(struct be_req *be_req, int pam_status)
{
    struct pam_data *pd;
    pd = talloc_get_type(be_req->req_data, struct pam_data);
    pd->pam_status = pam_status;

    if (pam_status == PAM_SUCCESS || pam_status == PAM_PERM_DENIED) {
        be_req->fn(be_req, DP_ERR_OK, pam_status, NULL);
    } else {
        be_req->fn(be_req, DP_ERR_FATAL, pam_status, NULL);
    }
}

static void sdap_access_done(struct tevent_req *req);
void sdap_pam_access_handler(struct be_req *breq)
{
    struct pam_data *pd;
    struct tevent_req *req;
    struct sdap_access_ctx *access_ctx;

    pd = talloc_get_type(breq->req_data, struct pam_data);

    access_ctx =
            talloc_get_type(breq->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                            struct sdap_access_ctx);

    req = sdap_access_send(breq,
                           breq->be_ctx->ev,
                           breq->be_ctx,
                           breq->be_ctx->domain,
                           access_ctx,
                           pd);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to start sdap_access request\n"));
        sdap_access_reply(breq, PAM_SYSTEM_ERR);
        return;
    }

    tevent_req_set_callback(req, sdap_access_done, breq);
}

static void sdap_access_done(struct tevent_req *req)
{
    errno_t ret;
    int pam_status = PAM_SYSTEM_ERR;
    struct be_req *breq =
            tevent_req_callback_data(req, struct be_req);

    ret = sdap_access_recv(req, &pam_status);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error retrieving access check result.\n"));
        pam_status = PAM_SYSTEM_ERR;
    }

    sdap_access_reply(breq, pam_status);
}
