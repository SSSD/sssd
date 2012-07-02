/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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
#include "src/providers/ad/ad_access.h"
#include "src/providers/ldap/sdap_access.h"

static void
ad_access_done(struct tevent_req *req);

void
ad_access_handler(struct be_req *breq)
{
    struct tevent_req *req;
    struct ad_access_ctx *access_ctx =
            talloc_get_type(breq->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                            struct ad_access_ctx);

    struct pam_data *pd = talloc_get_type(breq->req_data, struct pam_data);

    /* Handle subdomains */
    if (strcasecmp(pd->domain, breq->be_ctx->domain->name) != 0) {
        breq->domain = new_subdomain(breq, breq->be_ctx->domain, pd->domain,
                                     NULL, NULL);
        if (breq->domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("new_subdomain failed.\n"));
            breq->fn(breq, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
            return;
        }
        breq->sysdb = breq->domain->sysdb;
    }

    /* Verify that the account is not locked */
    req = sdap_access_send(breq,
                           breq->be_ctx->ev,
                           breq,
                           access_ctx->sdap_access_ctx,
                           pd);
    if (!req) {
        breq->fn(breq, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
        return;
    }
    tevent_req_set_callback(req, ad_access_done, breq);
}

static void
ad_access_done(struct tevent_req *req)
{
    errno_t ret;
    int pam_status;
    struct be_req *breq =
            tevent_req_callback_data(req, struct be_req);
    struct pam_data *pd = talloc_get_type(breq->req_data, struct pam_data);

    ret = sdap_access_recv(req, &pam_status);
    talloc_zfree(req);
    if (ret != EOK) {
        breq->fn(breq, DP_ERR_FATAL, PAM_SYSTEM_ERR, strerror(ret));
        return;
    }

    pd->pam_status = pam_status;

    if (pam_status == PAM_SUCCESS || pam_status == PAM_PERM_DENIED) {
        /* We got the proper approval or denial */
        breq->fn(breq, DP_ERR_OK, pam_status, NULL);
        return;
    }

    /* Something went wrong */
    pd->pam_status = PAM_SYSTEM_ERR;
    breq->fn(breq, DP_ERR_FATAL, pam_status, pam_strerror(NULL, pam_status));
    return;
}
