/*
   SSSD

   NSS Responder - Data Provider Interfaces

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include <talloc.h>
#include <tevent.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_pam_data.h"
#include "responder/pam/pamsrv.h"
#include "sss_iface/sss_iface_async.h"

static void
pam_dp_send_req_done(struct tevent_req *subreq);

errno_t
pam_dp_send_req(struct pam_auth_req *preq)
{
    struct tevent_req *subreq;
    struct be_conn *be_conn;
    errno_t ret;

    ret = sss_dp_get_domain_conn(preq->cctx->rctx, preq->domain->conn_name,
                                 &be_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "The Data Provider connection for %s is not "
              "available! This maybe a bug, it shouldn't happen!\n",
               preq->domain->conn_name);
        return EIO;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Sending request with the following data:\n");
    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, preq->pd);

    subreq = sbus_call_dp_dp_pamHandler_send(preq, be_conn->conn,
                 be_conn->bus_name, SSS_BUS_PATH, preq->pd);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, pam_dp_send_req_done, preq);

    return EOK;
}

static void
pam_dp_send_req_done(struct tevent_req *subreq)
{
    struct pam_data *pam_response;
    struct response_data *resp;
    struct pam_auth_req *preq;
    errno_t ret;

    preq = tevent_req_callback_data(subreq, struct pam_auth_req);

    ret = sbus_call_dp_dp_pamHandler_recv(preq, subreq, &pam_response);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "PAM handler failed [%d]: %s\n",
              ret, sss_strerror(ret));
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    preq->pd->pam_status = pam_response->pam_status;
    preq->pd->account_locked = pam_response->account_locked;

    DEBUG(SSSDBG_FUNC_DATA, "received: [%d (%s)][%s]\n",
          pam_response->pam_status,
          pam_strerror(NULL, pam_response->pam_status),
          preq->pd->domain);

    for (resp = pam_response->resp_list; resp != NULL; resp = resp->next) {
        talloc_steal(preq->pd, resp);

        if (resp->next == NULL) {
            resp->next = preq->pd->resp_list;
            preq->pd->resp_list = pam_response->resp_list;
            break;
        }
    }

    talloc_zfree(pam_response);

done:
    preq->callback(preq);
}
