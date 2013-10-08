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
#include "src/providers/ad/ad_common.h"
#include "src/providers/ldap/sdap_access.h"

static void
ad_access_done(struct tevent_req *req);
static errno_t
ad_access_step(struct tevent_req *req, struct sdap_id_conn_ctx *conn);

struct ad_access_state {
    struct tevent_context *ev;
    struct ad_access_ctx *ctx;
    struct pam_data *pd;
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;

    struct sdap_id_conn_ctx **clist;
    int cindex;
};

static struct tevent_req *
ad_access_send(TALLOC_CTX *mem_ctx,
               struct tevent_context *ev,
               struct be_ctx *be_ctx,
               struct sss_domain_info *domain,
               struct ad_access_ctx *ctx,
               struct pam_data *pd)
{
    struct tevent_req *req;
    struct ad_access_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_access_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->ctx = ctx;
    state->pd = pd;
    state->be_ctx = be_ctx;
    state->domain = domain;

    state->clist = talloc_zero_array(state, struct sdap_id_conn_ctx *, 3);
    if (state->clist == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Always try GC first */
    ctx->gc_ctx->ignore_mark_offline = false;
    state->clist[0] = ctx->gc_ctx;
    if (IS_SUBDOMAIN(domain) == false) {
        /* fall back to ldap if gc is not available */
        state->clist[0]->ignore_mark_offline = true;

        /* With root domain users we have the option to
         * fall back to LDAP in case ie POSIX attributes
         * are used but not replicated to GC
         */
        state->clist[1] = ctx->ldap_ctx;
    }

    ret = ad_access_step(req, state->clist[state->cindex]);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static errno_t
ad_access_step(struct tevent_req *req, struct sdap_id_conn_ctx *conn)
{
    struct tevent_req *subreq;
    struct ad_access_state *state;

    state = tevent_req_data(req, struct ad_access_state);

    subreq = sdap_access_send(req, state->ev, state->be_ctx,
                              state->domain, state->ctx->sdap_access_ctx,
                              conn, state->pd);
    if (req == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ad_access_done, req);
    return EOK;
}

static void
ad_access_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_access_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_access_state);

    ret = sdap_access_recv(subreq);
    talloc_zfree(subreq);
    switch (ret) {
    case EOK:
        tevent_req_done(req);
        return;

    case ERR_ACCOUNT_EXPIRED:
        tevent_req_error(req, ret);
        return;

    case ERR_ACCESS_DENIED:
        /* Retry on ACCESS_DENIED, too, to make sure that we don't
         * miss out any attributes not present in GC
         * FIXME - this is slow. We should retry only if GC failed
         * and LDAP succeeded after the first ACCESS_DENIED
         */
        break;

    default:
        break;
    }

    /* If possible, retry with LDAP */
    state->cindex++;
    if (state->clist[state->cindex] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
            ("Error retrieving access check result: %s\n",
            sss_strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    ret = ad_access_step(req, state->clist[state->cindex]);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Another check in progress */
}

static errno_t
ad_access_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void
ad_access_check_done(struct tevent_req *req);

void
ad_access_handler(struct be_req *breq)
{
    struct tevent_req *req;
    struct be_ctx *be_ctx = be_req_get_be_ctx(breq);
    struct ad_access_ctx *access_ctx =
            talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                            struct ad_access_ctx);
    struct pam_data *pd =
                    talloc_get_type(be_req_get_data(breq), struct pam_data);
    struct sss_domain_info *domain;

    /* Handle subdomains */
    if (strcasecmp(pd->domain, be_ctx->domain->name) != 0) {
        domain = find_subdomain_by_name(be_ctx->domain, pd->domain, true);
        if (domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("find_subdomain_by_name failed.\n"));
            be_req_terminate(breq, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
            return;
        }
    } else {
        domain = be_ctx->domain;
    }

    /* Verify that the account is not locked */
    req = ad_access_send(breq, be_ctx->ev, be_ctx, domain,
                         access_ctx, pd);
    if (!req) {
        be_req_terminate(breq, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
        return;
    }
    tevent_req_set_callback(req, ad_access_check_done, breq);
}

static void
ad_access_check_done(struct tevent_req *req)
{
    errno_t ret;
    struct be_req *breq =
            tevent_req_callback_data(req, struct be_req);
    struct pam_data *pd =
                    talloc_get_type(be_req_get_data(breq), struct pam_data);

    ret = ad_access_recv(req);
    talloc_zfree(req);
    switch (ret) {
    case EOK:
        pd->pam_status = PAM_SUCCESS;
        be_req_terminate(breq, DP_ERR_OK, PAM_SUCCESS, NULL);
        return;
    case ERR_ACCESS_DENIED:
        /* We got the proper denial */
        pd->pam_status = PAM_PERM_DENIED;
        be_req_terminate(breq, DP_ERR_OK, PAM_PERM_DENIED, NULL);
        return;
    case ERR_ACCOUNT_EXPIRED:
        pd->pam_status = PAM_ACCT_EXPIRED;
        be_req_terminate(breq, DP_ERR_OK, PAM_ACCT_EXPIRED, NULL);
        return;
    default:
        /* Something went wrong */
        pd->pam_status = PAM_SYSTEM_ERR;
        be_req_terminate(breq, DP_ERR_FATAL,
                         PAM_SYSTEM_ERR, sss_strerror(ret));
        return;
    }
}
