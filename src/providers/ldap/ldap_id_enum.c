/*
    SSSD

    LDAP Identity Enumeration

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_enum.h"

errno_t ldap_setup_enumeration(struct be_ctx *be_ctx,
                               struct sdap_options *opts,
                               struct sdap_domain *sdom,
                               be_ptask_send_t send_fn,
                               be_ptask_recv_t recv_fn,
                               void *pvt)
{
    errno_t ret;
    time_t first_delay;
    time_t period;
    bool has_enumerated;
    struct ldap_enum_ctx *ectx;

    ret = sysdb_has_enumerated(sdom->dom, &has_enumerated);
    if (ret != EOK) {
        return ret;
    }

    if (has_enumerated) {
        /* At least one enumeration has previously run,
         * so clients will get cached data. We will delay
         * starting to enumerate by 10s so we don't slow
         * down the startup process if this is happening
         * during system boot.
         */
        first_delay = 10;
    } else {
        /* This is our first startup. Schedule the
         * enumeration to start immediately once we
         * enter the mainloop.
         */
        first_delay = 0;
    }

    period = dp_opt_get_int(opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);

    ectx = talloc(sdom, struct ldap_enum_ctx);
    if (ectx == NULL) {
        return ENOMEM;
    }
    ectx->sdom = sdom;
    ectx->pvt = pvt;

    ret = be_ptask_create(sdom, be_ctx,
                          period,                   /* period */
                          first_delay,              /* first_delay */
                          5,                        /* enabled delay */
                          period,                   /* timeout */
                          BE_PTASK_OFFLINE_SKIP,
                          send_fn, recv_fn,
                          ectx, "enumeration", &sdom->enum_task);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to initialize enumeration periodic task\n");
        talloc_free(ectx);
        return ret;
    }

    talloc_steal(sdom->enum_task, ectx);
    return EOK;
}

struct ldap_enumeration_state {
    struct ldap_enum_ctx *ectx;
    struct sdap_id_ctx *id_ctx;
    struct sss_domain_info *dom;
};

static void ldap_enumeration_done(struct tevent_req *subreq);

struct tevent_req *
ldap_enumeration_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct be_ctx *be_ctx,
                      struct be_ptask *be_ptask,
                      void *pvt)
{
    struct ldap_enumeration_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ldap_enum_ctx *ectx;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ldap_enumeration_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    ectx = talloc_get_type(pvt, struct ldap_enum_ctx);
    if (ectx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot retrieve ldap_enum_ctx!\n");
        ret = EFAULT;
        goto fail;
    }
    state->ectx = ectx;
    state->dom = ectx->sdom->dom;
    state->id_ctx = talloc_get_type_abort(ectx->pvt, struct sdap_id_ctx);

    subreq = sdap_dom_enum_send(ectx, ev, state->id_ctx, ectx->sdom,
                                state->id_ctx->conn);
    if (subreq == NULL) {
        /* The ptask API will reschedule the enumeration on its own on
         * failure */
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to schedule enumeration, retrying later!\n");
        ret = EIO;
        goto fail;
    }

    tevent_req_set_callback(subreq, ldap_enumeration_done, req);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
ldap_enumeration_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    ret = sdap_dom_enum_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
ldap_enumeration_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
