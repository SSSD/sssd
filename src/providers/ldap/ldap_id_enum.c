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

errno_t ldap_id_setup_enumeration(struct be_ctx *be_ctx,
                                  struct sdap_id_ctx *id_ctx,
                                  struct sdap_domain *sdom,
                                  be_ptask_send_t send_fn,
                                  be_ptask_recv_t recv_fn,
                                  void *pvt)
{
    errno_t ret;
    time_t first_delay;
    time_t period;
    time_t offset;
    time_t cleanup;
    bool has_enumerated;
    struct ldap_enum_ctx *ectx = NULL;
    char *name = NULL;

    ret = sysdb_has_enumerated(sdom->dom, SYSDB_HAS_ENUMERATED_ID,
                               &has_enumerated);
    if (ret == ENOENT) {
        /* default value */
        has_enumerated = false;
    } else if (ret != EOK) {
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

    cleanup = dp_opt_get_int(id_ctx->opts->basic, SDAP_PURGE_CACHE_TIMEOUT);
    if (cleanup == 0) {
        /* We need to cleanup the cache once in a while when enumerating, otherwise
         * enumeration would only download deltas since the previous lastUSN and would
         * not detect removed entries
         */
        ret = dp_opt_set_int(id_ctx->opts->basic, SDAP_PURGE_CACHE_TIMEOUT,
                             LDAP_ENUM_PURGE_TIMEOUT);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot set cleanup timeout, enumeration wouldn't "
                  "detect removed entries!\n");
            return ret;
        }
    }

    period = dp_opt_get_int(id_ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    offset = dp_opt_get_int(id_ctx->opts->basic, SDAP_ENUM_REFRESH_OFFSET);

    ectx = talloc(sdom, struct ldap_enum_ctx);
    if (ectx == NULL) {
        return ENOMEM;
    }
    ectx->sdom = sdom;
    ectx->pvt = pvt;

    name = talloc_asprintf(NULL, "Enumeration [id] of %s",
                           sdom->dom->name);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_ptask_create(id_ctx, be_ctx,
                          period,                   /* period */
                          first_delay,              /* first_delay */
                          5,                        /* enabled delay */
                          offset,                   /* random offset */
                          period,                   /* timeout */
                          0,                        /* max_backoff */
                          send_fn, recv_fn,
                          ectx, name,
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &id_ctx->task);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to initialize enumeration periodic task\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(name);
    if (ret != EOK) {
        talloc_free(ectx);
    }
    return ret;
}

struct ldap_enumeration_state {
    struct ldap_enum_ctx *ectx;
    struct sdap_id_ctx *id_ctx;
    struct sss_domain_info *dom;
};

static void ldap_enumeration_done(struct tevent_req *subreq);

struct tevent_req *
ldap_id_enumeration_send(TALLOC_CTX *mem_ctx,
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

    subreq = sdap_dom_enum_send(state, ev, state->id_ctx, ectx->sdom,
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
ldap_id_enumeration_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
