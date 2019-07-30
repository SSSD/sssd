/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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

#include "providers/ad/ad_common.h"
#include "providers/ad/ad_resolver.h"

static errno_t
ad_resolver_setup_enumeration(struct be_ctx *be_ctx,
                              struct ad_resolver_ctx *resolver_ctx,
                              be_ptask_send_t send_fn,
                              be_ptask_recv_t recv_fn)
{
    errno_t ret;
    time_t first_delay;
    time_t period;
    time_t cleanup;
    bool has_enumerated;
    char *name = NULL;
    struct sdap_id_ctx *id_ctx = resolver_ctx->ad_id_ctx->sdap_id_ctx;

    ret = sysdb_has_enumerated(id_ctx->opts->sdom->dom,
                               SYSDB_HAS_ENUMERATED_RESOLVER,
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

    name = talloc_asprintf(resolver_ctx, "Enumeration [resolver] of %s",
                           id_ctx->opts->sdom->dom->name);
    if (name == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = be_ptask_create(resolver_ctx, be_ctx,
                          period,                   /* period */
                          first_delay,              /* first_delay */
                          5,                        /* enabled delay */
                          0,                        /* random offset */
                          period,                   /* timeout */
                          0,                        /* max_backoff */
                          send_fn, recv_fn,
                          resolver_ctx, name,
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &resolver_ctx->sdap_resolver_ctx->task);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to initialize enumeration periodic task\n");
        goto fail;
    }

    talloc_free(name);

    return EOK;

fail:
    if (name != NULL) {
        talloc_free(name);
    }
    return ret;
}

static errno_t
ad_resolver_cleanup_task(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct be_ctx *be_ctx,
                         struct be_ptask *be_ptask,
                         void *pvt)
{
    struct ad_resolver_ctx *resolver_ctx = NULL;

    resolver_ctx = talloc_get_type(pvt, struct ad_resolver_ctx);
    if (resolver_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot retrieve ad_resolver_ctx!\n");
        return EINVAL;
    }

    // TODO
    return EOK;
}

static errno_t
ad_resolver_setup_cleanup(struct ad_resolver_ctx *resolver_ctx)
{
    errno_t ret;
    time_t first_delay;
    time_t period;
    char *name = NULL;
    struct sdap_id_ctx *id_ctx = resolver_ctx->ad_id_ctx->sdap_id_ctx;

    period = dp_opt_get_int(id_ctx->opts->basic, SDAP_PURGE_CACHE_TIMEOUT);
    if (period == 0) {
        /* Cleanup has been explicitly disabled, so we won't
         * create any cleanup tasks. */
        ret = EOK;
        goto done;
    }

    /* Run the first one in a couple of seconds so that we have time to
     * finish initializations first. */
    first_delay = 10;

    name = talloc_asprintf(resolver_ctx, "Cleanup [resolver] of %s",
                           id_ctx->opts->sdom->dom->name);
    if (name == NULL) {
        return ENOMEM;
    }

    ret = be_ptask_create_sync(resolver_ctx, id_ctx->be, period, first_delay,
                               5 /* enabled delay */, 0 /* random offset */,
                               period /* timeout */, 0,
                               ad_resolver_cleanup_task, resolver_ctx, name,
                               BE_PTASK_OFFLINE_SKIP,
                               &resolver_ctx->sdap_resolver_ctx->task);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to initialize cleanup periodic task for %s\n",
              id_ctx->opts->sdom->dom->name);
        goto done;
    }

    ret = EOK;

done:
    if (name != NULL) {
        talloc_free(name);
    }

    return ret;
}

errno_t
ad_resolver_setup_tasks(struct be_ctx *be_ctx,
                        struct ad_resolver_ctx *resolver_ctx,
                        be_ptask_send_t send_fn,
                        be_ptask_recv_t recv_fn)
{
    errno_t ret;
    struct sdap_id_ctx *id_ctx = resolver_ctx->ad_id_ctx->sdap_id_ctx;
    struct sdap_domain *sdom = id_ctx->opts->sdom;

    /* set up enumeration task */
    if (sdom->dom->enumerate) {
        DEBUG(SSSDBG_TRACE_FUNC, "Setting up resolver enumeration for %s\n",
              sdom->dom->name);
        ret = ad_resolver_setup_enumeration(be_ctx, resolver_ctx,
                                            send_fn, recv_fn);
    } else {
        /* the enumeration task, runs the cleanup process by itself,
         * but if enumeration is not running we need to schedule it */
        DEBUG(SSSDBG_TRACE_FUNC, "Setting up resolver cleanup task for %s\n",
              sdom->dom->name);
        ret = ad_resolver_setup_cleanup(resolver_ctx);
    }

    return ret;
}

struct ad_resolver_enum_state {
    int dummy;
};

struct tevent_req *
ad_resolver_enumeration_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct be_ctx *be_ctx,
                             struct be_ptask *be_ptask,
                             void *pvt)
{
    struct ad_resolver_enum_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct ad_resolver_enum_state);
    if (req == NULL) {
        return NULL;
    }

    tevent_req_done(req);
    return tevent_req_post(req, ev);
}

errno_t
ad_resolver_enumeration_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
