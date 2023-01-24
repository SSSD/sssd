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
#include "providers/ad/ad_domain_info.h"
#include "providers/ad/ad_resolver.h"
#include "providers/ldap/sdap_async_resolver_enum.h"
#include "providers/ldap/ldap_resolver_enum.h"

static errno_t
ad_resolver_setup_enumeration(struct be_ctx *be_ctx,
                              struct ad_resolver_ctx *resolver_ctx,
                              be_ptask_send_t send_fn,
                              be_ptask_recv_t recv_fn)
{
    errno_t ret;
    time_t first_delay;
    time_t period;
    time_t offset;
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
    offset = dp_opt_get_int(id_ctx->opts->basic, SDAP_ENUM_REFRESH_OFFSET);

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
                          offset,                   /* random offset */
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

    return ldap_resolver_cleanup(resolver_ctx->sdap_resolver_ctx);
}

static errno_t
ad_resolver_setup_cleanup(struct ad_resolver_ctx *resolver_ctx)
{
    errno_t ret;
    time_t first_delay;
    time_t period;
    time_t offset;
    char *name = NULL;
    struct sdap_id_ctx *id_ctx = resolver_ctx->ad_id_ctx->sdap_id_ctx;

    period = dp_opt_get_int(id_ctx->opts->basic, SDAP_PURGE_CACHE_TIMEOUT);
    if (period == 0) {
        /* Cleanup has been explicitly disabled, so we won't
         * create any cleanup tasks. */
        ret = EOK;
        goto done;
    }
    offset = dp_opt_get_int(id_ctx->opts->basic, SDAP_PURGE_CACHE_OFFSET);

    /* Run the first one in a couple of seconds so that we have time to
     * finish initializations first. */
    first_delay = 10;

    name = talloc_asprintf(resolver_ctx, "Cleanup [resolver] of %s",
                           id_ctx->opts->sdom->dom->name);
    if (name == NULL) {
        return ENOMEM;
    }

    ret = be_ptask_create_sync(resolver_ctx, id_ctx->be, period, first_delay,
                               5 /* enabled delay */, offset /* random offset */,
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
    struct ad_resolver_ctx *resolver_ctx;
    struct sdap_id_op *sdap_op;
    struct tevent_context *ev;

    const char *realm;
    struct sdap_domain *sdom;
    struct sdap_domain *sditer;
};

static void ad_resolver_enumeration_conn_done(struct tevent_req *subreq);

struct tevent_req *
ad_resolver_enumeration_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct be_ctx *be_ctx,
                             struct be_ptask *be_ptask,
                             void *pvt)
{
    struct ad_resolver_enum_state *state;
    struct ad_resolver_ctx *ctx;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;
    struct sdap_id_ctx *sdap_id_ctx;

    req = tevent_req_create(mem_ctx, &state, struct ad_resolver_enum_state);
    if (req == NULL) {
        return NULL;
    }

    ctx = talloc_get_type(pvt, struct ad_resolver_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot retrieve ad_resolver_ctx!\n");
        ret = EFAULT;
        goto fail;
    }

    sdap_id_ctx = ctx->ad_id_ctx->sdap_id_ctx;

    state->resolver_ctx = ctx;
    state->ev = ev;
    state->sdom = sdap_id_ctx->opts->sdom;
    state->sditer = state->sdom;
    state->realm = dp_opt_get_cstring(ctx->ad_id_ctx->ad_options->basic,
                                      AD_KRB5_REALM);
    if (state->realm == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Missing realm\n");
        ret = EINVAL;
        goto fail;
    }

    state->sdap_op = sdap_id_op_create(state, sdap_id_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
        goto fail;
    }
    tevent_req_set_callback(subreq, ad_resolver_enumeration_conn_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ad_resolver_enumeration_master_done(struct tevent_req *subreq);

static void
ad_resolver_enumeration_conn_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_resolver_enum_state *state = tevent_req_data(req,
                                                 struct ad_resolver_enum_state);
    struct sdap_id_ctx *id_ctx = state->resolver_ctx->ad_id_ctx->sdap_id_ctx;
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Backend is marked offline, retry later!\n");
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Domain enumeration failed to connect to " \
                   "LDAP server: (%d)[%s]\n", ret, strerror(ret));
            tevent_req_error(req, ret);
        }
        return;
    }

    subreq = ad_domain_info_send(state, state->ev, id_ctx->conn,
                                 state->sdap_op, state->sdom->dom->name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_domain_info_send failed.\n");
        tevent_req_error(req, ret);
        return;
    }
    tevent_req_set_callback(subreq, ad_resolver_enumeration_master_done, req);
}

static errno_t
ad_resolver_enum_sdom(struct tevent_req *req,
                      struct sdap_domain *sd,
                      struct sdap_resolver_ctx *sdap_resolver_ctx,
                      struct ad_id_ctx *id_ctx);

static void
ad_resolver_enumeration_master_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_resolver_enum_state *state = tevent_req_data(req,
                                                struct ad_resolver_enum_state);
    char *flat_name;
    const char *dns_name;
    char *master_sid;
    char *forest;
    struct ad_id_ctx *ad_id_ctx;

    ret = ad_domain_info_recv(subreq, state,
                                &flat_name, &master_sid, NULL, &forest);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot retrieve master domain info\n");
        tevent_req_error(req, ret);
        return;
    }

    ad_id_ctx = talloc_get_type(state->sdom->pvt, struct ad_id_ctx);
    if (ad_id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot retrieve ad_id_ctx!\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    dns_name = dp_opt_get_cstring(ad_id_ctx->ad_options->basic, AD_DOMAIN);
    if (dns_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing domain name\n");
        ret = EINVAL;
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_master_domain_add_info(state->sdom->dom, state->realm,
                                       flat_name, dns_name,
                                       master_sid, forest, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot save master domain info\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = ad_resolver_enum_sdom(req, state->sdom,
                                state->resolver_ctx->sdap_resolver_ctx,
                                ad_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
                "Could not enumerate domain %s\n", state->sdom->dom->name);
        tevent_req_error(req, ret);
        return;
    }

    /* Execution will resume in ad_enumeration_done */
}

static void ad_resolver_enum_sdom_done(struct tevent_req *subreq);

static errno_t
ad_resolver_enum_sdom(struct tevent_req *req,
                      struct sdap_domain *sd,
                      struct sdap_resolver_ctx *sdap_resolver_ctx,
                      struct ad_id_ctx *id_ctx)
{
    struct tevent_req *subreq;
    struct ad_resolver_enum_state *state = tevent_req_data(req,
                                                struct ad_resolver_enum_state);

    /* iphosts are searched for in LDAP */
    subreq = sdap_dom_resolver_enum_send(state, state->ev,
                                         sdap_resolver_ctx,
                                         id_ctx->sdap_id_ctx,
                                         sd,
                                         id_ctx->ldap_ctx);
    if (subreq == NULL) {
        /* The ptask API will reschedule the enumeration on its own on
         * failure */
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to schedule enumeration, retrying later!\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ad_resolver_enum_sdom_done, req);

    return EOK;
}

static void
ad_resolver_enum_sdom_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_resolver_enum_state *state = tevent_req_data(req,
                                                struct ad_resolver_enum_state);

    ret = sdap_dom_resolver_enum_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not enumerate domain %s\n", state->sditer->dom->name);
        tevent_req_error(req, ret);
        return;
    }

    do {
        state->sditer = state->sditer->next;
    } while (state->sditer &&
             state->sditer->dom->enumerate == false);

    if (state->sditer != NULL) {
        struct ad_id_ctx *ad_id_ctx;

        ad_id_ctx = talloc_get_type(state->sditer->pvt, struct ad_id_ctx);
        if (ad_id_ctx == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot retrieve ad_id_ctx!\n");
            tevent_req_error(req, EINVAL);
            return;
        }

        ret = ad_resolver_enum_sdom(req, state->sditer,
                                    state->resolver_ctx->sdap_resolver_ctx,
                                    ad_id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not enumerate domain %s\n",
                  state->sditer->dom->name);
            tevent_req_error(req, ret);
            return;
        }

        return;
    }

    tevent_req_done(req);
}

errno_t
ad_resolver_enumeration_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
