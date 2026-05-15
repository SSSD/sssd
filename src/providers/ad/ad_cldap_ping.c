/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2020 Red Hat

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

#include <string.h>
#include <talloc.h>
#include <tevent.h>
#include <ndr.h>
#include <ndr/ndr_nbt.h>

#include "util/util.h"
#include "util/sss_ldap.h"
#include "resolv/async_resolv.h"
#include "providers/backend.h"
#include "providers/ad/ad_srv.h"
#include "providers/ad/ad_common.h"
#include "providers/fail_over.h"
#include "providers/fail_over_srv.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "db/sysdb.h"

#ifdef HAVE_LDAP_IS_LDAPC_URL
#define AD_PING_PROTOCOL "cldap"
#else
#define AD_PING_PROTOCOL "ldap"
#endif

struct ad_cldap_ping_dc_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct be_resolv_ctx *be_res;
    struct fo_server_info *dc;
    struct sdap_handle *sh;
    const char *ad_domain;

    char *site;
    char *forest;
};

static void ad_cldap_ping_dc_connect_done(struct tevent_req *subreq);
static void ad_cldap_ping_dc_done(struct tevent_req *subreq);

static struct tevent_req *ad_cldap_ping_dc_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct sdap_options *opts,
                                                struct be_resolv_ctx *be_res,
                                                enum host_database *host_db,
                                                struct fo_server_info *dc,
                                                const char *ad_domain)
{
    struct ad_cldap_ping_dc_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_cldap_ping_dc_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->be_res = be_res;
    state->dc = dc;
    state->ad_domain = ad_domain;

    subreq = sdap_connect_host_send(state, ev, opts, be_res->resolv,
                                    be_res->family_order, host_db,
                                    AD_PING_PROTOCOL, dc->host, dc->port,
                                    false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_cldap_ping_dc_connect_done, req);

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ad_cldap_ping_dc_connect_done(struct tevent_req *subreq)
{
    static const char *attrs[] = {AD_AT_NETLOGON, NULL};
    struct ad_cldap_ping_dc_state *state;
    struct tevent_req *req;
    char *ntver;
    char *filter;
    int timeout;
    errno_t ret;
    div_t timeout_int;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_cldap_ping_dc_state);

    ret = sdap_connect_host_recv(state, subreq, &state->sh);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ntver = sss_ldap_encode_ndr_uint32(state, NETLOGON_NT_VERSION_5EX |
                                       NETLOGON_NT_VERSION_WITH_CLOSEST_SITE);
    if (ntver == NULL) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(%s=%s))", AD_AT_DNS_DOMAIN,
                             state->ad_domain, AD_AT_NT_VERSION, ntver);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* DP_RES_OPT_RESOLVER_SERVER_TIMEOUT is in milli-seconds and
     * sdap_get_generic_send() expects seconds */
    timeout_int = div(dp_opt_get_int(state->be_res->opts,
                                     DP_RES_OPT_RESOLVER_SERVER_TIMEOUT),
                      1000);
    timeout = (timeout_int.quot > 0) ? timeout_int.quot : 1;
    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh, "",
                                   LDAP_SCOPE_BASE, filter, attrs, NULL,
                                   0, timeout, false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_cldap_ping_dc_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void ad_cldap_ping_dc_done(struct tevent_req *subreq)
{
    struct ad_cldap_ping_dc_state *state;
    struct tevent_req *req;
    struct sysdb_attrs **reply;
    size_t reply_count;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_cldap_ping_dc_state);

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);

    talloc_zfree(subreq);
    talloc_zfree(state->sh);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "%s:%d: unable to get netlogon information\n",
              state->dc->host, state->dc->port);
        goto done;
    }

    if (reply_count == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "%s:%d: no netlogon information available\n",
              state->dc->host, state->dc->port);
        ret = ENOENT;
        goto done;
    }

    ret = netlogon_get_domain_info(state, reply[0], true, NULL, &state->site,
                                   &state->forest);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "%s:%d: unable to retrieve site name [%d]: %s\n",
              state->dc->host, state->dc->port, ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "%s:%d: found site (%s) and forest (%s)\n",
          state->dc->host, state->dc->port, state->site, state->forest);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ad_cldap_ping_dc_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     const char **_site,
                                     const char **_forest)
{
    struct ad_cldap_ping_dc_state *state = NULL;
    state = tevent_req_data(req, struct ad_cldap_ping_dc_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_site = talloc_steal(mem_ctx, state->site);
    *_forest = talloc_steal(mem_ctx, state->forest);

    return EOK;
}

struct ad_cldap_ping_parallel_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct be_resolv_ctx *be_res;
    enum host_database *host_db;
    const char *ad_domain;
    struct fo_server_info *dc_list;
    size_t dc_count;

    TALLOC_CTX *reqs_ctx;
    struct tevent_timer *te;
    int active_requests;
    size_t next_dc;
    int batch;

    const char *site;
    const char *forest;
};

static void ad_cldap_ping_parallel_batch(struct tevent_context *ev,
                                         struct tevent_timer *te,
                                         struct timeval tv,
                                         void *data);
static void ad_cldap_ping_parallel_done(struct tevent_req *subreq);

static struct tevent_req *
ad_cldap_ping_parallel_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sdap_options *opts,
                            struct be_resolv_ctx *be_res,
                            enum host_database *host_db,
                            struct fo_server_info *dc_list,
                            size_t dc_count,
                            const char *ad_domain)
{
    struct ad_cldap_ping_parallel_state *state;
    struct tevent_req *req;
    struct timeval tv = {0, 0};
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_cldap_ping_parallel_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->be_res = be_res;
    state->host_db = host_db;
    state->ad_domain = ad_domain;
    state->dc_list = dc_list;
    state->dc_count = dc_count;

    state->reqs_ctx = talloc_new(state);
    if (state->reqs_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->next_dc = 0;
    state->batch = 1;
    ad_cldap_ping_parallel_batch(ev, NULL, tv, req);

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ad_cldap_ping_parallel_batch(struct tevent_context *ev,
                                         struct tevent_timer *te,
                                         struct timeval tv,
                                         void *data)
{
    struct ad_cldap_ping_parallel_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    uint32_t delay;
    size_t limit;
    size_t i;

    req = talloc_get_type(data, struct tevent_req);
    state = tevent_req_data(req, struct ad_cldap_ping_parallel_state);

    state->te = NULL;

    /* Issue three batches in total to avoid pinging too many domain controllers
     * if not necessary. The first batch (5 pings) is issued immediately and we
     * will wait 400ms for it to finish. If we don't get a reply in time we
     * issue next batch (5 pings) and wait 200ms. If we still have no reply,
     * we contact remaining domain controllers.
     *
     * This follows algorithm described at section 5.4.5.3 of MS-DISO:
     * https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-DISO%5d.pdf
     */
    switch (state->batch) {
        case 1:
        case 2:
            limit = MIN(state->dc_count, 5 + state->next_dc);
            delay = 400000 / state->batch;
            break;
        default:
            limit = state->dc_count;
            delay = 0;
    }

    for (i = state->next_dc; i < limit; i++) {
        DEBUG(SSSDBG_TRACE_ALL, "Batch %d: %s:%d\n", state->batch,
              state->dc_list[i].host, state->dc_list[i].port);
    }

    for (; state->next_dc < limit; state->next_dc++) {
        subreq = ad_cldap_ping_dc_send(state->reqs_ctx, ev, state->opts,
                                       state->be_res, state->host_db,
                                       &state->dc_list[state->next_dc],
                                       state->ad_domain);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to create new ping request\n");
            goto fail;
        }

        state->active_requests++;
        tevent_req_set_callback(subreq, ad_cldap_ping_parallel_done, req);
    }

    state->batch++;
    if (delay > 0) {
        tv = tevent_timeval_current_ofs(0, delay);
        state->te = tevent_add_timer(ev, state->reqs_ctx, tv,
                                     ad_cldap_ping_parallel_batch, req);
        if (state->te == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to schedule next batch!\n");
            goto fail;
        }
    }

    return;

fail:
    if (state->active_requests == 0) {
        tevent_req_error(req, ENOMEM);
        if (state->batch == 1) {
            tevent_req_post(req, ev);
        }
    }
}

static void ad_cldap_ping_parallel_done(struct tevent_req *subreq)
{
    struct ad_cldap_ping_parallel_state *state;
    struct timeval tv = {0, 0};
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_cldap_ping_parallel_state);

    ret = ad_cldap_ping_dc_recv(state, subreq, &state->site, &state->forest);
    talloc_zfree(subreq);
    state->active_requests--;

    if (ret == EOK) {
        /* We have the answer. Terminate other attempts and finish. */
        talloc_zfree(state->reqs_ctx);
        tevent_req_done(req);
    } else if (state->active_requests == 0) {
        /* There are still servers to try, don't wait for the timer. */
        if (state->next_dc < state->dc_count) {
            talloc_zfree(state->te);
            ad_cldap_ping_parallel_batch(state->ev, NULL, tv, req);
            return;
        }
        /* There is no available server. */
        tevent_req_error(req, ENOENT);
    }

    /* Wait for another request to finish. */
}

static errno_t ad_cldap_ping_parallel_recv(TALLOC_CTX *mem_ctx,
                                           struct tevent_req *req,
                                           const char **_site,
                                           const char **_forest)
{
    struct ad_cldap_ping_parallel_state *state = NULL;
    state = tevent_req_data(req, struct ad_cldap_ping_parallel_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_site = talloc_steal(mem_ctx, state->site);
    *_forest = talloc_steal(mem_ctx, state->forest);

    return EOK;
}

struct ad_cldap_ping_domain_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct be_resolv_ctx *be_res;
    enum host_database *host_db;
    const char *ad_domain;

    struct fo_server_info *dc_list;
    size_t dc_count;
    const char *site;
    const char *forest;
};

static void ad_cldap_ping_domain_discovery_done(struct tevent_req *subreq);
static void ad_cldap_ping_domain_done(struct tevent_req *subreq);

static struct tevent_req *
ad_cldap_ping_domain_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct sdap_options *opts,
                          struct be_resolv_ctx *be_res,
                          enum host_database *host_db,
                          const char *ad_domain,
                          const char *discovery_domain)
{
    struct ad_cldap_ping_domain_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char **domains;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_cldap_ping_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->be_res = be_res;
    state->host_db = host_db;
    state->ad_domain = ad_domain;

    domains = talloc_zero_array(state, const char *, 2);
    if (domains == NULL) {
        ret = ENOMEM;
        goto done;
    }

    domains[0] = discovery_domain;
    domains[1] = NULL;
    if (domains[0] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bad argument (discovery_domain)");
        ret = ENOMEM;
        goto done;
    }

    /* Even though we use CLDAP (UDP) to perform the ping we need to discover
     * domain controllers in TCP namespace as they are not automatically
     * available under UDP. */
    subreq = fo_discover_srv_send(state, ev, be_res->resolv, "ldap",
                                  FO_PROTO_TCP, domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_cldap_ping_domain_discovery_done, req);

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ad_cldap_ping_domain_discovery_done(struct tevent_req *subreq)
{
    struct ad_cldap_ping_domain_state *state;
    struct tevent_req *req;
    char *domain;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_cldap_ping_domain_state);

    ret = fo_discover_srv_recv(state, subreq, &domain, NULL, &state->dc_list,
                               &state->dc_count);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Found %zu domain controllers in domain %s\n",
          state->dc_count, domain);

    subreq = ad_cldap_ping_parallel_send(state, state->ev, state->opts,
                                         state->be_res, state->host_db,
                                         state->dc_list, state->dc_count,
                                         state->ad_domain);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_cldap_ping_domain_done, req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
}

static void ad_cldap_ping_domain_done(struct tevent_req *subreq)
{
    struct ad_cldap_ping_domain_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_cldap_ping_domain_state);

    ret = ad_cldap_ping_parallel_recv(state, subreq, &state->site,
                                      &state->forest);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ad_cldap_ping_domain_recv(TALLOC_CTX *mem_ctx,
                                         struct tevent_req *req,
                                         const char **_site,
                                         const char **_forest)
{
    struct ad_cldap_ping_domain_state *state = NULL;
    state = tevent_req_data(req, struct ad_cldap_ping_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_site = talloc_steal(mem_ctx, state->site);
    *_forest = talloc_steal(mem_ctx, state->forest);

    return EOK;
}

struct ad_cldap_ping_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct be_resolv_ctx *be_res;
    enum host_database *host_db;
    const char *ad_domain;
    const char *discovery_domain;
    bool all_tried;

    const char *site;
    const char *forest;
};

static errno_t ad_cldap_ping_step(struct tevent_req *req,
                                  const char *domain);
static void ad_cldap_ping_done(struct tevent_req *subreq);

struct tevent_req *ad_cldap_ping_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct ad_srv_plugin_ctx *srv_ctx,
                                      const char *discovery_domain)
{
    struct ad_cldap_ping_state *state;
    struct tevent_req *req;
    const char *domain;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_cldap_ping_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (!srv_ctx->renew_site) {
        state->site = talloc_strdup(state, srv_ctx->ad_options->current_site);
        state->forest = talloc_strdup(state,
                                      srv_ctx->ad_options->current_forest);
        if ((srv_ctx->ad_options->current_site != NULL && state->site == NULL)
                || (srv_ctx->ad_options->current_forest != NULL
                                    && state->forest == NULL)) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to copy current site or forest name.\n");
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "CLDAP ping is not necessary, using site '%s' and forest '%s'\n",
              state->site != NULL ? state->site : "unknown",
              state->forest != NULL ? state->forest : "unknown");
        ret = EOK;
        goto done;
    }

    if (strcmp(srv_ctx->ad_domain, discovery_domain) != 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Trying to discover domain [%s] "
              "which is not our local domain [%s], skipping CLDAP ping.\n",
              discovery_domain, srv_ctx->ad_domain);
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Sending CLDAP ping\n");

    state->ev = ev;
    state->opts = srv_ctx->opts;
    state->be_res = srv_ctx->be_res;
    state->host_db = srv_ctx->host_dbs;
    state->ad_domain = srv_ctx->ad_domain;
    state->discovery_domain = discovery_domain;

    /* If possible, lookup the information in the current site first. */
    if (srv_ctx->ad_options->current_site != NULL) {
        state->all_tried = false;
        domain = ad_site_dns_discovery_domain(state,
                                              srv_ctx->ad_options->current_site,
                                              discovery_domain);
        if (domain == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!");
            ret = ENOMEM;
            goto done;
        }
    } else {
        state->all_tried = true;
        domain = discovery_domain;
    }

    ret = ad_cldap_ping_step(req, domain);
    if (ret != EOK) {
        goto done;
    }

    return req;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t ad_cldap_ping_step(struct tevent_req *req,
                                  const char *domain)
{
    struct ad_cldap_ping_state *state;
    struct tevent_req *subreq;
    struct timeval tv;
    int timeout;

    state = tevent_req_data(req, struct ad_cldap_ping_state);

    subreq = ad_cldap_ping_domain_send(state, state->ev, state->opts,
                                       state->be_res, state->host_db,
                                       state->ad_domain, domain);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ad_cldap_ping_done, req);

    timeout = dp_opt_get_int(state->be_res->opts,
                             DP_RES_OPT_RESOLVER_OP_TIMEOUT);
    if (timeout > 0) {
        tv = tevent_timeval_current_ofs(timeout, 0);
        tevent_req_set_endtime(subreq, state->ev, tv);
    }

    return EOK;
}

static void ad_cldap_ping_done(struct tevent_req *subreq)
{
    struct ad_cldap_ping_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_cldap_ping_state);

    ret = ad_cldap_ping_domain_recv(state, subreq, &state->site,
                                    &state->forest);
    talloc_zfree(subreq);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Found site: %s\n", state->site);
        DEBUG(SSSDBG_TRACE_FUNC, "Found forest: %s\n", state->forest);
        tevent_req_done(req);
        return;
    }

    if (!state->all_tried) {
        state->all_tried = true;
        ret = ad_cldap_ping_step(req, state->discovery_domain);
        if (ret == EOK) {
            return;
        }
    }

    DEBUG(SSSDBG_OP_FAILURE,
          "Unable to get site and forest information [%d]: %s\n",
          ret, sss_strerror(ret));

    tevent_req_error(req, ret);
}

errno_t ad_cldap_ping_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           const char **_site,
                           const char **_forest)
{
    struct ad_cldap_ping_state *state = NULL;
    state = tevent_req_data(req, struct ad_cldap_ping_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_site = talloc_steal(mem_ctx, state->site);
    *_forest = talloc_steal(mem_ctx, state->forest);

    return EOK;
}
