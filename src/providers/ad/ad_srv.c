/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#define AD_SITE_DOMAIN_FMT "%s._sites.%s"

char *ad_site_dns_discovery_domain(TALLOC_CTX *mem_ctx,
                                   const char *site,
                                   const char *domain)
{
    return talloc_asprintf(mem_ctx, AD_SITE_DOMAIN_FMT, site, domain);
}

static errno_t ad_sort_servers_by_dns(TALLOC_CTX *mem_ctx,
                                      const char *domain,
                                      struct fo_server_info **_srv,
                                      size_t num)
{
    struct fo_server_info *out = NULL;
    struct fo_server_info *srv = NULL;
    struct fo_server_info in_domain[num];
    struct fo_server_info out_domain[num];
    size_t srv_index = 0;
    size_t in_index = 0;
    size_t out_index = 0;
    size_t i, j;

    if (_srv == NULL) {
        return EINVAL;
    }

    srv = *_srv;

    if (num <= 1) {
        return EOK;
    }

    out = talloc_zero_array(mem_ctx, struct fo_server_info, num);
    if (out == NULL) {
        return ENOMEM;
    }

    /* When several servers share priority, we will prefer the one that
     * is located in the same domain as client (e.g. child domain instead
     * of forest root) but obey their weight. We will use the fact that
     * the servers are already sorted by priority. */

    for (i = 0; i < num; i++) {
        if (is_host_in_domain(srv[i].host, domain)) {
            /* this is a preferred server, push it to the in domain list */
            in_domain[in_index] = srv[i];
            in_index++;
        } else {
            /* this is a normal server, push it to the out domain list */
            out_domain[out_index] = srv[i];
            out_index++;
        }

        if (i + 1 == num || srv[i].priority != srv[i + 1].priority) {
            /* priority has changed or we have reached the end of the srv list,
             * we will merge the list into final list and start over with
             * next priority */
            for (j = 0; j < in_index; j++) {
                out[srv_index] = in_domain[j];
                talloc_steal(out, out[srv_index].host);
                srv_index++;
            }

            for (j = 0; j < out_index; j++) {
                out[srv_index] = out_domain[j];
                talloc_steal(out, out[srv_index].host);
                srv_index++;
            }

            in_index = 0;
            out_index = 0;
        }
    }

    talloc_free(*_srv);
    *_srv = out;
    return EOK;
}

static void ad_srv_mark_renew_site(void *pvt)
{
    struct ad_srv_plugin_ctx *ctx;

    ctx = talloc_get_type(pvt, struct ad_srv_plugin_ctx);
    ctx->renew_site = true;
}

struct ad_srv_plugin_ctx *
ad_srv_plugin_ctx_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct be_resolv_ctx *be_res,
                       enum host_database *host_dbs,
                       struct sdap_options *opts,
                       struct ad_options *ad_options,
                       const char *hostname,
                       const char *ad_domain,
                       const char *ad_site_override)
{
    struct ad_srv_plugin_ctx *ctx = NULL;
    errno_t ret;

    ctx = talloc_zero(mem_ctx, struct ad_srv_plugin_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->be_ctx = be_ctx;
    ctx->be_res = be_res;
    ctx->host_dbs = host_dbs;
    ctx->opts = opts;
    ctx->renew_site = true;
    ctx->ad_options = ad_options;

    ctx->hostname = talloc_strdup(ctx, hostname);
    if (ctx->hostname == NULL) {
        goto fail;
    }

    ctx->ad_domain = talloc_strdup(ctx, ad_domain);
    if (ctx->ad_domain == NULL) {
        goto fail;
    }

    if (ad_site_override != NULL) {
        ctx->ad_site_override = talloc_strdup(ctx, ad_site_override);
        if (ctx->ad_site_override == NULL) {
            goto fail;
        }

        ctx->ad_options->current_site = talloc_strdup(ctx->ad_options,
                                                      ad_site_override);
        if (ctx->ad_options->current_site == NULL) {
            goto fail;
        }
    } else {
        ret = sysdb_get_site(ctx->ad_options, be_ctx->domain,
                             &ctx->ad_options->current_site);
        if (ret != EOK) {
            /* Not fatal. */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unable to get current site from cache [%d]: %s\n",
                  ret, sss_strerror(ret));
            ctx->ad_options->current_site = NULL;
        }
    }

    ret = be_add_offline_cb(ctx, be_ctx, ad_srv_mark_renew_site, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_add_offline_cb failed.\n");
        goto fail;
    }

    return ctx;

fail:
    talloc_free(ctx);
    return NULL;
}

struct ad_srv_plugin_state {
    struct tevent_context *ev;
    struct ad_srv_plugin_ctx *ctx;
    const char *service;
    const char *protocol;
    const char *discovery_domain;

    const char *site;
    char *dns_domain;
    uint32_t ttl;
    const char *forest;
    struct fo_server_info *primary_servers;
    size_t num_primary_servers;
    struct fo_server_info *backup_servers;
    size_t num_backup_servers;
};

static void ad_srv_plugin_ping_done(struct tevent_req *subreq);
static void ad_srv_plugin_servers_done(struct tevent_req *subreq);

/* 1. Do a DNS lookup to find any DC in domain
 *    _ldap._tcp.domain.name
 * 2. Send a CLDAP ping to the found DC to get the desirable site
 * 3. Do a DNS lookup to find SRV in the site (a)
 *    _service._protocol.site-name._sites.domain.name
 * 4. Do a DNS lookup to find global SRV records (b)
 *    _service._protocol.domain.name
 * 5. If the site is found, use (a) as primary and (b) as backup servers,
 *    otherwise use (b) as primary servers
 */
struct tevent_req *ad_srv_plugin_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       const char *service,
                                       const char *protocol,
                                       const char *discovery_domain,
                                       void *pvt)
{
    struct ad_srv_plugin_state *state = NULL;
    struct ad_srv_plugin_ctx *ctx = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_srv_plugin_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    ctx = talloc_get_type(pvt, struct ad_srv_plugin_ctx);
    if (ctx == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->ev = ev;
    state->ctx = ctx;

    state->service = talloc_strdup(state, service);
    if (state->service == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->protocol = talloc_strdup(state, protocol);
    if (state->protocol == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (discovery_domain != NULL) {
        state->discovery_domain = talloc_strdup(state, discovery_domain);
    } else {
        state->discovery_domain = talloc_strdup(state, ctx->ad_domain);
    }
    if (state->discovery_domain == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    subreq = ad_cldap_ping_send(state, ev, state->ctx, state->discovery_domain);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_srv_plugin_ping_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ad_srv_plugin_ping_done(struct tevent_req *subreq)
{
    struct ad_srv_plugin_state *state = NULL;
    struct tevent_req *req = NULL;
    const char *primary_domain = NULL;
    const char *backup_domain = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_srv_plugin_state);

    ret = ad_cldap_ping_recv(state, subreq, &state->site, &state->forest);
    talloc_zfree(subreq);

    /* Ignore AD site found by dns discovery if specific site is set in
     * configuration file. */
    if (state->ctx->ad_site_override != NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Ignoring AD site found by DNS discovery: '%s', "
              "using configured value: '%s' instead.\n",
              state->site, state->ctx->ad_site_override);
        state->site = state->ctx->ad_site_override;

        if (state->forest == NULL) {
            DEBUG(SSSDBG_TRACE_FUNC, "Missing forest information, using %s\n",
                  state->discovery_domain);
            state->forest = state->discovery_domain;
        }

        ret = EOK;
    }

    primary_domain = state->discovery_domain;
    backup_domain = NULL;

    if (ret == EOK) {
        /* Remember current site so it can be used during next lookup so
         * we can contact directory controllers within a known reachable
         * site first. */
        if (state->site != NULL) {
            ret = ad_options_switch_site(state->ctx->ad_options,
                                         state->ctx->be_ctx,
                                         state->site, state->forest);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set site [%d]: %s\n",
                      ret, sss_strerror(ret));
                goto done;
            }

            /* Do not renew the site again unless we go offline. */
            state->ctx->renew_site = false;
        }

        if (strcmp(state->service, "gc") == 0) {
            if (state->forest != NULL) {
                if (state->site != NULL) {
                    primary_domain = ad_site_dns_discovery_domain(
                                                            state,
                                                            state->site,
                                                            state->forest);
                    if (primary_domain == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }

                    backup_domain = state->forest;
                } else {
                    primary_domain = state->forest;
                    backup_domain = NULL;
                }
            }
        } else {
            if (state->site != NULL) {
                primary_domain = ad_site_dns_discovery_domain(
                                                 state,
                                                 state->site,
                                                 state->discovery_domain);
                if (primary_domain == NULL) {
                    ret = ENOMEM;
                    goto done;
                }

                backup_domain = state->discovery_domain;
            }
        }
    } else if (ret != ENOENT && ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "About to discover primary and "
                              "backup servers\n");

    subreq = fo_discover_servers_send(state, state->ev,
                                      state->ctx->be_res->resolv,
                                      state->service, state->protocol,
                                      primary_domain, backup_domain);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_srv_plugin_servers_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void ad_srv_plugin_servers_done(struct tevent_req *subreq)
{
    struct ad_srv_plugin_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_srv_plugin_state);

    ret = fo_discover_servers_recv(state, subreq, &state->dns_domain,
                                   &state->ttl,
                                   &state->primary_servers,
                                   &state->num_primary_servers,
                                   &state->backup_servers,
                                   &state->num_backup_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got %zu primary and %zu backup servers\n",
          state->num_primary_servers, state->num_backup_servers);

    ret = ad_sort_servers_by_dns(state, state->discovery_domain,
                                 &state->primary_servers,
                                 state->num_primary_servers);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to sort primary servers by DNS"
                                     "[%d]: %s\n", ret, sss_strerror(ret));
        /* continue */
    }

    ret = ad_sort_servers_by_dns(state, state->discovery_domain,
                                 &state->backup_servers,
                                 state->num_backup_servers);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to sort backup servers by DNS"
                                     "[%d]: %s\n", ret, sss_strerror(ret));
        /* continue */
    }

    tevent_req_done(req);
}

errno_t ad_srv_plugin_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           char **_dns_domain,
                           uint32_t *_ttl,
                           struct fo_server_info **_primary_servers,
                           size_t *_num_primary_servers,
                           struct fo_server_info **_backup_servers,
                           size_t *_num_backup_servers)
{
    struct ad_srv_plugin_state *state = NULL;
    state = tevent_req_data(req, struct ad_srv_plugin_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_primary_servers) {
        *_primary_servers = talloc_steal(mem_ctx, state->primary_servers);
    }

    if (_num_primary_servers) {
        *_num_primary_servers = state->num_primary_servers;
    }

    if (_backup_servers) {
        *_backup_servers = talloc_steal(mem_ctx, state->backup_servers);
    }

    if (_num_backup_servers) {
        *_num_backup_servers = state->num_backup_servers;
    }

    if (_dns_domain) {
        *_dns_domain = talloc_steal(mem_ctx, state->dns_domain);
    }

    if (_ttl) {
        *_ttl = state->ttl;
    }

    return EOK;
}
