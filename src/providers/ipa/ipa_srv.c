/*
    Authors:
        Pavel B??ezina <pbrezina@redhat.com>

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

#include "util/util.h"
#include "resolv/async_resolv.h"
#include "providers/fail_over_srv.h"

#define IPA_DNS_LOCATION "_location"

struct ipa_srv_plugin_ctx {
    struct resolv_ctx *resolv_ctx;
    const char *hostname;
    const char *ipa_domain;
};

struct ipa_srv_plugin_ctx *
ipa_srv_plugin_ctx_init(TALLOC_CTX *mem_ctx,
                        struct resolv_ctx *resolv_ctx,
                        const char *hostname,
                        const char *ipa_domain)
{
    struct ipa_srv_plugin_ctx *ctx = NULL;

    ctx = talloc_zero(mem_ctx, struct ipa_srv_plugin_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->resolv_ctx = resolv_ctx;

    ctx->hostname = talloc_strdup(ctx, hostname);
    if (ctx->hostname == NULL) {
        goto fail;
    }

    ctx->ipa_domain = talloc_strdup(ctx, ipa_domain);
    if (ctx->ipa_domain == NULL) {
        goto fail;
    }

    return ctx;

fail:
    talloc_free(ctx);
    return NULL;
}

struct ipa_srv_plugin_state {
    struct tevent_context *ev;
    struct ipa_srv_plugin_ctx *ctx;
    const char *service;
    const char *protocol;
    const char *discovery_domain;

    char *dns_domain;
    struct fo_server_info *primary_servers;
    size_t num_primary_servers;
    struct fo_server_info *backup_servers;
    size_t num_backup_servers;
};

static void ipa_srv_plugin_primary_done(struct tevent_req *subreq);
static void ipa_srv_plugin_backup_done(struct tevent_req *subreq);

/* If IPA server supports sites, we will use
 * _locations.hostname.discovery_domain for primary servers and
 * discovery_domain for backup servers. If the server does not support sites or
 * client's SRV record is not found, we will use the latter for primary
 * servers, setting backup servers to NULL */
struct tevent_req *ipa_srv_plugin_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       const char *service,
                                       const char *protocol,
                                       const char *discovery_domain,
                                       void *pvt)
{
    struct ipa_srv_plugin_state *state = NULL;
    struct ipa_srv_plugin_ctx *ctx = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    const char **domains = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_srv_plugin_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    ctx = talloc_get_type(pvt, struct ipa_srv_plugin_ctx);
    if (ctx == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->ev = ev;
    state->ctx = ctx;
    state->service = service;
    state->protocol = protocol;

    if (discovery_domain != NULL) {
        state->discovery_domain = discovery_domain;
    } else {
        state->discovery_domain = ctx->ipa_domain;
    }
    if (state->discovery_domain == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Looking up primary servers\n"));

    domains = talloc_zero_array(state, const char *, 3);
    if (domains == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (strchr(ctx->hostname, '.') == NULL) {
        /* not FQDN, append domain name */
        domains[0] = talloc_asprintf(domains, IPA_DNS_LOCATION ".%s.%s",
                                     ctx->hostname, state->discovery_domain);
    } else {
        domains[0] = talloc_asprintf(domains, IPA_DNS_LOCATION ".%s",
                                     ctx->hostname);
    }
    if (domains[0] == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    domains[1] = state->discovery_domain;

    subreq = fo_discover_srv_send(state, ev, ctx->resolv_ctx,
                                  state->service, state->protocol, domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_srv_plugin_primary_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ipa_srv_plugin_primary_done(struct tevent_req *subreq)
{
    struct ipa_srv_plugin_state *state = NULL;
    struct tevent_req *req = NULL;
    const char **domains = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_srv_plugin_state);

    ret = fo_discover_srv_recv(state, subreq,
                               &state->dns_domain,
                               &state->primary_servers,
                               &state->num_primary_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    if (strcmp(state->dns_domain, state->discovery_domain) == 0) {
        /* IPA server does not support sites or this host is in default site */
        state->backup_servers = NULL;
        state->num_backup_servers = 0;

        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Looking up backup servers\n"));

    domains = talloc_zero_array(state, const char *, 3);
    if (domains == NULL) {
        ret = ENOMEM;
        goto done;
    }

    domains[0] = state->discovery_domain;

    subreq = fo_discover_srv_send(state, state->ev, state->ctx->resolv_ctx,
                                  state->service, state->protocol, domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_srv_plugin_backup_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void ipa_srv_plugin_backup_done(struct tevent_req *subreq)
{
    struct ipa_srv_plugin_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_srv_plugin_state);

    ret = fo_discover_srv_recv(state, subreq, NULL,
                               &state->backup_servers,
                               &state->num_backup_servers);
    talloc_zfree(subreq);
    if (ret == ERR_SRV_NOT_FOUND || ret == ERR_SRV_LOOKUP_ERROR) {
        /* we have successfully fetched primary servers, so we will
         * finish the request normally */
        DEBUG(SSSDBG_MINOR_FAILURE, ("Unable to retrieve backup servers "
                                     "[%d]: %s\n", ret, sss_strerror(ret)));
        ret = EOK;
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t ipa_srv_plugin_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            char **_dns_domain,
                            struct fo_server_info **_primary_servers,
                            size_t *_num_primary_servers,
                            struct fo_server_info **_backup_servers,
                            size_t *_num_backup_servers)
{
    struct ipa_srv_plugin_state *state = NULL;
    state = tevent_req_data(req, struct ipa_srv_plugin_state);

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


    return EOK;
}
