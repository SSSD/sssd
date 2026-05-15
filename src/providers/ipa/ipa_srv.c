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

#include "util/util.h"
#include "resolv/async_resolv.h"
#include "providers/fail_over_srv.h"
#include "providers/ipa/ipa_srv.h"

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
    char *dns_domain;
    uint32_t ttl;
    struct fo_server_info *primary_servers;
    size_t num_primary_servers;
    struct fo_server_info *backup_servers;
    size_t num_backup_servers;
};

static void ipa_srv_plugin_done(struct tevent_req *subreq);

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
    const char *primary_domain = NULL;
    const char *backup_domain = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_srv_plugin_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    ctx = talloc_get_type(pvt, struct ipa_srv_plugin_ctx);
    if (ctx == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    if (discovery_domain != NULL) {
        backup_domain = talloc_strdup(state, discovery_domain);
    } else {
        backup_domain = talloc_strdup(state, ctx->ipa_domain);
    }
    if (backup_domain == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (strchr(ctx->hostname, '.') == NULL) {
        /* not FQDN, append domain name */
        primary_domain = talloc_asprintf(state, IPA_DNS_LOCATION ".%s.%s",
                                         ctx->hostname, backup_domain);
    } else {
        primary_domain = talloc_asprintf(state, IPA_DNS_LOCATION ".%s",
                                         ctx->hostname);
    }
    if (primary_domain == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "About to discover primary and "
                              "backup servers\n");

    subreq = fo_discover_servers_send(state, ev, ctx->resolv_ctx, service,
                                      protocol, primary_domain, backup_domain);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_srv_plugin_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ipa_srv_plugin_done(struct tevent_req *subreq)
{
    struct ipa_srv_plugin_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_srv_plugin_state);

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

    tevent_req_done(req);
}

errno_t ipa_srv_plugin_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            char **_dns_domain,
                            uint32_t *_ttl,
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

    if (_ttl) {
        *_ttl = state->ttl;
    }

    return EOK;
}
