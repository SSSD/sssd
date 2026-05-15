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

#include <strings.h>
#include <talloc.h>
#include <tevent.h>

#include "util/util.h"
#include "resolv/async_resolv.h"
#include "providers/fail_over_srv.h"

struct fo_discover_srv_state {
    char *dns_domain;
    struct fo_server_info *servers;
    size_t num_servers;
    uint32_t ttl;
};

static void fo_discover_srv_done(struct tevent_req *subreq);

struct tevent_req *fo_discover_srv_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct resolv_ctx *resolv_ctx,
                                        const char *service,
                                        const char *protocol,
                                        const char **discovery_domains)
{
    struct fo_discover_srv_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct fo_discover_srv_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    subreq = resolv_discover_srv_send(state, ev, resolv_ctx, service,
                                      protocol, discovery_domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, fo_discover_srv_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void fo_discover_srv_done(struct tevent_req *subreq)
{
    struct fo_discover_srv_state *state = NULL;
    struct tevent_req *req = NULL;
    struct ares_srv_reply *reply_list = NULL;
    struct ares_srv_reply *record = NULL;
    int i;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct fo_discover_srv_state);

    ret = resolv_discover_srv_recv(state, subreq,
                                   &reply_list, &state->ttl, &state->dns_domain);
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        ret = ERR_SRV_NOT_FOUND;
        goto done;
    } else if (ret == EIO) {
        ret = ERR_SRV_LOOKUP_ERROR;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got answer. Processing...\n");

    /* sort and store the answer */
    ret = resolv_sort_srv_reply(&reply_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not sort the answers from DNS "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    state->num_servers = 0;
    for (record = reply_list; record != NULL; record = record->next) {
        state->num_servers++;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got %zu servers\n", state->num_servers);

    state->servers = talloc_array(state, struct fo_server_info,
                                  state->num_servers);
    if (state->servers == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (record = reply_list, i = 0;
         record != NULL;
         record = record->next, i++) {
        state->servers[i].host = talloc_steal(state->servers, record->host);
        state->servers[i].port = record->port;
        state->servers[i].priority = record->priority;
    }

    talloc_zfree(reply_list);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t fo_discover_srv_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             char **_dns_domain,
                             uint32_t *_ttl,
                             struct fo_server_info **_servers,
                             size_t *_num_servers)
{
    struct fo_discover_srv_state *state = NULL;
    state = tevent_req_data(req, struct fo_discover_srv_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_dns_domain != NULL) {
        *_dns_domain = talloc_steal(mem_ctx, state->dns_domain);
    }

    if (_servers != NULL) {
        *_servers = talloc_steal(mem_ctx, state->servers);
    }

    if (_ttl != NULL) {
        *_ttl = state->ttl;
    }

    if (_num_servers != NULL) {
        *_num_servers = state->num_servers;
    }

    return EOK;
}

struct fo_discover_servers_state {
    struct tevent_context *ev;
    struct resolv_ctx *resolv_ctx;
    const char *service;
    const char *protocol;
    const char *primary_domain;
    const char *backup_domain;

    char *dns_domain;
    uint32_t ttl;
    struct fo_server_info *primary_servers;
    size_t num_primary_servers;
    struct fo_server_info *backup_servers;
    size_t num_backup_servers;
};

static void fo_discover_servers_primary_done(struct tevent_req *subreq);
static void fo_discover_servers_backup_done(struct tevent_req *subreq);

struct tevent_req *fo_discover_servers_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct resolv_ctx *resolv_ctx,
                                            const char *service,
                                            const char *protocol,
                                            const char *primary_domain,
                                            const char *backup_domain)
{
    struct fo_discover_servers_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    const char **domains = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct fo_discover_servers_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (primary_domain == NULL) {
        if (backup_domain == NULL) {
            state->primary_servers = NULL;
            state->num_primary_servers = 0;
            state->backup_servers = NULL;
            state->num_backup_servers = 0;
            state->dns_domain = NULL;
            state->ttl = 0;

            ret = EOK;
            goto immediately;
        } else {
            primary_domain = backup_domain;
            backup_domain = NULL;
        }
    }

    state->ev = ev;
    state->resolv_ctx = resolv_ctx;

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

    state->primary_domain = talloc_strdup(state, primary_domain);
    if (state->primary_domain == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->backup_domain = talloc_strdup(state, backup_domain);
    if (state->backup_domain == NULL && backup_domain != NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Looking up primary servers\n");

    domains = talloc_zero_array(state, const char *, 3);
    if (domains == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    domains[0] = state->primary_domain;
    domains[1] = state->backup_domain;

    subreq = fo_discover_srv_send(state, ev, resolv_ctx,
                                  state->service, state->protocol, domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, fo_discover_servers_primary_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void fo_discover_servers_primary_done(struct tevent_req *subreq)
{
    struct fo_discover_servers_state *state = NULL;
    struct tevent_req *req = NULL;
    const char **domains = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct fo_discover_servers_state);

    ret = fo_discover_srv_recv(state, subreq,
                               &state->dns_domain,
                               &state->ttl,
                               &state->primary_servers,
                               &state->num_primary_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve primary servers "
                                  "[%d]: %s\n", ret, sss_strerror(ret));
        if (ret != ERR_SRV_NOT_FOUND && ret != ERR_SRV_LOOKUP_ERROR) {
            /* abort on system error */
            goto done;
        }
    }

    if (state->backup_domain == NULL) {
        /* if there is no backup domain, we are done */
        DEBUG(SSSDBG_TRACE_FUNC, "No backup domain specified\n");
        goto done;
    }

    if (state->dns_domain != NULL
            && strcasecmp(state->dns_domain, state->backup_domain) == 0) {
        /* If there was no error and dns_domain is the same as backup domain,
         * it means that we were unable to resolve SRV in primary domain, but
         * SRV from backup domain was resolved and those servers are considered
         * to be primary. We are done. */
        state->backup_servers = NULL;
        state->num_backup_servers = 0;

        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Looking up backup servers\n");

    domains = talloc_zero_array(state, const char *, 2);
    if (domains == NULL) {
        ret = ENOMEM;
        goto done;
    }

    domains[0] = state->backup_domain;

    subreq = fo_discover_srv_send(state, state->ev, state->resolv_ctx,
                                  state->service, state->protocol, domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, fo_discover_servers_backup_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void fo_discover_servers_backup_done(struct tevent_req *subreq)
{
    struct fo_discover_servers_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct fo_discover_servers_state);

    ret = fo_discover_srv_recv(state, subreq, NULL,
                               NULL, &state->backup_servers,
                               &state->num_backup_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to retrieve backup servers "
                                     "[%d]: %s\n", ret, sss_strerror(ret));
        if (ret == ERR_SRV_NOT_FOUND || ret == ERR_SRV_LOOKUP_ERROR) {
            /* we have successfully fetched primary servers, so we will
             * finish the request normally on non system error */
            ret = EOK;
        }
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t fo_discover_servers_recv(TALLOC_CTX *mem_ctx,
                                 struct tevent_req *req,
                                 char **_dns_domain,
                                 uint32_t *_ttl,
                                 struct fo_server_info **_primary_servers,
                                 size_t *_num_primary_servers,
                                 struct fo_server_info **_backup_servers,
                                 size_t *_num_backup_servers)
{
    struct fo_discover_servers_state *state = NULL;
    state = tevent_req_data(req, struct fo_discover_servers_state);

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

struct fo_resolve_srv_dns_ctx {
    struct resolv_ctx *resolv_ctx;
    enum restrict_family family_order;
    enum host_database *host_dbs;
    char *hostname;
    char *sssd_domain;
    char *detected_domain;
    bool last_family_tried;
};

struct fo_resolve_srv_dns_state {
    struct tevent_context *ev;
    struct fo_resolve_srv_dns_ctx *ctx;
    const char *service;
    const char *protocol;
    const char *discovery_domain;

    char *dns_domain;
    uint32_t ttl;
    struct fo_server_info *servers;
    size_t num_servers;
};

static void fo_resolve_srv_dns_domain_done(struct tevent_req *subreq);
static errno_t fo_resolve_srv_dns_discover(struct tevent_req *req);
static void fo_resolve_srv_dns_done(struct tevent_req *subreq);

struct fo_resolve_srv_dns_ctx *
fo_resolve_srv_dns_ctx_init(TALLOC_CTX *mem_ctx,
                            struct resolv_ctx *resolv_ctx,
                            enum restrict_family family_order,
                            enum host_database *host_dbs,
                            const char *hostname,
                            const char *sssd_domain)
{
    struct fo_resolve_srv_dns_ctx *ctx = NULL;

    ctx = talloc_zero(mem_ctx, struct fo_resolve_srv_dns_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->resolv_ctx = resolv_ctx;
    ctx->family_order = family_order;
    ctx->host_dbs = host_dbs;

    ctx->hostname = talloc_strdup(ctx, hostname);
    if (ctx->hostname == NULL) {
        goto fail;
    }

    ctx->sssd_domain = talloc_strdup(ctx, sssd_domain);
    if (ctx->sssd_domain == NULL) {
        goto fail;
    }

    return ctx;

fail:
    talloc_free(ctx);
    return NULL;
}

struct tevent_req *fo_resolve_srv_dns_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           const char *service,
                                           const char *protocol,
                                           const char *discovery_domain,
                                           void *pvt)
{
    struct fo_resolve_srv_dns_state *state = NULL;
    struct fo_resolve_srv_dns_ctx *ctx = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct fo_resolve_srv_dns_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    ctx = talloc_get_type(pvt, struct fo_resolve_srv_dns_ctx);
    if (ctx == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->ev = ev;
    state->ctx = ctx;
    state->service = service;
    state->protocol = protocol;

    if (discovery_domain == NULL) {
        state->discovery_domain = NULL;
    } else {
        state->discovery_domain = discovery_domain;
    }

    if (discovery_domain == NULL && ctx->detected_domain == NULL) {
        /* we will try to detect proper discovery domain */
        subreq = resolv_get_domain_send(state, state->ev, ctx->resolv_ctx,
                                        ctx->hostname, ctx->host_dbs,
                                        ctx->family_order);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto immediately;
        }

        tevent_req_set_callback(subreq, fo_resolve_srv_dns_domain_done, req);
    } else {
        /* we will use either provided or previously detected
         * discovery domain */
        ret = fo_resolve_srv_dns_discover(req);
        if (ret != EAGAIN) {
            goto immediately;
        }
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void fo_resolve_srv_dns_domain_done(struct tevent_req *subreq)
{
    struct fo_resolve_srv_dns_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct fo_resolve_srv_dns_state);

    ret = resolv_get_domain_recv(state->ctx, subreq,
                                 &state->ctx->detected_domain);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = fo_resolve_srv_dns_discover(req);

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t fo_resolve_srv_dns_discover(struct tevent_req *req)
{
    struct fo_resolve_srv_dns_state *state = NULL;
    struct fo_resolve_srv_dns_ctx *ctx = NULL;
    struct tevent_req *subreq = NULL;
    const char **domains = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct fo_resolve_srv_dns_state);
    ctx = state->ctx;

    domains = talloc_zero_array(state, const char *, 3);
    if (domains == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (state->discovery_domain == NULL) {
        /* we will use detected domain with SSSD domain as fallback */
        domains[0] = talloc_strdup(domains, ctx->detected_domain);
        if (domains[0] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (strcasecmp(ctx->detected_domain, ctx->sssd_domain) != 0) {
            domains[1] = talloc_strdup(domains, ctx->sssd_domain);
            if (domains[1] == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    } else {
        /* We will use only discovery domain that was provided via plugin
         * interface. We don't have to dup here because it is already on
         * state. */
        domains[0] = state->discovery_domain;
    }

    subreq = fo_discover_srv_send(state, state->ev, ctx->resolv_ctx,
                                  state->service, state->protocol, domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, fo_resolve_srv_dns_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        talloc_free(domains);
    }

    return ret;
}

static void fo_resolve_srv_dns_done(struct tevent_req *subreq)
{
    struct fo_resolve_srv_dns_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct fo_resolve_srv_dns_state);

    ret = fo_discover_srv_recv(state, subreq,
                               &state->dns_domain, &state->ttl,
                               &state->servers, &state->num_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t fo_resolve_srv_dns_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                char **_dns_domain,
                                uint32_t *_ttl,
                                struct fo_server_info **_primary_servers,
                                size_t *_num_primary_servers,
                                struct fo_server_info **_backup_servers,
                                size_t *_num_backup_servers)
{
    struct fo_resolve_srv_dns_state *state = NULL;
    state = tevent_req_data(req, struct fo_resolve_srv_dns_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_primary_servers) {
        *_primary_servers = talloc_steal(mem_ctx, state->servers);
    }

    if (_num_primary_servers) {
        *_num_primary_servers = state->num_servers;
    }

    /* backup servers are not supported by simple srv lookup */
    if (_backup_servers) {
        *_backup_servers = NULL;
    }

    if (_num_backup_servers) {
        *_num_backup_servers = 0;
    }

    if (_dns_domain) {
        *_dns_domain = talloc_steal(mem_ctx, state->dns_domain);
    }

    if (_ttl) {
        *_ttl = state->ttl;
    }

    return EOK;
}
