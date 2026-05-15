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
#include <unistd.h>
#include <limits.h>

#include "util/util.h"
#include "resolv/async_resolv.h"

struct resolv_get_domain_state {
    char *fqdn;
    char *hostname;
};

static void resolv_get_domain_done(struct tevent_req *subreq);

struct tevent_req *
resolv_get_domain_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct resolv_ctx *resolv_ctx,
                        const char *hostname,
                        enum host_database *host_dbs,
                        enum restrict_family family_order)
{
    struct resolv_get_domain_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    char system_hostname[HOST_NAME_MAX + 1];
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct resolv_get_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (hostname == NULL) {
        /* use system hostname */
        ret = gethostname(system_hostname, sizeof(system_hostname));
        if (ret) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "gethostname() failed: [%d]: %s\n",
                                        ret, strerror(ret));
            goto immediately;
        }
        system_hostname[HOST_NAME_MAX] = '\0';
        hostname = system_hostname;
    }

    state->fqdn = NULL;
    state->hostname = talloc_strdup(state, hostname);
    if (state->hostname == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Host name is: %s\n", state->hostname);

    subreq = resolv_gethostbyname_send(state, ev, resolv_ctx, state->hostname,
                                       family_order, host_dbs);
    if (subreq == NULL) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, resolv_get_domain_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void resolv_get_domain_done(struct tevent_req *subreq)
{
    struct resolv_get_domain_state *state = NULL;
    struct tevent_req *req = NULL;
    struct resolv_hostent *rhostent;
    int resolv_status;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct resolv_get_domain_state);

    ret = resolv_gethostbyname_recv(subreq, req, &resolv_status,
                                    NULL, &rhostent);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not get fully qualified name for host name %s "
               "error [%d]: %s, resolver returned: [%d]: %s\n",
               state->hostname, ret, strerror(ret), resolv_status,
               resolv_strerror(resolv_status));
        state->fqdn = state->hostname;
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "The FQDN is: %s\n", rhostent->name);
        state->fqdn = talloc_steal(state, rhostent->name);
        talloc_zfree(rhostent);
    }

    tevent_req_done(req);
}

errno_t resolv_get_domain_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               char **_dns_domain)
{
    struct resolv_get_domain_state *state = NULL;
    char *dns_domain = NULL;
    char *domptr = NULL;

    state = tevent_req_data(req, struct resolv_get_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    domptr = strchr(state->fqdn, '.');
    if (domptr == NULL || (*(domptr+1) == '\0')) {
        /* If the FQDN did not contain a dot or the dot was the last character
         * (broken DNS server perhaps) */
        dns_domain = state->fqdn;
    } else {
        dns_domain = domptr + 1;
    }

    *_dns_domain = talloc_strdup(mem_ctx, dns_domain);
    if (*_dns_domain == NULL) {
        return ENOMEM;
    }

    return EOK;
}

struct resolv_discover_srv_state {
    struct tevent_context *ev;
    struct resolv_ctx *resolv_ctx;
    const char *service;
    const char *protocol;
    const char **discovery_domains;
    int domain_index;

    struct ares_srv_reply *reply_list;
    uint32_t ttl;
};

static errno_t resolv_discover_srv_next_domain(struct tevent_req *req);
static void resolv_discover_srv_done(struct tevent_req *subreq);

struct tevent_req *resolv_discover_srv_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct resolv_ctx *resolv_ctx,
                                            const char *service,
                                            const char *protocol,
                                            const char **discovery_domains)
{
    struct resolv_discover_srv_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct resolv_discover_srv_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (resolv_ctx == NULL || service == NULL || protocol == NULL
        || discovery_domains == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->ev = ev;
    state->resolv_ctx = resolv_ctx;
    state->discovery_domains = discovery_domains;
    state->service = service;
    state->protocol = protocol;
    state->domain_index = 0;

    ret = resolv_discover_srv_next_domain(req);
    if (ret != EAGAIN) {
        goto immediately;
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

static errno_t resolv_discover_srv_next_domain(struct tevent_req *req)
{
    struct resolv_discover_srv_state *state = NULL;
    struct tevent_req *subreq = NULL;
    const char *domain = NULL;
    char *query = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct resolv_discover_srv_state);

    domain = state->discovery_domains[state->domain_index];
    if (domain == NULL) {
        ret = EOK;
        goto done;
    }

    query = talloc_asprintf(state, "_%s._%s.%s", state->service,
                            state->protocol, domain);
    if (query == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "SRV resolution of service '%s'. Will use DNS "
          "discovery domain '%s'\n", state->service, domain);

    subreq = resolv_getsrv_send(state, state->ev,
                                state->resolv_ctx, query);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, resolv_discover_srv_done, req);

    state->domain_index++;
    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        talloc_free(query);
    }

    return ret;
}

static void resolv_discover_srv_done(struct tevent_req *subreq)
{
    struct resolv_discover_srv_state *state = NULL;
    struct tevent_req *req = NULL;
    int status;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct resolv_discover_srv_state);

    ret = resolv_getsrv_recv(state, subreq, &status, NULL,
                             &state->reply_list, &state->ttl);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "SRV query failed [%d]: %s\n",
                                  status, resolv_strerror(status));

        if (status == ARES_ENOTFOUND) {
            /* continue with next discovery domain */
            ret = resolv_discover_srv_next_domain(req);
            if (ret == EOK) {
                /* there are no more domains to try */
                ret = ENOENT;
            }

            goto done;
        }

        /* critical error when fetching SRV record */
        ret = EIO;
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

errno_t resolv_discover_srv_recv(TALLOC_CTX *mem_ctx,
                                 struct tevent_req *req,
                                 struct ares_srv_reply **_reply_list,
                                 uint32_t *_ttl,
                                 char **_dns_domain)
{
    struct resolv_discover_srv_state *state = NULL;
    char *domain = NULL;

    state = tevent_req_data(req, struct resolv_discover_srv_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_dns_domain != NULL) {
        /* domain_index now points to selected domain + 1 */
        domain = talloc_strdup(mem_ctx,
                           state->discovery_domains[state->domain_index - 1]);
        if (domain == NULL) {
            return ENOMEM;
        }

        *_dns_domain = domain;
    }

    if (_reply_list != NULL) {
        *_reply_list = talloc_steal(mem_ctx, state->reply_list);
    }

    if (_ttl != NULL) {
        *_ttl = state->ttl;
    }

    return EOK;
}
