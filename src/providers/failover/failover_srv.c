/*
    Copyright (C) 2025 Red Hat

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

#include <ares.h>
#include <arpa/inet.h>
#include <talloc.h>
#include <time.h>

#include "config.h"
#include "providers/failover/failover.h"
#include "providers/failover/failover_server.h"
#include "resolv/async_resolv.h"
#include "util/util.h"

struct sss_failover_resolve_srv_state {
    struct sss_failover_server **servers;
    char *final_discovery_domain;
    uint32_t ttl;
};

static void sss_failover_resolve_srv_done(struct tevent_req *subreq);

struct tevent_req *
sss_failover_srv_resolve_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct sss_failover_ctx *fctx,
                              const char *service,
                              const char *protocol,
                              const char * const * discovery_domains)
{
    struct sss_failover_resolve_srv_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char **domains_dup;
    size_t count;
    size_t i;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_resolve_srv_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    for (count = 0; discovery_domains[count] != NULL; count++);
    domains_dup = talloc_zero_array(state, const char *, count + 1);
    for (i = 0; discovery_domains[i] != NULL; i++) {
        domains_dup[i] = talloc_strdup(domains_dup, discovery_domains[i]);
        if (domains_dup[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Discovering servers for %s/%s from DNS\n",
          service, protocol);

    subreq = resolv_discover_srv_send(state, ev, fctx->resolver_ctx, service,
                                      protocol, domains_dup);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_failover_resolve_srv_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sss_failover_resolve_srv_done(struct tevent_req *subreq)
{
    struct sss_failover_resolve_srv_state *state;
    struct ares_srv_reply *reply_list;
    struct ares_srv_reply *record;
    struct tevent_req *req;
    size_t num_servers;
    errno_t ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_resolve_srv_state);

    ret = resolv_discover_srv_recv(state, subreq, &reply_list, &state->ttl,
                                   &state->final_discovery_domain);
    talloc_zfree(subreq);
    if (ret != EOK) {
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

    num_servers = 0;
    for (record = reply_list; record != NULL; record = record->next) {
        num_servers++;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got %zu servers\n", num_servers);

    state->servers = talloc_zero_array(state, struct sss_failover_server *,
                                       num_servers + 1);
    if (state->servers == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (record = reply_list, i = 0;
         record != NULL;
         record = record->next, i++) {
        // TODO handle uri
        state->servers[i] = sss_failover_server_new(
            state->servers, record->host, "ldap://master.ldap.test", record->port, record->priority,
            record->weight);
        if (state->servers[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            goto done;
        }
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

errno_t
sss_failover_srv_resolve_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              uint32_t *_ttl,
                              struct sss_failover_server ***_servers)
{
    struct sss_failover_resolve_srv_state *state;

    state = tevent_req_data(req, struct sss_failover_resolve_srv_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_servers = talloc_steal(mem_ctx, state->servers);

    return EOK;
}
