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

#include <talloc.h>
#include <tevent.h>
#include <time.h>

#include "config.h"
#include "providers/failover/failover_server.h"
#include "resolv/async_resolv.h"
#include "util/util.h"

static bool
sss_failover_server_resolve_address_changed(struct sss_failover_server *server,
                                            struct resolv_hostent *hostent)
{
    if (server->addr == NULL) {
        /* this is the first resolution */
        return true;
    }

    if (server->addr->family != hostent->family) {
        /* new address has different family */
        return true;
    }

    return memcmp(server->addr->binary, hostent->addr_list[0]->ipaddr,
                  server->addr->binary_len) == 0;
}

struct sss_failover_server_resolve_state {
    struct sss_failover_server *server;
    bool changed;
};

static void
sss_failover_server_resolve_done(struct tevent_req *subreq);

struct tevent_req *
sss_failover_server_resolve_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct resolv_ctx *resolv_ctx,
                                 enum restrict_family family_order,
                                 struct sss_failover_server *server)
{
    struct sss_failover_server_resolve_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;
    time_t now;

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_server_resolve_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->changed = false;
    state->server = talloc_reference(mem_ctx, server);
    if (state->server == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }


    now = time(NULL);
    if (state->server->addr != NULL && state->server->addr->expire > now) {
        /* Address is still valid. */
        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    subreq = resolv_gethostbyname_send(state, ev, resolv_ctx, server->name,
                                       family_order, default_host_dbs);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_failover_server_resolve_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
sss_failover_server_resolve_done(struct tevent_req *subreq)
{
    struct sss_failover_server_resolve_state *state;
    struct resolv_hostent *hostent;
    struct tevent_req *req;
    int resolv_status;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_server_resolve_state);

    ret = resolv_gethostbyname_recv(subreq, req, &resolv_status, NULL,
                                    &hostent);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (resolv_status == ARES_EFILE) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to resolve server '%s': %s [local hosts file]\n",
                  state->server->name, resolv_strerror(resolv_status));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to resolve server '%s': %s\n",
                  state->server->name, resolv_strerror(resolv_status));
        }

        tevent_req_error(req, ret);
        return;
    }

    if (hostent->addr_list == NULL || hostent->addr_list[0] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No IP address found\n");
        tevent_req_error(req, ENOENT);
        return;
    }

    /* check if address has changed */
    state->changed = sss_failover_server_resolve_address_changed(state->server,
                                                                 hostent);

    ret = sss_failover_server_set_address(state->server, hostent->family,
                                          hostent->addr_list[0]->ttl,
                                          hostent->addr_list[0]->ipaddr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set server address [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sss_failover_server_resolve_recv(struct tevent_req *req,
                                 bool *_changed)
{
    struct sss_failover_server_resolve_state *state;

    state = tevent_req_data(req, struct sss_failover_server_resolve_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_changed != NULL) {
        *_changed = state->changed;
    }

    return EOK;
}
