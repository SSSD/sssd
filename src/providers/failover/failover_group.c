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

#include "config.h"
#include "providers/failover/failover_group.h"
#include "providers/failover/failover_server.h"
#include "providers/failover/failover_srv.h"
#include "providers/failover/failover.h"
#include "util/util.h"

static errno_t
sss_failover_group_allocate_slot(struct sss_failover_ctx *fctx,
                                 unsigned int *_slot)
{
    size_t count;
    unsigned int slot;

    count = talloc_array_length(fctx->groups);

    for (slot = 0; fctx->groups[slot] != NULL && slot < count; slot++) {
        /* Find the first NULL slot. slot < count is just for safety */
    }

    /* We need to allocate more items? */
    if (slot >= count - 1) {
        fctx->groups = talloc_realloc(fctx, fctx->groups,
                                      struct sss_failover_group *, count + 1);
        if (fctx->groups == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            return ENOMEM;
        }

        fctx->groups[count] = NULL;
        fctx->groups[count - 1] = NULL;
        slot = count - 1;
    }

    *_slot = slot;

    return EOK;
}

struct sss_failover_group *
sss_failover_group_new(struct sss_failover_ctx *fctx,
                       const char *name)
{
    struct sss_failover_group *group;
    unsigned int slot;
    errno_t ret;

    if (name == NULL || fctx == NULL || fctx->groups == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid parameters!\n");
        return NULL;
    }

    ret = sss_failover_group_allocate_slot(fctx, &slot);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to allocate slot [%d]: %s\n", ret,
              sss_strerror(ret));
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Creating failover group %s:%u\n", name, slot);

    group = talloc_zero(fctx->groups, struct sss_failover_group);
    if (group == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    group->name = talloc_strdup(group, name);
    if (group->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    group->slot = slot;

    group->configured_servers = talloc_zero_array(group, struct sss_failover_server *, 1);
    if (group->configured_servers == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        goto done;
    }

    group->dns_discovery_enabled = false;
    group->discovered_servers = talloc_zero_array(group, struct sss_failover_server *, 1);
    if (group->discovered_servers == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        goto done;
    }

    group->servers = talloc_zero_array(group, struct sss_failover_server *, 1);
    if (group->servers == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        goto done;
    }

    fctx->groups[slot] = group;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(group);
        return NULL;
    }

    return group;
}

errno_t
sss_failover_group_setup_dns_discovery(struct sss_failover_group *group)
{
    group->dns_discovery_enabled = true;

    return EOK;
}

errno_t
sss_failover_group_add_server(struct sss_failover_group *group,
                              struct sss_failover_server *server)
{
    struct sss_failover_server **new_array;
    size_t count;

    if (group == NULL || group->configured_servers == NULL || server == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid arguments\n");
        return EINVAL;
    }

    count = talloc_array_length(group->configured_servers);

    new_array = talloc_realloc(group, group->configured_servers,
                               struct sss_failover_server *, count + 1);
    if (new_array == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    group->configured_servers = new_array;
    group->configured_servers[count - 1] = talloc_steal(group->configured_servers, server);
    group->configured_servers[count] = NULL;

    return EOK;
}

struct sss_failover_group_resolve_state {
    struct sss_failover_ctx *fctx;
    struct sss_failover_group *group;
};

static void sss_failover_group_resolve_done(struct tevent_req *subreq);

struct tevent_req *
sss_failover_group_resolve_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct sss_failover_ctx *fctx,
                                struct sss_failover_group *group)
{
    struct sss_failover_group_resolve_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;
    time_t now;

    DEBUG(SSSDBG_TRACE_FUNC, "Resolving server group %s:%d\n", group->name,
          group->slot);

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_group_resolve_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->fctx = fctx;
    state->group = group;

    now = time(NULL);
    if (group->dns_discovery_enabled && group->dns_expiration_time < now) {
        /* Refresh SRV records. */
        const char *domains[] = {"ldap.test", NULL};
        const char *protocol = "tcp";
        const char *service = "ldap";

        // TODO handle protocol, service, domains and plugin
        subreq = sss_failover_srv_resolve_send(state, ev, fctx, service,
                                               protocol, domains);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, sss_failover_group_resolve_done, req);

        ret = EAGAIN;
    } else {
        /* We have what we need. */
        ret = EOK;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sss_failover_group_resolve_done(struct tevent_req *subreq)
{
    struct sss_failover_group_resolve_state *state;
    struct sss_failover_server **servers;
    struct tevent_req *req;
    uint32_t ttl;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_group_resolve_state);

    ret = sss_failover_srv_resolve_recv(state, subreq, &ttl,
                                        &servers);
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        ttl = state->fctx->opts.negative_dns_srv_ttl;
        servers = talloc_zero_array(state, struct sss_failover_server *, 1);
        if (servers == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            ret = ENOMEM;
            goto done;
        }
        ret = EOK;
    } else if (ret != EOK) {
        goto done;
    }

    talloc_zfree(state->group->discovered_servers);
    state->group->discovered_servers = talloc_steal(state->group, servers);
    state->group->dns_expiration_time = time(NULL) + ttl;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sss_failover_group_resolve_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                struct sss_failover_server ***_servers)
{
    struct sss_failover_group_resolve_state *state;
    struct sss_failover_server *current;
    struct sss_failover_server **out;
    size_t count_conf;
    size_t count_dns;
    size_t count;
    int i, j, k;
    bool found;

    state = tevent_req_data(req, struct sss_failover_group_resolve_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    count_conf = talloc_array_length(state->group->configured_servers) - 1;
    count_dns = talloc_array_length(state->group->discovered_servers) - 1;
    count = count_conf + count_dns;

    DEBUG(SSSDBG_TRACE_FUNC,
          "There are %zu configured servers inside group %d:%s:\n",
          count_conf, state->group->slot, state->group->name);

    if (DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        for (i = 0; state->group->configured_servers[i] != NULL; i++) {
            current = state->group->configured_servers[i];
            DEBUG(SSSDBG_TRACE_ALL, "- %s:%u\n", current->name, current->port);
        }
    }

    if (state->group->dns_discovery_enabled) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Discovered %zu servers from DNS inside group %d:%s:\n",
              count_dns, state->group->slot, state->group->name);

        if (DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
            for (i = 0; state->group->discovered_servers[i] != NULL; i++) {
                current = state->group->discovered_servers[i];
                DEBUG(SSSDBG_TRACE_ALL, "- %s:%u\n", current->name,
                      current->port);
            }
        }
    }

    out = talloc_zero_array(mem_ctx, struct sss_failover_server *, count + 1);
    if (out == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    /* Add configured servers first. */
    for (i = 0; state->group->configured_servers[i] != NULL; i++) {
        out[i] = talloc_reference(out, state->group->configured_servers[i]);
        if (out[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            talloc_free(out);
            return ENOMEM;
        }
    }

    /* Now add discovered servers. But avoid adding duplicates. */
    for (j = 0; state->group->discovered_servers[j] != NULL; j++, i++) {
        found = false;
        current = state->group->discovered_servers[j];
        for (k = 0; out[k] != NULL; k++) {
            if (sss_failover_server_equal(out[k], current)) {
                found = true;
                break;
            }
        }

        if (found) {
            break;
        }

        out[i] = talloc_reference(out, current);
        if (out[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            talloc_free(out);
            return ENOMEM;
        }
    }


    // TODO sort by priority and weight

    for (count = 0; out[count] != NULL; count++);
    out = talloc_realloc(mem_ctx, out, struct sss_failover_server *, count + 1);
    if (out == NULL) {
        talloc_free(out);
        return ENOMEM;
    }

    if (DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        DEBUG(SSSDBG_TRACE_ALL, "Sorted server list without duplicates:\n");
        for (i = 0; out[i] != NULL; i++) {
            DEBUG(SSSDBG_TRACE_ALL, "- %s:%u\n", out[i]->name, out[i]->port);
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Returning %zu servers from group %d:%s\n", count,
          state->group->slot, state->group->name);

    *_servers = out;

    return EOK;
}
