;/*
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

#ifndef _FAILOVER_GROUP_H_
#define _FAILOVER_GROUP_H_

#include <talloc.h>

#include "config.h"
#include "util/util.h"
#include "providers/failover/failover_server.h"

struct sss_failover_ctx;

struct sss_failover_group {
    struct sss_failover_ctx *fctx;

    /* Group name. */
    char *name;

    /* Priority. 0 = highest priority (primary servers). */
    unsigned int slot;

    /* DNS SRV plugin information */
    bool dns_discovery_enabled;
    time_t dns_expiration_time;
    void *dns_plugin_data;
    void *dns_plugin;

    /* Configured or discovered servers. */
    struct sss_failover_server **configured_servers;
    struct sss_failover_server **discovered_servers;

    /* Servers inside this group. Sorted by priority and weight. */
    struct sss_failover_server **servers;
};

/**
 * @brief Create new server group @name.
 *
 * Add new static servers to it with @sss_failover_server_group_add_server.
 *
 * @param fctx
 * @param name
 * @return struct sss_failover_group*
 */
struct sss_failover_group *
sss_failover_group_new(struct sss_failover_ctx *fctx,
                       const char *name);

/**
 * @brief Enable DNS discovery within this group.
 *
 * @param group
 * @return errno_t
 */
errno_t
sss_failover_group_setup_dns_discovery(struct sss_failover_group *group);

/**
 * @brief Add new server to the failover group.
 *
 * @param group
 * @param server
 * @return errno_t
 */
errno_t
sss_failover_group_add_server(struct sss_failover_group *group,
                                     struct sss_failover_server *server);

/**
 * @brief Resolve servers within this group.
 *
 * It does not resolve servers to IP address, it resolves the DNS SRV record
 * (if required) and combine SRV servers with those statically configured.
 *
 * @param mem_ctx
 * @param ev
 * @param fctx
 * @param group
 * @return struct tevent_req*
 */
struct tevent_req *
sss_failover_group_resolve_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct sss_failover_ctx *fctx,
                                struct sss_failover_group *group);

/**
 * @brief Return list of servers within this group.
 *
 * @param mem_ctx
 * @param req
 * @param _servers
 * @return errno_t
 */
errno_t
sss_failover_group_resolve_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                struct sss_failover_server ***_servers);

#endif /* _FAILOVER_GROUP_H_ */
