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

#ifndef _FAILOVER_H_
#define _FAILOVER_H_

#include <tevent.h>
#include <talloc.h>

#include "config.h"
#include "resolv/async_resolv.h"
#include "providers/failover/failover_server.h"
#include "providers/failover/failover_group.h"
#include "providers/failover/failover_vtable.h"
#include "util/util.h"

struct sss_failover_candidates_ctx {
    /* List of servers that were found as working. */
    struct sss_failover_server **servers;

    /* Active refresh request. NULL if there is no ongoing refresh. */
    struct tevent_req *refresh_req;

    /* This queue serves as a notification mechanism. It is started when
     * candidates list were refreshed and is stopped when the list is being
     * refreshed.
     */
    struct tevent_queue *notify_queue;

    /* Last refresh time. */
    unsigned int last_refresh_time;

    /* Do not issue new refresh if now < last_refresh_time + min_refresh_time */
    unsigned int min_refresh_time;
};

struct sss_failover_options {
    /* Maximum number of candidate servers. */
    unsigned int max_candidates;

    /* Minimum time that has to elapse before refreshing candidates again. */
    unsigned int min_refresh_time;

    /* Minimum amount of time that will wait for candidates servers to respond
    to a ping. If any server is found within this time, we do not wait for other
    servers to respond and return what we have. */
    unsigned int min_candidates_lookup_time;

    /* How long do we want to wait for a server ping to succeed. */
    unsigned int ping_timeout;

    /* TTL for missing DNS SRV records. */
    unsigned int negative_dns_srv_ttl;
};

struct sss_failover_ctx {
    struct tevent_context *ev;
    char *name;
    struct resolv_ctx *resolver_ctx;
    struct sss_failover_vtable *vtable;
    enum restrict_family family_order;

    struct sss_failover_options opts;

    /* NULL-terminated list of failover server groups. The first group has the
     * highest priority. */
    struct sss_failover_group **groups;

    /* Currently selected group that provided server candidates. */
    unsigned int current_group;

    /* Non-NULL if kinit is required to connect to the server. The context may
     * be the same to make sure the same server is used for KDC and connection
     * or different. */
    struct sss_failover_ctx *kinit_ctx;

    /* Candidate servers. */
    struct sss_failover_candidates_ctx *candidates;

    /* Currently active server. */
    struct sss_failover_server *active_server;

    /* Backend specific established connection. */
    void *connection;

    /* Queue of sss_vtable_op tevent requests. These requests are used to
     * connect to the server and the queue serializes the requests to ensure
     * that we establish only one connection that is then reused. */
    struct tevent_queue *vtable_op_queue;
};

/**
 * @brief Initialize failover context.
 *
 * @param mem_ctx
 * @param ev
 * @param resolver_ctx
 * @param family_order
 * @return struct sss_failover_ctx*
 */
struct sss_failover_ctx *
sss_failover_init(TALLOC_CTX *mem_ctx,
                  struct tevent_context *ev,
                  const char *name,
                  struct resolv_ctx *resolver_ctx,
                  enum restrict_family family_order);

/**
 * @brief Set active server.
 *
 * This is a noop if @server and @fctx->active_server is identical.
 */
void
sss_failover_set_active_server(struct sss_failover_ctx *fctx,
                               struct sss_failover_server *server);

/**
 * @brief Set new connection, release old one.
 *
 * This is a noop if @connection and @fctx->connection is identical.
 */
void
sss_failover_set_connection(struct sss_failover_ctx *fctx, void *connection);

/**
 * @brief Get connection.
 *
 * The connection is talloc_reference to mem_ctx.
 *
 * @param mem_ctx
 * @param fctx
 * @return void*
 */
void *
sss_failover_get_connection(TALLOC_CTX *mem_ctx, struct sss_failover_ctx *fctx);

#endif /* _FAILOVER_H_ */
