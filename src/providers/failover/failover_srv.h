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

#ifndef _FAILOVER_SRV_H_
#define _FAILOVER_SRV_H_

#include <talloc.h>
#include <tevent.h>

#include "config.h"
#include "providers/failover/failover.h"
#include "providers/failover/failover_server.h"
#include "util/util.h"

/**
 * @brief Resolve DNS SRV record using selected discovery domains.
 *
 * If the first discovery domain yields no servers, we proceed with the next
 * domain.
 *
 * @param mem_ctx
 * @param ev
 * @param fctx
 * @param service
 * @param protocol
 * @param discovery_domains
 * @return struct tevent_req*
 */
struct tevent_req *
sss_failover_srv_resolve_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct sss_failover_ctx *fctx,
                              const char *service,
                              const char *protocol,
                              const char * const * discovery_domains);

/**
 * @brief Get TTL and discovered servers.
 *
 * @param mem_ctx
 * @param req
 * @param _ttl
 * @param _servers
 * @return errno_t
 */
errno_t
sss_failover_srv_resolve_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              uint32_t *_ttl,
                              struct sss_failover_server ***_servers);

#endif /* _FAILOVER_SRV_H_ */
