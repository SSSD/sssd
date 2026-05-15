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

#ifndef _FAILOVER_SERVER_RESOLVE_H_
#define _FAILOVER_SERVER_RESOLVE_H_

#include <talloc.h>
#include <tevent.h>

#include "config.h"
#include "resolv/async_resolv.h"
#include "util/util.h"

/**
 * @brief Resolve server hostname into an IP address.
 *
 * When IP address is resolved, it calls @sss_failover_server_set_address to
 * store the address in the @sss_failover_server record. Otherwise it keeps it
 * intact.
 *
 * @param mem_ctx
 * @param ev
 * @param resolv_ctx
 * @param family_order
 * @param server
 * @return struct tevent_req*
 */
struct tevent_req *
sss_failover_server_resolve_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct resolv_ctx *resolv_ctx,
                                 enum restrict_family family_order,
                                 struct sss_failover_server *server);

/**
 * @brief Receives the return code.
 *
 * If EOK, IP address has been stored inside the server record. @_changed is
 * true if the IP address of the host has changed, false if it is still the
 * same.
 *
 * @param req
 * @param _changed
 * @return errno_t
 */
errno_t
sss_failover_server_resolve_recv(struct tevent_req *req,
                                 bool *_changed);

#endif /* _FAILOVER_SERVER_RESOLVE_H_ */
