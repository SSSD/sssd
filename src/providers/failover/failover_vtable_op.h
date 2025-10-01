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

#ifndef _FAILOVER_VTABLE_OP_H_
#define _FAILOVER_VTABLE_OP_H_

#include <tevent.h>
#include <talloc.h>

#include "config.h"
#include "providers/failover/failover.h"
#include "providers/failover/failover_server.h"
#include "util/util.h"

/**
 * @defgroup Failover vtable operations.
 *
 * The purpose of sss_failover_vtable_op_* requests is to find a working server
 * on which the operation succeeds.
 *
 * - If there is already working and active server, use it.
 * - Otherwise find first available server, resolve its hostname and use it.
 * - If the operation succeeds, mark the server as working and store operation
 *   data.
 * - If the operation fails, mark the server as not working and try next server.
 *
 * Note that this request does not decide if the operation should be started or
 * not (e.g. if the server is already connected or not). To simplify the logic,
 * this is the responsibility of the operation it self (e.g. check if the server
 * is already connected in the @send_fn and then shortcut, otherwise try to
 * establish connection).
 *
 * The requests are serialized in @fctx->vtable_op_queue to ensure that we
 * always talk to a single server at the same time.
 *
 * @{
 */

/**
 * @brief Select a KDC and attempt to kinit with the host credentials.
 *
 * @param mem_ctx
 * @param ev
 * @param fctx
 * @return struct tevent_req *
 */
struct tevent_req *
sss_failover_vtable_op_kinit_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sss_failover_ctx *fctx);

/**
 * @brief Receive result of the operation.
 *
 * If @_server is not NULL and EOK is returned, it contains the server that was
 * successfully used to finish the operation. The server reference count is
 * increased and linked to @mem_ctx.
 *
 * @param mem_ctx
 * @param req
 * @param _server
 * @param _expiration_time Host TGT expiration time.
 * @return errno_t
 */
errno_t
sss_failover_vtable_op_kinit_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  struct sss_failover_server **_server,
                                  time_t *_expiration_time);

/**
 * @brief Select a server and attempt to establish a working connection.
 *
 * @param mem_ctx
 * @param ev
 * @param fctx
 * @param reuse_connection
 * @param authenticate_connection
 * @param read_rootdse
 * @param force_tls
 * @param kinit_expiration_time
 * @return struct tevent_req *
 */
struct tevent_req *
sss_failover_vtable_op_connect_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sss_failover_ctx *fctx,
                                    bool reuse_connection,
                                    bool authenticate_connection,
                                    bool read_rootdse,
                                    enum sss_failover_transaction_tls force_tls,
                                    time_t kinit_expiration_time);

/**
 * @brief Receive result of the operation.
 *
 * If @_server is not NULL and EOK is returned, it contains the server that was
 * successfully used to finish the operation. The server reference count is
 * increased and linked to @mem_ctx.
 *
 * @param mem_ctx
 * @param req
 * @param _server
 * @param _connection Established connection data.
 * @return errno_t
 */
errno_t
sss_failover_vtable_op_connect_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct sss_failover_server **_server,
                                    void **_connection);

/**
 * @}
 */

#endif /* _FAILOVER_VTABLE_OP_H_ */
