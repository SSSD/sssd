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

/**
 * The failover transaction code is responsible for choosing and connecting to a
 * server and retrying the whole operation if the server stops working in the
 * middle of the request.
 *
 * The operation is wrapped by @sss_failover_transaction_send and it should make
 * sure to fetch all required data from the server before writing them to the
 * sysdb. If the operation fails due to the server failure, the operation tevent
 * request must fail with ERR_SERVER_FAILURE to indicate the failure to the
 * failover transaction code. In this case, the failover mechanism marks the
 * server as offline, picks the next available server and restarts the whole
 * operation. Neither the caller nor the operation has to deal with any failover
 * mechanics.
 *
 * The result of the operation can be received by
 * @sss_failover_transaction_recv.
 */

#ifndef _FAILOVER_TRANSACTION_H_
#define _FAILOVER_TRANSACTION_H_

#include <talloc.h>
#include <tevent.h>

#include "config.h"
#include "resolv/async_resolv.h"
#include "util/util.h"

struct sss_failover_ctx;

enum sss_failover_transaction_tls {
    SSS_FAILOVER_TRANSACTION_TLS_DEFAULT,
    SSS_FAILOVER_TRANSACTION_TLS_ON,
    SSS_FAILOVER_TRANSACTION_TLS_OFF
};

errno_t
sss_failover_transaction_ex_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct sss_failover_ctx *fctx,
                                 struct tevent_req *caller_req,
                                 tevent_req_fn connected_callback,
                                 bool reuse_connection,
                                 bool authenticate_connection,
                                 bool read_rootdse,
                                 enum sss_failover_transaction_tls force_tls);

errno_t
sss_failover_transaction_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct sss_failover_ctx *fctx,
                              struct tevent_req *caller_req,
                              tevent_req_fn connected_callback);

/**
 * @brief Submit a failover transaction.
 *
 * The failover code will pick a working server and submit a working connection
 * to the underlying @req_send tevent request, passing @input_data along.
 *
 * If the receive @req_recv function returns ERR_SERVER_FAILURE, the transaction
 * is repeated with another server as long as there is a server available. The
 * transaction is cancelled if there are no more servers to try.
 *
 * The callback and data types are checked during compilation.
 */

void *
_sss_failover_transaction_connected_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req);

#define sss_failover_transaction_connected_recv(mem_ctx, req, type) \
	talloc_get_type_abort(_sss_failover_transaction_connected_recv((mem_ctx), (req)), type)

#endif /* _FAILOVER_TRANSACTION_H_ */
