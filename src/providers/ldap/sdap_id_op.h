/*
    SSSD

    LDAP ID backend operation retry logic and connection cache

    Authors:
        Eugene Indenbom <eindenbom@gmail.com>

    Copyright (C) 2008-2010 Red Hat

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

#ifndef _SDAP_ID_OP_H_
#define _SDAP_ID_OP_H_

struct sdap_id_ctx;
struct sdap_id_conn_ctx;

/* LDAP async connection cache */
struct sdap_id_conn_cache;

/* LDAP async operation tracker:
 *  - keeps track of connection usage
 *  - keeps track of operation retries */
struct sdap_id_op;

/* Create a connection cache */
int sdap_id_conn_cache_create(TALLOC_CTX *memctx,
                              struct sdap_id_conn_ctx *id_conn,
                              struct sdap_id_conn_cache** conn_cache_out);

/* Create an operation object */
struct sdap_id_op *sdap_id_op_create(TALLOC_CTX *memctx, struct sdap_id_conn_cache *cache);

/* Begin to connect to LDAP server. */
struct tevent_req *sdap_id_op_connect_send(struct sdap_id_op *op,
                                           TALLOC_CTX *memctx,
                                           int *ret_out);

/* Get the result of an asynchronous connect operation on sdap_id_op
 *
 * In dp_error data provider error code is returned:
 *   DP_ERR_OK - connection established
 *   DP_ERR_OFFLINE - backend is offline, operation result is set EAGAIN
 *   DP_ERR_FATAL - operation failed
 */
int sdap_id_op_connect_recv(struct tevent_req *req, int *dp_error);

/* Report completion of LDAP operation and release associated connection.
 * Returns operation result (possible updated) passed in ret parameter.
 *
 * In dp_error data provider error code is returned:
 *   DP_ERR_OK (operation result = EOK) - operation completed
 *   DP_ERR_OK (operation result != EOK) - operation can be retried
 *   DP_ERR_OFFLINE - backend is offline, operation result is set EAGAIN
 *   DP_ERR_FATAL - operation failed */
int sdap_id_op_done(struct sdap_id_op*, int ret, int *dp_error);

/* Get SDAP handle associated with operation by sdap_id_op_connect */
struct sdap_handle *sdap_id_op_handle(struct sdap_id_op *op);
/* Get root DSE entry of connected LDAP server */
const struct sysdb_attrs *sdap_id_op_rootDSE(struct sdap_id_op *op);

#endif /* _SDAP_ID_OP_H_ */
