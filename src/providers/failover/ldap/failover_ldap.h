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

#ifndef _FAILOVER_LDAP_H_
#define _FAILOVER_LDAP_H_

#include <tevent.h>
#include <talloc.h>

#include "config.h"
#include "resolv/async_resolv.h"
#include "providers/failover/failover.h"
#include "providers/failover/failover_server.h"
#include "util/util.h"

/**
 * @brief LDAP connection.
 *
 * The connection is terminated via a talloc destructor when the last reference
 * to the instance is dropped.
 */
struct sss_failover_ldap_connection {
    struct sss_failover_ctx *fctx;
    struct sss_failover_server *server;
    struct sdap_server_opts *srv_opts;
    struct sdap_handle *sh;
    char *uri;
    time_t idle_timeout;

    int op_count;
    time_t idle_since;
};

struct tevent_req *
sss_failover_ldap_kinit_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sss_failover_ctx *fctx,
                             struct sss_failover_server *server,
                             void *pvt);

errno_t
sss_failover_ldap_kinit_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             time_t *_expiration_time);

struct tevent_req *
sss_failover_ldap_connect_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct sss_failover_ctx *fctx,
                               struct sss_failover_server *server,
                               bool authenticate_connection,
                               bool read_rootdse,
                               enum sss_failover_transaction_tls force_tls,
                               time_t kinit_expiration_time,
                               void *pvt);

errno_t
sss_failover_ldap_connect_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               void **_connection);

void
sss_failover_ldap_connect_op_start(struct sss_failover_ctx *fctx,
                                   void *connection,
                                   void *pvt);

void
sss_failover_ldap_connect_op_done(struct sss_failover_ctx *fctx,
                                  void *connection,
                                  void *pvt);

#endif /* _FAILOVER_LDAP_H_ */
