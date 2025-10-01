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

#ifndef _FAILOVER_VTABLE_H_
#define _FAILOVER_VTABLE_H_

#include <tevent.h>
#include <talloc.h>

#include "config.h"
#include "resolv/async_resolv.h"
#include "providers/failover/failover_server.h"
#include "util/util.h"

struct sss_failover_ctx;
enum sss_failover_transaction_tls;

struct sss_failover_vtable_kinit_output_data {
    time_t expiration_time;
};

typedef struct tevent_req *
(*sss_failover_vtable_kinit_send_t)(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sss_failover_ctx *fctx,
                                    struct sss_failover_server *server,
                                    bool addr_changed,
                                    void *pvt);

typedef errno_t
(*sss_failover_vtable_kinit_recv_t)(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *,
                                    time_t *_expiration_time);

struct sss_failover_vtable_kinit {
    sss_failover_vtable_kinit_send_t send;
    sss_failover_vtable_kinit_recv_t recv;
    void *data;
};

typedef struct tevent_req *
(*sss_failover_vtable_connect_send_t)(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sss_failover_ctx *fctx,
                                      struct sss_failover_server *server,
                                      bool addr_changed,
                                      bool reuse_connection,
                                      bool authenticate_connection,
                                      bool read_rootdse,
                                      enum sss_failover_transaction_tls force_tls,
                                      time_t kinit_expiration_time,
                                      void *pvt);

typedef errno_t
(*sss_failover_vtable_connect_recv_t)(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      void **_connection);


struct sss_failover_vtable_connect {
    sss_failover_vtable_connect_send_t send;
    sss_failover_vtable_connect_recv_t recv;
    void *data;
};

struct sss_failover_vtable {
    struct sss_failover_vtable_kinit kinit;
    struct sss_failover_vtable_connect connect;
};

void
sss_failover_vtable_set_connect(struct sss_failover_ctx *fctx,
                                sss_failover_vtable_connect_send_t send_fn,
                                sss_failover_vtable_connect_recv_t recv_fn,
                                void *data);

void
sss_failover_vtable_set_kinit(struct sss_failover_ctx *fctx,
                              sss_failover_vtable_kinit_send_t send_fn,
                              sss_failover_vtable_kinit_recv_t recv_fn,
                              void *data);

#endif /* _FAILOVER_VTABLE_H_ */
