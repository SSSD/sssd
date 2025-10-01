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
#include <tevent.h>

#include "config.h"
#include "providers/failover/failover_vtable.h"
#include "providers/failover/failover.h"
#include "util/util.h"

void
sss_failover_vtable_set_connect(struct sss_failover_ctx *fctx,
                                sss_failover_vtable_connect_send_t send_fn,
                                sss_failover_vtable_connect_recv_t recv_fn,
                                void *data)
{
    fctx->vtable->connect.send = send_fn;
    fctx->vtable->connect.recv = recv_fn;
    fctx->vtable->connect.data = data;
}

void
sss_failover_vtable_set_kinit(struct sss_failover_ctx *fctx,
                              sss_failover_vtable_kinit_send_t send_fn,
                              sss_failover_vtable_kinit_recv_t recv_fn,
                              void *data)
{
    fctx->vtable->kinit.send = send_fn;
    fctx->vtable->kinit.recv = recv_fn;
    fctx->vtable->kinit.data = data;
}
