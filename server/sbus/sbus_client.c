/*
   SSSD

   Data Provider Helpers

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include "util/util.h"
#include "talloc.h"
#include "sbus_client.h"

int sbus_client_init(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     const char *server_address,
                     struct sbus_method_ctx *sm_ctx,
                     void *conn_pvt_data,
                     sbus_conn_destructor_fn destructor,
                     struct service_sbus_ctx **srvs_ctx)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct service_sbus_ctx *ss_ctx;

    /* Validate input */
    if (server_address == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ss_ctx = talloc_zero(tmp_ctx, struct service_sbus_ctx);
    if (ss_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
    ss_ctx->ev = ev;

    ret = sbus_new_connection(ss_ctx, ss_ctx->ev,
                              server_address, &ss_ctx->scon_ctx,
                              destructor);
    if (ret != EOK) goto done;

    ret = sbus_conn_add_method_ctx(ss_ctx->scon_ctx, sm_ctx);
    if (ret != EOK) goto done;
    ss_ctx->sm_ctx = sm_ctx;
    if (talloc_reference(ss_ctx, sm_ctx) == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if(conn_pvt_data) {
        sbus_conn_set_private_data(ss_ctx->scon_ctx, conn_pvt_data);
    }

    talloc_steal(mem_ctx, ss_ctx);
    *srvs_ctx = ss_ctx;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
