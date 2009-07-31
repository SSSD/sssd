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
                     struct tevent_context *ev,
                     struct sbus_method_ctx *sm_ctx,
                     const char *server_address,
                     struct sbus_conn_ctx **_conn_ctx,
                     sbus_conn_destructor_fn destructor,
                     void *conn_pvt_data)
{
    struct sbus_conn_ctx *conn_ctx = NULL;
    int ret;

    /* Validate input */
    if (server_address == NULL) {
        return EINVAL;
    }

    ret = sbus_new_connection(mem_ctx, ev, server_address, &conn_ctx);
    if (ret != EOK) {
        goto fail;
    }

    ret = sbus_conn_add_method_ctx(conn_ctx, sm_ctx);
    if (ret != EOK) {
        goto fail;
    }

    /* Set connection destructor and private data */
    sbus_conn_set_destructor(conn_ctx, destructor);
    sbus_conn_set_private_data(conn_ctx, conn_pvt_data);

    *_conn_ctx = conn_ctx;
    return EOK;

fail:
    talloc_free(conn_ctx);
    return ret;
}
