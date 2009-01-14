/*
   SSSD

   Data Provider Helpers

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include "providers/data_provider.h"

int dp_sbus_cli_init(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct confdb_ctx *cdb,
                     struct sbus_method *methods,
                     void *conn_pvt_data,
                     sbus_conn_destructor_fn destructor,
                     struct service_sbus_ctx **srvs_ctx)
{
    struct service_sbus_ctx *ss_ctx;
    struct sbus_method_ctx *sm_ctx;
    TALLOC_CTX *tmp_ctx;
    char *default_dp_address;
    char *sbus_address;
    DBusConnection *conn;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ss_ctx = talloc_zero(tmp_ctx, struct service_sbus_ctx);
    if (ss_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
    ss_ctx->ev = ev;

    default_dp_address = talloc_asprintf(tmp_ctx, "unix:path=%s/%s",
                                         PIPE_PATH, DATA_PROVIDER_PIPE);
    if (default_dp_address == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_get_string(cdb, tmp_ctx,
                            "config/services/dp", "sbusAddress",
                            default_dp_address, &sbus_address);
    if (ret != EOK) goto done;

    ret = sbus_new_connection(ss_ctx, ss_ctx->ev,
                              sbus_address, &ss_ctx->scon_ctx,
                              NULL);
    if (ret != EOK) goto done;

    conn = sbus_get_connection(ss_ctx->scon_ctx);

    /* set up handler for service methods */
    sm_ctx = talloc_zero(ss_ctx, struct sbus_method_ctx);
    if (sm_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sm_ctx->interface = talloc_strdup(sm_ctx, DATA_PROVIDER_INTERFACE);
    sm_ctx->path = talloc_strdup(sm_ctx, DATA_PROVIDER_PATH);
    if (!sm_ctx->interface || !sm_ctx->path) {
        ret = ENOMEM;
        goto done;
    }

    /* Set up required monitor methods */
    sm_ctx->methods = methods;

    sm_ctx->message_handler = sbus_message_handler;
    sbus_conn_add_method_ctx(ss_ctx->scon_ctx, sm_ctx);

    if (conn_pvt_data) {
        sbus_conn_set_private_data(ss_ctx->scon_ctx, conn_pvt_data);
    }

    if (destructor) {
        sbus_conn_set_destructor(ss_ctx->scon_ctx, destructor);
    }

    talloc_steal(mem_ctx, ss_ctx);
    *srvs_ctx = ss_ctx;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

