/*
 SSSD

 Service monitor

 Copyright (C) Stephen Gallagher    2008

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
#include "events.h"
#include "sbus/sssd_dbus.h"
#include "confdb/confdb.h"
#include "service_helpers.h"
#include "sbus_interfaces.h"

/*
 * Set up an SBUS connection to the monitor
 */
struct service_sbus_ctx *sssd_service_sbus_init(TALLOC_CTX *mem_ctx,
                                                struct event_context *ev,
                                                struct confdb_ctx *cdb,
                                                sbus_msg_handler_fn get_identity,
                                                sbus_msg_handler_fn ping)
{
    struct service_sbus_ctx *ss_ctx;
    struct sbus_method_ctx *sm_ctx;
    TALLOC_CTX *ctx;
    char *sbus_address;
    DBusConnection *conn;
    int ret;

    ctx = talloc_new(mem_ctx);
    if (ctx == NULL) goto error;

    ss_ctx = talloc_zero(ctx, struct service_sbus_ctx);
    if (ss_ctx == NULL) return NULL;

    ret = confdb_get_string(cdb, ctx,
                            "config/services/monitor", "sbusAddress",
                            DEFAULT_SBUS_ADDRESS, &sbus_address);
    if (ret != EOK) goto error;
    ss_ctx->ev = ev;

    ret = sbus_new_connection(ss_ctx, ss_ctx->ev,
                              sbus_address, &ss_ctx->scon_ctx,
                              NULL);
    if (ret != EOK) goto error;

    conn = sbus_get_connection(ss_ctx->scon_ctx);

    /* set up handler for service methods */
    sm_ctx = talloc_zero(ss_ctx, struct sbus_method_ctx);
    if (sm_ctx == NULL) goto error;

    sm_ctx->interface = talloc_strdup(sm_ctx, SERVICE_INTERFACE);
    sm_ctx->path = talloc_strdup(sm_ctx, SERVICE_PATH);
    if (!sm_ctx->interface || !sm_ctx->path) goto error;

    /* Set up required monitor methods */
    sm_ctx->methods = talloc_array(sm_ctx, struct sbus_method, 3);
    if (sm_ctx->methods == NULL) goto error;

    /* Handle getIdentity */
    sm_ctx->methods[0].method = SERVICE_METHOD_IDENTITY;
    sm_ctx->methods[0].fn = get_identity;

    /* Handle ping */
    sm_ctx->methods[1].method = SERVICE_METHOD_PING;
    sm_ctx->methods[1].fn = ping;

    /* Terminate the list */
    sm_ctx->methods[2].method = NULL;
    sm_ctx->methods[2].fn = NULL;

    sm_ctx->message_handler = sbus_message_handler;
    sbus_conn_add_method_ctx(ss_ctx->scon_ctx, sm_ctx);

    talloc_steal(mem_ctx,ss_ctx);
    talloc_free(ctx);
    return ss_ctx;

error:
    talloc_free(ctx);
    return NULL;
}
