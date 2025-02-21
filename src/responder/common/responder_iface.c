/*
    Copyright (C) 2016 Red Hat

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
#include "sss_iface/sss_iface_async.h"
#include "responder/common/negcache.h"
#include "responder/common/responder.h"

static errno_t
sss_resp_reset_ncache_users(TALLOC_CTX *mem_ctx,
                            struct sbus_request *sbus_req,
                            struct resp_ctx *rctx)
{
    sss_ncache_reset_users(rctx->ncache);

    return EOK;
}

static errno_t
sss_resp_reset_ncache_groups(TALLOC_CTX *mem_ctx,
                            struct sbus_request *sbus_req,
                            struct resp_ctx *rctx)
{
    sss_ncache_reset_groups(rctx->ncache);

    return EOK;
}

errno_t
sss_resp_register_sbus_iface(struct sbus_connection *conn,
                             struct resp_ctx *rctx)
{
    errno_t ret;

    struct sbus_listener listeners[] = SBUS_LISTENERS(
        SBUS_LISTEN_SYNC(sssd_Responder_NegativeCache, ResetUsers,
                         SSS_BUS_PATH, sss_resp_reset_ncache_users, rctx),
        SBUS_LISTEN_SYNC(sssd_Responder_NegativeCache, ResetGroups,
                         SSS_BUS_PATH, sss_resp_reset_ncache_groups, rctx)
    );

    ret = sbus_router_listen_map(conn, listeners);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to add listeners [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

errno_t
sss_resp_register_service_iface(struct resp_ctx *rctx)
{
    errno_t ret;

    SBUS_INTERFACE(iface_svc,
        sssd_service,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_service, rotateLogs, responder_logrotate, rctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, sssd_service, debug_level, generic_get_debug_level, NULL),
            SBUS_SYNC(SETTER, sssd_service, debug_level, generic_set_debug_level, NULL)
        )
    );

    ret = sbus_connection_add_path(rctx->sbus_conn, SSS_BUS_PATH, &iface_svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register service interface"
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    return ret;
}
