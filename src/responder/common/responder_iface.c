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

static void set_domain_state_by_name(struct resp_ctx *rctx,
                                     const char *domain_name,
                                     enum sss_domain_state state)
{
    struct sss_domain_info *dom;

    if (domain_name == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "BUG: NULL domain name\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Setting state of domain %s\n", domain_name);

    for (dom = rctx->domains;
         dom != NULL;
         dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {

        if (strcasecmp(dom->name, domain_name) == 0) {
            break;
        }
    }

    if (dom != NULL) {
        sss_domain_set_state(dom, state);
    }
}

static errno_t
sss_resp_domain_active(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct resp_ctx *rctx,
                       const char *domain_name)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Enabling domain %s\n", domain_name);

    set_domain_state_by_name(rctx, domain_name, DOM_ACTIVE);

    return EOK;
}

static errno_t
sss_resp_domain_inconsistent(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct resp_ctx *rctx,
                             const char *domain_name)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Disabling domain %s\n", domain_name);

    set_domain_state_by_name(rctx, domain_name, DOM_INCONSISTENT);

    return EOK;
}

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

    SBUS_INTERFACE(iface_resp_domain,
        sssd_Responder_Domain,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_Responder_Domain, SetActive, sss_resp_domain_active, rctx),
            SBUS_SYNC(METHOD, sssd_Responder_Domain, SetInconsistent, sss_resp_domain_inconsistent, rctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_resp_negcache,
        sssd_Responder_NegativeCache,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_Responder_NegativeCache, ResetUsers, sss_resp_reset_ncache_users, rctx),
            SBUS_SYNC(METHOD, sssd_Responder_NegativeCache, ResetGroups, sss_resp_reset_ncache_groups, rctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    struct sbus_path paths[] = {
        {SSS_BUS_PATH, &iface_resp_domain},
        {SSS_BUS_PATH, &iface_resp_negcache},
        {NULL, NULL}
    };

    ret = sbus_connection_add_path_map(conn, paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to add paths [%d]: %s\n",
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
            SBUS_SYNC(METHOD, sssd_service, resInit, monitor_common_res_init, NULL),
            SBUS_SYNC(METHOD, sssd_service, rotateLogs, responder_logrotate, rctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    ret = sbus_connection_add_path(rctx->mon_conn, SSS_BUS_PATH, &iface_svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register service interface"
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    return ret;
}
