/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <talloc.h>

#include "config.h"
#include "providers/data_provider/dp.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "sbus/sbus.h"
#include "sss_iface/sss_iface_async.h"
#include "providers/backend.h"
#include "util/util.h"

static errno_t
dp_init_interface(struct data_provider *provider)
{
    errno_t ret;

    SBUS_INTERFACE(iface_dp_backend,
        sssd_DataProvider_Backend,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_DataProvider_Backend, IsOnline, dp_backend_is_online, provider->be_ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_dp_failover,
        sssd_DataProvider_Failover,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_DataProvider_Failover, ListServices, dp_failover_list_services, provider->be_ctx),
            SBUS_SYNC(METHOD, sssd_DataProvider_Failover, ListServers, dp_failover_list_servers, provider->be_ctx),
            SBUS_SYNC(METHOD, sssd_DataProvider_Failover, ActiveServer, dp_failover_active_server, provider->be_ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_dp_access,
        sssd_DataProvider_AccessControl,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, sssd_DataProvider_AccessControl, RefreshRules, dp_access_control_refresh_rules_send, dp_access_control_refresh_rules_recv, provider)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_autofs,
       sssd_DataProvider_Autofs,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, sssd_DataProvider_Autofs, GetMap, dp_autofs_get_map_send, dp_autofs_get_map_recv, provider),
            SBUS_ASYNC(METHOD, sssd_DataProvider_Autofs, GetEntry, dp_autofs_get_entry_send, dp_autofs_get_entry_recv, provider),
            SBUS_ASYNC(METHOD, sssd_DataProvider_Autofs, Enumerate, dp_autofs_enumerate_send, dp_autofs_enumerate_recv, provider)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_dp,
        sssd_dataprovider,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, sssd_dataprovider, pamHandler, dp_pam_handler_send, dp_pam_handler_recv, provider),
            SBUS_ASYNC(METHOD, sssd_dataprovider, sudoHandler, dp_sudo_handler_send, dp_sudo_handler_recv, provider),
            SBUS_ASYNC(METHOD, sssd_dataprovider, hostHandler, dp_host_handler_send, dp_host_handler_recv, provider),
            SBUS_ASYNC(METHOD, sssd_dataprovider, resolverHandler, dp_resolver_handler_send, dp_resolver_handler_recv, provider),
            SBUS_ASYNC(METHOD, sssd_dataprovider, getDomains, dp_subdomains_handler_send, dp_subdomains_handler_recv, provider),
            SBUS_ASYNC(METHOD, sssd_dataprovider, getAccountInfo, dp_get_account_info_send, dp_get_account_info_recv, provider),
            SBUS_ASYNC(METHOD, sssd_dataprovider, getAccountDomain, dp_get_account_domain_send, dp_get_account_domain_recv, provider)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_responder_domain,
        sssd_Responder_Domain,
        SBUS_METHODS(SBUS_NO_METHODS),
        SBUS_SIGNALS(
            SBUS_EMITS(sssd_Responder_Domain, SetActive),
            SBUS_EMITS(sssd_Responder_Domain, SetInconsistent)
        ),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_responder_negativecache,
        sssd_Responder_NegativeCache,
        SBUS_METHODS(SBUS_NO_METHODS),
        SBUS_SIGNALS(
            SBUS_EMITS(sssd_Responder_NegativeCache, ResetUsers),
            SBUS_EMITS(sssd_Responder_NegativeCache, ResetGroups)
        ),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_nss_memorycache,
        sssd_nss_MemoryCache,
        SBUS_METHODS(SBUS_NO_METHODS),
        SBUS_SIGNALS(
            SBUS_EMITS(sssd_nss_MemoryCache, InvalidateAllUsers),
            SBUS_EMITS(sssd_nss_MemoryCache, InvalidateAllGroups),
            SBUS_EMITS(sssd_nss_MemoryCache, InvalidateAllInitgroups),
            SBUS_EMITS(sssd_nss_MemoryCache, InvalidateGroupById)
         ),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    struct sbus_path paths[] = {
        {SSS_BUS_PATH, &iface_dp_backend},
        {SSS_BUS_PATH, &iface_dp_failover},
        {SSS_BUS_PATH, &iface_dp_access},
        {SSS_BUS_PATH, &iface_dp},
        {SSS_BUS_PATH, &iface_autofs},
        {SSS_BUS_PATH, &iface_responder_domain},
        {SSS_BUS_PATH, &iface_responder_negativecache},
        {SSS_BUS_PATH, &iface_nss_memorycache},
        {NULL, NULL}
    };

    ret = sbus_connection_add_path_map(provider->sbus_conn, paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to add paths [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

static int dp_destructor(struct data_provider *provider)
{
    provider->terminating = true;

    dp_terminate_active_requests(provider);

    return 0;
}

errno_t
dp_init(struct tevent_context *ev,
        struct be_ctx *be_ctx,
        const char *sbus_name)
{
    struct data_provider *provider;
    errno_t ret;

    provider = talloc_zero(be_ctx, struct data_provider);
    if (provider == NULL) {
        ret = ENOMEM;
        goto done;
    }
    provider->be_ctx = be_ctx;
    provider->ev = ev;
    talloc_set_destructor(provider, dp_destructor);

    ret = sss_sbus_connect(provider, ev, sbus_name, NULL, &provider->sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to SSSD D-Bus server "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* We need to set the field here because we are about to run the dlopen
       initialization code that expects that be_ctx is fully initialized. */
    be_ctx->provider = provider;
    be_ctx->conn = provider->sbus_conn;

    ret = dp_init_modules(provider, &provider->modules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize DP modules "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = dp_init_targets(provider, be_ctx, provider, provider->modules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize DP targets "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = dp_init_interface(provider);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize DP interface "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(provider);
        be_ctx->provider = NULL;
    }

    return ret;
}

struct sbus_connection *
dp_sbus_conn(struct data_provider *provider)
{
    if (provider == NULL) {
        return NULL;
    }

    return provider->sbus_conn;
}

struct sbus_server *
dp_sbus_server(struct data_provider *provider)
{
    if (provider == NULL) {
        return NULL;
    }

    return provider->sbus_server;
}
