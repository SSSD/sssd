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
#include "sss_iface/sss_iface_async.h"
#include "providers/backend.h"
#include "util/util.h"

static errno_t
dp_init_interface(struct data_provider *provider)
{
    errno_t ret;

    SBUS_INTERFACE(iface_dp_client,
        sssd_DataProvider_Client,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_DataProvider_Client, Register, dp_client_register, provider)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

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

    struct sbus_path paths[] = {
        {SSS_BUS_PATH, &iface_dp_client},
        {SSS_BUS_PATH, &iface_dp_backend},
        {SSS_BUS_PATH, &iface_dp_failover},
        {SSS_BUS_PATH, &iface_dp_access},
        {SSS_BUS_PATH, &iface_dp},
        {SSS_BUS_PATH, &iface_autofs},
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
    enum dp_clients client;

    provider->terminating = true;

    dp_terminate_active_requests(provider);

    for (client = 0; client != DP_CLIENT_SENTINEL; client++) {
        talloc_zfree(provider->clients[client]);
    }

    return 0;
}

struct dp_init_state {
    struct be_ctx *be_ctx;
    struct data_provider *provider;
};

static void dp_init_done(struct tevent_req *subreq);

struct tevent_req *
dp_init_send(TALLOC_CTX *mem_ctx,
             struct tevent_context *ev,
             struct be_ctx *be_ctx,
             uid_t uid,
             gid_t gid,
             const char *sbus_name)
{
    struct dp_init_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    char *sbus_address;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_init_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    sbus_address = sss_iface_domain_address(state, be_ctx->domain);
    if (sbus_address == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not get sbus backend address.\n");
        ret = ENOMEM;
        goto done;
    }

    state->provider = talloc_zero(be_ctx, struct data_provider);
    if (state->provider == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->be_ctx = be_ctx;
    state->provider->ev = ev;
    state->provider->uid = uid;
    state->provider->gid = gid;
    state->provider->be_ctx = be_ctx;

    /* Initialize data provider bus. Data provider can receive client
     * registration and other D-Bus methods. However no data provider
     * request will be executed as long as the modules and targets
     * are not initialized.
     */
    talloc_set_destructor(state->provider, dp_destructor);

    subreq = sbus_server_create_and_connect_send(state->provider, ev,
        sbus_name, NULL, sbus_address, true, 1000, uid, gid,
        (sbus_server_on_connection_cb)dp_client_init,
        (sbus_server_on_connection_data)state->provider);
    if (subreq == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_init_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_init_done(struct tevent_req *subreq)
{
    struct dp_init_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_init_state);

    ret = sbus_server_create_and_connect_recv(state->provider, subreq,
                                              &state->provider->sbus_server,
                                              &state->provider->sbus_conn);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* be_ctx->provider must be accessible from modules and targets */
    state->be_ctx->provider = talloc_steal(state->be_ctx, state->provider);

    ret = dp_init_modules(state->provider, &state->provider->modules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize DP modules "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = dp_init_targets(state->provider, state->provider->be_ctx,
                          state->provider, state->provider->modules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize DP targets "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = dp_init_interface(state->provider);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize DP interface "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        talloc_zfree(state->be_ctx->provider);
        tevent_req_error(req, ret);
    }

    tevent_req_done(req);
}

errno_t dp_init_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
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
