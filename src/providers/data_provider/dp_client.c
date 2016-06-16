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

#include "providers/backend.h"
#include "providers/data_provider/dp_iface_generated.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/data_provider/dp.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_errors.h"
#include "util/util.h"

struct dp_client {
    struct data_provider *provider;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
    const char *name;
    bool initialized;
};

const char *dp_client_to_string(enum dp_clients client)
{
    switch (client) {
    case DPC_NSS:
        return "NSS";
    case DPC_PAM:
        return "PAM";
    case DPC_IFP:
        return "InfoPipe";
    case DPC_PAC:
        return "PAC";
    case DPC_SUDO:
        return "SUDO";
    case DPC_HOST:
        return "SSH";
    case DPC_AUTOFS:
        return "autofs";
    case DP_CLIENT_SENTINEL:
        return "Invalid";
    }

    return "Invalid";
}

static int dp_client_destructor(struct dp_client *dp_cli)
{
    struct data_provider *provider;
    enum dp_clients client;

    if (dp_cli->provider == NULL) {
        return 0;
    }

    provider = dp_cli->provider;

    for (client = 0; client != DP_CLIENT_SENTINEL; client++) {
        if (provider->clients[client] == dp_cli) {
            provider->clients[client] = NULL;
            DEBUG(SSSDBG_TRACE_FUNC, "Removed %s client\n",
                  dp_client_to_string(client));
            break;
        }
    }

    if (client == DP_CLIENT_SENTINEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown client removed...\n");
    }

    return 0;
}

static int
dp_client_register(struct sbus_request *sbus_req,
                   void *data,
                   const char *client_name)
{
    struct data_provider *provider;
    struct dp_client *dp_cli;
    struct DBusError *error;
    enum dp_clients client;
    errno_t ret;

    dp_cli = talloc_get_type(data, struct dp_client);
    if (dp_cli == NULL) {
        /* Do not send D-Bus error here. */
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: dp_cli is NULL\n");
        return EINVAL;
    }

    provider = dp_cli->provider;
    dp_cli->name = talloc_strdup(dp_cli, client_name);
    if (dp_cli->name == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Cancel DP ID timeout [%p]\n", dp_cli->timeout);
    talloc_zfree(dp_cli->timeout);

    for (client = 0; client != DP_CLIENT_SENTINEL; client++) {
        if (strcasecmp(client_name, dp_client_to_string(client)) == 0) {
            provider->clients[client] = dp_cli;
            break;
        }
    }

    if (client == DP_CLIENT_SENTINEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown client! [%s]\n", client_name);
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "Unknown client [%s]", client_name);

        /* Kill this client. */
        talloc_free(dp_cli);
        return sbus_request_fail_and_finish(sbus_req, error);
    }

    talloc_set_destructor(dp_cli, dp_client_destructor);

    ret = iface_dp_client_Register_finish(sbus_req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Unable to send ack to the client [%s], "
              "disconnecting...\n", client_name);
        sbus_disconnect(sbus_req->conn);
        return ret;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Added Frontend client [%s]\n", client_name);

    dp_cli->initialized = true;
    return EOK;
}

static void
dp_client_handshake_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t,
                            void *ptr)
{
    struct dp_client *dp_cli;

    DEBUG(SSSDBG_OP_FAILURE,
          "Client timed out before identification [%p]!\n", te);

    dp_cli = talloc_get_type(ptr, struct dp_client);

    sbus_disconnect(dp_cli->conn);
    talloc_zfree(dp_cli);
}

errno_t dp_client_init(struct sbus_connection *conn, void *data)
{
    struct data_provider *provider;
    struct dp_client *dp_cli;
    struct timeval tv;
    errno_t ret;

    static struct iface_dp_client iface_dp_client = {
        { &iface_dp_client_meta, 0 },

        .Register = dp_client_register,
    };

    provider = talloc_get_type(data, struct data_provider);

    /* When connection is lost we also free the client. */
    dp_cli = talloc_zero(conn, struct dp_client);
    if (dp_cli == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory, killing connection.\n");
        talloc_free(conn);
        return ENOMEM;
    }

    dp_cli->provider = provider;
    dp_cli->conn = conn;
    dp_cli->initialized = false;
    dp_cli->timeout = NULL;

    /* Allow access from the SSSD user. */
    sbus_allow_uid(conn, &provider->uid);

    /* Setup timeout in case client fails to register himself in time. */
    tv = tevent_timeval_current_ofs(5, 0);
    dp_cli->timeout = tevent_add_timer(provider->ev, dp_cli, tv,
                                       dp_client_handshake_timeout, dp_cli);
    if (dp_cli->timeout == NULL) {
        /* Connection is closed in the caller. */
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory, killing connection\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Set-up Backend ID timeout [%p]\n", dp_cli->timeout);

    /* Setup D-Bus interfaces and methods. */
    ret = sbus_conn_register_iface(conn, &iface_dp_client.vtable,
                                   DP_PATH, dp_cli);
    if (ret != EOK) {
        /* Connection is closed in the caller. */
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register D-Bus interface, "
              "killing connection [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    ret = dp_register_sbus_interface(conn, dp_cli);
    if (ret != EOK) {
        /* Connection is closed in the caller. */
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register D-Bus interface, "
              "killing connection [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return ret;
}

struct data_provider *
dp_client_provider(struct dp_client *dp_cli)
{
    if (dp_cli == NULL) {
        return NULL;
    }

    return dp_cli->provider;
}

struct be_ctx *
dp_client_be(struct dp_client *dp_cli)
{
    if (dp_cli == NULL || dp_cli->provider == NULL) {
        return NULL;
    }

    return dp_cli->provider->be_ctx;
}

struct sbus_connection *
dp_client_conn(struct dp_client *dp_cli)
{
    if (dp_cli == NULL) {
        return NULL;
    }

    return dp_cli->conn;
}
