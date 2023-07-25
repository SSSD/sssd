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
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/data_provider/dp.h"
#include "sbus/sbus_request.h"
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
        return "IFP";
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

errno_t
dp_client_register(TALLOC_CTX *mem_ctx,
                   struct sbus_request *sbus_req,
                   struct data_provider *provider,
                   const char *name)
{
    struct sbus_connection *cli_conn;
    struct dp_client *dp_cli;
    enum dp_clients client;

    cli_conn = sbus_server_find_connection(dp_sbus_server(provider),
                                           sbus_req->sender->name);
    if (cli_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown client: %s\n",
              sbus_req->sender->name);
        return ENOENT;
    }

    dp_cli = sbus_connection_get_data(cli_conn, struct dp_client);

    dp_cli->name = talloc_strdup(dp_cli, name);
    if (dp_cli->name == NULL) {
        talloc_free(dp_cli);
        return ENOMEM;
    }

    for (client = 0; client != DP_CLIENT_SENTINEL; client++) {
        if (strcasecmp(name, dp_client_to_string(client)) == 0) {
            provider->clients[client] = dp_cli;
            break;
        }
    }

    if (client == DP_CLIENT_SENTINEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown client! [%s]\n", name);
        return ENOENT;
    }

    talloc_set_destructor(dp_cli, dp_client_destructor);

    dp_cli->initialized = true;
    DEBUG(SSSDBG_CONF_SETTINGS, "Added Frontend client [%s]\n", name);
    DEBUG(SSSDBG_CONF_SETTINGS, "Cancel DP ID timeout [%p]\n", dp_cli->timeout);
    talloc_zfree(dp_cli->timeout);

    return EOK;
}

static void
dp_client_handshake_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t,
                            void *ptr)
{
    struct sbus_connection *conn;
    struct dp_client *dp_cli;
    const char *be_name;
    const char *name;

    dp_cli = talloc_get_type(ptr, struct dp_client);
    conn = dp_cli->conn;
    be_name = dp_cli->provider->be_ctx->sbus_name;

    talloc_set_destructor(dp_cli, NULL);

    name = sbus_connection_get_name(dp_cli->conn);
    if (name != NULL && strcmp(name, be_name) == 0) {
        /* This is the data provider connection. Just free the client record
         * but keep the connection opened. */
        talloc_zfree(dp_cli);
        return;
    }

    DEBUG(SSSDBG_OP_FAILURE,
          "Client [%s] timed out before identification [%p]!\n",
          name == NULL ? "unknown" : name, te);

    /* Kill the connection. */
    talloc_zfree(dp_cli);
    talloc_zfree(conn);
}

void dp_client_cancel_timeout(struct sbus_connection *conn)
{
    struct dp_client *dp_cli;

    dp_cli = sbus_connection_get_data(conn, struct dp_client);
    if (dp_cli != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Cancel DP client timeout [%p]\n", dp_cli->timeout);
        talloc_zfree(dp_cli->timeout);
    }
}

errno_t
dp_client_init(struct sbus_connection *cli_conn,
               struct data_provider *provider)
{
    struct dp_client *dp_cli;
    struct timeval tv;

    /* When connection is lost we also free the client. */
    dp_cli = talloc_zero(cli_conn, struct dp_client);
    if (dp_cli == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory, killing connection.\n");
        return ENOMEM;
    }

    dp_cli->provider = provider;
    dp_cli->conn = cli_conn;
    dp_cli->initialized = false;
    dp_cli->timeout = NULL;

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

    sbus_connection_set_data(cli_conn, dp_cli);

    return EOK;
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
