/*
    SSSD

    proxy_init.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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
#include "providers/proxy/proxy.h"
#include "sss_iface/sss_iface_async.h"

struct proxy_client {
    struct proxy_auth_ctx *proxy_auth_ctx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
};

errno_t
proxy_client_register(TALLOC_CTX *mem_ctx,
                      struct sbus_request *sbus_req,
                      struct proxy_auth_ctx *auth_ctx,
                      uint32_t cli_id)
{
    struct proxy_client *proxy_cli;
    struct proxy_child_ctx *child_ctx;
    struct pc_init_ctx *init_ctx;
    struct tevent_req *req;
    hash_value_t value;
    hash_key_t key;
    int hret;
    struct sbus_connection *cli_conn;

    /* When connection is lost we also free the client. */
    proxy_cli = talloc_zero(sbus_req->conn, struct proxy_client);
    if (proxy_cli == NULL) {
        return ENOMEM;
    }

    proxy_cli->proxy_auth_ctx = auth_ctx;
    proxy_cli->conn = sbus_req->conn;

    key.type = HASH_KEY_ULONG;
    key.ul = cli_id;
    if (!hash_has_key(proxy_cli->proxy_auth_ctx->request_table, &key)) {
        talloc_free(proxy_cli);
        return EIO;
    }

    hret = hash_lookup(proxy_cli->proxy_auth_ctx->request_table, &key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Hash error [%d]: %s\n", hret, hash_error_string(hret));
        talloc_free(proxy_cli);
        return EIO;
    }

    /* Signal that the child is up and ready to receive the request */
    req = talloc_get_type(value.ptr, struct tevent_req);
    child_ctx = tevent_req_data(req, struct proxy_child_ctx);

    if (!child_ctx->running) {
        /* This should hopefully be impossible, but protect
         * against it anyway. If we're not marked running, then
         * the init_req will be NULL below and things will
         * break.
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Client connection from a request "
              "that's not marked as running\n");
        talloc_free(proxy_cli);
        return EIO;
    }

    init_ctx = tevent_req_data(child_ctx->init_req, struct pc_init_ctx);
    init_ctx->conn = sbus_req->conn;
    tevent_req_done(child_ctx->init_req);
    child_ctx->init_req = NULL;

    /* Remove the timeout handler added by dp_client_init() */
    cli_conn = sbus_server_find_connection(dp_sbus_server(auth_ctx->be->provider),
                                           sbus_req->sender->name);
    if (cli_conn != NULL) {
        dp_client_cancel_timeout(cli_conn);
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "No connection found for [%s].\n", sbus_req->sender->name);
    }

    return EOK;
}

errno_t
proxy_client_init(struct sbus_connection *conn,
                  struct proxy_auth_ctx *auth_ctx)
{
    errno_t ret;

    SBUS_INTERFACE(iface,
        sssd_ProxyChild_Client,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_ProxyChild_Client, Register, proxy_client_register, auth_ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    struct sbus_path paths[] = {
        {SSS_BUS_PATH, &iface},
        {NULL, NULL}
    };

    ret = sbus_connection_add_path_map(conn, paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to add paths [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}
