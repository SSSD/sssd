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
#include "providers/proxy/proxy_iface_generated.h"
#include "providers/proxy/proxy.h"

struct proxy_client {
    struct proxy_auth_ctx *proxy_auth_ctx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
    bool initialized;
};

static int proxy_client_register(struct sbus_request *sbus_req,
                                 void *data,
                                 uint32_t cli_id)
{
    struct sbus_connection *conn;
    struct proxy_client *proxy_cli;
    int hret;
    hash_key_t key;
    hash_value_t value;
    struct tevent_req *req;
    struct proxy_child_ctx *child_ctx;
    struct pc_init_ctx *init_ctx;

    conn = sbus_req->conn;
    proxy_cli = talloc_get_type(data, struct proxy_client);
    if (proxy_cli == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Connection holds no valid init data\n");
        return EINVAL;
    }

    /* First thing, cancel the timeout */
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Cancel proxy client ID timeout [%p]\n", proxy_cli->timeout);
    talloc_zfree(proxy_cli->timeout);

    DEBUG(SSSDBG_FUNC_DATA, "Proxy client [%"PRIu32"] connected\n", cli_id);

    /* Check the hash table */
    key.type = HASH_KEY_ULONG;
    key.ul = cli_id;
    if (!hash_has_key(proxy_cli->proxy_auth_ctx->request_table, &key)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown child ID. Killing the connection\n");
        sbus_disconnect(proxy_cli->conn);
        return EIO;
    }

    iface_proxy_client_Register_finish(sbus_req);

    hret = hash_lookup(proxy_cli->proxy_auth_ctx->request_table, &key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Hash error [%d]: %s\n", hret, hash_error_string(hret));
        sbus_disconnect(conn);
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
        return EIO;
    }

    init_ctx = tevent_req_data(child_ctx->init_req, struct pc_init_ctx);
    init_ctx->conn = conn;
    tevent_req_done(child_ctx->init_req);
    child_ctx->init_req = NULL;

    return EOK;
}

static void proxy_client_timeout(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval t,
                                 void *ptr)
{
    struct proxy_client *proxy_cli;

    DEBUG(SSSDBG_OP_FAILURE,
          "Client timed out before Identification [%p]!\n", te);

    proxy_cli = talloc_get_type(ptr, struct proxy_client);

    sbus_disconnect(proxy_cli->conn);
    talloc_zfree(proxy_cli);

    /* If we time out here, we will also time out to
     * pc_init_timeout(), so we'll finish the request
     * there.
     */
}

int proxy_client_init(struct sbus_connection *conn, void *data)
{
    struct proxy_auth_ctx *auth_ctx;
    struct proxy_client *proxy_cli;
    struct timeval tv;
    errno_t ret;

    static struct iface_proxy_client iface_proxy_client = {
        { &iface_proxy_client_meta, 0 },

        .Register = proxy_client_register,
    };

    auth_ctx = talloc_get_type(data, struct proxy_auth_ctx);

    /* When connection is lost we also free the client. */
    proxy_cli = talloc_zero(conn, struct proxy_client);
    if (proxy_cli == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory, killing connection.\n");
        talloc_free(conn);
        return ENOMEM;
    }

    proxy_cli->proxy_auth_ctx = auth_ctx;
    proxy_cli->conn = conn;
    proxy_cli->initialized = false;

    /* Setup timeout in case client fails to register himself in time. */
    tv = tevent_timeval_current_ofs(5, 0);
    proxy_cli->timeout = tevent_add_timer(auth_ctx->be->ev, proxy_cli, tv,
                                          proxy_client_timeout, proxy_cli);
    if (proxy_cli->timeout == NULL) {
        /* Connection is closed in the caller. */
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory, killing connection\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Set-up proxy client ID timeout [%p]\n", proxy_cli->timeout);

    /* Setup D-Bus interfaces and methods. */
    ret = sbus_conn_register_iface(conn, &iface_proxy_client.vtable,
                                   PROXY_CHILD_PATH, proxy_cli);
    if (ret != EOK) {
        /* Connection is closed in the caller. */
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register D-Bus interface, "
              "killing connection [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return ret;
}
