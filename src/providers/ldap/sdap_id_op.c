/*
    SSSD

    LDAP ID backend operation retry logic and connection cache

    Authors:
        Eugene Indenbom <eindenbom@gmail.com>

    Copyright (C) 2008-2010 Red Hat

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

#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_id_op.h"
#include "util/sss_chain_id.h"

/* LDAP async connection cache */
struct sdap_id_conn_cache {
    struct sdap_id_conn_ctx *id_conn;

    /* list of all open connections */
    struct sdap_id_conn_data *connections;
    /* cached (current) connection */
    struct sdap_id_conn_data *cached_connection;
};

/* LDAP async operation tracker:
 *  - keeps track of connection usage
 *  - keeps track of operation retries */
struct sdap_id_op {
    /* ID backend context */
    struct sdap_id_conn_cache *conn_cache;
    /* double linked list pointers */
    struct sdap_id_op *prev, *next;
    /* current connection */
    struct sdap_id_conn_data *conn_data;
    /* number of reconnects for this operation */
    int reconnect_retry_count;
    /* connection request
     * It is required as we need to know which requests to notify
     * when shared connection request to sdap_handle completes.
     * This member is cleared when sdap_id_op_connect_state
     * associated with request is destroyed */
    struct tevent_req *connect_req;

    /* chain id of the request that created this op */
    uint64_t chain_id;
};

/* LDAP connection cache connection attempt/established connection data */
struct sdap_id_conn_data {
    /* LDAP connection cache */
    struct sdap_id_conn_cache *conn_cache;
    /* double linked list pointers */
    struct sdap_id_conn_data *prev, *next;
    /* sdap handle */
    struct sdap_handle *sh;
    /* connection request */
    struct tevent_req *connect_req;
    /* timer for connection expiration */
    struct tevent_timer *expire_timer;
    /* timer for idle connection expiration */
    struct tevent_timer *idle_timer;
    /* number of running connection notifies */
    int notify_lock;
    /* list of operations using connect */
    struct sdap_id_op *ops;
    /* A flag which is signalizing that this
     * connection will be disconnected and should
     * not be used any more */
    bool disconnecting;
};

static void sdap_id_conn_cache_be_offline_cb(void *pvt);
static void sdap_id_conn_cache_fo_reconnect_cb(void *pvt);

static void sdap_id_release_conn_data(struct sdap_id_conn_data *conn_data);
static int sdap_id_conn_data_destroy(struct sdap_id_conn_data *conn_data);
static bool sdap_is_connection_expired(struct sdap_id_conn_data *conn_data, int timeout);
static bool sdap_can_reuse_connection(struct sdap_id_conn_data *conn_data);
static void sdap_id_conn_data_expire_handler(struct tevent_context *ev,
                                             struct tevent_timer *te,
                                             struct timeval current_time,
                                             void *pvt);
static int sdap_id_conn_data_set_expire_timer(struct sdap_id_conn_data *conn_data);
static void sdap_id_conn_data_idle_handler(struct tevent_context *ev,
                                           struct tevent_timer *te,
                                           struct timeval current_time,
                                           void *pvt);
static int sdap_id_conn_data_start_idle_timer(struct sdap_id_conn_data *conn_data);
static void sdap_id_conn_data_not_idle(struct sdap_id_conn_data *conn_data);
static void sdap_id_conn_data_idle(struct sdap_id_conn_data *conn_data);

static void sdap_id_op_hook_conn_data(struct sdap_id_op *op, struct sdap_id_conn_data *conn_data);
static int sdap_id_op_destroy(void *pvt);
static bool sdap_id_op_can_reconnect(struct sdap_id_op *op);

static void sdap_id_op_connect_req_complete(struct sdap_id_op *op, int dp_error, int ret);
static int sdap_id_op_connect_state_destroy(void *pvt);
static int sdap_id_op_connect_step(struct tevent_req *req);
static void sdap_id_op_connect_done(struct tevent_req *subreq);

/* Create a connection cache */
int sdap_id_conn_cache_create(TALLOC_CTX *memctx,
                              struct sdap_id_conn_ctx *id_conn,
                              struct sdap_id_conn_cache** conn_cache_out)
{
    int ret;
    struct sdap_id_conn_cache *conn_cache = talloc_zero(memctx, struct sdap_id_conn_cache);
    if (!conn_cache) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "talloc_zero(struct sdap_id_conn_cache) failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    conn_cache->id_conn = id_conn;

    ret = be_add_offline_cb(conn_cache, id_conn->id_ctx->be,
                            sdap_id_conn_cache_be_offline_cb, conn_cache,
                            NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_add_offline_cb failed.\n");
        goto fail;
    }

    ret = be_add_reconnect_cb(conn_cache, id_conn->id_ctx->be,
                              sdap_id_conn_cache_fo_reconnect_cb, conn_cache,
                              NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_add_reconnect_cb failed.\n");
        goto fail;
    }

    *conn_cache_out = conn_cache;
    return EOK;

fail:
    talloc_zfree(conn_cache);
    return ret;
}

/* Callback on BE going offline */
static void sdap_id_conn_cache_be_offline_cb(void *pvt)
{
    struct sdap_id_conn_cache *conn_cache = talloc_get_type(pvt, struct sdap_id_conn_cache);
    struct sdap_id_conn_data *cached_connection = conn_cache->cached_connection;

    /* Release any cached connection on going offline */
    if (cached_connection != NULL) {
        conn_cache->cached_connection = NULL;
        sdap_id_release_conn_data(cached_connection);
    }
}

/* Callback for attempt to reconnect to primary server */
static void sdap_id_conn_cache_fo_reconnect_cb(void *pvt)
{
    struct sdap_id_conn_cache *conn_cache = talloc_get_type(pvt, struct sdap_id_conn_cache);
    struct sdap_id_conn_data *cached_connection = conn_cache->cached_connection;

    /* Release any cached connection on going offline */
    if (cached_connection != NULL) {
        cached_connection->disconnecting = true;
    }
}

/* Release sdap_id_conn_data and destroy it if no longer needed */
static void sdap_id_release_conn_data(struct sdap_id_conn_data *conn_data)
{
    ber_socket_t fd = -1;
    Sockbuf *sb;
    int ret;
    struct sdap_id_conn_cache *conn_cache;
    if (!conn_data || conn_data->ops || conn_data->notify_lock) {
        /* connection is in use */
        return;
    }

    conn_cache = conn_data->conn_cache;
    if (conn_data == conn_cache->cached_connection) {
        return;
    }

    if (conn_data->sh && conn_data->sh->ldap) {
        ret = ldap_get_option(conn_data->sh->ldap, LDAP_OPT_SOCKBUF, &sb);
        if (ret == LDAP_OPT_SUCCESS) {
            if (ber_sockbuf_ctrl(sb, LBER_SB_OPT_GET_FD, &fd) != 1) {
                fd = -1;
            }
        }
    }

    DEBUG(SSSDBG_TRACE_ALL, "Releasing unused connection with fd [%d]\n", fd);

    DLIST_REMOVE(conn_cache->connections, conn_data);
    talloc_zfree(conn_data);
}

/* Destructor for struct sdap_id_conn_data */
static int sdap_id_conn_data_destroy(struct sdap_id_conn_data *conn_data)
{
    struct sdap_id_op *op;

    /* we clean out list of ops to make sure that order of destruction does not matter */
    while ((op = conn_data->ops) != NULL) {
        op->conn_data = NULL;
        DLIST_REMOVE(conn_data->ops, op);
    }

    return 0;
}

/* Check whether connection will expire after timeout seconds */
static bool sdap_is_connection_expired(struct sdap_id_conn_data *conn_data, int timeout)
{
    time_t expire_time;
    if (!conn_data || !conn_data->sh || !conn_data->sh->connected) {
        return true;
    }

    expire_time = conn_data->sh->expire_time;
    if ((expire_time != 0) && (expire_time < time( NULL ) + timeout) ) {
        return true;
    }

    return false;
}

/* Check whether connection can be reused for next LDAP ID operation */
static bool sdap_can_reuse_connection(struct sdap_id_conn_data *conn_data)
{
    int timeout;

    if (!conn_data || !conn_data->sh ||
        !conn_data->sh->connected || conn_data->disconnecting) {
        return false;
    }

    timeout = dp_opt_get_int(conn_data->conn_cache->id_conn->id_ctx->opts->basic,
                             SDAP_OPT_TIMEOUT);
    return !sdap_is_connection_expired(conn_data, timeout);
}

/* Set expiration timer for connection if needed */
static int sdap_id_conn_data_set_expire_timer(struct sdap_id_conn_data *conn_data)
{
    int timeout;
    struct timeval tv;

    talloc_zfree(conn_data->expire_timer);

    memset(&tv, 0, sizeof(tv));

    tv.tv_sec = conn_data->sh->expire_time;
    if (tv.tv_sec <= 0) {
        return EOK;
    }

    timeout = dp_opt_get_int(conn_data->conn_cache->id_conn->id_ctx->opts->basic,
                             SDAP_OPT_TIMEOUT);
    if (timeout > 0) {
        tv.tv_sec -= timeout;
    }

    if (tv.tv_sec <= time(NULL)) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Not starting expire timer because connection is already expired\n");
        return EOK;
    }

    conn_data->expire_timer =
              tevent_add_timer(conn_data->conn_cache->id_conn->id_ctx->be->ev,
                               conn_data, tv,
                               sdap_id_conn_data_expire_handler,
                               conn_data);
    if (!conn_data->expire_timer) {
        return ENOMEM;
    }

    return EOK;
}

/* Handler for connection expiration timer */
static void sdap_id_conn_data_expire_handler(struct tevent_context *ev,
                                              struct tevent_timer *te,
                                              struct timeval current_time,
                                              void *pvt)
{
    struct sdap_id_conn_data *conn_data = talloc_get_type(pvt,
                                                          struct sdap_id_conn_data);
    struct sdap_id_conn_cache *conn_cache = conn_data->conn_cache;

    if (conn_cache->cached_connection == conn_data) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Connection is about to expire, releasing it\n");
        conn_cache->cached_connection = NULL;
        sdap_id_release_conn_data(conn_data);
    }
}

/* We could simply cancel the idle timer at the beginning of every operation
 * then reschedule it at the end of every operation.  However, to reduce the
 * overhead associated with canceling and rescheduling the timer, we instead
 * update conn_data->sh->idle_time at the beginning and end of each operation,
 * then have the timer handler check idle_time and reschedule the timer as
 * needed.
 *
 * Note that sdap_id_conn_data_not_idle() and/or sdap_id_conn_data_idle() may be
 * called before sdap_id_conn_data_start_idle_timer() is called for a particular
 * connection.
 */

/* Start idle timer for connection if needed */
static int sdap_id_conn_data_start_idle_timer(struct sdap_id_conn_data *conn_data)
{
    time_t now;
    int idle_timeout;
    struct timeval tv;

    now = time(NULL);
    conn_data->sh->idle_time = now;

    talloc_zfree(conn_data->idle_timer);

    idle_timeout = dp_opt_get_int(conn_data->conn_cache->id_conn->id_ctx->opts->basic,
                                  SDAP_IDLE_TIMEOUT);
    conn_data->sh->idle_timeout = idle_timeout;
    DEBUG(SSSDBG_CONF_SETTINGS, "idle timeout is %d\n", idle_timeout);
    if (idle_timeout <= 0) {
        return EOK;
    }

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = now + idle_timeout;
    DEBUG(SSSDBG_TRACE_ALL,
          "Scheduling connection idle timer to run at %"SPRItime"\n", tv.tv_sec);

    conn_data->idle_timer =
              tevent_add_timer(conn_data->conn_cache->id_conn->id_ctx->be->ev,
                               conn_data, tv,
                               sdap_id_conn_data_idle_handler,
                               conn_data);
    if (!conn_data->idle_timer) {
        return ENOMEM;
    }

    return EOK;
}

/* Handler for idle connection expiration timer */
static void sdap_id_conn_data_idle_handler(struct tevent_context *ev,
                                           struct tevent_timer *te,
                                           struct timeval current_time,
                                           void *pvt)
{
    struct sdap_id_conn_data *conn_data = talloc_get_type(pvt,
                                                          struct sdap_id_conn_data);
    struct sdap_id_conn_cache *conn_cache = conn_data->conn_cache;

    time_t now;
    time_t idle_time;
    int idle_timeout;
    struct timeval tv;

    if (conn_cache->cached_connection != conn_data) {
        DEBUG(SSSDBG_TRACE_ALL, "Abandoning idle timer for released connection\n");
        return;
    }

    now = time(NULL);
    idle_time = conn_data->sh->idle_time;
    idle_timeout = conn_data->sh->idle_timeout;

    if (idle_time != 0 && idle_time + idle_timeout <= now) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Connection has reached idle timeout, releasing it\n");
        conn_cache->cached_connection = NULL;
        sdap_id_release_conn_data(conn_data);
        return;
    }

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = (idle_time == 0 ? now : idle_time) + idle_timeout;
    DEBUG(SSSDBG_TRACE_ALL,
          "Rescheduling connection idle timer to run at %"SPRItime"\n", tv.tv_sec);

    conn_data->idle_timer =
              tevent_add_timer(conn_data->conn_cache->id_conn->id_ctx->be->ev,
                               conn_data, tv,
                               sdap_id_conn_data_idle_handler,
                               conn_data);
    if (!conn_data->idle_timer) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_id_conn_data_idle_handler() failed to reschedule connection idle timer");
    }
}

/* Mark connection as not idle */
static void sdap_id_conn_data_not_idle(struct sdap_id_conn_data *conn_data)
{
    if (conn_data && conn_data->sh) {
        DEBUG(SSSDBG_TRACE_ALL, "Marking connection as not idle\n");
        conn_data->sh->idle_time = 0;
    }
}

/* Mark connection as idle */
static void sdap_id_conn_data_idle(struct sdap_id_conn_data *conn_data)
{
    if (conn_data && conn_data->sh) {
        DEBUG(SSSDBG_TRACE_ALL, "Marking connection as idle\n");
        conn_data->sh->idle_time = time(NULL);
    }
}

/* Create an operation object */
struct sdap_id_op *sdap_id_op_create(TALLOC_CTX *memctx, struct sdap_id_conn_cache *conn_cache)
{
    struct sdap_id_op *op = talloc_zero(memctx, struct sdap_id_op);
    if (!op) {
        return NULL;
    }

    op->conn_cache = conn_cache;

    /* Remember the current chain id so we can use it when connection is
     * established. This is required since the connection might be done
     * by other request that was called before. */
    op->chain_id = sss_chain_id_get();

    talloc_set_destructor((void*)op, sdap_id_op_destroy);
    return op;
}

/* Attach/detach connection to sdap_id_op */
static void sdap_id_op_hook_conn_data(struct sdap_id_op *op, struct sdap_id_conn_data *conn_data)
{
    struct sdap_id_conn_data *current;

    if (!op) {
        DEBUG(SSSDBG_FATAL_FAILURE, "NULL op passed!!!\n");
        return;
    }

    current = op->conn_data;
    if (conn_data == current) {
        return;
    }

    if (current) {
        DLIST_REMOVE(current->ops, op);
    }

    op->conn_data = conn_data;

    if (conn_data) {
        sdap_id_conn_data_not_idle(conn_data);
        DLIST_ADD_END(conn_data->ops, op, struct sdap_id_op*);
    }

    if (current && !current->ops) {
        if (current == current->conn_cache->cached_connection) {
            sdap_id_conn_data_idle(current);
        } else {
            sdap_id_release_conn_data(current);
        }
    }
}

/* Destructor for sdap_id_op */
static int sdap_id_op_destroy(void *pvt)
{
    struct sdap_id_op *op = talloc_get_type(pvt, struct sdap_id_op);

    if (op->conn_data) {
        DEBUG(SSSDBG_TRACE_ALL, "releasing operation connection\n");
        sdap_id_op_hook_conn_data(op, NULL);
    }

    return 0;
}

/* Check whether retry with reconnect can be performed for the operation */
static bool sdap_id_op_can_reconnect(struct sdap_id_op *op)
{
    /* we allow 2 retries for failover server configured:
     *   - one for connection broken during request execution
     *   - one for the following (probably failed) reconnect attempt */
    int max_retries;
    int count;

    count = be_fo_get_server_count(op->conn_cache->id_conn->id_ctx->be,
                                   op->conn_cache->id_conn->service->name);
    max_retries = 2 * count -1;
    if (max_retries < 1) {
        max_retries = 1;
    }

    return op->reconnect_retry_count < max_retries;
}

/* state of connect request */
struct sdap_id_op_connect_state {
    struct sdap_id_conn_ctx *id_conn;
    struct tevent_context *ev;
    struct sdap_id_op *op;
    int dp_error;
    int result;
};

/* Destructor for operation connection request */
static int sdap_id_op_connect_state_destroy(void *pvt)
{
    struct sdap_id_op_connect_state *state = talloc_get_type(pvt,
                                             struct sdap_id_op_connect_state);
    if (state->op != NULL) {
        /* clear destroyed connection request */
        state->op->connect_req = NULL;
    }

    return 0;
}

/* Begin to connect to LDAP server */
struct tevent_req *sdap_id_op_connect_send(struct sdap_id_op *op,
                                           TALLOC_CTX *memctx,
                                           int *ret_out)
{
    struct tevent_req *req = NULL;
    struct sdap_id_op_connect_state *state;
    int ret = EOK;

    if (!memctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: no memory context passed.\n");
        ret = EINVAL;
        goto done;
    }

    if (op->connect_req) {
        /* Connection already in progress, invalid operation */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Bug: connection request is already running or completed and leaked.\n");
        ret = EINVAL;
        goto done;
    }

    req = tevent_req_create(memctx, &state, struct sdap_id_op_connect_state);
    if (!req) {
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor((void*)state, sdap_id_op_connect_state_destroy);

    state->id_conn = op->conn_cache->id_conn;
    state->ev = state->id_conn->id_ctx->be->ev;
    state->op = op;
    op->connect_req = req;

    if (op->conn_data) {
        /* If the operation is already connected,
         * reuse existing connection regardless of its status */
        DEBUG(SSSDBG_TRACE_ALL, "reusing operation connection\n");
        ret = EOK;
        goto done;
    }

    ret = sdap_id_op_connect_step(req);
    if (ret != EOK) {
        goto done;
    }

done:
    if (ret != EOK) {
        talloc_zfree(req);
    } else if (op->conn_data && !op->conn_data->connect_req) {
        /* Connection is already established */
        tevent_req_done(req);
        tevent_req_post(req, state->ev);
    }

    if (ret_out) {
        *ret_out = ret;
    }

    return req;
}

/* Begin a connection retry to LDAP server */
static int sdap_id_op_connect_step(struct tevent_req *req)
{
    struct sdap_id_op_connect_state *state =
                    tevent_req_data(req, struct sdap_id_op_connect_state);
    struct sdap_id_op *op = state->op;
    struct sdap_id_conn_cache *conn_cache = op->conn_cache;

    int ret = EOK;
    struct sdap_id_conn_data *conn_data;
    struct tevent_req *subreq = NULL;

    /* Try to reuse context cached connection */
    conn_data = conn_cache->cached_connection;
    if (conn_data) {
        if (conn_data->connect_req) {
            DEBUG(SSSDBG_TRACE_ALL, "waiting for connection to complete\n");
            sdap_id_op_hook_conn_data(op, conn_data);
            goto done;
        }

        if (sdap_can_reuse_connection(conn_data)) {
            DEBUG(SSSDBG_TRACE_ALL, "reusing cached connection\n");
            sdap_id_op_hook_conn_data(op, conn_data);
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL, "releasing expired cached connection\n");
        conn_cache->cached_connection = NULL;
        sdap_id_release_conn_data(conn_data);
    }

    DEBUG(SSSDBG_TRACE_ALL, "beginning to connect\n");

    conn_data = talloc_zero(conn_cache, struct sdap_id_conn_data);
    if (!conn_data) {
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor(conn_data, sdap_id_conn_data_destroy);

    conn_data->conn_cache = conn_cache;
    subreq = sdap_cli_connect_send(conn_data, state->ev,
                                   state->id_conn->id_ctx->opts,
                                   state->id_conn->id_ctx->be,
                                   state->id_conn->service, false,
                                   CON_TLS_DFL, false);

    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_id_op_connect_done, conn_data);
    conn_data->connect_req = subreq;

    DLIST_ADD(conn_cache->connections, conn_data);
    conn_cache->cached_connection = conn_data;

    sdap_id_op_hook_conn_data(op, conn_data);

done:
    if (ret != EOK && conn_data) {
        sdap_id_release_conn_data(conn_data);
    }

    if (ret != EOK) {
        talloc_zfree(subreq);
    }

    return ret;
}

static void sdap_id_op_connect_reinit_done(struct tevent_req *req);

/* Subrequest callback for connection completion */
static void sdap_id_op_connect_done(struct tevent_req *subreq)
{
    struct sdap_id_conn_data *conn_data =
                tevent_req_callback_data(subreq, struct sdap_id_conn_data);
    struct sdap_id_conn_cache *conn_cache = conn_data->conn_cache;
    struct sdap_server_opts *srv_opts = NULL;
    struct sdap_server_opts *current_srv_opts = NULL;
    bool can_retry = false;
    bool is_offline = false;
    struct tevent_req *reinit_req = NULL;
    bool reinit = false;
    int ret;
    int ret_nonfatal;

    ret = sdap_cli_connect_recv(subreq, conn_data, &can_retry,
                                &conn_data->sh, &srv_opts);
    conn_data->connect_req = NULL;
    talloc_zfree(subreq);

    conn_data->notify_lock++;

    if (ret == ENOTSUP) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Authentication mechanism not Supported by server\n");
    }

    if (ret == EOK && (!conn_data->sh || !conn_data->sh->connected)) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "sdap_cli_connect_recv returned bogus connection\n");
        ret = EFAULT;
    }

    if (ret != EOK && !can_retry) {
        if (conn_cache->id_conn->ignore_mark_offline) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Failed to connect to server, but ignore mark offline "
                   "is enabled.\n");
        } else {
            /* be is going offline as there is no more servers to try */
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect, going offline (%d [%s])\n",
                   ret, strerror(ret));
            is_offline = true;
            be_mark_offline(conn_cache->id_conn->id_ctx->be);
        }
    }

    if (ret == EOK) {
        current_srv_opts = conn_cache->id_conn->id_ctx->srv_opts;
        if (current_srv_opts) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Old USN: %lu, New USN: %lu\n", current_srv_opts->last_usn, srv_opts->last_usn);

            if (strcmp(srv_opts->server_id, current_srv_opts->server_id) == 0
                    && srv_opts->supports_usn
                    && current_srv_opts->last_usn > srv_opts->last_usn) {
                DEBUG(SSSDBG_FUNC_DATA, "Server was probably re-initialized\n");

                current_srv_opts->max_user_value = 0;
                current_srv_opts->max_group_value = 0;
                current_srv_opts->max_service_value = 0;
                current_srv_opts->max_sudo_value = 0;
                current_srv_opts->max_iphost_value = 0;
                current_srv_opts->max_ipnetwork_value = 0;
                current_srv_opts->last_usn = srv_opts->last_usn;

                reinit = true;
            }
        }
        ret_nonfatal = sdap_id_conn_data_set_expire_timer(conn_data);
        if (ret_nonfatal != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "sdap_id_conn_data_set_expire_timer() failed [%d]: %s",
                  ret_nonfatal, sss_strerror(ret_nonfatal));
        }
        ret_nonfatal = sdap_id_conn_data_start_idle_timer(conn_data);
        if (ret_nonfatal != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "sdap_id_conn_data_start_idle_timer() failed [%d]: %s",
                  ret_nonfatal, sss_strerror(ret_nonfatal));
        }
        sdap_steal_server_opts(conn_cache->id_conn->id_ctx, &srv_opts);
    }

    if (can_retry) {
        switch (ret) {
            case EOK:
            case ENOTSUP:
            case EACCES:
            case EIO:
            case EFAULT:
            case ETIMEDOUT:
            case ERR_AUTH_FAILED:
                break;

            default:
                /* do not attempt to retry on errors like ENOMEM */
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Marking the backend \"%s\" offline [%d]: %s\n",
                      conn_cache->id_conn->id_ctx->be->domain->name,
                      ret, sss_strerror(ret));
                can_retry = false;
                is_offline = true;
                be_mark_offline(conn_cache->id_conn->id_ctx->be);
                break;
        }
    }

    int notify_count = 0;

    /* Notify about connection */
    for(;;) {
        struct sdap_id_op *op;

        if (ret == EOK && !conn_data->sh->connected) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "connection was broken after %d notifies\n", notify_count);
        }

        DLIST_FOR_EACH(op, conn_data->ops) {
            if (op->connect_req) {
                break;
            }
        }

        if (!op) {
            break;
        }

        /* another operation to notify */
        notify_count++;

        if (ret != EOK || !conn_data->sh->connected) {
            /* failed to connect or connection got broken during notify */
            bool retry = false;

            /* drop connection from cache now */
            if (conn_cache->cached_connection == conn_data) {
                conn_cache->cached_connection = NULL;
            }

            if (can_retry) {
                /* determining whether retry is possible */
                if (be_is_offline(conn_cache->id_conn->id_ctx->be)) {
                    /* be is offline, no retry possible */
                    if (ret == EOK) {
                        DEBUG(SSSDBG_TRACE_ALL,
                              "skipping automatic retry on op #%d as be is offline\n", notify_count);
                        ret = EIO;
                    }

                    can_retry = false;
                    is_offline = true;
                } else {
                    if (ret == EOK) {
                        DEBUG(SSSDBG_TRACE_ALL,
                              "attempting automatic retry on op #%d\n", notify_count);
                        retry = true;
                    } else if (sdap_id_op_can_reconnect(op)) {
                        DEBUG(SSSDBG_TRACE_ALL,
                              "attempting failover retry on op #%d\n", notify_count);
                        op->reconnect_retry_count++;
                        retry = true;
                    }
                }
            }

            if (retry && op->connect_req) {
                int retry_ret = sdap_id_op_connect_step(op->connect_req);
                if (retry_ret != EOK) {
                    can_retry = false;
                    sdap_id_op_connect_req_complete(op, DP_ERR_FATAL, retry_ret);
                }

                continue;
            }
        }

        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "notify connected to op #%d\n", notify_count);
            sdap_id_op_connect_req_complete(op, DP_ERR_OK, ret);
        } else if (is_offline) {
            DEBUG(SSSDBG_TRACE_ALL, "notify offline to op #%d\n", notify_count);
            sdap_id_op_connect_req_complete(op, DP_ERR_OFFLINE, EAGAIN);
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "notify error to op #%d: %d [%s]\n", notify_count, ret, strerror(ret));
            sdap_id_op_connect_req_complete(op, DP_ERR_FATAL, ret);
        }
    }

    /* all operations notified */
    if (conn_data->notify_lock > 0) {
        conn_data->notify_lock--;
    }

    if ((ret == EOK)
            && conn_data->sh->connected
            && !be_is_offline(conn_cache->id_conn->id_ctx->be)) {
        DEBUG(SSSDBG_TRACE_ALL,
              "caching successful connection after %d notifies\n", notify_count);
        conn_cache->cached_connection = conn_data;

        /* Run any post-connection routines */
        be_run_unconditional_online_cb(conn_cache->id_conn->id_ctx->be);
        be_run_online_cb(conn_cache->id_conn->id_ctx->be);

    } else {
        if (conn_cache->cached_connection == conn_data) {
            conn_cache->cached_connection = NULL;
        }

        sdap_id_release_conn_data(conn_data);
    }

    if (reinit) {
        DEBUG(SSSDBG_TRACE_FUNC, "Server reinitialization detected. "
                                  "Cleaning cache.\n");
        reinit_req = sdap_reinit_cleanup_send(conn_cache->id_conn->id_ctx->be,
                                              conn_cache->id_conn->id_ctx->be,
                                              conn_cache->id_conn->id_ctx);
        if (reinit_req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to perform reinitialization "
                                        "clean up.\n");
            return;
        }

        tevent_req_set_callback(reinit_req, sdap_id_op_connect_reinit_done,
                                NULL);
    }
}

static void sdap_id_op_connect_reinit_done(struct tevent_req *req)
{
    errno_t ret;

    ret = sdap_reinit_cleanup_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to perform reinitialization "
              "clean up [%d]: %s\n", ret, strerror(ret));
        /* not fatal */
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Reinitialization clean up completed\n");
}

/* Mark operation connection request as complete */
static void sdap_id_op_connect_req_complete(struct sdap_id_op *op, int dp_error, int ret)
{
    struct tevent_req *req = op->connect_req;
    struct sdap_id_op_connect_state *state;
    uint64_t old_chain_id;

    if (!req) {
        return;
    }

    op->connect_req = NULL;

    state = tevent_req_data(req, struct sdap_id_op_connect_state);
    state->dp_error = dp_error;
    state->result = ret;

    /* Set the chain id to the one associated with this request. */
    old_chain_id = sss_chain_id_set(op->chain_id);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        sdap_id_op_hook_conn_data(op, NULL);
        tevent_req_error(req, ret);
    }
    sss_chain_id_set(old_chain_id);
}

/* Get the result of an asynchronous connect operation on sdap_id_op
 *
 * In dp_error data provider error code is returned:
 *   DP_ERR_OK - connection established
 *   DP_ERR_OFFLINE - backend is offline, operation result is set EAGAIN
 *   DP_ERR_FATAL - operation failed
 */
int sdap_id_op_connect_recv(struct tevent_req *req, int *dp_error)
{
    struct sdap_id_op_connect_state *state = tevent_req_data(req,
                                                             struct sdap_id_op_connect_state);

    *dp_error = state->dp_error;
    return state->result;
}

/* Report completion of LDAP operation and release associated connection.
 * Returns operation result (possible updated) passed in ret parameter.
 *
 * In dp_error data provider error code is returned:
 *   DP_ERR_OK (operation result = EOK) - operation completed
 *   DP_ERR_OK (operation result != EOK) - operation can be retried
 *   DP_ERR_OFFLINE - backend is offline, operation result is set EAGAIN
 *   DP_ERR_FATAL - operation failed */
int sdap_id_op_done(struct sdap_id_op *op, int retval, int *dp_err_out)
{
    bool communication_error;
    struct sdap_id_conn_data *current_conn = op->conn_data;
    switch (retval) {
        case EIO:
        case ETIMEDOUT:
            /* this currently the only possible communication error after connection is established */
            communication_error = true;
            break;

        default:
            communication_error = false;
            break;
    }

    if (communication_error && current_conn != 0
            && current_conn == op->conn_cache->cached_connection) {
        /* do not reuse failed connection */
        op->conn_cache->cached_connection = NULL;

        DEBUG(SSSDBG_FUNC_DATA,
              "communication error on cached connection, moving to next server\n");
        be_fo_try_next_server(op->conn_cache->id_conn->id_ctx->be,
                              op->conn_cache->id_conn->service->name);
    }

    int dp_err;
    if (retval == EOK) {
        dp_err = DP_ERR_OK;
    } else if (be_is_offline(op->conn_cache->id_conn->id_ctx->be)) {
        /* if backend is already offline, just report offline, do not duplicate errors */
        dp_err = DP_ERR_OFFLINE;
        retval = EAGAIN;
        DEBUG(SSSDBG_TRACE_ALL, "falling back to offline data...\n");
    } else if (communication_error) {
        /* communication error, can try to reconnect */

        if (!sdap_id_op_can_reconnect(op)) {
            dp_err = DP_ERR_FATAL;
            DEBUG(SSSDBG_TRACE_ALL,
                  "too many communication failures, giving up...\n");
        } else {
            dp_err = DP_ERR_OK;
            retval = EAGAIN;
        }
    } else {
        dp_err = DP_ERR_FATAL;
    }

    if (dp_err == DP_ERR_OK && retval != EOK) {
        /* reconnect retry */
        op->reconnect_retry_count++;
        DEBUG(SSSDBG_TRACE_ALL,
              "advising for connection retry #%i\n", op->reconnect_retry_count);
    } else {
        /* end of request */
        op->reconnect_retry_count = 0;
    }

    if (current_conn) {
        DEBUG(SSSDBG_TRACE_ALL, "releasing operation connection\n");
        sdap_id_op_hook_conn_data(op, NULL);
    }

    *dp_err_out = dp_err;
    return retval;
}

/* Get SDAP handle associated with operation by sdap_id_op_connect */
struct sdap_handle *sdap_id_op_handle(struct sdap_id_op *op)
{
    return op && op->conn_data ? op->conn_data->sh : NULL;
}
