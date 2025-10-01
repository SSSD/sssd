/*
    Copyright (C) 2025 Red Hat

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
#include <tevent.h>

#include "config.h"
#include "providers/failover/failover_transaction.h"
#include "providers/failover/failover_vtable_op.h"
#include "util/util.h"

errno_t
sss_failover_transaction_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct sss_failover_ctx *fctx,
                              struct tevent_req *caller_req,
                              tevent_req_fn connected_callback)
{
    return sss_failover_transaction_ex_send(mem_ctx, ev, fctx, caller_req,
                                            connected_callback, true, true, true,
                                            SSS_FAILOVER_TRANSACTION_TLS_DEFAULT);
}

struct sss_failover_transaction_connected_state {
    struct sss_failover_ctx *fctx;
};

struct sss_failover_transaction_state {
    struct tevent_context *ev;
    struct sss_failover_ctx *fctx;

    bool reuse_connection;
    bool authenticate_connection;
    bool read_rootdse;
    enum sss_failover_transaction_tls force_tls;

    /* Top level tevent request. Finished when this transaction is done. */
    struct tevent_req *caller_req;
    void *caller_data;
    size_t caller_data_size;
    const char *caller_data_type;

    /* Connection request. Finished when we have a connection and
     * connected_callback is fired. */
    struct tevent_req *connected_req;
    tevent_req_fn connected_callback;

    /* Single transaction attempt. If successful, the main transaction request
     * is finished. Otherwise, we try next server. */
    struct tevent_req *attempt_req;

    /* How many times was this transaction restarted. */
    unsigned int attempts;

    /* Connection information. */
    struct sss_failover_server *current_server;
    time_t kinit_expiration_time;
    void *connection;
};

static errno_t
sss_failover_transaction_restart(struct tevent_req *req);

static errno_t
sss_failover_transaction_next(struct tevent_req *req);

static errno_t
sss_failover_transaction_kinit(struct tevent_req *req);

static void
sss_failover_transaction_kinit_done(struct tevent_req *subreq);

static errno_t
sss_failover_transaction_connect(struct tevent_req *req);

static void
sss_failover_transaction_connect_done(struct tevent_req *subreq);

static void
sss_failover_transaction_attempt_done(struct tevent_req *attempt_req);

static void
sss_failover_transaction_done(struct tevent_req *subreq);

errno_t
sss_failover_transaction_ex_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct sss_failover_ctx *fctx,
                                 struct tevent_req *caller_req,
                                 tevent_req_fn connected_callback,
                                 bool reuse_connection,
                                 bool authenticate_connection,
                                 bool read_rootdse,
                                 enum sss_failover_transaction_tls force_tls)
{
    struct sss_failover_transaction_state *state;
    struct tevent_req *req;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Creating new failover transaction for service %s\n", fctx->name);

    req = tevent_req_create(mem_ctx, &state, struct sss_failover_transaction_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return ENOMEM;
    }

    state->ev = ev;
    state->fctx = fctx;
    state->reuse_connection = reuse_connection;
    state->authenticate_connection = authenticate_connection;
    state->read_rootdse = read_rootdse;

    state->caller_req = caller_req;
    state->caller_data = _tevent_req_data(caller_req);
    state->caller_data_size = talloc_get_size(state->caller_data);
    state->caller_data_type = talloc_get_name(state->caller_data);
    state->connected_callback = connected_callback;
    state->attempts = 0;

    tevent_req_set_callback(req, sss_failover_transaction_done, caller_req);

    ret = sss_failover_transaction_restart(req);
    if (ret != EOK) {
        /* We cannot get any working server. Just cancel this request. */
        talloc_free(req);
    }

    return ret;
}

static errno_t
sss_failover_transaction_restart(struct tevent_req *req)
{
    struct sss_failover_transaction_connected_state *connected_state;
    struct sss_failover_transaction_state *state;
    void *attempt_state;
    errno_t ret;

    state = tevent_req_data(req, struct sss_failover_transaction_state);
    state->attempts++;

    DEBUG(SSSDBG_TRACE_FUNC, "Transaction attempt %u\n", state->attempts);

    /* This request is what fires up the connected_callback - we have active
     * connection to a server and the user can start querying it. */
    state->connected_req = tevent_req_create(state,
        &connected_state, struct sss_failover_transaction_connected_state);
    if (state->connected_req == NULL) {
        ret = ENOMEM;
        goto done;
    }
    connected_state->fctx = state->fctx;

    /* Create attempt req, this is used by the user as a replacement for
     * caller_req. The user will seamlessly call
     * tevent_req_done/error(attempt_req). */
    state->attempt_req = __tevent_req_create(state, &attempt_state,
        state->caller_data_size, state->caller_data_type,
        __func__, __location__);
    if (state->attempt_req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Switch the attempt_req state to caller_req state so it is used seamlessly
     * by the user. This is quite a hack and the attempt_state must stay
     * attached to attempt_req otherwise tevent_req_destructor will cause double
     * free. We also cannot free req nor attempt_req to make sure all data is
     * available to the caller_req recv function. This is not nice, but OK as
     * there should not be many retry attempts and the memory is freed when
     * caller_req is freed. */
    memcpy(attempt_state, state->caller_data, state->caller_data_size);

    tevent_req_set_callback(state->attempt_req,
                            sss_failover_transaction_attempt_done, req);

    tevent_req_set_callback(state->connected_req, state->connected_callback,
                            state->attempt_req);

    ret = sss_failover_transaction_next(req);

done:
    if (ret != EOK && state->attempts > 1) {
        /* The failover transaction was restarted due to server error but we
         * cannot retrieve any new server. Terminate the main request since we
         * are already in an async loop. This in turn will finish the
         * caller_req. */
        tevent_req_error(req, ret);
    }

    return ret;
}

static errno_t
sss_failover_transaction_next(struct tevent_req *req)
{
    struct sss_failover_transaction_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct sss_failover_transaction_state);

    /* Unlink current server to decrease refcount. */
    if (state->current_server != NULL) {
        talloc_unlink(state, state->current_server);
        state->current_server = NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Trying to find a working server\n");
    if (state->fctx->kinit_ctx != NULL && state->authenticate_connection) {
        ret = sss_failover_transaction_kinit(req);
    } else {
        ret = sss_failover_transaction_connect(req);
    }

    return ret;
}

static errno_t
sss_failover_transaction_kinit(struct tevent_req *req)
{
    struct sss_failover_transaction_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sss_failover_transaction_state);

    DEBUG(SSSDBG_TRACE_FUNC, "Attempting to kinit\n");

    subreq = sss_failover_vtable_op_kinit_send(state, state->ev,
                                               state->fctx->kinit_ctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sss_failover_transaction_kinit_done, req);
    return EOK;
}

static void
sss_failover_transaction_kinit_done(struct tevent_req *subreq)
{
    struct sss_failover_transaction_state *state;
    struct sss_failover_server *server;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_transaction_state);

    ret = sss_failover_vtable_op_kinit_recv(state, subreq, &server,
                                            &state->kinit_expiration_time);
    talloc_zfree(subreq);
    if (ret == ERR_NO_MORE_SERVERS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "There are no more servers to try, cancelling operation\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error while attempting to kinit, cancelling operation [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "kinit against KDC %s was successful\n",
          server->name);

    /* We do not need this server anymore. */
    talloc_unlink(state, server);

    ret = sss_failover_transaction_connect(req);

done:
    if (ret != EOK) {
        /* We cannot get TGT. Terminate main request. */
        tevent_req_error(req, ret);
        return;
    }
}

static errno_t
sss_failover_transaction_connect(struct tevent_req *req)
{
    struct sss_failover_transaction_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sss_failover_transaction_state);

    DEBUG(SSSDBG_TRACE_FUNC, "Trying to establish connection\n");

    subreq = sss_failover_vtable_op_connect_send(state, state->ev, state->fctx,
                                                 state->reuse_connection,
                                                 state->authenticate_connection,
                                                 state->read_rootdse,
                                                 state->force_tls,
                                                 state->kinit_expiration_time);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sss_failover_transaction_connect_done, req);
    return EOK;
}

static void
sss_failover_transaction_connect_done(struct tevent_req *subreq)
{
    struct sss_failover_transaction_state *state;
    struct tevent_req *req;
    void *connection;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_transaction_state);

    /* If successful, state->current_server is additional talloc_reference
     * to an active, connected server. */
    ret = sss_failover_vtable_op_connect_recv(state, subreq,
                                              &state->current_server,
                                              &connection);
    talloc_zfree(subreq);
    if (ret == ERR_NO_MORE_SERVERS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "There are no more servers to try, cancelling operation\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error while attempting to connect, cancelling operation [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Connected to %s, connection %p\n",
          state->current_server->name, connection);

    sss_failover_set_active_server(state->fctx, state->current_server);
    sss_failover_set_connection(state->fctx, connection);

    /* We are connected. Now continue with connected_callback. */
    tevent_req_done(state->connected_req);

done:
    if (ret != EOK) {
        /* We cannot establish connection. Terminate main request. */
        tevent_req_error(req, ret);
        return;
    }
}

/* Finish the main failover transaction request or try next server. */
static void sss_failover_transaction_attempt_done(struct tevent_req *attempt_req)
{
    struct sss_failover_transaction_state *state;
    struct tevent_req *req;
    void *attempt_state;
    enum tevent_req_state treq_state;
    uint64_t treq_error;

    req = tevent_req_callback_data(attempt_req, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_transaction_state);
    attempt_state = _tevent_req_data(attempt_req);

    /* Copy the transaction_req state back to the caller_req state. We can not
     * free the transaction state as there is no way to move possible new data
     * to the caller state context. If the transaction is restarted we will
     * allocate new transaction state, keeping this one hanging. It is OK as
     * there is only finite number of possible restarts and eventually all the
     * memory will be freed when the caller_req state is freed. */
    memcpy(state->caller_data, attempt_state, state->caller_data_size);

    if (tevent_req_is_error(attempt_req, &treq_state, &treq_error)) {
        switch (treq_state) {
        case TEVENT_REQ_USER_ERROR:
            /* Try next server. */
            if (treq_error == ERR_SERVER_FAILURE) {
                sss_failover_server_mark_offline(state->current_server);
                sss_failover_transaction_restart(req);
                return;
            }

            tevent_req_error(req, treq_error);
            return;
        case TEVENT_REQ_TIMED_OUT:
            tevent_req_error(req, ETIMEDOUT);
            return;
        case TEVENT_REQ_NO_MEMORY:
            tevent_req_oom(req);
            return;
        default:
            tevent_req_error(req, ERR_INTERNAL);
            return;
        }
    }

    tevent_req_done(req);
}

/* The failover transaction is done. Finish the caller request. */
static void sss_failover_transaction_done(struct tevent_req *req)
{
    struct tevent_req *caller_req;
    enum tevent_req_state req_state;
    uint64_t req_error;

    caller_req = tevent_req_callback_data(req, struct tevent_req);

    /* Terminate the caller req. */
    if (tevent_req_is_error(req, &req_state, &req_error)) {
        switch (req_state) {
        case TEVENT_REQ_USER_ERROR:
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Failover transaction end up with error "
                  "[%" PRIu64 "]: %s\n", req_error, sss_strerror(req_error));
            tevent_req_error(caller_req, req_error);
            return;
        case TEVENT_REQ_TIMED_OUT:
            DEBUG(SSSDBG_TRACE_FUNC, "Failover transaction timed out\n");
            tevent_req_error(caller_req, ETIMEDOUT);
            return;
        case TEVENT_REQ_NO_MEMORY:
            tevent_req_oom(caller_req);
            return;
        default:
            DEBUG(SSSDBG_TRACE_FUNC, "Bug: Unexpected state %d\n", req_state);
            tevent_req_error(caller_req, ERR_INTERNAL);
            return;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Failover transaction was successful\n");
    tevent_req_done(caller_req);
}

/* Return connection. This is only called if we have a successful connection. */
void *
_sss_failover_transaction_connected_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req)
{
    struct sss_failover_transaction_connected_state *state;
    void *connection;

    state = tevent_req_data(req,
                            struct sss_failover_transaction_connected_state);

    connection = sss_failover_get_connection(mem_ctx, state->fctx);
    if (connection == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: connection should not be NULL!\n");
    }

    return connection;
}
