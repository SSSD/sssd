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
#include "providers/failover/failover.h"
#include "providers/failover/failover_transaction.h"
#include "providers/failover/failover_server.h"
#include "providers/failover/failover_server_resolve.h"
#include "providers/failover/failover_refresh_candidates.h"
#include "providers/failover/failover_vtable_op.h"
#include "util/util.h"

static struct sss_failover_server *
sss_failover_vtable_op_pick_server(TALLOC_CTX *mem_ctx,
                                   struct sss_failover_ctx *fctx)
{
    struct sss_failover_server *server;
    size_t index;
    size_t start;
    size_t count;

    /* Total count of elements. */
    count = talloc_array_length(fctx->candidates->servers) - 1;

    start = sss_rand() % count;
    for (size_t i = 0; i < count; i++) {
        index = (start + i) % count;

        server = fctx->candidates->servers[index];

        /* This slot is empty. Continue. */
        if (server == NULL) {
            continue;
        }

        if (sss_failover_server_maybe_working(server)) {
            return talloc_reference(mem_ctx, server);
        }
    }

    /* We iterated over all candidates and none is working. */
    return NULL;
}

enum sss_failover_vtable_op {
    /* Perform kinit against given KDC. */
    SSS_FAILOVER_VTABLE_OP_KINIT,

    /* Connect to the server. */
    SSS_FAILOVER_VTABLE_OP_CONNECT,
};

/**
 * @brief Issue vtable operation against specific server.
 *
 * The operation should check the @server state and shortcut if possible (for
 * example if the server is already connected and working). @addr_changed is
 * true if the server hostname resolved to different address then what is stored
 * (it was previously unresolved, or the DNS record has changed). The operation
 * should take this information into consideration (e.g. reconnect to the server
 * with new address).
 *
 * The server state can be unknown, reachable or working. The server address
 * is guaranteed to be resolved.
 */
typedef struct tevent_req *
(*sss_failover_vtable_op_send_t)(TALLOC_CTX *mem_ctx,
                                 struct sss_failover_ctx *fctx,
                                 struct sss_failover_server *server,
                                 bool addr_changed);

/**
 * @brief Receive operation result and point to its private data.
 *
 * The private data is then stored on the server structure by caller.
 */
typedef errno_t
(*sss_failover_vtable_op_recv_t)(TALLOC_CTX *mem_ctx,
                                 struct tevent_req *,
                                 void **_op_private_data);

struct sss_failover_vtable_op_args {
    union {
        struct {
            bool reuse_connection;
            bool authenticate_connection;
            bool read_rootdse;
            enum sss_failover_transaction_tls force_tls;
            time_t expiration_time;
        } connect;
    } input;

    union {
        struct {
            time_t expiration_time;
        } kinit;

        struct {
            void *connection;
        } connect;
    } output;
};

struct sss_failover_vtable_op_state {
    struct tevent_context *ev;
    struct sss_failover_ctx *fctx;
    enum sss_failover_vtable_op operation;
    struct sss_failover_vtable_op_args *args;

    struct sss_failover_server *current_server;
    bool candidates_refreshed;
};

static void
sss_failover_vtable_op_trigger(struct tevent_req *req,
                               void *pvt);

static errno_t
sss_failover_vtable_op_server_next(struct tevent_req *req);

static errno_t
sss_failover_vtable_op_refresh_candidates(struct tevent_req *req);

static void
sss_failover_vtable_op_refresh_candidates_done(struct tevent_req *subreq);

static void
sss_failover_vtable_op_server_resolved(struct tevent_req *subreq);

static struct tevent_req *
sss_failover_vtable_op_subreq_send(struct sss_failover_vtable_op_state *state,
                                   bool addr_changed);

static errno_t
sss_failover_vtable_op_subreq_recv(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *subreq);

static void
sss_failover_vtable_op_done(struct tevent_req *subreq);

static struct tevent_req *
sss_failover_vtable_op_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sss_failover_ctx *fctx,
                            enum sss_failover_vtable_op operation,
                            struct sss_failover_vtable_op_args *args)
{
    struct sss_failover_vtable_op_state *state;
    struct tevent_req *req;
    errno_t ret;
    bool bret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_vtable_op_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");

        /* Free args to simplify logic in the caller. */
        talloc_free(args);
        return NULL;
    }

    state->ev = ev;
    state->fctx = fctx;
    state->operation = operation;
    state->args = talloc_steal(state, args);

    switch (state->operation) {
    case SSS_FAILOVER_VTABLE_OP_KINIT:
    case SSS_FAILOVER_VTABLE_OP_CONNECT:
        /* Correct operation. */
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid operation: [%d]\n", state->operation);
        ret = EINVAL;
        goto done;
    }

    /* Queuing the requests ensures that there is only one request that does
     * actual server selection and resolution. All subsequent requests will just
     * shortcut and pick the last selected server, if it is still working. */
    bret = tevent_queue_add(fctx->vtable_op_queue, fctx->ev, req,
                            sss_failover_vtable_op_trigger, NULL);
    if (!bret) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to add request to tevent queue\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
sss_failover_vtable_op_trigger(struct tevent_req *req,
                               void *pvt)
{
    errno_t ret;

    ret = sss_failover_vtable_op_server_next(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static errno_t
sss_failover_vtable_op_server_next(struct tevent_req *req)
{
    struct sss_failover_vtable_op_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sss_failover_vtable_op_state);

    if (state->current_server == NULL) {
        /* Select first server to try.*/
        if (state->fctx->active_server != NULL
            && sss_failover_server_maybe_working(state->fctx->active_server)) {
            /* Try active server first. */
            state->current_server = state->fctx->active_server;
            DEBUG(SSSDBG_TRACE_FUNC, "Trying current active server: %s\n",
                  state->current_server->name);
        } else {
            /* Pick a first server from candidates. */
            state->current_server = sss_failover_vtable_op_pick_server(state, state->fctx);
            if (state->current_server == NULL) {
                /* No candidates are available, schedule a refresh. */
                return sss_failover_vtable_op_refresh_candidates(req);
            }

            DEBUG(SSSDBG_TRACE_FUNC, "Trying candidate server: %s\n",
                  state->current_server->name);
        }
    } else {
        /* We already tried this server and it is not working. Submit an out of
         * band request of server candidates and try the next available
         * server. */

        DEBUG(SSSDBG_TRACE_FUNC, "Server %s does not work\n",
              state->current_server->name);

        DEBUG(SSSDBG_TRACE_FUNC, "Issuing out of band refresh of candidates\n");

        if (sss_failover_refresh_candidates_oob_can_run(state->fctx)) {
            sss_failover_refresh_candidates_oob_send(state->fctx, state->ev,
                                                     state->fctx);
        }

        state->current_server = sss_failover_vtable_op_pick_server(state, state->fctx);
        if (state->current_server == NULL) {
            /* No candidates are available. Wait for new ones. */
            return sss_failover_vtable_op_refresh_candidates(req);
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Trying next candidate server: %s\n",
                state->current_server->name);
    }

    /* TODO shortcut if already connected */

    /* First resolve the hostname. */
    DEBUG(SSSDBG_TRACE_FUNC, "Resolving hostname of %s\n",
          state->current_server->name);

    subreq = sss_failover_server_resolve_send(state, state->ev,
                                              state->fctx->resolver_ctx,
                                              state->fctx->family_order,
                                              state->current_server);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sss_failover_vtable_op_server_resolved,
                            req);

    return EOK;
}

static errno_t
sss_failover_vtable_op_refresh_candidates(struct tevent_req *req)
{
    struct sss_failover_vtable_op_state *state;
    struct tevent_queue *queue;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sss_failover_vtable_op_state);
    queue = state->fctx->candidates->notify_queue;

    if (state->candidates_refreshed) {
        /* We already refreshed the candidates. */
        DEBUG(SSSDBG_TRACE_FUNC, "Refresh did not find any working server\n");
        return ERR_NO_MORE_SERVERS;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "No more candidate servers are available, wait for a refresh\n");

    state->candidates_refreshed = true;

    /* Issue refresh request if there is none. */
    if (sss_failover_refresh_candidates_oob_can_run(state->fctx)) {
        sss_failover_refresh_candidates_oob_send(state->fctx, state->ev,
                                                 state->fctx);
    }

    /* Register for notification. */
    subreq = tevent_queue_wait_send(state, state->ev, queue);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq,
                            sss_failover_vtable_op_refresh_candidates_done,
                            req);

    return EOK;
}

static void
sss_failover_vtable_op_refresh_candidates_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sss_failover_vtable_op_server_next(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void
sss_failover_vtable_op_server_resolved(struct tevent_req *subreq)
{
    struct sss_failover_vtable_op_state *state;
    struct tevent_req *req;
    bool addr_changed;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_vtable_op_state);

    ret = sss_failover_server_resolve_recv(subreq, &addr_changed);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to resolve server hostname %s [%d]: %s\n",
              state->current_server->name, ret, sss_strerror(ret));
        sss_failover_server_mark_resolver_error(state->current_server);
        ret = sss_failover_vtable_op_server_next(req);
        goto done;
    }

    /* Trigger the operation. */
    DEBUG(SSSDBG_TRACE_FUNC, "Name resolved, starting vtable operation\n");

    subreq = sss_failover_vtable_op_subreq_send(state, addr_changed);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_failover_vtable_op_done, req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
}

static struct tevent_req *
sss_failover_vtable_op_subreq_send(struct sss_failover_vtable_op_state *state,
                                   bool addr_changed)
{
    switch (state->operation) {
    case SSS_FAILOVER_VTABLE_OP_KINIT:
        return state->fctx->vtable->kinit.send(
            state, state->ev, state->fctx, state->current_server, addr_changed,
            state->fctx->vtable->kinit.data);
    case SSS_FAILOVER_VTABLE_OP_CONNECT:
        return state->fctx->vtable->connect.send(
            state, state->ev, state->fctx, state->current_server, addr_changed,
            state->args->input.connect.reuse_connection,
            state->args->input.connect.authenticate_connection,
            state->args->input.connect.read_rootdse,
            state->args->input.connect.force_tls,
            state->args->input.connect.expiration_time,
            state->fctx->vtable->connect.data);
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "Bug: Unknown operation\n");
    return NULL;
}

static errno_t
sss_failover_vtable_op_subreq_recv(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *subreq)
{
    struct sss_failover_vtable_op_state *state;
    struct tevent_req *req;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_vtable_op_state);

    switch (state->operation) {
    case SSS_FAILOVER_VTABLE_OP_KINIT:
        return state->fctx->vtable->kinit.recv(state, subreq,
                    &state->args->output.kinit.expiration_time);
    case SSS_FAILOVER_VTABLE_OP_CONNECT:
        return state->fctx->vtable->connect.recv(state, subreq,
                    &state->args->output.connect.connection);
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "Bug: Unknown operation\n");
    return ENOTSUP;
}

static void sss_failover_vtable_op_done(struct tevent_req *subreq)
{
    struct sss_failover_vtable_op_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_vtable_op_state);

    ret = sss_failover_vtable_op_subreq_recv(state, subreq);
    talloc_zfree(subreq);

    switch (ret) {
    case EOK:
        /* The operation was successful. */
        sss_failover_server_mark_working(state->current_server);

        /* Remember this server. */
        talloc_unlink(state->fctx, state->fctx->active_server);
        state->fctx->active_server = talloc_reference(state->fctx,
                                                      state->current_server);
        break;
    case ENOMEM:
        /* There is no reason to retry if we our out of memory. */
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        goto done;
    default:
        /* Server is not working. */
        sss_failover_server_mark_offline(state->current_server);
        ret = sss_failover_vtable_op_server_next(req);
        if (ret == EOK) {
            return;
        }
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
sss_failover_vtable_op_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            struct sss_failover_server **_server,
                            struct sss_failover_vtable_op_args **_args)
{
    struct sss_failover_vtable_op_state *state = NULL;
    state = tevent_req_data(req, struct sss_failover_vtable_op_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_server != NULL) {
        *_server = talloc_reference(mem_ctx, state->current_server);
    }

    if (_args != NULL) {
        *_args = talloc_steal(mem_ctx, state->args);
    }

    return EOK;
}

struct tevent_req *
sss_failover_vtable_op_kinit_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sss_failover_ctx *fctx)
{
    struct sss_failover_vtable_op_args *args;

    args = talloc_zero(NULL, struct sss_failover_vtable_op_args);
    if (args == NULL) {
        return NULL;
    }

    return sss_failover_vtable_op_send(mem_ctx, ev, fctx,
                                       SSS_FAILOVER_VTABLE_OP_KINIT, args);
}

errno_t
sss_failover_vtable_op_kinit_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  struct sss_failover_server **_server,
                                  time_t *_expiration_time)
{
    struct sss_failover_vtable_op_args *args;
    errno_t ret;

    ret = sss_failover_vtable_op_recv(mem_ctx, req, _server, &args);
    if (ret != EOK) {
        return ret;
    }

    if (_expiration_time != NULL) {
        *_expiration_time = args->output.kinit.expiration_time;
    }

    talloc_free(args);
    return EOK;
}

struct tevent_req *
sss_failover_vtable_op_connect_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sss_failover_ctx *fctx,
                                    bool reuse_connection,
                                    bool authenticate_connection,
                                    bool read_rootdse,
                                    enum sss_failover_transaction_tls force_tls,
                                    time_t kinit_expiration_time)
{
    struct sss_failover_vtable_op_args *args;

    args = talloc_zero(NULL, struct sss_failover_vtable_op_args);
    if (args == NULL) {
        return NULL;
    }

    args->input.connect.reuse_connection = reuse_connection;
    args->input.connect.authenticate_connection = authenticate_connection;
    args->input.connect.read_rootdse = read_rootdse;
    args->input.connect.force_tls = force_tls;
    args->input.connect.expiration_time = kinit_expiration_time;
    return sss_failover_vtable_op_send(mem_ctx, ev, fctx,
                                       SSS_FAILOVER_VTABLE_OP_CONNECT, args);
}

errno_t
sss_failover_vtable_op_connect_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct sss_failover_server **_server,
                                    void **_connection)
{
    struct sss_failover_vtable_op_args *args;
    errno_t ret;

    ret = sss_failover_vtable_op_recv(mem_ctx, req, _server, &args);
    if (ret != EOK) {
        return ret;
    }

    if (_connection != NULL) {
        *_connection = talloc_steal(mem_ctx, args->output.connect.connection);
    }

    talloc_free(args);
    return EOK;
}
