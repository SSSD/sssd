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
#include <time.h>
#include <sys/param.h>

#include "config.h"
#include "util/util.h"
#include "providers/failover/failover.h"
#include "providers/failover/failover_group.h"
#include "providers/failover/failover_refresh_candidates.h"
#include "providers/failover/failover_server_resolve.h"
#include "util/sss_sockets.h"

struct sss_failover_ping_state {
    struct tevent_context *ev;
    struct sss_failover_ctx *fctx;
    struct sss_failover_server *server;
    unsigned int timeout;

    struct timeval ping_start;
};

static void
sss_failover_ping_resolved(struct tevent_req *subreq);

static void
sss_failover_ping_done(struct tevent_req *subreq);

static struct tevent_req *
sss_failover_ping_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sss_failover_ctx *fctx,
                       struct sss_failover_server *server,
                       unsigned int timeout)
{
    struct sss_failover_ping_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_ping_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->fctx = fctx;
    state->server = server;
    state->timeout = timeout;

    subreq = sss_failover_server_resolve_send(state, ev,
                                              state->fctx->resolver_ctx,
                                              state->fctx->family_order,
                                              state->server);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_failover_ping_resolved, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
sss_failover_ping_resolved(struct tevent_req *subreq)
{
    struct sss_failover_ping_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_ping_state);

    ret = sss_failover_server_resolve_recv(subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Pinging %s:%d (%s)\n", state->server->name,
          state->server->port, state->server->addr->human);

    state->ping_start = tevent_timeval_current();

    subreq = sssd_async_socket_init_send(state, state->ev, false,
                                         state->server->addr->sockaddr,
                                         state->server->addr->sockaddr_len,
                                         state->timeout);
    if (subreq == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        goto done;
    }

    tevent_req_set_callback(subreq, sss_failover_ping_done, req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
}

static void sss_failover_ping_done(struct tevent_req *subreq)
{
    struct sss_failover_ping_state *state;
    struct timeval ping_duration;
    struct timeval ping_end;
    struct tevent_req *req;
    errno_t ret;
    int fd;

    ping_end = tevent_timeval_current();
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_ping_state);

    ret = sssd_async_socket_init_recv(subreq, &fd);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Server %s:%d is not reachable within %d seconds [%d]: %s\n",
              state->server->name, state->server->port, state->timeout, ret,
              sss_strerror(ret));
        goto done;
    }

    close(fd);

    ping_duration = tevent_timeval_until(&state->ping_start, &ping_end);
    DEBUG(SSSDBG_TRACE_FUNC, "Server %s:%d responded in %lds:%ldus\n",
          state->server->name, state->server->port, ping_duration.tv_sec,
          ping_duration.tv_usec);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
sss_failover_ping_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct sss_failover_server **_server)
{
    struct sss_failover_ping_state *state;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    state = tevent_req_data(req, struct sss_failover_ping_state);
    *_server = talloc_reference(mem_ctx, state->server);

    return EOK;
}

struct sss_failover_ping_parallel_state {
    struct tevent_context *ev;
    struct sss_failover_ctx *fctx;
    struct sss_failover_server **servers;
    unsigned int shortcut_time;
    unsigned int max_servers;

    TALLOC_CTX *reqs_ctx;
    struct tevent_timer *shortcut_te;
    struct tevent_timer *batch_te;
    unsigned int shortcut_attempts;
    unsigned int active_requests;
    unsigned int batch;
    size_t next_server;
    size_t count;

    struct sss_failover_server **candidates;
    size_t candidates_index;
};

static void
sss_failover_ping_parallel_cleanup(struct tevent_req *req,
                                   enum tevent_req_state req_state);

static struct tevent_timer *
sss_failover_ping_parallel_shortcut_setup(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          unsigned int delay,
                                          struct tevent_req *req);
static void
sss_failover_ping_parallel_shortcut(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv,
                                    void *data);

static void
sss_failover_ping_parallel_batch(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv,
                               void *data);

static void
sss_failover_ping_parallel_done(struct tevent_req *subreq);

static struct tevent_req *
sss_failover_ping_parallel_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct sss_failover_ctx *fctx,
                                struct sss_failover_server **servers,
                                unsigned int max_servers,
                                unsigned int shortcut_time)
{
    struct sss_failover_ping_parallel_state *state;
    struct timeval tv = {0, 0};
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_ping_parallel_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->fctx = fctx;
    state->servers = servers;
    state->max_servers = max_servers;
    state->shortcut_time = shortcut_time;

    state->batch = 1;
    state->next_server = 0;
    state->count = talloc_array_length(servers) - 1;

    state->reqs_ctx = talloc_new(state);
    if (state->reqs_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    state->candidates_index = 0;
    state->candidates = talloc_zero_array(state, struct sss_failover_server *,
                                          max_servers + 1);
    if (state->candidates == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_cleanup_fn(req, sss_failover_ping_parallel_cleanup);

    state->shortcut_attempts = 0;
    state->shortcut_te = sss_failover_ping_parallel_shortcut_setup(
        state, state->ev, state->shortcut_time, req);

    sss_failover_ping_parallel_batch(ev, NULL, tv, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
sss_failover_ping_parallel_cleanup(struct tevent_req *req,
                                   enum tevent_req_state req_state)
{
    struct sss_failover_ping_parallel_state *state;

    state = tevent_req_data(req, struct sss_failover_ping_parallel_state);

    /* This request is done. Terminate any remaining timers and pings. */
    talloc_zfree(state->shortcut_te);
    talloc_zfree(state->batch_te);
    talloc_zfree(state->reqs_ctx);
    state->active_requests = 0;
}

static struct tevent_timer *
sss_failover_ping_parallel_shortcut_setup(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          unsigned int delay,
                                          struct tevent_req *req)
{
    struct tevent_timer *te;
    struct timeval tv;

    tv = tevent_timeval_current_ofs(delay, 0);
    te = tevent_add_timer(ev, mem_ctx, tv,
                          sss_failover_ping_parallel_shortcut, req);
    if (te == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to schedule next shortcut!\n");
    }

    return te;
}

static void
sss_failover_ping_parallel_shortcut(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv,
                                    void *data)
{
    struct sss_failover_ping_parallel_state *state;
    struct tevent_req *req;

    req = talloc_get_type(data, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_ping_parallel_state);

    state->shortcut_te = NULL;
    state->shortcut_attempts++;

    /* There is at least one candidate server available. Return it. */
    if (state->candidates[0] != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Some candidates were already found in %d seconds, do not wait "
              "for others\n",
              state->shortcut_time * state->shortcut_attempts);
        tevent_req_done(req);
        return;
    }

    state->shortcut_te = sss_failover_ping_parallel_shortcut_setup(
        state, state->ev, state->shortcut_time, req);
}

static void
sss_failover_ping_parallel_batch(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv,
                                 void *data)
{
    struct sss_failover_ping_parallel_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    uint32_t delay;
    size_t limit;
    size_t i;

    req = talloc_get_type(data, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_ping_parallel_state);

    state->batch_te = NULL;

    /* Issue three batches in total to avoid pinging too many servers if not
     * necessary. We want to find @max_servers working servers. The first batch
     * (@max_servers pings) is issued immediately and we will wait 400ms for it
     * to finish. If we don't get a reply in time we issue next batch
     * (@max_servers pings) and wait 200ms. If we still have no reply, we ping
     * remaining servers.
     */
    switch (state->batch) {
        case 1:
        case 2:
            limit = MIN(state->count, state->max_servers + state->next_server);
            delay = 400000 / state->batch;
            break;
        default:
            limit = state->count;
            delay = 0;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Sending ping to servers from batch %d\n",
          state->batch);

    for (i = state->next_server; i < limit; i++) {
        DEBUG(SSSDBG_TRACE_ALL, "Batch %d: %s:%d\n", state->batch,
              state->servers[i]->name, state->servers[i]->port);
    }

    for (; state->next_server < limit; state->next_server++) {
        subreq = sss_failover_ping_send(state->reqs_ctx, ev, state->fctx,
                                        state->servers[state->next_server],
                                        state->fctx->opts.ping_timeout);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to create new ping request\n");
            goto fail;
        }

        state->active_requests++;
        tevent_req_set_callback(subreq, sss_failover_ping_parallel_done, req);
    }

    state->batch++;
    if (delay > 0) {
        tv = tevent_timeval_current_ofs(0, delay);
        state->batch_te = tevent_add_timer(ev, state, tv,
                                     sss_failover_ping_parallel_batch, req);
        if (state->batch_te == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to schedule next batch!\n");
            goto fail;
        }
    }

    return;

fail:
    if (state->active_requests == 0) {
        tevent_req_error(req, ENOMEM);
        if (state->batch == 1) {
            tevent_req_post(req, ev);
        }
    }
}

static void
sss_failover_ping_parallel_done(struct tevent_req *subreq)
{
    struct sss_failover_ping_parallel_state *state;
    struct timeval tv = {0, 0};
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_ping_parallel_state);

    ret = sss_failover_ping_recv(state->candidates, subreq,
                                 &state->candidates[state->candidates_index]);
    talloc_zfree(subreq);
    state->active_requests--;

    if (ret == EOK) {
        state->candidates_index++;
    }

    /* Are we done? */
    if (state->candidates_index == state->max_servers) {
        tevent_req_done(req);
        return;
    }

    if (state->active_requests == 0) {
        /* There are still servers to try, don't wait for the timer. */
        if (state->next_server < state->count) {
            talloc_zfree(state->batch_te);
            sss_failover_ping_parallel_batch(state->ev, NULL, tv, req);
            return;
        }

        /* All servers were tried. */
        tevent_req_done(req);
        return;
    }

    /* Wait for another ping to finish. */
}

static errno_t
sss_failover_ping_parallel_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                size_t *_num_servers,
                                struct sss_failover_server ***_servers)
{
    struct sss_failover_ping_parallel_state *state;

    state = tevent_req_data(req, struct sss_failover_ping_parallel_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_num_servers = state->candidates_index;
    *_servers = talloc_steal(mem_ctx, state->candidates);

    return EOK;
}

struct sss_failover_refresh_candidates_state {
    struct tevent_context *ev;
    struct sss_failover_ctx *fctx;

    unsigned int current_group;
    struct sss_failover_group *group;
    struct sss_failover_server **group_servers;
};

static errno_t
sss_failover_refresh_candidates_group_next(struct tevent_req *req);

static void
sss_failover_refresh_candidates_group_resolved(struct tevent_req *subreq);

static void
sss_failover_refresh_candidates_done(struct tevent_req *subreq);

errno_t
sss_failover_refresh_candidates_recv(struct tevent_req *subreq);

struct tevent_req *
sss_failover_refresh_candidates_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sss_failover_ctx *fctx)
{
    struct sss_failover_refresh_candidates_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_refresh_candidates_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->fctx = fctx;
    state->current_group = 0;
    state->group = state->fctx->groups[0];

    state->fctx->candidates->last_refresh_time = time(NULL);
    state->fctx->candidates->refresh_req = req;

    DEBUG(SSSDBG_TRACE_FUNC, "Refreshing failover server candidates\n");

    /* Stop the queue as we are refreshing the candidates list now. */
    DEBUG(SSSDBG_TRACE_FUNC, "Stopping candidates notification queue\n");
    tevent_queue_stop(fctx->candidates->notify_queue);

    ret = sss_failover_refresh_candidates_group_next(req);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t
sss_failover_refresh_candidates_group_next(struct tevent_req *req)
{
    struct sss_failover_refresh_candidates_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sss_failover_refresh_candidates_state);
    state->group = state->fctx->groups[state->current_group];

    if (state->group == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No more groups to try\n");
        return ENOENT;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Trying failover group: %s:%u\n",
          state->group->name, state->group->slot);

    subreq = sss_failover_group_resolve_send(state, state->ev, state->fctx,
                                             state->group);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq,
                            sss_failover_refresh_candidates_group_resolved,
                            req);

    return EOK;
}

static void
sss_failover_refresh_candidates_group_resolved(struct tevent_req *subreq)
{
    struct sss_failover_refresh_candidates_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_refresh_candidates_state);

    talloc_zfree(state->group_servers);
    ret = sss_failover_group_resolve_recv(state, subreq, &state->group_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    /* No servers found, try next group. */
    if (state->group_servers[0] == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No servers found, trying next group\n");

        state->current_group++;
        ret = sss_failover_refresh_candidates_group_next(req);
        if (ret != EOK) {
            goto done;
        }

        return;
    }

    /* Servers found. Ping them in multiple batches. */
    subreq = sss_failover_ping_parallel_send(state, state->ev, state->fctx,
                                             state->group_servers,
                                             state->fctx->opts.max_candidates,
                                             state->fctx->opts.min_candidates_lookup_time);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_failover_refresh_candidates_done, req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void
sss_failover_refresh_candidates_done(struct tevent_req *subreq)
{
    struct sss_failover_refresh_candidates_state *state;
    struct sss_failover_server **candidates;
    struct tevent_req *req;
    size_t count;
    errno_t ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_refresh_candidates_state);

    ret = sss_failover_ping_parallel_recv(state, subreq, &count, &candidates);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* This is system error like ENOMEM. Not functional. */
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to ping any server [%d]: %s\n", ret,
              sss_strerror(ret));
        goto done;
    }

    if (count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No servers found, trying next group\n");

        state->current_group++;
        ret = sss_failover_refresh_candidates_group_next(req);
        if (ret != EOK) {
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Found %zu candidate servers in group %s:%u\n",
          count, state->group->name, state->group->slot);

    if (DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        for (i = 0; candidates[i] != NULL; i++) {
            DEBUG(SSSDBG_TRACE_ALL, "Found candidate server: %s:%u\n",
                  candidates[i]->name, candidates[i]->port);
        }
    }

    talloc_unlink(state->fctx->candidates, state->fctx->candidates->servers);
    state->fctx->candidates->servers = talloc_steal(state->fctx->candidates,
                                                    candidates);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sss_failover_refresh_candidates_recv(struct tevent_req *req)
{
    struct sss_failover_refresh_candidates_state *state;

    state = tevent_req_data(req, struct sss_failover_refresh_candidates_state);

    state->fctx->candidates->last_refresh_time = time(NULL);
    state->fctx->candidates->refresh_req = NULL;

    /* Notify listeners that refresh is finished. */
    DEBUG(SSSDBG_TRACE_FUNC, "Starting candidates notification queue\n");
    tevent_queue_start(state->fctx->candidates->notify_queue);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

bool
sss_failover_refresh_candidates_oob_can_run(struct sss_failover_ctx *fctx)
{
    time_t now;

    now = time(NULL);

    /* There is ongoing active request? */
    if (fctx->candidates->refresh_req != NULL) {
        return false;
    }

    /* Has enough time elapsed? */
    if (now <= fctx->candidates->last_refresh_time
            + fctx->candidates->min_refresh_time) {
        return false;
    }

    return true;
}

static void
sss_failover_refresh_candidates_oob_done(struct tevent_req *subreq);

void
sss_failover_refresh_candidates_oob_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sss_failover_ctx *fctx)
{
    struct tevent_req *subreq;

    if (!sss_failover_refresh_candidates_oob_can_run(fctx)) {
        DEBUG(SSSDBG_TRACE_FUNC, "Minimum refresh time has not elapsed yet or "
              "there is an active refresh request.\n");
        return;
    }

    subreq = sss_failover_refresh_candidates_send(mem_ctx, ev, fctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return;
    }

    tevent_req_set_callback(subreq, sss_failover_refresh_candidates_oob_done,
                            NULL);
}

static void
sss_failover_refresh_candidates_oob_done(struct tevent_req *subreq)
{
    sss_failover_refresh_candidates_recv(subreq);
    talloc_free(subreq);
}
