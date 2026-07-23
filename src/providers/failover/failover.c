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
#include "providers/failover/failover_group.h"
#include "util/util.h"
#include "util/sss_ptr_list.h"

static struct sss_failover_candidates_ctx *
sss_failover_candidates_init(TALLOC_CTX *mem_ctx,
                             unsigned int max_servers,
                             unsigned int min_refresh_time)
{
    struct sss_failover_candidates_ctx *ctx;
    errno_t ret;

    ctx = talloc_zero(mem_ctx, struct sss_failover_candidates_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    ctx->refresh_req = NULL;
    ctx->last_refresh_time = 0;
    ctx->min_refresh_time = min_refresh_time;

    /* Setup list of candidate servers. */
    ctx->servers = talloc_zero_array(ctx, struct sss_failover_server *,
                                     max_servers + 1);
    if (ctx->servers == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    ctx->notify_queue = tevent_queue_create(ctx, "candidates_notify_queue");
    if (ctx->notify_queue == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    /* Stop the queue. It will be started when candidates are refreshed. */
    tevent_queue_stop(ctx->notify_queue);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
        return NULL;
    }

    return ctx;
}

static int
sss_failover_destructor(struct sss_failover_ctx *fctx)
{
    return 0;
}

struct sss_failover_ctx *
sss_failover_init(TALLOC_CTX *mem_ctx,
                  struct tevent_context *ev,
                  const char *name,
                  struct resolv_ctx *resolver_ctx,
                  enum restrict_family family_order)
{
    struct sss_failover_ctx *fctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Creating failover context for service %s\n",
          name);

    fctx = talloc_zero(mem_ctx, struct sss_failover_ctx);
    if (fctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    /* TODO init */
    fctx->ev = ev;
    fctx->name = talloc_strdup(fctx, name);
    fctx->resolver_ctx = resolver_ctx;
    fctx->family_order = family_order;
    fctx->kinit_ctx = NULL;

    if (fctx->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    /* Configuration. TODO make it configurable. */
    fctx->opts.max_candidates = 5;
    fctx->opts.min_refresh_time = 60;
    fctx->opts.ping_timeout = 3;
    fctx->opts.negative_dns_srv_ttl = 3600;
    fctx->opts.min_candidates_lookup_time = 1;

    /* Setup server groups. We expect at least two groups: primary and backup */
    fctx->current_group = 0;
    fctx->groups = talloc_zero_array(fctx, struct sss_failover_group *, 3);
    if (fctx->groups == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    /* Setup list of candidate servers. */
    fctx->candidates = sss_failover_candidates_init(
        fctx, fctx->opts.max_candidates, fctx->opts.min_refresh_time);
    if (fctx->candidates == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    /* We are not connected to any server yet. */
    fctx->active_server = NULL;
    fctx->state = SSS_FAILOVER_STATE_DISCONNECTED;

    fctx->vtable = talloc_zero(fctx, struct sss_failover_vtable);
    if (fctx->vtable == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    fctx->vtable_op_queue = tevent_queue_create(fctx, "vtable_op_queue");
    if (fctx->vtable_op_queue == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor(fctx, sss_failover_destructor);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(fctx);
    }

    return fctx;
}

void
sss_failover_mark_offline(struct sss_failover_ctx *fctx)
{
    sss_failover_active_server_set(fctx, NULL);

    DEBUG(SSSDBG_OP_FAILURE, "Failover [%s] is going offline\n", fctx->name);
    fctx->state = SSS_FAILOVER_STATE_OFFLINE;
}

bool
sss_failover_is_offline(struct sss_failover_ctx *fctx)
{
    return fctx->state == SSS_FAILOVER_STATE_OFFLINE;
}

void
sss_failover_active_server_set(struct sss_failover_ctx *fctx,
                               struct sss_failover_server *server)
{
    if (fctx->active_server != NULL) {
        if (server == fctx->active_server) {
            /* it is the same server, nothing to do */
            return;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Releasing old active server %s\n",
              fctx->active_server->name);

        talloc_unlink(fctx, fctx->active_server);
    }

    if (server == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Setting active server to NULL (we are not connected)\n");
        sss_failover_connection_set(fctx, NULL);
        fctx->active_server = NULL;
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Setting new active server %s\n", server->name);
    fctx->active_server = talloc_reference(fctx, server);
    if (fctx->active_server == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        sss_failover_connection_set(fctx, NULL);
        return;
    }
}

struct sss_failover_server *
sss_failover_active_server_get_ref(TALLOC_CTX *mem_ctx,
                                   struct sss_failover_ctx *fctx)
{
    void *srv;

    if (fctx->active_server == NULL) {
        return NULL;
    }

    srv = talloc_reference(mem_ctx, fctx->active_server);
    if (srv == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    return srv;
}

bool
sss_failover_active_server_cmp(struct sss_failover_ctx *fctx,
                               struct sss_failover_server *server)
{
    return fctx->active_server == server;
}

bool
sss_failover_active_server_is_working(struct sss_failover_ctx *fctx)
{
    if (fctx->active_server == NULL) {
        return false;
    }

    return sss_failover_server_is_working(fctx->active_server);
}

bool
sss_failover_active_server_maybe_working(struct sss_failover_ctx *fctx)
{
    if (fctx->active_server == NULL) {
        return false;
    }

    return sss_failover_server_maybe_working(fctx->active_server);
}

void
sss_failover_connection_set(struct sss_failover_ctx *fctx, void *connection)
{
    size_t ref_count;
    void *ptr;

    if (connection == fctx->connection) {
        /* It is the same connection, nothing to do. This also covers the case
         * where both are set to NULL. */
        return;
    }

    ptr = fctx->connection;

    if (fctx->connection != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Releasing old connection %p\n",
              fctx->connection);

        ref_count = talloc_reference_count(fctx->connection);
        if (ref_count == 0) {
            DEBUG(SSSDBG_TRACE_FUNC, "The connection is no longer used, it "
                                     "will be freed immediately\n");
        } else {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "The connection is still used at %zu places, it will be "
                  "freed once it reaches 0\n",
                  ref_count - 1);
        }

        /* Old connection is removed. At this point we are not connected. */
        fctx->connection = NULL;
        fctx->state = SSS_FAILOVER_STATE_DISCONNECTED;

        /* Notify backend that this connection is dropped. */
        if (fctx->vtable->disconnected.cb != NULL) {
            fctx->vtable->disconnected.cb(fctx, ptr,
                                          fctx->vtable->disconnected.data);
        }

        /* If this is the last parent, the connection will be gracefully
         * terminated via talloc destructor. Otherwise it will wait until the
         * refcount drops to zero. */
        talloc_unlink(fctx, ptr);
    }

    if (connection == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Connection %p was dropped\n", ptr);
        return;
    }

    if (fctx->active_server == NULL) {
        /* This may be a bug in the code or OOM scenario that we can't detect in
         * caller to simplify the API. Let's be defensive here. */
        DEBUG(SSSDBG_OP_FAILURE, "Trying to set connection without an active "
                                 "server, connection was dropped\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Setting new connection %p\n", connection);
    fctx->connection = talloc_steal(fctx, connection);
    fctx->state = SSS_FAILOVER_STATE_CONNECTED;
}

void *
sss_failover_connection_get_ref(TALLOC_CTX *mem_ctx, struct sss_failover_ctx *fctx)
{
    void *conn;

    if (fctx->connection == NULL) {
        return NULL;
    }

    conn = talloc_reference(mem_ctx, fctx->connection);
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    return conn;
}
