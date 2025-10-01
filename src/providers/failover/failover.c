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
sss_failover_set_active_server(struct sss_failover_ctx *fctx,
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

    DEBUG(SSSDBG_TRACE_FUNC, "Setting new active server %s\n", server->name);
    fctx->active_server = talloc_reference(fctx, server);
}

void
sss_failover_set_connection(struct sss_failover_ctx *fctx, void *connection)
{
    if (fctx->connection != NULL) {
        if (connection == fctx->connection) {
            /* it is the same connection, nothing to do */
            return;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Releasing old connection %p\n",
              fctx->connection);

        talloc_unlink(fctx, fctx->connection);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Setting new connection %p\n", connection);
    fctx->connection = talloc_steal(fctx, connection);
}

void *
sss_failover_get_connection(TALLOC_CTX *mem_ctx, struct sss_failover_ctx *fctx)
{
    if (fctx->connection == NULL) {
        return NULL;
    }

    return talloc_reference(mem_ctx, fctx->connection);
}
