/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_groups.h"
#include "responder/ifp/ifp_cache.h"
#include "responder/ifp/ifp_domains.h"
#include "responder/ifp/ifp_iface/ifp_iface_async.h"

static errno_t
nodes_ifp(TALLOC_CTX *mem_ctx,
          const char *path,
          struct ifp_ctx *ctx,
          const char ***_nodes)
{
    static const char *nodes[] = {"Users", "Groups", "Domains", NULL};

    *_nodes = nodes;

    return EOK;
}

static errno_t
nodes_cached_objects(TALLOC_CTX *mem_ctx,
                     struct ifp_ctx *ifp_ctx,
                     enum ifp_cache_type type,
                     const char *prefix,
                     const char ***_nodes)
{
    TALLOC_CTX *tmp_ctx;
    const char **paths;
    const char **nodes;
    const char *node;
    int num_paths;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = ifp_cache_list_domains(tmp_ctx, ifp_ctx->rctx->domains, type, &paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to obtain cache objects list "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    num_paths = talloc_array_length(paths) - 1;
    nodes = talloc_zero_array(tmp_ctx, const char *, num_paths + 1);
    if (nodes == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_paths; i++) {
        node = sbus_opath_strip_prefix(paths[i], prefix);
        nodes[i] = talloc_strdup(nodes, node);
        if (nodes[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            ret = ENOMEM;
            goto done;
        }
    }

    *_nodes = talloc_steal(mem_ctx, nodes);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
nodes_users(TALLOC_CTX *mem_ctx,
            const char *path,
            struct ifp_ctx *ctx,
            const char ***_nodes)
{
    return nodes_cached_objects(mem_ctx, ctx, IFP_CACHE_USER,
                                IFP_PATH_USERS "/", _nodes);
}

static errno_t
nodes_groups(TALLOC_CTX *mem_ctx,
             const char *path,
             struct ifp_ctx *ctx,
             const char ***_nodes)
{
    return nodes_cached_objects(mem_ctx, ctx, IFP_CACHE_GROUP,
                                IFP_PATH_GROUPS "/", _nodes);
}

static errno_t
nodes_domains(TALLOC_CTX *mem_ctx,
              const char *path,
              struct ifp_ctx *ctx,
              const char ***_nodes)
{
    struct sss_domain_info *domain;
    const char **nodes;
    size_t count;

    count = 0;
    domain = ctx->rctx->domains;
    do {
        count++;
    } while ((domain = get_next_domain(domain, SSS_GND_ALL_DOMAINS)) != NULL);

    nodes = talloc_zero_array(mem_ctx, const char *, count + 1);
    if (nodes == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        return ENOMEM;
    }

    count = 0;
    domain = ctx->rctx->domains;
    do {
        nodes[count] = sbus_opath_escape(nodes, domain->name);
        if (nodes[count] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sbus_opath_escape_part() failed\n");
            talloc_free(nodes);
            return ENOMEM;
        }

        count++;
    } while ((domain = get_next_domain(domain, SSS_GND_ALL_DOMAINS)) != NULL);

    *_nodes = nodes;

    return EOK;
}

errno_t
ifp_register_nodes(struct ifp_ctx *ctx, struct sbus_connection *conn)
{
    struct sbus_node nodes[] = SBUS_NODES(
        SBUS_NODE_SYNC(IFP_PATH,         nodes_ifp, ctx),
        SBUS_NODE_SYNC(IFP_PATH_USERS,   nodes_users, ctx),
        SBUS_NODE_SYNC(IFP_PATH_GROUPS,  nodes_groups, ctx),
        SBUS_NODE_SYNC(IFP_PATH_DOMAINS, nodes_domains, ctx)
    );

    return sbus_router_add_node_map(conn, nodes);
}
