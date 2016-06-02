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

#include "sbus/sssd_dbus.h"
#include "responder/ifp/ifp_iface_generated.h"
#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_groups.h"
#include "responder/ifp/ifp_cache.h"
#include "responder/ifp/ifp_domains.h"

static const char **
nodes_ifp(TALLOC_CTX *mem_ctx, const char *path, void *data)
{
    static const char *nodes[] = {"Users", "Groups", "Domains", NULL};

    return nodes;
}

static const char **
nodes_cached_objects(TALLOC_CTX *mem_ctx,
                     void *data,
                     enum ifp_cache_type type,
                     const char *prefix)
{
    TALLOC_CTX *tmp_ctx;
    struct ifp_ctx *ifp_ctx;
    const char **paths;
    const char **nodes;
    const char *node;
    int num_paths;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        goto fail;
    }

    ret = ifp_cache_list_domains(tmp_ctx, ifp_ctx->rctx->domains,
                                 type, &paths, &num_paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to obtain cache objects list "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    nodes = talloc_zero_array(tmp_ctx, const char *, num_paths + 1);
    if (nodes == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        goto fail;
    }

    for (i = 0; i < num_paths; i++) {
        node = sbus_opath_strip_prefix(paths[i], prefix);
        nodes[i] = talloc_strdup(nodes, node);
        if (nodes[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            goto fail;
        }
    }

    talloc_steal(mem_ctx, nodes);
    talloc_free(tmp_ctx);

    return nodes;

fail:
    talloc_free(tmp_ctx);
    return NULL;
}

static const char **
nodes_users(TALLOC_CTX *mem_ctx, const char *path, void *data)
{
    return nodes_cached_objects(mem_ctx, data, IFP_CACHE_USER,
                                IFP_PATH_USERS "/");
}

static const char **
nodes_groups(TALLOC_CTX *mem_ctx, const char *path, void *data)
{
    return nodes_cached_objects(mem_ctx, data, IFP_CACHE_GROUP,
                                IFP_PATH_GROUPS "/");
}

static const char **
nodes_domains(TALLOC_CTX *mem_ctx, const char *path, void *data)
{
    struct ifp_ctx *ctx;
    struct sss_domain_info *domain;
    const char **nodes;
    size_t count;

    ctx = talloc_get_type(data, struct ifp_ctx);

    count = 0;
    domain = ctx->rctx->domains;
    do {
        count++;
    } while ((domain = get_next_domain(domain, SSS_GND_ALL_DOMAINS)) != NULL);

    nodes = talloc_zero_array(mem_ctx, const char *, count + 1);
    if (nodes == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        return NULL;
    }

    count = 0;
    domain = ctx->rctx->domains;
    do {
        nodes[count] = sbus_opath_escape_part(nodes, domain->name);
        if (nodes == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sbus_opath_escape_part() failed\n");
            talloc_free(nodes);
            return NULL;
        }

        count++;
    } while ((domain = get_next_domain(domain, SSS_GND_ALL_DOMAINS)) != NULL);


    return nodes;
}

struct nodes_map {
    const char *path;
    sbus_nodes_fn fn;
};

static struct nodes_map nodes_map[] = {
    { IFP_PATH, nodes_ifp },
    { IFP_PATH_USERS, nodes_users },
    { IFP_PATH_GROUPS, nodes_groups },
    { IFP_PATH_DOMAINS, nodes_domains },
    { NULL, NULL}
};

void ifp_register_nodes(struct ifp_ctx *ctx, struct sbus_connection *conn)
{
    int i;

    for (i = 0; nodes_map[i].path != NULL; i++) {
        sbus_conn_register_nodes(conn, nodes_map[i].path,
                                 nodes_map[i].fn, ctx);
    }
}
