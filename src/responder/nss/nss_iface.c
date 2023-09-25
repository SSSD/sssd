/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include "responder/nss/nss_private.h"
#include "responder/nss/nss_iface.h"
#include "sss_iface/sss_iface_async.h"

static void
sss_nss_update_initgr_memcache(struct sss_nss_ctx *nctx,
                               const char *fq_name, const char *domain,
                               int gnum, uint32_t *groups)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_domain_info *dom;
    struct ldb_result *res;
    struct sized_string *delete_name;
    bool changed = false;
    uint32_t id;
    uint32_t gids[gnum];
    int ret;
    int i, j;

    for (dom = nctx->rctx->domains;
         dom;
         dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        if (strcasecmp(dom->name, domain) == 0) {
            break;
        }
    }

    if (dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unknown domain (%s) requested by provider\n", domain);
        return;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return;
    }

    ret = sized_output_name(tmp_ctx, nctx->rctx, fq_name, dom, &delete_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sized_output_name failed for '%s': %d [%s]\n",
              fq_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_initgroups(tmp_ctx, dom, fq_name, &res);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_initgroups() failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    /* copy, we need the original intact in case we need to invalidate
     * all the original groups */
    memcpy(gids, groups, gnum * sizeof(uint32_t));

    if (ret == ENOENT || res->count == 0) {
        /* The user is gone. Invalidate the mc record */
        ret = sss_mmap_cache_pw_invalidate(&nctx->pwd_mc_ctx, delete_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Internal failure in memory cache code: %d [%s]\n",
                  ret, strerror(ret));
        }

        /* Also invalidate his groups */
        changed = true;
    } else {
        /* we skip the first entry, it's the user itself */
        for (i = 0; i < res->count; i++) {
            id = ldb_msg_find_attr_as_uint(res->msgs[i], SYSDB_GIDNUM, 0);
            if (id == 0) {
                /* probably non-POSIX group, skip */
                continue;
            }
            for (j = 0; j < gnum; j++) {
                if (gids[j] == id) {
                    gids[j] = 0;
                    break;
                }
            }
            if (j >= gnum) {
                /* we couldn't find a match, this means the groups have
                 * changed after the refresh */
                changed = true;
                break;
            }
        }

        if (!changed) {
            for (j = 0; j < gnum; j++) {
                if (gids[j] != 0) {
                    /* we found an un-cleared groups, this means the groups
                     * have changed after the refresh (some got deleted) */
                    changed = true;
                    break;
                }
            }
        }
    }

    if (changed) {
        for (i = 0; i < gnum; i++) {
            id = groups[i];

            ret = sss_mmap_cache_gr_invalidate_gid(&nctx->grp_mc_ctx, id);
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Internal failure in memory cache code: %d [%s]\n",
                      ret, strerror(ret));
            }
        }

        to_sized_string(delete_name, fq_name);
        ret = sss_mmap_cache_initgr_invalidate(&nctx->initgr_mc_ctx,
                                               delete_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Internal failure in memory cache code: %d [%s]\n",
                  ret, strerror(ret));
        }
    }

done:
    talloc_free(tmp_ctx);
}

static errno_t
sss_nss_memorycache_invalidate_users(TALLOC_CTX *mem_ctx,
                                     struct sbus_request *sbus_req,
                                     struct sss_nss_ctx *nctx)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Invalidating all users in memory cache\n");
    sss_mmap_cache_reset(nctx->pwd_mc_ctx);

    return EOK;
}

static errno_t
sss_nss_memorycache_invalidate_groups(TALLOC_CTX *mem_ctx,
                                      struct sbus_request *sbus_req,
                                      struct sss_nss_ctx *nctx)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Invalidating all groups in memory cache\n");
    sss_mmap_cache_reset(nctx->grp_mc_ctx);

    return EOK;
}

static errno_t
sss_nss_memorycache_invalidate_initgroups(TALLOC_CTX *mem_ctx,
                                          struct sbus_request *sbus_req,
                                          struct sss_nss_ctx *nctx)
{
    DEBUG(SSSDBG_TRACE_LIBS,
          "Invalidating all initgroup records in memory cache\n");
    sss_mmap_cache_reset(nctx->initgr_mc_ctx);

    return EOK;
}

static errno_t
sss_nss_memorycache_update_initgroups(TALLOC_CTX *mem_ctx,
                                      struct sbus_request *sbus_req,
                                      struct sss_nss_ctx *nctx,
                                      const char *user,
                                      const char *domain,
                                      uint32_t *groups)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Updating initgroups memory cache of [%s@%s]\n",
          user, domain);

    sss_nss_update_initgr_memcache(nctx, user, domain,
                               talloc_array_length(groups), groups);

    return EOK;
}

static errno_t
sss_nss_memorycache_invalidate_group_by_id(TALLOC_CTX *mem_ctx,
                                           struct sbus_request *sbus_req,
                                           struct sss_nss_ctx *nctx,
                                           uint32_t gid)
{

    DEBUG(SSSDBG_TRACE_LIBS,
          "Invalidating group %u from memory cache\n", gid);

    sss_mmap_cache_gr_invalidate_gid(&nctx->grp_mc_ctx, gid);

    return EOK;
}

errno_t
sss_nss_register_backend_iface(struct sbus_connection *conn,
                               struct sss_nss_ctx *nss_ctx)
{
    errno_t ret;

    SBUS_INTERFACE(iface,
        sssd_nss_MemoryCache,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_nss_MemoryCache, UpdateInitgroups, sss_nss_memorycache_update_initgroups, nss_ctx),
            SBUS_SYNC(METHOD, sssd_nss_MemoryCache, InvalidateAllUsers, sss_nss_memorycache_invalidate_users, nss_ctx),
            SBUS_SYNC(METHOD, sssd_nss_MemoryCache, InvalidateAllGroups, sss_nss_memorycache_invalidate_groups, nss_ctx),
            SBUS_SYNC(METHOD, sssd_nss_MemoryCache, InvalidateAllInitgroups, sss_nss_memorycache_invalidate_initgroups, nss_ctx),
            SBUS_SYNC(METHOD, sssd_nss_MemoryCache, InvalidateGroupById, sss_nss_memorycache_invalidate_group_by_id, nss_ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    ret = sbus_connection_add_path(conn, SSS_BUS_PATH, &iface);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register service interface"
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    return ret;
}
