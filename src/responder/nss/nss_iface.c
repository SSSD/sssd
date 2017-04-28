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

#include "sbus/sssd_dbus.h"
#include "responder/nss/nss_iface.h"
#include "responder/nss/nss_private.h"

void nss_update_initgr_memcache(struct nss_ctx *nctx,
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
              "Failed to make request to our cache! [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    /* copy, we need the original intact in case we need to invalidate
     * all the original groups */
    memcpy(gids, groups, gnum * sizeof(uint32_t));

    if (ret == ENOENT || res->count == 0) {
        /* The user is gone. Invalidate the mc record */
        ret = sss_mmap_cache_pw_invalidate(nctx->pwd_mc_ctx, delete_name);
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
                /* probably non-posix group, skip */
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

            ret = sss_mmap_cache_gr_invalidate_gid(nctx->grp_mc_ctx, id);
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Internal failure in memory cache code: %d [%s]\n",
                      ret, strerror(ret));
            }
        }

        to_sized_string(delete_name, fq_name);
        ret = sss_mmap_cache_initgr_invalidate(nctx->initgr_mc_ctx,
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

int nss_memorycache_invalidate_users(struct sbus_request *req, void *data)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);
    struct nss_ctx *nctx = talloc_get_type(rctx->pvt_ctx, struct nss_ctx);

    DEBUG(SSSDBG_TRACE_LIBS, "Invalidating all users in memory cache\n");
    sss_mmap_cache_reset(nctx->pwd_mc_ctx);

    return iface_nss_memorycache_InvalidateAllUsers_finish(req);
}

int nss_memorycache_invalidate_groups(struct sbus_request *req, void *data)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);
    struct nss_ctx *nctx = talloc_get_type(rctx->pvt_ctx, struct nss_ctx);

    DEBUG(SSSDBG_TRACE_LIBS, "Invalidating all groups in memory cache\n");
    sss_mmap_cache_reset(nctx->grp_mc_ctx);

    return iface_nss_memorycache_InvalidateAllGroups_finish(req);
}

int nss_memorycache_invalidate_initgroups(struct sbus_request *req, void *data)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);
    struct nss_ctx *nctx = talloc_get_type(rctx->pvt_ctx, struct nss_ctx);

    DEBUG(SSSDBG_TRACE_LIBS,
          "Invalidating all initgroup records in memory cache\n");
    sss_mmap_cache_reset(nctx->initgr_mc_ctx);

    return iface_nss_memorycache_InvalidateAllInitgroups_finish(req);
}


int nss_memorycache_update_initgroups(struct sbus_request *sbus_req,
                                      void *data,
                                      const char *user,
                                      const char *domain,
                                      uint32_t *groups,
                                      int num_groups)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);
    struct nss_ctx *nctx = talloc_get_type(rctx->pvt_ctx, struct nss_ctx);

    DEBUG(SSSDBG_TRACE_LIBS, "Updating initgroups memory cache of [%s@%s]\n",
          user, domain);

    nss_update_initgr_memcache(nctx, user, domain, num_groups, groups);

    return iface_nss_memorycache_UpdateInitgroups_finish(sbus_req);
}

struct iface_nss_memorycache iface_nss_memorycache = {
    { &iface_nss_memorycache_meta, 0 },
    .UpdateInitgroups = nss_memorycache_update_initgroups,
    .InvalidateAllUsers = nss_memorycache_invalidate_users,
    .InvalidateAllGroups = nss_memorycache_invalidate_groups,
    .InvalidateAllInitgroups = nss_memorycache_invalidate_initgroups,
};

static struct sbus_iface_map iface_map[] = {
    { NSS_MEMORYCACHE_PATH, &iface_nss_memorycache.vtable },
    { NULL, NULL }
};

struct sbus_iface_map *nss_get_sbus_interface()
{
    return iface_map;
}
