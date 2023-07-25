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

#include <talloc.h>
#include <ldb.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "providers/data_provider.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static const char *
cache_req_user_by_id_create_debug_name(TALLOC_CTX *mem_ctx,
                                       struct cache_req_data *data,
                                       struct sss_domain_info *domain)
{
    return talloc_asprintf(mem_ctx, "UID:%"PRIu32"@%s", data->id, domain->name);
}

static errno_t
cache_req_user_by_id_ncache_check(struct sss_nc_ctx *ncache,
                                  struct sss_domain_info *domain,
                                  struct cache_req_data *data)
{
    errno_t ret;

    if (domain != NULL) {
        ret = sss_ncache_check_uid(ncache, domain, data->id);
        if (ret == EEXIST) {
            return ret;
        }
    }

    return sss_ncache_check_uid(ncache, NULL, data->id);
}

static errno_t
cache_req_user_by_id_ncache_filter(struct sss_nc_ctx *ncache,
                                   struct sss_domain_info *domain,
                                   const char *name)
{
    return sss_ncache_check_user(ncache, domain, name);
}

static errno_t
cache_req_user_by_id_global_ncache_add(struct sss_nc_ctx *ncache,
                                       struct cache_req_data *data)
{
    return sss_ncache_set_uid(ncache, false, NULL, data->id);
}

static errno_t
cache_req_user_by_id_ncache_add(struct sss_nc_ctx *ncache,
                                struct sss_domain_info *domain,
                                struct cache_req_data *data)
{
    return sss_ncache_set_uid(ncache, false, domain, data->id);
}

static errno_t
cache_req_user_by_id_lookup(TALLOC_CTX *mem_ctx,
                            struct cache_req *cr,
                            struct cache_req_data *data,
                            struct sss_domain_info *domain,
                            struct ldb_result **_result)
{
    errno_t ret;
    ret = cache_req_idminmax_check(data, domain);
    if (ret != EOK) {
        return ret;
    }
    return sysdb_getpwuid_with_views(mem_ctx, domain, data->id, _result);
}

static errno_t
cache_req_user_by_id_dpreq_params(TALLOC_CTX *mem_ctx,
                                  struct cache_req *cr,
                                  struct ldb_result *result,
                                  const char **_string,
                                  uint32_t *_id,
                                  const char **_flag)
{
    uint32_t id;

    *_id = cr->data->id;
    *_string = NULL;
    *_flag = NULL;

    if (!DOM_HAS_VIEWS(cr->domain)) {
        return EOK;
    }

    /* We must search with views. */
    if (result == NULL || result->count == 0) {
        *_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
        return EOK;
    }

    /* If domain has views we will try to use original values instead of the
     * overridden ones. This is a must for the LOCAL view since we can't look
     * it up otherwise. But it is also a shortcut for non-local views where
     * we will not fail over to the overridden value. */

    id = ldb_msg_find_attr_as_uint64(result->msgs[0], SYSDB_UIDNUM, 0);
    if (id == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: id cannot be 0\n");
        *_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
        return EOK;
    }

    /* Now we have the original name and id. We don't have to search with
     * views unless some error occurred. */
    *_id = id;

    return EOK;
}

static struct tevent_req *
cache_req_user_by_id_dp_send(TALLOC_CTX *mem_ctx,
                             struct cache_req *cr,
                             struct cache_req_data *data,
                             struct sss_domain_info *domain,
                             struct ldb_result *result)
{
    const char *string;
    const char *flag;
    uint32_t id;
    errno_t ret;

    ret = cache_req_user_by_id_dpreq_params(mem_ctx, cr, result,
                                            &string, &id, &flag);
    if (ret != EOK) {
        return NULL;
    }

    return sss_dp_get_account_send(mem_ctx, cr->rctx, domain, true,
                                   SSS_DP_USER, string, id, flag);
}

static bool
cache_req_user_by_id_get_domain_check(struct resp_ctx *rctx,
                                      struct sss_domain_info *domain,
                                      struct cache_req_data *data)
{
    int nret;

    nret = sss_ncache_check_locate_uid(rctx->ncache, domain, data->id);
    if (nret == EEXIST) {
        return false;
    }

    return true;
}

static struct tevent_req *
cache_req_user_by_id_get_domain_send(TALLOC_CTX *mem_ctx,
                                     struct resp_ctx *rctx,
                                     struct sss_domain_info *domain,
                                     struct cache_req_data *data)
{
    int nret;

    nret = sss_ncache_set_locate_uid(rctx->ncache, domain, data->id);
    if (nret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot set negative cache, this might result in "
              "performance degradation\n");
        /* Not fatal */
    }

    return sss_dp_get_account_domain_send(mem_ctx,
                                          rctx,
                                          domain,
                                          true, /* fast_reply */
                                          SSS_DP_USER,
                                          data->id,
                                          NULL);
}

const struct cache_req_plugin cache_req_user_by_id = {
    .name = "User by ID",
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = false,
    .ignore_default_domain = false,
    .bypass_cache = false,
    .only_one_result = true,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = SSS_GND_DESCEND,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_user_by_id_create_debug_name,
    .global_ncache_add_fn = cache_req_user_by_id_global_ncache_add,
    .ncache_check_fn = cache_req_user_by_id_ncache_check,
    .ncache_add_fn = cache_req_user_by_id_ncache_add,
    .ncache_filter_fn = cache_req_user_by_id_ncache_filter,
    .lookup_fn = cache_req_user_by_id_lookup,
    .dp_send_fn = cache_req_user_by_id_dp_send,
    .dp_recv_fn = cache_req_common_dp_recv,
    .dp_get_domain_check_fn = cache_req_user_by_id_get_domain_check,
    .dp_get_domain_send_fn = cache_req_user_by_id_get_domain_send,
    .dp_get_domain_recv_fn = cache_req_common_get_acct_domain_recv,
};

struct tevent_req *
cache_req_user_by_id_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct resp_ctx *rctx,
                          struct sss_nc_ctx *ncache,
                          int cache_refresh_percent,
                          const char *domain,
                          uid_t uid)
{
    struct cache_req_data *data;

    data = cache_req_data_id(mem_ctx, CACHE_REQ_USER_BY_ID, uid);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
