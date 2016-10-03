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
    return talloc_asprintf(mem_ctx, "UID:%d@%s", data->id, domain->name);
}

static errno_t
cache_req_user_by_id_ncache_check(struct sss_nc_ctx *ncache,
                                  struct sss_domain_info *domain,
                                  struct cache_req_data *data)
{
    return sss_ncache_check_uid(ncache, NULL, data->id);
}

static errno_t
cache_req_user_by_id_global_ncache_add(struct sss_nc_ctx *ncache,
                                       struct cache_req_data *data)
{
    return sss_ncache_set_uid(ncache, false, NULL, data->id);
}

static errno_t
cache_req_user_by_id_lookup(TALLOC_CTX *mem_ctx,
                            struct cache_req *cr,
                            struct cache_req_data *data,
                            struct sss_domain_info *domain,
                            struct ldb_result **_result)
{
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

struct cache_req_plugin cache_req_user_by_id = {
    .name = "User by ID",
    .dp_type = SSS_DP_USER,
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = false,
    .bypass_cache = false,
    .only_one_result = true,
    .allow_missing_fqn = false,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = 0,

    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_user_by_id_create_debug_name,
    .global_ncache_add_fn = cache_req_user_by_id_global_ncache_add,
    .ncache_check_fn = cache_req_user_by_id_ncache_check,
    .ncache_add_fn = NULL,
    .lookup_fn = cache_req_user_by_id_lookup,
    .dpreq_params_fn = cache_req_user_by_id_dpreq_params
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
                                         cache_refresh_percent, domain, data);
}
