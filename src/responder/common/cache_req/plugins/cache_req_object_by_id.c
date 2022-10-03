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
cache_req_object_by_id_create_debug_name(TALLOC_CTX *mem_ctx,
                                         struct cache_req_data *data,
                                         struct sss_domain_info *domain)
{
    return talloc_asprintf(mem_ctx, "ID:%"PRIu32"@%s", data->id, domain->name);
}

static errno_t
cache_req_object_by_id_ncache_check(struct sss_nc_ctx *ncache,
                                    struct sss_domain_info *domain,
                                    struct cache_req_data *data)
{
    errno_t ret;

    ret = sss_ncache_check_uid(ncache, domain, data->id);
    if (ret == EEXIST) {
        ret = sss_ncache_check_gid(ncache, domain, data->id);
    }

    return ret;
}

static errno_t
cache_req_object_by_id_ncache_filter(struct sss_nc_ctx *ncache,
                                     struct sss_domain_info *domain,
                                     const char *name)
{
    errno_t ret;

    ret = sss_ncache_check_user(ncache, domain, name);
    if (ret == EEXIST) {
        ret = sss_ncache_check_group(ncache, domain, name);
    }

    return ret;
}

static errno_t
cache_req_object_by_id_global_ncache_add(struct sss_nc_ctx *ncache,
                                         struct cache_req_data *data)
{
    errno_t ret;

    ret = sss_ncache_set_uid(ncache, false, NULL, data->id);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_ncache_set_gid(ncache, false, NULL, data->id);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static errno_t
cache_req_object_by_id_ncache_add(struct sss_nc_ctx *ncache,
                                  struct sss_domain_info *domain,
                                  struct cache_req_data *data)
{
    errno_t ret;

    ret = sss_ncache_set_uid(ncache, false, domain, data->id);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_ncache_set_gid(ncache, false, domain, data->id);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static errno_t
cache_req_object_by_id_lookup(TALLOC_CTX *mem_ctx,
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
    return sysdb_search_object_by_id(mem_ctx, domain, data->id,
                                     data->attrs, _result);
}

static struct tevent_req *
cache_req_object_by_id_dp_send(TALLOC_CTX *mem_ctx,
                              struct cache_req *cr,
                              struct cache_req_data *data,
                              struct sss_domain_info *domain,
                              struct ldb_result *result)
{
    return sss_dp_get_account_send(mem_ctx, cr->rctx, domain, true,
                                   SSS_DP_USER_AND_GROUP, NULL,
                                   cr->data->id, NULL);
}

static bool
cache_req_object_by_id_get_domain_check(struct resp_ctx *rctx,
                                        struct sss_domain_info *domain,
                                        struct cache_req_data *data)
{
    int nret;

    nret = sss_ncache_check_locate_uid(rctx->ncache, domain, data->id);
    if (nret == EEXIST) {
        nret = sss_ncache_check_locate_gid(rctx->ncache, domain, data->id);
        if (nret == EEXIST) {
            return false;
        }
    }

    return true;
}

static struct tevent_req *
cache_req_object_by_id_get_domain_send(TALLOC_CTX *mem_ctx,
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

    nret = sss_ncache_set_locate_gid(rctx->ncache, domain, data->id);
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
                                          SSS_DP_USER_AND_GROUP,
                                          data->id,
                                          NULL);
}

const struct cache_req_plugin cache_req_object_by_id = {
    .name = "Object by ID",
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
    .create_debug_name_fn = cache_req_object_by_id_create_debug_name,
    .global_ncache_add_fn = cache_req_object_by_id_global_ncache_add,
    .ncache_check_fn = cache_req_object_by_id_ncache_check,
    .ncache_add_fn = cache_req_object_by_id_ncache_add,
    .ncache_filter_fn = cache_req_object_by_id_ncache_filter,
    .lookup_fn = cache_req_object_by_id_lookup,
    .dp_send_fn = cache_req_object_by_id_dp_send,
    .dp_recv_fn = cache_req_common_dp_recv,
    .dp_get_domain_check_fn = cache_req_object_by_id_get_domain_check,
    .dp_get_domain_send_fn = cache_req_object_by_id_get_domain_send,
    .dp_get_domain_recv_fn = cache_req_common_get_acct_domain_recv,
};

struct tevent_req *
cache_req_object_by_id_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int cache_refresh_percent,
                            const char *domain,
                            uint32_t id,
                            const char **attrs)
{
    struct cache_req_data *data;

    data = cache_req_data_id_attrs(mem_ctx, CACHE_REQ_OBJECT_BY_ID, id, attrs);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
