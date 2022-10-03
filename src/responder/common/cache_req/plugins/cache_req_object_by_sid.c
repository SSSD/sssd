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

static errno_t
cache_req_object_by_sid_well_known(TALLOC_CTX *mem_ctx,
                                   struct cache_req *cr,
                                   struct cache_req_data *data,
                                   struct cache_req_result **_result)
{
    struct cache_req_result *result;
    const char *domname;
    const char *name;
    errno_t ret;

    ret = well_known_sid_to_name(data->sid, &domname, &name);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_TRACE_ALL, cr,
                        "SID [%s] is not a Well-Known SID.\n", data->sid);
        return ret;
    }

    result = cache_req_well_known_sid_result(mem_ctx, cr, domname,
                                             data->sid, name);
    if (result == NULL) {
        return ENOMEM;
    }

    *_result = result;

    return EOK;
}

static const char *
cache_req_object_by_sid_create_debug_name(TALLOC_CTX *mem_ctx,
                                          struct cache_req_data *data,
                                          struct sss_domain_info *domain)
{
    return talloc_asprintf(mem_ctx, "SID:%s@%s", data->sid, domain->name);
}

static errno_t
cache_req_object_by_sid_ncache_check(struct sss_nc_ctx *ncache,
                                     struct sss_domain_info *domain,
                                     struct cache_req_data *data)
{
    return sss_ncache_check_sid(ncache, domain, data->sid);
}

static errno_t
cache_req_object_by_sid_global_ncache_add(struct sss_nc_ctx *ncache,
                                          struct cache_req_data *data)
{
    return sss_ncache_set_sid(ncache, false, NULL, data->sid);
}

static errno_t
cache_req_object_by_sid_ncache_add(struct sss_nc_ctx *ncache,
                                   struct sss_domain_info *domain,
                                   struct cache_req_data *data)
{
    return sss_ncache_set_sid(ncache, false, domain, data->sid);
}

static errno_t
cache_req_object_by_sid_lookup(TALLOC_CTX *mem_ctx,
                               struct cache_req *cr,
                               struct cache_req_data *data,
                               struct sss_domain_info *domain,
                               struct ldb_result **_result)
{
    return sysdb_search_object_by_sid(mem_ctx, domain, data->sid, data->attrs,
                                     _result);
}

static struct tevent_req *
cache_req_object_by_sid_dp_send(TALLOC_CTX *mem_ctx,
                                struct cache_req *cr,
                                struct cache_req_data *data,
                                struct sss_domain_info *domain,
                                struct ldb_result *result)
{
    return sss_dp_get_account_send(mem_ctx, cr->rctx, domain, true,
                                   SSS_DP_SECID, cr->data->sid, 0, NULL);
}

static bool
cache_req_object_by_sid_get_domain_check(struct resp_ctx *rctx,
                                         struct sss_domain_info *domain,
                                         struct cache_req_data *data)
{
    int nret;

    nret = sss_ncache_check_locate_sid(rctx->ncache, domain, data->sid);
    if (nret == EEXIST) {
        return false;
    }

    return true;
}

static struct tevent_req *
cache_req_object_by_sid_get_domain_send(TALLOC_CTX *mem_ctx,
                                        struct resp_ctx *rctx,
                                        struct sss_domain_info *domain,
                                        struct cache_req_data *data)
{
    int nret;

    nret = sss_ncache_set_locate_sid(rctx->ncache, domain, data->sid);
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
                                          SSS_DP_SECID,
                                          0,
                                          data->sid);
}


const struct cache_req_plugin cache_req_object_by_sid = {
    .name = "Object by SID",
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

    .is_well_known_fn = cache_req_object_by_sid_well_known,
    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_object_by_sid_create_debug_name,
    .global_ncache_add_fn = cache_req_object_by_sid_global_ncache_add,
    .ncache_check_fn = cache_req_object_by_sid_ncache_check,
    .ncache_add_fn = cache_req_object_by_sid_ncache_add,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_object_by_sid_lookup,
    .dp_send_fn = cache_req_object_by_sid_dp_send,
    .dp_recv_fn = cache_req_common_dp_recv,
    .dp_get_domain_check_fn = cache_req_object_by_sid_get_domain_check,
    .dp_get_domain_send_fn = cache_req_object_by_sid_get_domain_send,
    .dp_get_domain_recv_fn = cache_req_common_get_acct_domain_recv,
};

struct tevent_req *
cache_req_object_by_sid_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct resp_ctx *rctx,
                             struct sss_nc_ctx *ncache,
                             int cache_refresh_percent,
                             const char *domain,
                             const char *sid,
                             const char **attrs)
{
    struct cache_req_data *data;

    data = cache_req_data_sid(mem_ctx, CACHE_REQ_OBJECT_BY_SID, sid, attrs);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
