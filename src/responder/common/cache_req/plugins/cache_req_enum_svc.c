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
#include "db/sysdb_services.h"
#include "util/util.h"
#include "providers/data_provider.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static const char *
cache_req_enum_svc_create_debug_name(TALLOC_CTX *mem_ctx,
                                     struct cache_req_data *data,
                                     struct sss_domain_info *domain)
{
    return talloc_strdup(mem_ctx, "Services enumeration");
}

static errno_t
cache_req_enum_svc_lookup(TALLOC_CTX *mem_ctx,
                          struct cache_req *cr,
                          struct cache_req_data *data,
                          struct sss_domain_info *domain,
                          struct ldb_result **_result)
{
    return sysdb_enumservent(mem_ctx, domain, _result);
}

static errno_t
cache_req_enum_svc_dpreq_params(TALLOC_CTX *mem_ctx,
                                struct cache_req *cr,
                                struct ldb_result *result,
                                const char **_string,
                                uint32_t *_id,
                                const char **_flag)
{
    *_id = 0;
    *_string = NULL;
    *_flag = NULL;

    return EOK;
}

const struct cache_req_plugin cache_req_enum_svc = {
    .name = "Enumerate services",
    .dp_type = SSS_DP_SERVICES,
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = false,
    .bypass_cache = true,
    .only_one_result = false,
    .search_all_domains = true,
    .require_enumeration = true,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = 0,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_enum_svc_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = NULL,
    .ncache_add_fn = NULL,
    .lookup_fn = cache_req_enum_svc_lookup,
    .dpreq_params_fn = cache_req_enum_svc_dpreq_params
};

struct tevent_req *
cache_req_enum_svc_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct resp_ctx *rctx,
                        struct sss_nc_ctx *ncache,
                        int cache_refresh_percent,
                        const char *domain)
{
    struct cache_req_data *data;

    data = cache_req_data_enum(mem_ctx, CACHE_REQ_ENUM_SVC);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent, domain, data);
}
