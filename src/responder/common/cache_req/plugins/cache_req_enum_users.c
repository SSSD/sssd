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
cache_req_enum_users_create_debug_name(TALLOC_CTX *mem_ctx,
                                       struct cache_req_data *data,
                                       struct sss_domain_info *domain)
{
    return talloc_strdup(mem_ctx, "Users enumeration");
}

static errno_t
cache_req_enum_users_lookup(TALLOC_CTX *mem_ctx,
                            struct cache_req *cr,
                            struct cache_req_data *data,
                            struct sss_domain_info *domain,
                            struct ldb_result **_result)
{
    return sysdb_enumpwent_with_views(mem_ctx, domain, _result);
}

static struct tevent_req *
cache_req_enum_users_dp_send(TALLOC_CTX *mem_ctx,
                             struct cache_req *cr,
                             struct cache_req_data *data,
                             struct sss_domain_info *domain,
                             struct ldb_result *result)
{
    return sss_dp_get_account_send(mem_ctx, cr->rctx, domain, true,
                                   SSS_DP_USER, NULL, 0, NULL);
}

static errno_t
cache_req_enum_users_ncache_filter(struct sss_nc_ctx *ncache,
                                   struct sss_domain_info *domain,
                                   const char *name)
{
    return sss_ncache_check_user(ncache, domain, name);
}

const struct cache_req_plugin cache_req_enum_users = {
    .name = "Enumerate users",
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = false,
    .ignore_default_domain = false,
    .bypass_cache = true,
    .only_one_result = false,
    .search_all_domains = true,
    .require_enumeration = true,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = SSS_GND_DESCEND,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_enum_users_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = NULL,
    .ncache_add_fn = NULL,
    .ncache_filter_fn = cache_req_enum_users_ncache_filter,
    .lookup_fn = cache_req_enum_users_lookup,
    .dp_send_fn = cache_req_enum_users_dp_send,
    .dp_recv_fn = cache_req_common_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};
