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
cache_req_user_by_upn_prepare_domain_data(struct cache_req *cr,
                                          struct cache_req_data *data,
                                          struct sss_domain_info *domain)
{
    const char *name;

    if (cr->data->name.name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: parsed UPN is NULL?\n");
        return ERR_INTERNAL;
    }

    /* When looking up UPNs we don't want to reverse-replace spaces,
     * just search whatever the user passed in. strdup the name so we
     * can safely steal it later.
     */
    name = talloc_strdup(data, cr->data->name.name);
    if (name == NULL) {
        return ENOMEM;
    }

    talloc_zfree(data->name.lookup);
    data->name.lookup = talloc_steal(data, name);

    return EOK;
}

static const char *
cache_req_user_by_upn_create_debug_name(TALLOC_CTX *mem_ctx,
                                        struct cache_req_data *data,
                                        struct sss_domain_info *domain)
{
    return talloc_strdup(mem_ctx, data->name.lookup);
}

static errno_t
cache_req_user_by_upn_ncache_check(struct sss_nc_ctx *ncache,
                                   struct sss_domain_info *domain,
                                   struct cache_req_data *data)
{
    return sss_ncache_check_user(ncache, domain, data->name.lookup);
}

static errno_t
cache_req_user_by_upn_ncache_add(struct sss_nc_ctx *ncache,
                                 struct sss_domain_info *domain,
                                 struct cache_req_data *data)
{
    return sss_ncache_set_user(ncache, false, domain, data->name.lookup);
}

static errno_t
cache_req_user_by_upn_lookup(TALLOC_CTX *mem_ctx,
                             struct cache_req *cr,
                             struct cache_req_data *data,
                             struct sss_domain_info *domain,
                             struct ldb_result **_result)
{
    return sysdb_getpwupn(mem_ctx, domain, data->name.lookup, _result);
}

static errno_t
cache_req_user_by_upn_dpreq_params(TALLOC_CTX *mem_ctx,
                                   struct cache_req *cr,
                                   struct ldb_result *result,
                                   const char **_string,
                                   uint32_t *_id,
                                   const char **_flag)
{
    *_id = 0;
    *_string = cr->data->name.lookup;
    *_flag = EXTRA_NAME_IS_UPN;

    return EOK;
}

struct cache_req_plugin cache_req_user_by_upn = {
    .name = "User by UPN",
    .dp_type = SSS_DP_USER,
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = false,
    .bypass_cache = false,
    .only_one_result = true,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = SSS_GND_DESCEND,

    .prepare_domain_data_fn = cache_req_user_by_upn_prepare_domain_data,
    .create_debug_name_fn = cache_req_user_by_upn_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = cache_req_user_by_upn_ncache_check,
    .ncache_add_fn = cache_req_user_by_upn_ncache_add,
    .lookup_fn = cache_req_user_by_upn_lookup,
    .dpreq_params_fn = cache_req_user_by_upn_dpreq_params
};
