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
    return sss_ncache_check_upn(ncache, domain, data->name.lookup);
}

static errno_t
cache_req_user_by_upn_ncache_add(struct sss_nc_ctx *ncache,
                                 struct sss_domain_info *domain,
                                 struct cache_req_data *data)
{
    return sss_ncache_set_upn(ncache, false, domain, data->name.lookup);
}

static errno_t
cache_req_user_by_upn_lookup(TALLOC_CTX *mem_ctx,
                             struct cache_req *cr,
                             struct cache_req_data *data,
                             struct sss_domain_info *domain,
                             struct ldb_result **_result)
{
    if (data->attrs == NULL) {
        return sysdb_getpwupn(mem_ctx, domain, true, data->name.lookup, _result);
    }

    return sysdb_search_user_by_upn_res(mem_ctx, domain, true,
                                        data->name.lookup, data->attrs,
                                        _result);
}

static struct tevent_req *
cache_req_user_by_upn_dp_send(TALLOC_CTX *mem_ctx,
                              struct cache_req *cr,
                              struct cache_req_data *data,
                              struct sss_domain_info *domain,
                              struct ldb_result *result)
{
    return sss_dp_get_account_send(mem_ctx, cr->rctx, domain, true,
                                   SSS_DP_USER, cr->data->name.lookup,
                                   0, EXTRA_NAME_IS_UPN);
}

const struct cache_req_plugin cache_req_user_by_upn = {
    .name = "User by UPN",
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
    .prepare_domain_data_fn = cache_req_user_by_upn_prepare_domain_data,
    .create_debug_name_fn = cache_req_user_by_upn_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = cache_req_user_by_upn_ncache_check,
    .ncache_add_fn = cache_req_user_by_upn_ncache_add,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_user_by_upn_lookup,
    .dp_send_fn = cache_req_user_by_upn_dp_send,
    .dp_recv_fn = cache_req_common_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};

struct tevent_req *
cache_req_user_by_upn_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int cache_refresh_percent,
                           enum cache_req_dom_type req_dom_type,
                           const char *domain,
                           const char *upn)
{
    struct cache_req_data *data;

    data = cache_req_data_name(mem_ctx, CACHE_REQ_USER_BY_UPN, upn);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         req_dom_type, domain,
                                         data);
}
