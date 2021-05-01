/*
    Copyright (C) 2021 Red Hat

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
#include "db/sysdb_subid.h"
#include "util/util.h"
#include "providers/data_provider.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static errno_t
cache_req_subid_ranges_by_name_prepare_domain_data(struct cache_req *cr,
                                                   struct cache_req_data *data,
                                                   struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    errno_t ret;

    if (cr->data->name.name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: parsed name is NULL?\n");
        return ERR_INTERNAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    name = sss_get_cased_name(tmp_ctx, cr->data->name.name,
                              domain->case_sensitive);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    name = sss_reverse_replace_space(tmp_ctx, name, cr->rctx->override_space);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_zfree(data->name.lookup);
    data->name.lookup = talloc_steal(data, name);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static const char *
cache_req_subid_ranges_by_name_create_debug_name(TALLOC_CTX *mem_ctx,
                                                 struct cache_req_data *data,
                                                 struct sss_domain_info *domain)
{
    return talloc_strdup(mem_ctx, data->name.lookup);
}

static errno_t
cache_req_subid_ranges_by_name_lookup(TALLOC_CTX *mem_ctx,
                                      struct cache_req *cr,
                                      struct cache_req_data *data,
                                      struct sss_domain_info *domain,
                                      struct ldb_result **_result)
{
    struct ldb_result *result;
    struct ldb_message *msg;
    errno_t ret;

    ret = sysdb_get_subid_ranges(mem_ctx, domain, data->name.name,
                                 data->attrs, &msg);
    if (ret != EOK) {
        return ret;
    }

    result = cache_req_create_ldb_result_from_msg(mem_ctx, msg);
    if (result == NULL) {
        return ENOMEM;
    }

    *_result = result;

    return EOK;
}

static struct tevent_req *
cache_req_subid_ranges_by_name_dp_send(TALLOC_CTX *mem_ctx,
                                       struct cache_req *cr,
                                       struct cache_req_data *data,
                                       struct sss_domain_info *domain,
                                       struct ldb_result *result)
{
    /* Views aren't yet supported */
    return sss_dp_get_account_send(mem_ctx, cr->rctx, domain, true,
                                   SSS_DP_SUBID_RANGES, cr->data->name.lookup, 0, NULL);
}

const struct cache_req_plugin cache_req_subid_ranges_by_name = {
    .name = "SubID ranges by name",
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = true,
    .ignore_default_domain = false,
    .bypass_cache = false,
    .only_one_result = false,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = false,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = SSS_GND_DESCEND,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = cache_req_subid_ranges_by_name_prepare_domain_data,
    .create_debug_name_fn = cache_req_subid_ranges_by_name_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = NULL,
    .ncache_add_fn = NULL,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_subid_ranges_by_name_lookup,
    .dp_send_fn = cache_req_subid_ranges_by_name_dp_send,
    .dp_recv_fn = cache_req_common_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};
