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
cache_req_user_by_cert_create_debug_name(TALLOC_CTX *mem_ctx,
                                         struct cache_req_data *data,
                                         struct sss_domain_info *domain)
{
    /* Certificates might be quite long, thus we only use
     * the last 10 characters for logging. */
    return talloc_asprintf(mem_ctx, "CERT:%s@%s",
                           get_last_x_chars(data->cert, 10), domain->name);
}

static errno_t
cache_req_user_by_cert_ncache_check(struct sss_nc_ctx *ncache,
                                    struct sss_domain_info *domain,
                                    struct cache_req_data *data)
{
    return sss_ncache_check_cert(ncache, data->cert);
}

static errno_t
cache_req_user_by_cert_global_ncache_add(struct sss_nc_ctx *ncache,
                                         struct cache_req_data *data)
{
    return sss_ncache_set_cert(ncache, false, data->cert);
}

static errno_t
cache_req_user_by_cert_lookup(TALLOC_CTX *mem_ctx,
                              struct cache_req *cr,
                              struct cache_req_data *data,
                              struct sss_domain_info *domain,
                              struct ldb_result **_result)
{
    return sysdb_search_user_by_cert_with_views(mem_ctx, domain, data->cert,
                                                _result);
}

static errno_t
cache_req_user_by_cert_dpreq_params(TALLOC_CTX *mem_ctx,
                                    struct cache_req *cr,
                                    struct ldb_result *result,
                                    const char **_string,
                                    uint32_t *_id,
                                    const char **_flag)
{
    *_id = 0;
    *_string = cr->data->cert;
    *_flag = NULL;

    return EOK;
}

struct cache_req_plugin cache_req_user_by_cert = {
    .name = "User by certificate",
    .dp_type = SSS_DP_CERT,
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = false,
    .bypass_cache = false,
    .only_one_result = true,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = SSS_GND_DESCEND,

    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_user_by_cert_create_debug_name,
    .global_ncache_add_fn = cache_req_user_by_cert_global_ncache_add,
    .ncache_check_fn = cache_req_user_by_cert_ncache_check,
    .ncache_add_fn = NULL,
    .lookup_fn = cache_req_user_by_cert_lookup,
    .dpreq_params_fn = cache_req_user_by_cert_dpreq_params
};

struct tevent_req *
cache_req_user_by_cert_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int cache_refresh_percent,
                            const char *domain,
                            const char *pem_cert)
{
    struct cache_req_data *data;

    data = cache_req_data_cert(mem_ctx, CACHE_REQ_USER_BY_CERT, pem_cert);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         domain, data);
}
