/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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
#include "db/sysdb_iphosts.h"
#include "util/util.h"
#include "providers/data_provider.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static errno_t
cache_req_ip_host_by_name_prepare_domain_data(struct cache_req *cr,
                                              struct cache_req_data *data,
                                              struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    errno_t ret;

    if (data->name.name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: parsed name is NULL?\n");
        return ERR_INTERNAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Host names always case insensitive */
    name = sss_get_cased_name(tmp_ctx, data->name.name, false);
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
cache_req_ip_host_by_name_create_debug_name(TALLOC_CTX *mem_ctx,
                                            struct cache_req_data *data,
                                            struct sss_domain_info *domain)
{
    const char *name = data->name.lookup;

    return talloc_asprintf(mem_ctx, "%s@%s", name, domain->name);
}

static errno_t
cache_req_ip_host_by_name_lookup(TALLOC_CTX *mem_ctx,
                                 struct cache_req *cr,
                                 struct cache_req_data *data,
                                 struct sss_domain_info *domain,
                                 struct ldb_result **_result)
{
    return sysdb_gethostbyname(mem_ctx, domain, data->name.lookup,
                               _result);
}

static struct tevent_req *
cache_req_ip_host_by_name_dp_send(TALLOC_CTX *mem_ctx,
                                  struct cache_req *cr,
                                  struct cache_req_data *data,
                                  struct sss_domain_info *domain,
                                  struct ldb_result *result)
{
    return sss_dp_resolver_get_send(mem_ctx, cr->rctx, domain, true,
                                    BE_REQ_HOST, BE_FILTER_NAME,
                                    data->name.lookup);
}

static bool
cache_req_ip_host_by_name_dp_recv(struct tevent_req *subreq,
                                  struct cache_req *cr)
{
    bool bret;
    uint16_t err_maj;
    uint32_t err_min;
    errno_t ret;
    const char *err_msg;

    ret = sss_dp_resolver_get_recv(subreq, subreq, &err_maj, &err_min,
                                   &err_msg);
    bret = cache_req_common_process_dp_reply(cr, ret, err_maj,
                                             err_min, err_msg);

    return bret;
}

const struct cache_req_plugin cache_req_ip_host_by_name = {
    .name = "IP host by name",
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = true,
    .ignore_default_domain = true,
    .bypass_cache = false,
    .only_one_result = true,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = 0,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = cache_req_ip_host_by_name_prepare_domain_data,
    .create_debug_name_fn = cache_req_ip_host_by_name_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = NULL,
    .ncache_add_fn = NULL,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_ip_host_by_name_lookup,
    .dp_send_fn = cache_req_ip_host_by_name_dp_send,
    .dp_recv_fn = cache_req_ip_host_by_name_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};

struct tevent_req *
cache_req_ip_host_by_name_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct resp_ctx *rctx,
                               struct sss_nc_ctx *ncache,
                               int cache_refresh_percent,
                               const char *domain,
                               const char *name,
                               const char **attrs)
{
    struct cache_req_data *data;

    data = cache_req_data_name_attrs(mem_ctx, CACHE_REQ_IP_HOST_BY_NAME,
                                     name, attrs);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
