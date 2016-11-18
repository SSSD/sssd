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

static errno_t
cache_req_svc_by_name_prepare_domain_data(struct cache_req *cr,
                                          struct cache_req_data *data,
                                          struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    const char *protocol;
    errno_t ret;

    if (data->svc.name->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: parsed name is NULL?\n");
        return ERR_INTERNAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    name = sss_get_cased_name(tmp_ctx, data->svc.name->name,
                              domain->case_sensitive);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (data->svc.protocol.name == NULL) {
        protocol = NULL;
    } else {
        protocol = sss_get_cased_name(tmp_ctx, data->svc.protocol.name,
                                      domain->case_sensitive);
        if (protocol == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    talloc_zfree(data->svc.name->lookup);
    talloc_zfree(data->svc.protocol.lookup);
    data->svc.name->lookup = talloc_steal(data, name);
    data->svc.protocol.lookup = talloc_steal(data, protocol);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static const char *
cache_req_svc_by_name_create_debug_name(TALLOC_CTX *mem_ctx,
                                        struct cache_req_data *data,
                                        struct sss_domain_info *domain)
{
    const char *protocol = data->svc.protocol.lookup;
    const char *name = data->svc.name->lookup;

    protocol = protocol == NULL ? "<ANY>" : protocol;

    return talloc_asprintf(mem_ctx, "%s %s@%s", protocol, name, domain->name);
}

static errno_t
cache_req_svc_by_name_ncache_check(struct sss_nc_ctx *ncache,
                                   struct sss_domain_info *domain,
                                   struct cache_req_data *data)
{
    return sss_ncache_check_service(ncache, domain, data->svc.name->lookup,
                                    data->svc.protocol.lookup);
}

static errno_t
cache_req_svc_by_name_ncache_add(struct sss_nc_ctx *ncache,
                                 struct sss_domain_info *domain,
                                 struct cache_req_data *data)
{
    return sss_ncache_set_service_name(ncache, false, domain,
                                       data->svc.name->lookup,
                                       data->svc.protocol.lookup);
}

static errno_t
cache_req_svc_by_name_lookup(TALLOC_CTX *mem_ctx,
                             struct cache_req *cr,
                             struct cache_req_data *data,
                             struct sss_domain_info *domain,
                             struct ldb_result **_result)
{
    return sysdb_getservbyname(mem_ctx, domain, data->svc.name->lookup,
                               data->svc.protocol.lookup, _result);
}

static errno_t
cache_req_svc_by_name_dpreq_params(TALLOC_CTX *mem_ctx,
                                   struct cache_req *cr,
                                   struct ldb_result *result,
                                   const char **_string,
                                   uint32_t *_id,
                                   const char **_flag)
{
    *_id = 0;
    *_string = cr->data->svc.name->lookup;
    *_flag = cr->data->svc.protocol.lookup;

    return EOK;
}

const struct cache_req_plugin cache_req_svc_by_name = {
    .name = "Service by name",
    .dp_type = SSS_DP_SERVICES,
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = true,
    .bypass_cache = false,
    .only_one_result = false,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = false,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = 0,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = cache_req_svc_by_name_prepare_domain_data,
    .create_debug_name_fn = cache_req_svc_by_name_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = cache_req_svc_by_name_ncache_check,
    .ncache_add_fn = cache_req_svc_by_name_ncache_add,
    .lookup_fn = cache_req_svc_by_name_lookup,
    .dpreq_params_fn = cache_req_svc_by_name_dpreq_params
};

struct tevent_req *
cache_req_svc_by_name_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int cache_refresh_percent,
                           const char *domain,
                           const char *name,
                           const char *protocol)
{
    struct cache_req_data *data;

    data = cache_req_data_svc(mem_ctx, CACHE_REQ_SVC_BY_NAME, name, protocol, 0);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent, domain, data);
}
