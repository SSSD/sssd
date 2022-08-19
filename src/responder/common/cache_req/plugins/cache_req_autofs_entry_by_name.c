/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2019 Red Hat

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
#include "db/sysdb_autofs.h"
#include "util/util.h"
#include "util/sss_chain_id.h"
#include "providers/data_provider.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static const char *
cache_req_autofs_entry_by_name_create_debug_name(TALLOC_CTX *mem_ctx,
                                                 struct cache_req_data *data,
                                                 struct sss_domain_info *domain)
{
    return talloc_asprintf(mem_ctx, "%s:%s",
                           data->name.name,
                           data->autofs_entry_name);
}

static errno_t
cache_req_autofs_entry_by_name_lookup(TALLOC_CTX *mem_ctx,
                                      struct cache_req *cr,
                                      struct cache_req_data *data,
                                      struct sss_domain_info *domain,
                                      struct ldb_result **_result)
{
    struct ldb_message *entry;
    struct ldb_result *result;
    errno_t ret;

    ret = sysdb_get_autofsentry(mem_ctx, domain, data->name.name,
                                data->autofs_entry_name, &entry);
    if (ret != EOK) {
        return ret;
    }

    result = cache_req_create_ldb_result_from_msg(mem_ctx, entry);
    if (result == NULL) {
        talloc_free(entry);
        return ENOMEM;
    }

    *_result = talloc_steal(mem_ctx, result);
    return EOK;
}

static struct tevent_req *
cache_req_autofs_entry_by_name_dp_send(TALLOC_CTX *mem_ctx,
                                       struct cache_req *cr,
                                       struct cache_req_data *data,
                                       struct sss_domain_info *domain,
                                       struct ldb_result *result)
{
    struct be_conn *be_conn;
    errno_t ret;

    ret = sss_dp_get_domain_conn(cr->rctx, domain->conn_name, &be_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "BUG: The Data Provider connection for %s is not available!\n",
              domain->name);
        return NULL;
    }

    return sbus_call_dp_autofs_GetEntry_send(mem_ctx, be_conn->conn,
                                             be_conn->bus_name, SSS_BUS_PATH,
                                             0, data->name.name,
                                             data->autofs_entry_name,
                                             sss_chain_id_get());
}

bool
cache_req_autofs_entry_by_name_dp_recv(struct tevent_req *subreq,
                                       struct cache_req *cr)
{
    errno_t ret;

    ret = sbus_call_dp_autofs_GetEntry_recv(subreq);

    if (ret == ERR_MISSING_DP_TARGET || ret == ENOENT) {
        ret = EOK;
    }

    return ret == EOK;
}

const struct cache_req_plugin cache_req_autofs_entry_by_name = {
    .name = "Get autofs entry",
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = true,
    .ignore_default_domain = true,
    .bypass_cache = false,
    .only_one_result = false,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = 0,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_autofs_entry_by_name_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = NULL,
    .ncache_add_fn = NULL,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_autofs_entry_by_name_lookup,
    .dp_send_fn = cache_req_autofs_entry_by_name_dp_send,
    .dp_recv_fn = cache_req_autofs_entry_by_name_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};

struct tevent_req *
cache_req_autofs_entry_by_name_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct resp_ctx *rctx,
                                    struct sss_nc_ctx *ncache,
                                    int cache_refresh_percent,
                                    const char *domain,
                                    const char *mapname,
                                    const char *entryname)
{
    struct cache_req_data *data;

    data = cache_req_data_autofs_entry(mem_ctx, CACHE_REQ_AUTOFS_ENTRY_BY_NAME,
                                       mapname, entryname);
    if (data == NULL) {
        return NULL;
    }

    cache_req_data_set_propogate_offline_status(data, true);

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
