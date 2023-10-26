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
cache_req_autofs_map_entries_create_debug_name(TALLOC_CTX *mem_ctx,
                                               struct cache_req_data *data,
                                               struct sss_domain_info *domain)
{
    return talloc_strdup(mem_ctx, data->name.name);
}

static errno_t
cache_req_autofs_map_entries_lookup(TALLOC_CTX *mem_ctx,
                                    struct cache_req *cr,
                                    struct cache_req_data *data,
                                    struct sss_domain_info *domain,
                                    struct ldb_result **_result)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *map;
    struct ldb_message **mounts;
    struct ldb_message **msgs;
    struct ldb_result *result;
    size_t count;
    size_t i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_get_map_byname(tmp_ctx, domain, data->name.name, &map);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_autofs_entries_by_map(tmp_ctx, domain, data->name.name,
                                      &count, &mounts);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    msgs = talloc_zero_array(tmp_ctx, struct ldb_message *, count + 1);
    if (msgs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msgs[0] = talloc_steal(msgs, map);
    for (i = 0; i < count; i++) {
        msgs[i + 1] = talloc_steal(msgs, mounts[i]);
    }

    result = cache_req_create_ldb_result_from_msg_list(tmp_ctx, msgs, count + 1);
    if (result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_result = talloc_steal(mem_ctx, result);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static struct tevent_req *
cache_req_autofs_map_entries_dp_send(TALLOC_CTX *mem_ctx,
                                     struct cache_req *cr,
                                     struct cache_req_data *data,
                                     struct sss_domain_info *domain,
                                     struct ldb_result *result)
{
    if (cr->rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        return NULL;
    }

    return sbus_call_dp_autofs_Enumerate_send(mem_ctx, cr->rctx->sbus_conn,
                                              domain->conn_name, SSS_BUS_PATH,
                                              0, data->name.name,
                                              sss_chain_id_get());
}

bool
cache_req_autofs_map_entries_dp_recv(struct tevent_req *subreq,
                                     struct cache_req *cr)
{
    errno_t ret;

    ret = sbus_call_dp_autofs_Enumerate_recv(subreq);

    if (ret == ERR_MISSING_DP_TARGET || ret == ENOENT) {
        ret = EOK;
    }

    return ret == EOK;
}

const struct cache_req_plugin cache_req_autofs_map_entries = {
    .name = "Get autofs entries",
    .attr_expiration = SYSDB_ENUM_EXPIRE,
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
    .create_debug_name_fn = cache_req_autofs_map_entries_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = NULL,
    .ncache_add_fn = NULL,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_autofs_map_entries_lookup,
    .dp_send_fn = cache_req_autofs_map_entries_dp_send,
    .dp_recv_fn = cache_req_autofs_map_entries_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};

struct tevent_req *
cache_req_autofs_map_entries_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int cache_refresh_percent,
                                  const char *domain,
                                  const char *name)
{
    struct cache_req_data *data;

    data = cache_req_data_name(mem_ctx, CACHE_REQ_AUTOFS_MAP_ENTRIES, name);
    if (data == NULL) {
        return NULL;
    }

    cache_req_data_set_propogate_offline_status(data, true);

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
