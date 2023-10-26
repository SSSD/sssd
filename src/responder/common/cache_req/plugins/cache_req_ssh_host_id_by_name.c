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

#include "db/sysdb_ssh.h"
#include "util/util.h"
#include "util/sss_chain_id.h"
#include "providers/data_provider.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static const char *
cache_req_host_by_name_create_debug_name(TALLOC_CTX *mem_ctx,
                                         struct cache_req_data *data,
                                         struct sss_domain_info *domain)
{
    return talloc_strdup(mem_ctx, data->name.name);
}

static errno_t
cache_req_host_by_name_lookup(TALLOC_CTX *mem_ctx,
                              struct cache_req *cr,
                              struct cache_req_data *data,
                              struct sss_domain_info *domain,
                              struct ldb_result **_result)
{
#ifdef BUILD_SSH
    struct ldb_result *result;
    struct ldb_message *msg;
    errno_t ret;

    ret = sysdb_get_ssh_host(mem_ctx, domain, data->name.name,
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
#else
    return ERR_INTERNAL;
#endif /* BUILD_SSH */
}

static struct tevent_req *
cache_req_host_by_name_dp_send(TALLOC_CTX *mem_ctx,
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

    return sbus_call_dp_dp_hostHandler_send(mem_ctx, cr->rctx->sbus_conn,
                                            domain->conn_name, SSS_BUS_PATH,
                                            0, data->name.name, data->alias,
                                            sss_chain_id_get());
}

static bool
cache_req_host_by_name_dp_recv(struct tevent_req *subreq,
                               struct cache_req *cr)
{
    const char *err_msg;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    errno_t ret;
    bool bret;

    /* Use subreq as memory context so err_msg is freed with it. */
    ret = sbus_call_dp_dp_hostHandler_recv(subreq, subreq, &err_maj,
                                           &err_min, &err_msg);
    bret = cache_req_common_process_dp_reply(cr, ret, err_maj,
                                             err_min, err_msg);

    return bret;
}

const struct cache_req_plugin cache_req_ssh_host_id_by_name = {
    .name = "SSH Host ID by name",
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = true,
    .ignore_default_domain = true,
    .bypass_cache = true,
    .only_one_result = true,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = 0,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_host_by_name_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = NULL,
    .ncache_add_fn = NULL,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_host_by_name_lookup,
    .dp_send_fn = cache_req_host_by_name_dp_send,
    .dp_recv_fn = cache_req_host_by_name_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};

struct tevent_req *
cache_req_ssh_host_id_by_name_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct resp_ctx *rctx,
                                   struct sss_nc_ctx *ncache,
                                   int cache_refresh_percent,
                                   const char *domain,
                                   const char *name,
                                   const char *alias,
                                   const char **attrs)
{
    struct cache_req_data *data;

    data = cache_req_data_ssh_host_id(mem_ctx, CACHE_REQ_SSH_HOST_ID_BY_NAME,
                                      name, alias, attrs);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
