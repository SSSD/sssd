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
cache_req_user_by_filter_prepare_domain_data(struct cache_req *cr,
                                             struct cache_req_data *data,
                                             struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    char *name;
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

    sss_reverse_replace_space_inplace(name, cr->rctx->override_space);

    talloc_zfree(data->name.lookup);
    data->name.lookup = talloc_steal(data, name);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static const char *
cache_req_user_by_filter_create_debug_name(TALLOC_CTX *mem_ctx,
                                           struct cache_req_data *data,
                                           struct sss_domain_info *domain)
{
    return talloc_strdup(mem_ctx, data->name.lookup);
}

static errno_t
cache_req_user_by_filter_lookup(TALLOC_CTX *mem_ctx,
                                struct cache_req *cr,
                                struct cache_req_data *data,
                                struct sss_domain_info *domain,
                                struct ldb_result **_result)
{
    char *recent_filter;
    const char *attr = (data->name.attr == NULL ? SYSDB_NAME : data->name.attr);
    errno_t ret;

    /* It is impossible to use 'recent_filter' when asking for a non-"name"
     * attribute as it could not be present in the timestamp cache.
     */
    if (data->name.attr != NULL) {
        recent_filter = NULL;
    } else {
        recent_filter = talloc_asprintf(mem_ctx, "(%s>=%"SPRItime")", SYSDB_LAST_UPDATE,
                                        cr->req_start);
        if (recent_filter == NULL) {
            return ENOMEM;
        }
    }

    ret = sysdb_enumpwent_filter_with_views(mem_ctx, domain,
                                            attr, data->name.lookup,
                                            recent_filter, _result);
    talloc_free(recent_filter);

    return ret;
}

static struct tevent_req *
cache_req_user_by_filter_dp_send(TALLOC_CTX *mem_ctx,
                                 struct cache_req *cr,
                                 struct cache_req_data *data,
                                 struct sss_domain_info *domain,
                                 struct ldb_result *result)
{
    return sss_dp_get_account_send(mem_ctx, cr->rctx, domain, true,
                                   SSS_DP_WILDCARD_USER, cr->data->name.lookup,
                                   cr->data->id, NULL);
}

const struct cache_req_plugin cache_req_user_by_filter = {
    .name = "User by filter",
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = true,
    .ignore_default_domain = false,
    .bypass_cache = true,
    .only_one_result = false,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = false,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = SSS_GND_DESCEND,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = cache_req_user_by_filter_prepare_domain_data,
    .create_debug_name_fn = cache_req_user_by_filter_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = NULL,
    .ncache_add_fn = NULL,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_user_by_filter_lookup,
    .dp_send_fn = cache_req_user_by_filter_dp_send,
    .dp_recv_fn = cache_req_common_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};

struct tevent_req *
cache_req_user_by_filter_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              enum cache_req_dom_type req_dom_type,
                              const char *domain,
                              const char *attr,
                              const char *filter)
{
    struct cache_req_data *data;

    data = cache_req_data_attr(mem_ctx, CACHE_REQ_USER_BY_FILTER, attr, filter);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, NULL,
                                         0,
                                         req_dom_type, domain,
                                         data);
}
