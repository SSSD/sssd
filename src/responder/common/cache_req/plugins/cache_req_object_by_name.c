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
cache_req_object_by_name_well_known(TALLOC_CTX *mem_ctx,
                                    struct cache_req *cr,
                                    struct cache_req_data *data,
                                    struct cache_req_result **_result)
{
    struct cache_req_result *result;
    const char *sid;
    char *domname;
    char *name;
    errno_t ret;

    ret = sss_parse_name(mem_ctx, cr->rctx->global_names,
                         data->name.input, &domname, &name);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_OP_FAILURE, cr, "Unable to parse name "
                        "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    if (domname == NULL || name == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_FUNC_DATA, cr, "Unable to split [%s] in "
                        "name and domain part. Skipping detection of "
                        "well-known name.\n", data->name.input);
        return ENOENT;
    }

    ret = name_to_well_known_sid(domname, name, &sid);
    if (ret != EOK) {
        return ret;
    }

    result = cache_req_well_known_sid_result(mem_ctx, cr, domname, sid, name);
    talloc_free(domname);
    talloc_free(name);
    if (result == NULL) {
        return ENOMEM;
    }

    *_result = result;

    return EOK;
}

static errno_t
cache_req_object_by_name_prepare_domain_data(struct cache_req *cr,
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

    name = sss_create_internal_fqname(tmp_ctx, name, domain->name);
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
cache_req_object_by_name_create_debug_name(TALLOC_CTX *mem_ctx,
                                           struct cache_req_data *data,
                                           struct sss_domain_info *domain)
{
    return talloc_strdup(mem_ctx, data->name.lookup);
}

static errno_t
cache_req_object_by_name_ncache_check(struct sss_nc_ctx *ncache,
                                      struct sss_domain_info *domain,
                                      struct cache_req_data *data)
{
    errno_t ret;

    ret = sss_ncache_check_user(ncache, domain, data->name.lookup);
    if (ret == EEXIST) {
        ret = sss_ncache_check_group(ncache, domain, data->name.lookup);
    }

    return ret;
}

static errno_t
cache_req_object_by_name_ncache_add(struct sss_nc_ctx *ncache,
                                    struct sss_domain_info *domain,
                                    struct cache_req_data *data)
{
    errno_t ret;

    ret = sss_ncache_set_user(ncache, false, domain, data->name.lookup);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_ncache_set_group(ncache, false, domain, data->name.lookup);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static errno_t
cache_req_object_by_name_lookup(TALLOC_CTX *mem_ctx,
                                struct cache_req *cr,
                                struct cache_req_data *data,
                                struct sss_domain_info *domain,
                                struct ldb_result **_result)
{
    return sysdb_search_object_by_name(mem_ctx, domain, data->name.lookup,
                                       data->attrs, _result);
}

static struct tevent_req *
cache_req_object_by_name_dp_send(TALLOC_CTX *mem_ctx,
                                 struct cache_req *cr,
                                 struct cache_req_data *data,
                                 struct sss_domain_info *domain,
                                 struct ldb_result *result)
{
    return sss_dp_get_account_send(mem_ctx, cr->rctx, domain, true,
                                   SSS_DP_USER_AND_GROUP,
                                   cr->data->name.lookup, 0, NULL);
}

const struct cache_req_plugin cache_req_object_by_name = {
    .name = "Object by name",
    .attr_expiration = SYSDB_CACHE_EXPIRE,
    .parse_name = true,
    .ignore_default_domain = false,
    .bypass_cache = false,
    .only_one_result = false,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = false,
    .allow_switch_to_upn = true,
    .upn_equivalent = CACHE_REQ_USER_BY_UPN,
    .get_next_domain_flags = SSS_GND_DESCEND,

    .is_well_known_fn = cache_req_object_by_name_well_known,
    .prepare_domain_data_fn = cache_req_object_by_name_prepare_domain_data,
    .create_debug_name_fn = cache_req_object_by_name_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = cache_req_object_by_name_ncache_check,
    .ncache_add_fn = cache_req_object_by_name_ncache_add,
    .ncache_filter_fn = NULL,
    .lookup_fn = cache_req_object_by_name_lookup,
    .dp_send_fn = cache_req_object_by_name_dp_send,
    .dp_recv_fn = cache_req_common_dp_recv,
    .dp_get_domain_check_fn = NULL,
    .dp_get_domain_send_fn = NULL,
    .dp_get_domain_recv_fn = NULL,
};

struct tevent_req *
cache_req_object_by_name_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int cache_refresh_percent,
                              const char *domain,
                              const char *name,
                              const char **attrs)
{
    struct cache_req_data *data;

    data = cache_req_data_name_attrs(mem_ctx, CACHE_REQ_OBJECT_BY_NAME,
                                     name, attrs);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
