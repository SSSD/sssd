/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2026 Red Hat

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
#include "responder/common/cache_req/cache_req.h"
#include "responder/common/cache_req/cache_req_private.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static const char *
cache_req_initgroups_by_uid_create_debug_name(TALLOC_CTX *mem_ctx,
                                              struct cache_req_data *data,
                                              struct sss_domain_info *domain)
{
    return talloc_asprintf(mem_ctx, "UID:%"PRIu32"@%s", data->id, domain->name);
}

static errno_t
cache_req_initgroups_by_uid_ncache_check(struct sss_nc_ctx *ncache,
                                         struct sss_domain_info *domain,
                                         struct cache_req_data *data)
{
    errno_t ret;

    if (domain != NULL) {
        ret = sss_ncache_check_uid(ncache, domain, data->id);
        if (ret == EEXIST) {
            return ret;
        }
    }

    return sss_ncache_check_uid(ncache, NULL, data->id);
}

static errno_t
cache_req_initgroups_by_uid_ncache_filter(struct sss_nc_ctx *ncache,
                                          struct sss_domain_info *domain,
                                          const char *name)
{
    return sss_ncache_check_user(ncache, domain, name);
}

static errno_t
cache_req_initgroups_by_uid_lookup(TALLOC_CTX *mem_ctx,
                                   struct cache_req *cr,
                                   struct cache_req_data *data,
                                   struct sss_domain_info *domain,
                                   struct ldb_result **_result)
{
    struct ldb_result *user;
    const char *name;
    errno_t ret;

    ret = cache_req_idminmax_check(data, domain);
    if (ret != EOK) {
        return ret;
    }

    ret = sysdb_getpwuid(mem_ctx, domain, data->id, &user);
    if (ret != EOK) {
        return ret;
    }

    if (user->count == 0) {
        talloc_free(user);
        return ENOENT;
    }

    name = ldb_msg_find_attr_as_string(user->msgs[0], SYSDB_NAME, NULL);
    if (name == NULL) {
        talloc_free(user);
        return ERR_INTERNAL;
    }

    ret = sysdb_initgroups_with_views(mem_ctx, domain, name, _result);
    talloc_free(user);

    return ret;
}

struct cache_req_initgroups_by_uid_dp_state {
    struct cache_req *cr;
    struct cache_req_data *data;
    struct sss_domain_info *domain;
};

static void cache_req_initgroups_by_uid_dp_user_done(struct tevent_req *subreq);
static void cache_req_initgroups_by_uid_dp_initgr_done(struct tevent_req *subreq);

static struct tevent_req *
cache_req_initgroups_by_uid_dp_send(TALLOC_CTX *mem_ctx,
                                    struct cache_req *cr,
                                    struct cache_req_data *data,
                                    struct sss_domain_info *domain,
                                    struct ldb_result *result)
{
    struct cache_req_initgroups_by_uid_dp_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;

    req = tevent_req_create(mem_ctx, &state,
                            struct cache_req_initgroups_by_uid_dp_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->cr = cr;
    state->data = data;
    state->domain = domain;

    subreq = cache_req_user_by_id_send(state, cr->rctx->ev, cr->rctx,
                                       cr->ncache, cr->midpoint,
                                       domain->name, data->id);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, cr->rctx->ev);
        return req;
    }

    tevent_req_set_callback(subreq,
                            cache_req_initgroups_by_uid_dp_user_done, req);

    return req;
}

static void
cache_req_initgroups_by_uid_dp_user_done(struct tevent_req *subreq)
{
    struct cache_req_initgroups_by_uid_dp_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    const char *name;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req,
                            struct cache_req_initgroups_by_uid_dp_state);

    ret = cache_req_user_by_id_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (result->count == 0) {
        tevent_req_error(req, ENOENT);
        return;
    }

    name = ldb_msg_find_attr_as_string(result->msgs[0], SYSDB_NAME, NULL);
    if (name == NULL) {
        tevent_req_error(req, ERR_INTERNAL);
        return;
    }

    subreq = cache_req_initgr_by_name_send(state, state->cr->rctx->ev,
                                           state->cr->rctx, state->cr->ncache,
                                           state->cr->midpoint,
                                           CACHE_REQ_POSIX_DOM,
                                           state->domain->name, name);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq,
                            cache_req_initgroups_by_uid_dp_initgr_done, req);
}

static void
cache_req_initgroups_by_uid_dp_initgr_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = cache_req_initgr_by_name_recv(NULL, subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static bool
cache_req_initgroups_by_uid_dp_recv(struct tevent_req *subreq,
                                    struct cache_req *cr)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        CACHE_REQ_DEBUG(SSSDBG_OP_FAILURE, cr,
                        "Could not get account info [%s]\n",
                        sss_strerror((errno_t)err));
        return false;
    }

    return true;
}

static bool
cache_req_initgroups_by_uid_get_domain_check(struct resp_ctx *rctx,
                                             struct sss_domain_info *domain,
                                             struct cache_req_data *data)
{
    int nret;

    nret = sss_ncache_check_locate_uid(rctx->ncache, domain, data->id);
    if (nret == EEXIST) {
        return false;
    }

    return true;
}

static struct tevent_req *
cache_req_initgroups_by_uid_get_domain_send(TALLOC_CTX *mem_ctx,
                                            struct resp_ctx *rctx,
                                            struct sss_domain_info *domain,
                                            struct cache_req_data *data)
{
    int nret;

    nret = sss_ncache_set_locate_uid(rctx->ncache, domain, data->id);
    if (nret != EOK) {
        /* Not fatal */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot set negative cache, this might result in "
              "performance degradation\n");
    }

    return sss_dp_get_account_domain_send(mem_ctx,
                                          rctx,
                                          domain,
                                          true, /* fast_reply */
                                          SSS_DP_USER,
                                          data->id,
                                          NULL);
}

const struct cache_req_plugin cache_req_initgroups_by_uid = {
    .name = "Initgroups by UID",
    .attr_expiration = SYSDB_INITGR_EXPIRE,
    .parse_name = false,
    .ignore_default_domain = false,
    .bypass_cache = false,
    .only_one_result = false,
    .search_all_domains = false,
    .require_enumeration = false,
    .allow_missing_fqn = true,
    .allow_switch_to_upn = false,
    .upn_equivalent = CACHE_REQ_SENTINEL,
    .get_next_domain_flags = SSS_GND_DESCEND,

    .is_well_known_fn = NULL,
    .prepare_domain_data_fn = NULL,
    .create_debug_name_fn = cache_req_initgroups_by_uid_create_debug_name,
    .global_ncache_add_fn = NULL,
    .ncache_check_fn = cache_req_initgroups_by_uid_ncache_check,
    .ncache_add_fn = NULL,
    .ncache_filter_fn = cache_req_initgroups_by_uid_ncache_filter,
    .lookup_fn = cache_req_initgroups_by_uid_lookup,
    .dp_send_fn = cache_req_initgroups_by_uid_dp_send,
    .dp_recv_fn = cache_req_initgroups_by_uid_dp_recv,
    .dp_get_domain_check_fn = cache_req_initgroups_by_uid_get_domain_check,
    .dp_get_domain_send_fn = cache_req_initgroups_by_uid_get_domain_send,
    .dp_get_domain_recv_fn = cache_req_common_get_acct_domain_recv,
};

struct tevent_req *
cache_req_initgr_by_uid_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct resp_ctx *rctx,
                             struct sss_nc_ctx *ncache,
                             int cache_refresh_percent,
                             const char *domain,
                             uid_t uid)
{
    struct cache_req_data *data;

    data = cache_req_data_id(mem_ctx, CACHE_REQ_INITGROUPS_BY_UID, uid);
    if (data == NULL) {
        return NULL;
    }

    return cache_req_steal_data_and_send(mem_ctx, ev, rctx, ncache,
                                         cache_refresh_percent,
                                         CACHE_REQ_POSIX_DOM, domain,
                                         data);
}
