/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include "util/util.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "tests/cmocka/common_mock.h"

errno_t krb5_try_kdcip(struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct dp_option *opts,
                       int opt_id)
{
    return EOK;
}

struct sdap_options *mock_sdap_options_ldap(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            struct confdb_ctx *confdb_ctx,
                                            const char *conf_path)
{
    struct sdap_options *opts = NULL;
    errno_t ret;

    ret = ldap_get_options(mem_ctx, domain, confdb_ctx, conf_path, &opts);
    if (ret != EOK) {
        return NULL;
    }

    return opts;
}

struct sdap_handle *mock_sdap_handle(TALLOC_CTX *mem_ctx)
{
    struct sdap_handle *handle = talloc_zero(mem_ctx, struct sdap_handle);

    /* we will never connect to any LDAP server and any sdap API that
     * access sdap_handle should be mocked, thus returning empty structure
     * is enough */

    return handle;
}

/*
 * Mock sdap_async.c
 *
 * Every function that is placed in sdap_async.c module has to be mocked,
 * to avoid any attempt to communicate with remote servers. Therefore no test
 * can be compiled with sdap_async.c. If any of these functions is needed,
 * their mock equivalent shall be used.
 */

bool sdap_has_deref_support(struct sdap_handle *sh, struct sdap_options *opts)
{
    return sss_mock_type(bool);
}

struct tevent_req *sdap_get_generic_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh,
                                         const char *search_base,
                                         int scope,
                                         const char *filter,
                                         const char **attrs,
                                         struct sdap_attr_map *map,
                                         int map_num_attrs,
                                         int timeout,
                                         bool allow_paging)
{
    return test_req_succeed_send(mem_ctx, ev);
}

int sdap_get_generic_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          size_t *reply_count,
                          struct sysdb_attrs ***reply)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = sss_mock_type(size_t);
    *reply = sss_mock_ptr_type(struct sysdb_attrs **);

    return EOK;
}

struct tevent_req * sdap_deref_search_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sdap_options *opts,
                                           struct sdap_handle *sh,
                                           const char *base_dn,
                                           const char *deref_attr,
                                           const char **attrs,
                                           int num_maps,
                                           struct sdap_attr_map_info *maps,
                                           int timeout)
{
    return test_req_succeed_send(mem_ctx, ev);
}

int sdap_deref_search_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sdap_deref_attrs ***reply)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = sss_mock_type(size_t);
    *reply = talloc_steal(mem_ctx,
                          sss_mock_ptr_type(struct sdap_deref_attrs **));

    return EOK;
}
