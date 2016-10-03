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

#ifndef _CACHE_REQ_PLUGIN_H_
#define _CACHE_REQ_PLUGIN_H_

#include "responder/common/cache_req/cache_req_private.h"

enum cache_object_status {
    CACHE_OBJECT_VALID,
    CACHE_OBJECT_EXPIRED,
    CACHE_OBJECT_MISSING,
    CACHE_OBJECT_MIDPOINT
};

/**
 * Create an object debug name that is used in debug messages to identify
 * this object.
 *
 * @return EOK If everything went fine.
 * @return Other errno code in case of an error.
 */
typedef errno_t
(*cache_req_prepare_domain_data_fn)(struct cache_req *cr,
                                    struct cache_req_data *data,
                                    struct sss_domain_info *domain);

/**
 * Create an object debug name that is used in debug messages to identify
 * this object.
 *
 * @return Debug name or NULL in case of an error.
 **/
typedef const char *
(*cache_req_create_debug_name_fn)(TALLOC_CTX *mem_ctx,
                                  struct cache_req_data *data,
                                  struct sss_domain_info *domain);

/**
 * Check if an object is stored in negative cache.
 *
 * @return EOK    If the object is not found.
 * @return EEXIST If the object is found in negative cache.
 * @return Other errno code in case of an error.
 */
typedef errno_t
(*cache_req_ncache_check_fn)(struct sss_nc_ctx *ncache,
                             struct sss_domain_info *domain,
                             struct cache_req_data *data);

/**
 * Add an object into negative cache.
 *
 * @return EOK If everything went fine.
 * @return Other errno code in case of an error.
 */
typedef errno_t
(*cache_req_ncache_add_fn)(struct sss_nc_ctx *ncache,
                           struct sss_domain_info *domain,
                           struct cache_req_data *data);

/**
 * Add an object into global negative cache.
 *
 * @return EOK If everything went fine.
 * @return Other errno code in case of an error.
 */
typedef errno_t
(*cache_req_global_ncache_add_fn)(struct sss_nc_ctx *ncache,
                                  struct cache_req_data *data);

/**
 * Lookup object in sysdb.
 *
 * @return EOK    If the object is found.
 * @return ENOENT If the object is not found.
 * @return Other errno code in case of an error.
 */
typedef errno_t
(*cache_req_lookup_fn)(TALLOC_CTX *mem_ctx,
                       struct cache_req *cr,
                       struct cache_req_data *data,
                       struct sss_domain_info *domain,
                       struct ldb_result **_result);

/**
 * Return parameters for Data Provider request.
 *
 * @return EOK If everything went fine.
 * @return Other errno code in case of an error.
 */
typedef errno_t
(*cache_req_dpreq_params_fn)(TALLOC_CTX *mem_ctx,
                             struct cache_req *cr,
                             struct ldb_result *result,
                             const char **_string,
                             uint32_t *_id,
                             const char **_flag);

struct cache_req_plugin {
    /**
     * Plugin name.
     */
    const char *name;

    /**
     * Data provider request type.
     */
    enum sss_dp_acct_type dp_type;

    /**
     * Expiration timestamp attribute name.
     */
    const char *attr_expiration;

    /**
     * Flags that are passed to get_next_domain().
     */
    uint32_t get_next_domain_flags;

    /**
     * True if input name should be parsed for domain.
     */
    bool parse_name;

    /**
     * True if we always contact data provider.
     */
    bool bypass_cache;

    /**
     * True if only one result is expected.
     */
    bool only_one_result;

    /**
     * Allow missing domain part even if domain requires fully qualified name
     * on domain less searches.
     */
    bool allow_missing_fqn;

    /**
     * True if this plugin can be swapped for equivalent search with UPN.
     */
    bool allow_switch_to_upn;
    enum cache_req_type upn_equivalent;

    /* Operations */
    cache_req_prepare_domain_data_fn prepare_domain_data_fn;
    cache_req_create_debug_name_fn create_debug_name_fn;
    cache_req_global_ncache_add_fn global_ncache_add_fn;
    cache_req_ncache_check_fn ncache_check_fn;
    cache_req_ncache_add_fn ncache_add_fn;
    cache_req_lookup_fn lookup_fn;
    cache_req_dpreq_params_fn dpreq_params_fn;
};

#endif /* _CACHE_REQ_PLUGIN_H_ */
