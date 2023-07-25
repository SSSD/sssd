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
#include "sss_iface/sss_iface_async.h"

enum cache_object_status {
    CACHE_OBJECT_VALID,
    CACHE_OBJECT_EXPIRED,
    CACHE_OBJECT_MISSING,
    CACHE_OBJECT_MIDPOINT
};

/**
 * Create cache request result manually, if the searched object is well known
 * and thus can not be found in the cache.
 *
 *
 * @return EOK If it is a well known object and a result was created.
 * @return ENOENT If it is not a well known object.
 * @return Other errno code in case of an error.
 */
typedef errno_t
(*cache_req_is_well_known_result_fn)(TALLOC_CTX *mem_ctx,
                                     struct cache_req *cr,
                                     struct cache_req_data *data,
                                     struct cache_req_result **_result);

/**
 * Prepare domain data. Some plug-ins may require to alter lookup data
 * per specific domain rules, such as case sensitivity, fully qualified
 * format etc.
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
 * Filter the result through the negative cache.
 *
 * This is useful for plugins which don't use name as an input
 * token but can be affected by filter_users and filter_groups
 * options.
 */
typedef errno_t
(*cache_req_ncache_filter_fn)(struct sss_nc_ctx *ncache,
                              struct sss_domain_info *domain,
                              const char *name);

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
 * Send Data Provider request.
 *
 * @return Tevent request on success.
 * @return NULL on error.
 */
typedef struct tevent_req *
(*cache_req_dp_send_fn)(TALLOC_CTX *mem_ctx,
                        struct cache_req *cr,
                        struct cache_req_data *data,
                        struct sss_domain_info *domain,
                        struct ldb_result *result);

/**
 * Process result of Data Provider request.
 *
 * Do not free subreq! It will be freed in the caller.
 *
 * @return True if data provider request succeeded.
 * @return False if there was an error.
 */
typedef bool
(*cache_req_dp_recv_fn)(struct tevent_req *subreq,
                        struct cache_req *cr);

/**
 * Check whether the results of the domain locator can still
 * be considered valid or whether it is time to call the request
 * again.
 *
 * @param   resp_ctx        The responder context.
 * @param   domain          The domain to check. This should be the domain-head,
 *                          because the locator works across a domain and its
 *                          subdomains.
 * @param   data            The cache request data that contains primarily the key
 *                          to look for.
 *
 * @return True if the locator plugin should be ran again.
 * @return False if the lookup should just proceed with the
 * data that is already in the negative cache.
 */
typedef bool
(*cache_req_dp_get_domain_check_fn)(struct resp_ctx *rctx,
                                    struct sss_domain_info *domain,
                                    struct cache_req_data *data);
/**
 * Send Data Provider request to locate the domain
 * of an entry
 *
 * @param   resp_ctx        The responder context.
 * @param   domain          The domain to check. This should be the domain-head,
 *                          because the locator works across a domain and its
 *                          subdomains.
 * @param   data            The cache request data that contains primarily the key
 *                          to look for.
 *
 *
 * @return Tevent request on success.
 * @return NULL on error.
 */
typedef struct tevent_req *
(*cache_req_dp_get_domain_send_fn)(TALLOC_CTX *mem_ctx,
                                   struct resp_ctx *rctx,
                                   struct sss_domain_info *domain,
                                   struct cache_req_data *data);

/**
 * Process result of Data Provider find-domain request.
 *
 * Do not free subreq! It will be freed in the caller.
 *
 * @param       mem_ctx         The memory context that owns the _found_domain
 *                              result parameter.
 * @param       subreq          The request to finish.
 * @param       cr              The cache_req being processed.
 * @param       _found_domain   The domain the request account belongs to. This
 *                              parameter can be NULL even on success, in that
 *                              case the account was not found and no lookups are
 *                              needed, all domains can be skipped in this case.
 *
 * @return EOK if the request did not encounter any error. In this
 * case, the _found_domain parameter can be considered authoritative,
 * regarless of its value
 * @return errno on error. _found_domain should be NULL in this case.
 */
typedef errno_t
(*cache_req_dp_get_domain_recv_fn)(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *subreq,
                                   struct cache_req *cr,
                                   char **_found_domain);

struct cache_req_plugin {
    /**
     * Plugin name.
     */
    const char *name;

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
     * True if default domain suffix should be ignored when parsing name.
     */
    bool ignore_default_domain;

    /**
     * True if we always contact data provider.
     */
    bool bypass_cache;

    /**
     * True if only one result is expected.
     */
    bool only_one_result;

    /**
     * If true, cache request will iterate over all domains on domain-less
     * search and merge acquired results.
     */
    bool search_all_domains;

    /**
     * True if only domains with enumeration enabled are searched.
     */
    bool require_enumeration;

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
    cache_req_is_well_known_result_fn is_well_known_fn;
    cache_req_prepare_domain_data_fn prepare_domain_data_fn;
    cache_req_create_debug_name_fn create_debug_name_fn;
    cache_req_global_ncache_add_fn global_ncache_add_fn;
    cache_req_ncache_check_fn ncache_check_fn;
    cache_req_ncache_add_fn ncache_add_fn;
    cache_req_ncache_filter_fn ncache_filter_fn;
    cache_req_lookup_fn lookup_fn;
    cache_req_dp_send_fn dp_send_fn;
    cache_req_dp_recv_fn dp_recv_fn;
    cache_req_dp_get_domain_check_fn dp_get_domain_check_fn;
    cache_req_dp_get_domain_send_fn dp_get_domain_send_fn;
    cache_req_dp_get_domain_recv_fn dp_get_domain_recv_fn;
};

extern const struct cache_req_plugin cache_req_user_by_name;
extern const struct cache_req_plugin cache_req_user_by_upn;
extern const struct cache_req_plugin cache_req_user_by_id;
extern const struct cache_req_plugin cache_req_group_by_name;
extern const struct cache_req_plugin cache_req_group_by_id;
extern const struct cache_req_plugin cache_req_initgroups_by_name;
extern const struct cache_req_plugin cache_req_initgroups_by_upn;
#ifdef BUILD_SUBID
extern const struct cache_req_plugin cache_req_subid_ranges_by_name;
#endif
extern const struct cache_req_plugin cache_req_user_by_cert;
extern const struct cache_req_plugin cache_req_user_by_filter;
extern const struct cache_req_plugin cache_req_group_by_filter;
extern const struct cache_req_plugin cache_req_object_by_sid;
extern const struct cache_req_plugin cache_req_object_by_name;
extern const struct cache_req_plugin cache_req_object_by_id;
extern const struct cache_req_plugin cache_req_enum_users;
extern const struct cache_req_plugin cache_req_enum_groups;
extern const struct cache_req_plugin cache_req_enum_svc;
extern const struct cache_req_plugin cache_req_enum_ip_hosts;
extern const struct cache_req_plugin cache_req_enum_ip_networks;
extern const struct cache_req_plugin cache_req_svc_by_name;
extern const struct cache_req_plugin cache_req_svc_by_port;
extern const struct cache_req_plugin cache_req_netgroup_by_name;
extern const struct cache_req_plugin cache_req_ssh_host_id_by_name;
extern const struct cache_req_plugin cache_req_autofs_map_entries;
extern const struct cache_req_plugin cache_req_autofs_map_by_name;
extern const struct cache_req_plugin cache_req_autofs_entry_by_name;
extern const struct cache_req_plugin cache_req_ip_host_by_name;
extern const struct cache_req_plugin cache_req_ip_host_by_addr;
extern const struct cache_req_plugin cache_req_ip_network_by_name;
extern const struct cache_req_plugin cache_req_ip_network_by_addr;

#endif /* _CACHE_REQ_PLUGIN_H_ */
