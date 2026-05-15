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

#ifndef _CACHE_REQ_H_
#define _CACHE_REQ_H_

#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/common/negcache.h"

enum cache_req_type {
    CACHE_REQ_USER_BY_NAME,
    CACHE_REQ_USER_BY_UPN,
    CACHE_REQ_USER_BY_ID,
    CACHE_REQ_USER_BY_CERT,
    CACHE_REQ_USER_BY_FILTER,

    CACHE_REQ_GROUP_BY_NAME,
    CACHE_REQ_GROUP_BY_ID,
    CACHE_REQ_GROUP_BY_FILTER,

    CACHE_REQ_INITGROUPS,
    CACHE_REQ_INITGROUPS_BY_UPN,

#ifdef BUILD_SUBID
    CACHE_REQ_SUBID_RANGES_BY_NAME,
#endif

    CACHE_REQ_OBJECT_BY_SID,
    CACHE_REQ_OBJECT_BY_NAME,
    CACHE_REQ_OBJECT_BY_ID,

    CACHE_REQ_ENUM_USERS,
    CACHE_REQ_ENUM_GROUPS,
    CACHE_REQ_ENUM_SVC,
    CACHE_REQ_ENUM_HOST,
    CACHE_REQ_ENUM_IP_NETWORK,

    CACHE_REQ_SVC_BY_NAME,
    CACHE_REQ_SVC_BY_PORT,

    CACHE_REQ_NETGROUP_BY_NAME,

    CACHE_REQ_SSH_HOST_ID_BY_NAME,

    CACHE_REQ_AUTOFS_MAP_ENTRIES,
    CACHE_REQ_AUTOFS_MAP_BY_NAME,
    CACHE_REQ_AUTOFS_ENTRY_BY_NAME,

    CACHE_REQ_IP_HOST_BY_NAME,
    CACHE_REQ_IP_HOST_BY_ADDR,
    CACHE_REQ_IP_NETWORK_BY_NAME,
    CACHE_REQ_IP_NETWORK_BY_ADDR,

    CACHE_REQ_SENTINEL
};

/* Whether to limit the request type to a certain domain type
 * (POSIX/non-POSIX)
 */
enum cache_req_dom_type {
    /* Only look up data in POSIX domains */
    CACHE_REQ_POSIX_DOM,
    /* Only look up data in application domains */
    CACHE_REQ_APPLICATION_DOM,
    /* Look up data in any domain type */
    CACHE_REQ_ANY_DOM
};

/* Controls behavior about how to use cached information during
 * a lookup, this is to fine tune some behaviors for specific
 * situations
 */
enum cache_req_behavior {
    CACHE_REQ_NORMAL,
    CACHE_REQ_CACHE_FIRST,
    CACHE_REQ_BYPASS_CACHE,
    CACHE_REQ_BYPASS_PROVIDER,
};

/* Input data. */

struct cache_req_data;

struct cache_req_data *
cache_req_data_attr(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type,
                    const char *attr,
                    const char *filter);

struct cache_req_data *
cache_req_data_name(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type,
                    const char *name);

struct cache_req_data *
cache_req_data_name_attrs(TALLOC_CTX *mem_ctx,
                          enum cache_req_type type,
                          const char *name,
                          const char **attrs);

struct cache_req_data *
cache_req_data_id(TALLOC_CTX *mem_ctx,
                  enum cache_req_type type,
                  uint32_t id);

struct cache_req_data *
cache_req_data_id_attrs(TALLOC_CTX *mem_ctx,
                        enum cache_req_type type,
                        uint32_t id,
                        const char **attrs);

struct cache_req_data *
cache_req_data_cert(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type,
                    const char *cert);

struct cache_req_data *
cache_req_data_sid(TALLOC_CTX *mem_ctx,
                   enum cache_req_type type,
                   const char *sid,
                   const char **attrs);

struct cache_req_data *
cache_req_data_addr(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type,
                    uint32_t af,
                    uint32_t addrlen,
                    uint8_t *addr);

struct cache_req_data *
cache_req_data_enum(TALLOC_CTX *mem_ctx,
                    enum cache_req_type type);

struct cache_req_data *
cache_req_data_svc(TALLOC_CTX *mem_ctx,
                   enum cache_req_type type,
                   const char *name,
                   const char *protocol,
                   uint16_t port);

struct cache_req_data *
cache_req_data_ssh_host_id(TALLOC_CTX *mem_ctx,
                           enum cache_req_type type,
                           const char *name,
                           const char *alias,
                           const char **attrs);

struct cache_req_data *
cache_req_data_autofs_entry(TALLOC_CTX *mem_ctx,
                            enum cache_req_type type,
                            const char *mapname,
                            const char *entryname);

void
cache_req_data_set_bypass_cache(struct cache_req_data *data,
                                bool bypass_cache);

void
cache_req_data_set_bypass_dp(struct cache_req_data *data,
                             bool bypass_dp);

void
cache_req_data_set_requested_domains(struct cache_req_data *data,
                                     char **requested_domains);

void
cache_req_data_set_propogate_offline_status(struct cache_req_data *data,
                                            bool propogate_offline_status);

void
cache_req_data_set_hybrid_lookup(struct cache_req_data *data,
                                 bool hybrid_lookup);

enum cache_req_type
cache_req_data_get_type(struct cache_req_data *data);

/* Output data. */

struct cache_req_result {
    /**
     * SSSD domain where the result was obtained.
     */
    struct sss_domain_info *domain;

    /**
     * Result from ldb lookup.
     */
    struct ldb_result *ldb_result;

    /**
     * Shortcuts into ldb_result. This shortens the code a little since
     * callers usually don't don't need to work with ldb_result directly.
     */
    unsigned int count;
    struct ldb_message **msgs;

    /**
     * If name was used as a lookup parameter, @lookup_name contains name
     * normalized to @domain rules.
     */
    const char *lookup_name;

    /**
     * If true the result contain attributes of a well known object.
     * Since this result is manually created it may not contain all
     * requested attributes, depending on the plug-in.
     */
    bool well_known_object;

    /* If this is a well known object, it may not be part of any particular
     * SSSD domain, but still may be associated with a well known domain
     * name such as "BUILTIN", or "LOCAL AUTHORITY".
     */
    const char *well_known_domain;
};

/**
 * Shallow copy of cache request result, limiting the result to a maximum
 * numbers of records.
 */
struct cache_req_result *
cache_req_copy_limited_result(TALLOC_CTX *mem_ctx,
                              struct cache_req_result *result,
                              uint32_t start,
                              uint32_t limit);

/* Generic request. */

struct tevent_req *cache_req_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int midpoint,
                                  enum cache_req_dom_type req_dom_type,
                                  const char *domain,
                                  struct cache_req_data *data);

uint32_t cache_req_get_reqid(struct tevent_req *req);

errno_t cache_req_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct cache_req_result ***_results);

errno_t cache_req_single_domain_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     struct cache_req_result **_result);

/* Plug-ins. */

struct tevent_req *
cache_req_user_by_name_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int cache_refresh_percent,
                            enum cache_req_dom_type req_dom_type,
                            const char *domain,
                            const char *name);

#define cache_req_user_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_user_by_name_attrs_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int cache_refresh_percent,
                                  const char *domain,
                                  const char *name,
                                  const char **attrs);

#define cache_req_user_by_name_attrs_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_user_by_upn_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int cache_refresh_percent,
                           enum cache_req_dom_type req_dom_type,
                           const char *domain,
                           const char *upn);

#define cache_req_user_by_upn_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result);

struct tevent_req *
cache_req_user_by_id_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct resp_ctx *rctx,
                          struct sss_nc_ctx *ncache,
                          int cache_refresh_percent,
                          const char *domain,
                          uid_t uid);

#define cache_req_user_by_id_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result);

struct tevent_req *
cache_req_user_by_cert_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int cache_refresh_percent,
                            enum cache_req_dom_type req_dom_type,
                            const char *domain,
                            const char *pem_cert);

#define cache_req_user_by_cert_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_group_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct resp_ctx *rctx,
                             struct sss_nc_ctx *ncache,
                             int cache_refresh_percent,
                             enum cache_req_dom_type req_dom_type,
                             const char *domain,
                             const char *name);

#define cache_req_group_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_group_by_id_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int cache_refresh_percent,
                           const char *domain,
                           gid_t gid);

#define cache_req_group_by_id_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_initgr_by_name_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int cache_refresh_percent,
                              enum cache_req_dom_type req_dom_type,
                              const char *domain,
                              const char *name);

#define cache_req_initgr_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_user_by_filter_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              enum cache_req_dom_type req_dom_type,
                              const char *domain,
                              const char *attr,
                              const char *filter);

#define cache_req_user_by_filter_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_group_by_filter_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              enum cache_req_dom_type req_dom_type,
                              const char *domain,
                              const char *filter);

#define cache_req_group_by_filter_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_object_by_sid_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct resp_ctx *rctx,
                             struct sss_nc_ctx *ncache,
                             int cache_refresh_percent,
                             const char *domain,
                             const char *sid,
                             const char **attrs);

#define cache_req_object_by_sid_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_object_by_name_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int cache_refresh_percent,
                              const char *domain,
                              const char *name,
                              const char **attrs);

#define cache_req_object_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_object_by_id_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int cache_refresh_percent,
                            const char *domain,
                            uint32_t id,
                            const char **attrs);

#define cache_req_object_by_id_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_svc_by_name_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int cache_refresh_percent,
                           const char *domain,
                           const char *name,
                           const char *protocol);

#define cache_req_svc_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_svc_by_port_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int cache_refresh_percent,
                           const char *domain,
                           uint16_t port,
                           const char *protocol);

#define cache_req_svc_by_port_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_netgroup_by_name_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct resp_ctx *rctx,
                                struct sss_nc_ctx *ncache,
                                int cache_refresh_percent,
                                const char *domain,
                                const char *name);

#define cache_req_netgroup_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_ssh_host_id_by_name_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct resp_ctx *rctx,
                                   struct sss_nc_ctx *ncache,
                                   int cache_refresh_percent,
                                   const char *domain,
                                   const char *name,
                                   const char *alias,
                                   const char **attrs);

#define cache_req_ssh_host_id_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_autofs_map_entries_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int cache_refresh_percent,
                                  const char *domain,
                                  const char *name);

#define cache_req_autofs_map_entries_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_autofs_map_by_name_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int cache_refresh_percent,
                                  const char *domain,
                                  const char *name);

#define cache_req_autofs_map_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

struct tevent_req *
cache_req_autofs_entry_by_name_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct resp_ctx *rctx,
                                    struct sss_nc_ctx *ncache,
                                    int cache_refresh_percent,
                                    const char *domain,
                                    const char *mapname,
                                    const char *entryname);

#define cache_req_autofs_entry_by_name_recv(mem_ctx, req, _result) \
    cache_req_single_domain_recv(mem_ctx, req, _result)

#endif /* _CACHE_REQ_H_ */
