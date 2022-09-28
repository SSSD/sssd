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

#ifndef _CACHE_REQ_PRIVATE_H_
#define _CACHE_REQ_PRIVATE_H_

#include <stdint.h>

#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"

#define CACHE_REQ_DEBUG(level, cr, fmt, ...) \
    DEBUG(level, "CR #%u: " fmt, (cr)->reqid, ##__VA_ARGS__)

/* Tracing message, changing this can break log parsing tools */
#define SSS_REQ_TRACE_CID_CR(level, cr, fmt, ...) \
    CACHE_REQ_DEBUG(level, cr, "REQ_TRACE: " fmt, ##__VA_ARGS__)

struct cache_req {
    /* Provided input. */
    struct cache_req_data *data;

    const struct cache_req_plugin *plugin;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int midpoint;

    /* Domain related information. */
    struct sss_domain_info *domain;

    /* wanted cache behavior */
    enum cache_req_behavior cache_behavior;

    /* Only contact domains with this type */
    enum cache_req_dom_type req_dom_type;

    /* Debug information */
    uint32_t reqid;
    const char *reqname;
    const char *debugobj;

    /* Time when the request started. Useful for by-filter lookups */
    time_t req_start;
};

/**
 * Structure to hold the information the user passed as parameter
 * and some strings after processing this information.
 */
struct cache_req_parsed_name {
    const char *input;  /* Original input. */
    const char *name;   /* Parsed name or UPN. */
    const char *lookup; /* Converted per domain rules. */
    const char *attr;   /* Attribute name when looking for an attribute */
};

/**
 * Structure to hold the input strings that cannot contain domain
 * part but are transferred per each domain's case sensitivity.
 */
struct cache_req_cased_name {
    const char *name;   /* Parsed name or UPN. */
    const char *lookup; /* Converted per domain rules. */
};

/* Input data. */
struct cache_req_data {
    enum cache_req_type type;
    struct cache_req_parsed_name name;
    uint32_t id;
    const char *cert;
    const char *sid;
    const char *alias;
    const char **attrs;
    const char *autofs_entry_name;

    struct {
        struct cache_req_parsed_name *name;
        struct cache_req_cased_name protocol;
        uint16_t port;
    } svc;

    struct {
        uint32_t af;
        uint32_t len;
        uint8_t *data;
    } addr;

    bool bypass_cache;
    bool bypass_dp;

    /* if set, only search in the listed domains */
    char **requested_domains;

    /* if set, ERR_OFFLINE is returned if data provider is offline */
    bool propogate_offline_status;

    /* if set, only domains with MPG_HYBRID are searched */
    bool hybrid_lookup;
};

struct tevent_req *
cache_req_search_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct cache_req *cr,
                      bool first_iteration,
                      bool cache_only_override);

errno_t cache_req_search_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              struct ldb_result **_result,
                              bool *_dp_success);

struct tevent_req *cache_req_locate_domain_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct cache_req *cr);
errno_t cache_req_locate_domain_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     char **_found_domain);

struct tevent_req *
cache_req_steal_data_and_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int cache_refresh_percent,
                              enum cache_req_dom_type req_dom_type,
                              const char *domain,
                              struct cache_req_data *data);

void cache_req_search_ncache_add_to_domain(struct cache_req *cr,
                                           struct sss_domain_info *domain);

errno_t
cache_req_add_result(TALLOC_CTX *mem_ctx,
                     struct cache_req_result *new_result,
                     struct cache_req_result ***_results,
                     size_t *_num_results);

struct cache_req_result *
cache_req_create_result(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        struct ldb_result *ldb_result,
                        const char *lookup_name,
                        const char *well_known_domain);

errno_t
cache_req_create_and_add_result(TALLOC_CTX *mem_ctx,
                                struct cache_req *cr,
                                struct sss_domain_info *domain,
                                struct ldb_result *ldb_result,
                                const char *name,
                                struct cache_req_result ***_results,
                                size_t *_num_results);

struct ldb_result *
cache_req_create_ldb_result_from_msg_list(TALLOC_CTX *mem_ctx,
                                          struct ldb_message **ldb_msgs,
                                          size_t ldb_msg_count);

struct ldb_result *
cache_req_create_ldb_result_from_msg(TALLOC_CTX *mem_ctx,
                                     struct ldb_message *ldb_msg);

struct cache_req_result *
cache_req_create_result_from_msg(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 struct ldb_message *ldb_msg,
                                 const char *lookup_name,
                                 const char *well_known_domain);

struct tevent_req *
cache_req_sr_overlay_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct cache_req *cr,
                          struct cache_req_result **results,
                          size_t num_results);

errno_t
cache_req_sr_overlay_recv(struct tevent_req *req);

/* Plug-in common. */

struct cache_req_result *
cache_req_well_known_sid_result(TALLOC_CTX *mem_ctx,
                                struct cache_req *cr,
                                const char *domname,
                                const char *sid,
                                const char *name);

bool
cache_req_common_process_dp_reply(struct cache_req *cr,
                                  errno_t ret,
                                  uint16_t err_maj,
                                  uint32_t err_min,
                                  const char *err_msg);

bool
cache_req_common_dp_recv(struct tevent_req *subreq,
                         struct cache_req *cr);

errno_t
cache_req_common_get_acct_domain_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *subreq,
                                      struct cache_req *cr,
                                      char **_domain);

errno_t cache_req_idminmax_check(struct cache_req_data *data,
                                 struct sss_domain_info *domain);
#endif /* _CACHE_REQ_PRIVATE_H_ */
