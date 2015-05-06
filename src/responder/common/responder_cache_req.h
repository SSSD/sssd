/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#ifndef RESPONDER_CACHE_H_
#define RESPONDER_CACHE_H_

#include <talloc.h>
#include <tevent.h>
#include "db/sysdb.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"

enum cache_req_type {
    CACHE_REQ_USER_BY_NAME,
    CACHE_REQ_USER_BY_UPN,
    CACHE_REQ_USER_BY_ID,
    CACHE_REQ_GROUP_BY_NAME,
    CACHE_REQ_GROUP_BY_ID,
    CACHE_REQ_INITGROUPS,
    CACHE_REQ_INITGROUPS_BY_UPN,
    CACHE_REQ_USER_BY_CERT,
    CACHE_REQ_USER_BY_FILTER,
    CACHE_REQ_GROUP_BY_FILTER
};

struct cache_req_input;

struct cache_req_input *
cache_req_input_create(TALLOC_CTX *mem_ctx,
                       enum cache_req_type type,
                       const char *name,
                       uint32_t id,
                       const char *cert);

/**
 * Currently only SSS_DP_USER and SSS_DP_INITGROUPS are supported.
 *
 * @todo support other request types
 */
struct tevent_req *cache_req_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int neg_timeout,
                                  int cache_refresh_percent,
                                  const char *domain,
                                  struct cache_req_input *input);

errno_t cache_req_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ldb_result **_result,
                       struct sss_domain_info **_domain,
                       char **_name);

struct tevent_req *
cache_req_user_by_name_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct resp_ctx *rctx,
                            struct sss_nc_ctx *ncache,
                            int neg_timeout,
                            int cache_refresh_percent,
                            const char *domain,
                            const char *name);

#define cache_req_user_by_name_recv(mem_ctx, req, _result, _domain, _name) \
    cache_req_recv(mem_ctx, req, _result, _domain, _name)

struct tevent_req *
cache_req_user_by_id_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct resp_ctx *rctx,
                          struct sss_nc_ctx *ncache,
                          int neg_timeout,
                          int cache_refresh_percent,
                          const char *domain,
                          uid_t uid);

#define cache_req_user_by_id_recv(mem_ctx, req, _result, _domain) \
    cache_req_recv(mem_ctx, req, _result, _domain, NULL)

struct tevent_req *
cache_req_user_by_cert_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct resp_ctx *rctx,
                          struct sss_nc_ctx *ncache,
                          int neg_timeout,
                          int cache_refresh_percent,
                          const char *domain,
                          const char *pem_cert);

#define cache_req_user_by_cert_recv(mem_ctx, req, _result, _domain, _name) \
    cache_req_recv(mem_ctx, req, _result, _domain, _name)

struct tevent_req *
cache_req_group_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct resp_ctx *rctx,
                             struct sss_nc_ctx *ncache,
                             int neg_timeout,
                             int cache_refresh_percent,
                             const char *domain,
                             const char *name);

#define cache_req_group_by_name_recv(mem_ctx, req, _result, _domain, _name) \
    cache_req_recv(mem_ctx, req, _result, _domain, _name)

struct tevent_req *
cache_req_group_by_id_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_nc_ctx *ncache,
                           int neg_timeout,
                           int cache_refresh_percent,
                           const char *domain,
                           gid_t gid);

#define cache_req_group_by_id_recv(mem_ctx, req, _result, _domain) \
    cache_req_recv(mem_ctx, req, _result, _domain, NULL)

struct tevent_req *
cache_req_initgr_by_name_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int neg_timeout,
                              int cache_refresh_percent,
                              const char *domain,
                              const char *name);

#define cache_req_initgr_by_name_recv(mem_ctx, req, _result, _domain, _name) \
    cache_req_recv(mem_ctx, req, _result, _domain, _name)

struct tevent_req *
cache_req_user_by_filter_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              const char *domain,
                              const char *filter);

#define cache_req_user_by_filter_recv(mem_ctx, req, _result, _domain) \
    cache_req_recv(mem_ctx, req, _result, _domain, NULL)

struct tevent_req *
cache_req_group_by_filter_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              const char *domain,
                              const char *filter);

#define cache_req_group_by_filter_recv(mem_ctx, req, _result, _domain) \
    cache_req_recv(mem_ctx, req, _result, _domain, NULL)

#endif /* RESPONDER_CACHE_H_ */
