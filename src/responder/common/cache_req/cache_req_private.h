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
    DEBUG(level, "CR [%s #%u]: " fmt, \
          (cr)->reqname, (cr)->reqid, ##__VA_ARGS__)

struct cache_req {
    /* Provided input. */
    struct cache_req_data *data;

    struct cache_req_plugin *plugin;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int midpoint;

    /* Data Provider request type resolved from @type.
     * FIXME: This is currently needed for data provider calls. We should
     * refactor responder_dp.c to get rid of this member. */
    enum sss_dp_acct_type dp_type;

    /* Domain related informations. */
    struct sss_domain_info *domain;

    /* Debug information */
    uint32_t reqid;
    const char *reqname;
    const char *debugobj;

    /* Time when the request started. Useful for by-filter lookups */
    time_t req_start;
};

/* Input data. */
struct cache_req_data {
    enum cache_req_type type;
    struct {
        const char *input;  /* Original input. */
        const char *name;   /* Parsed name or UPN. */
        const char *lookup; /* Converted per domain rules. */
    } name;
    uint32_t id;
    const char *cert;
    const char *sid;
    const char **attrs;
};

struct tevent_req *
cache_req_search_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct cache_req *cr);

errno_t cache_req_search_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              struct ldb_result **_result);

struct tevent_req *
cache_req_steal_data_and_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct resp_ctx *rctx,
                              struct sss_nc_ctx *ncache,
                              int cache_refresh_percent,
                              const char *domain,
                              struct cache_req_data *data);

#endif /* _CACHE_REQ_PRIVATE_H_ */
