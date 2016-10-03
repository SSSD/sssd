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
    CACHE_REQ_SENTINEL
};

/* Input data. */

struct cache_req_data;

/* Generic request. */

struct tevent_req *cache_req_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *ncache,
                                  int midpoint,
                                  const char *domain,
                                  struct cache_req_data *data);

errno_t cache_req_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ldb_result **_result,
                       struct sss_domain_info **_domain,
                       char **_name);

#endif /* _CACHE_REQ_H_ */
