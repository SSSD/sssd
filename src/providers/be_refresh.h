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

#ifndef _DP_REFRESH_H_
#define _DP_REFRESH_H_

#include <tevent.h>
#include <talloc.h>

#include "providers/be_ptask.h"

/* solve circular dependency */
struct be_ctx;

#define REFRESH_SEND_RECV_FNS(outer_base, inner_base, req_type) \
                                                                \
static struct tevent_req *                                      \
outer_base ##_send(TALLOC_CTX *mem_ctx,                         \
                   struct tevent_context *ev,                   \
                   struct be_ctx *be_ctx,                       \
                   struct sss_domain_info *domain,              \
                   char **names,                                \
                   void *pvt)                                   \
{                                                               \
    return inner_base ##_send(mem_ctx, ev,                      \
                              be_ctx, domain,                   \
                              req_type, names, pvt);            \
}                                                               \
                                                                \
static errno_t outer_base ##_recv(struct tevent_req *req)       \
{                                                               \
    return inner_base ##_recv(req);                             \
}                                                               \

/**
 * name_list contains SYSDB_NAME of all expired records.
 */
typedef struct tevent_req *
(*be_refresh_send_t)(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct be_ctx *be_ctx,
                     struct sss_domain_info *domain,
                     char **values,
                     void *pvt);

typedef errno_t
(*be_refresh_recv_t)(struct tevent_req *req);

enum be_refresh_type {
    BE_REFRESH_TYPE_INITGROUPS,
    BE_REFRESH_TYPE_USERS,
    BE_REFRESH_TYPE_GROUPS,
    BE_REFRESH_TYPE_NETGROUPS,
    BE_REFRESH_TYPE_SENTINEL
};

struct be_refresh_cb {
    be_refresh_send_t send_fn;
    be_refresh_recv_t recv_fn;
    void *pvt;
};

struct be_refresh_ctx;

errno_t be_refresh_ctx_init_with_callbacks(struct be_ctx *be_ctx,
                                           const char *attr_name,
                                           struct be_refresh_cb *callbacks);

struct tevent_req *be_refresh_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *be_ctx,
                                   struct be_ptask *be_ptask,
                                   void *pvt);

errno_t be_refresh_recv(struct tevent_req *req);

struct dp_id_data *be_refresh_acct_req(TALLOC_CTX *mem_ctx,
                                       uint32_t entry_type,
                                       uint32_t filter_type,
                                       struct sss_domain_info *domain);

#endif /* _DP_REFRESH_H_ */
