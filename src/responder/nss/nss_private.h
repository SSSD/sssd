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

#ifndef _NSS_PRIVATE_H_
#define _NSS_PRIVATE_H_

#include <talloc.h>
#include <tevent.h>
#include <dhash.h>
#include <ldb.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/nss/nsssrv_mmap_cache.h"
#include "lib/idmap/sss_idmap.h"

struct nss_enum_index {
    unsigned int domain;
    unsigned int result;
};

struct nss_enum_ctx {
    struct cache_req_result **result;
    struct sysdb_netgroup_ctx **netgroup;
    size_t netgroup_count;

    /* Ongoing cache request that is constructing enumeration result. */
    struct tevent_req *ongoing;

    /* If true, the object is already constructed. */
    bool is_ready;

    /* List of setent requests awaiting the result. We finish
     * them when the ongoing cache request is completed. */
    struct setent_req_list *notify_list;
};

struct nss_state_ctx {
    struct nss_enum_index pwent;
    struct nss_enum_index grent;
    struct nss_enum_index svcent;
    struct nss_enum_index netgrent;

    const char *netgroup;
};

struct nss_ctx {
    struct resp_ctx *rctx;
    struct sss_idmap_ctx *idmap_ctx;

    /* Options. */
    int cache_refresh_percent;
    int enum_cache_timeout;
    bool filter_users_in_groups;
    char *pwfield;
    char *override_homedir;
    char *fallback_homedir;
    char *homedir_substr;
    const char **extra_attributes;

    /* Enumeration. */
    struct nss_enum_ctx pwent;
    struct nss_enum_ctx grent;
    struct nss_enum_ctx svcent;
    hash_table_t *netgrent;

    /* Memory cache. */
    struct sss_mc_ctx *pwd_mc_ctx;
    struct sss_mc_ctx *grp_mc_ctx;
    struct sss_mc_ctx *initgr_mc_ctx;
};

struct sss_cmd_table *get_nss_cmds(void);

int nss_connection_setup(struct cli_ctx *cli_ctx);

errno_t
memcache_delete_entry(struct nss_ctx *nss_ctx,
                      struct resp_ctx *rctx,
                      struct sss_domain_info *domain,
                      const char *name,
                      uint32_t id,
                      enum sss_mc_type type);

struct tevent_req *
nss_get_object_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct cli_ctx *cli_ctx,
                    struct cache_req_data *data,
                    enum sss_mc_type memcache,
                    const char *input_name,
                    uint32_t input_id);

errno_t
nss_get_object_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    struct cache_req_result **_result,
                    const char **_rawname);

struct tevent_req *
nss_setent_send(TALLOC_CTX *mem_ctx,
                struct tevent_context *ev,
                struct cli_ctx *cli_ctx,
                enum cache_req_type type,
                struct nss_enum_ctx *enum_ctx);

errno_t
nss_setent_recv(struct tevent_req *req);

struct tevent_req *
nss_setnetgrent_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct cli_ctx *cli_ctx,
                     enum cache_req_type type,
                     hash_table_t *table,
                     const char *netgroup);

errno_t
nss_setnetgrent_recv(struct tevent_req *req);

/* Utils. */

const char *
nss_get_name_from_msg(struct sss_domain_info *domain,
                      struct ldb_message *msg);

const char *
nss_get_pwfield(struct nss_ctx *nctx,
                struct sss_domain_info *dom);

#endif /* _NSS_PRIVATE_H_ */
