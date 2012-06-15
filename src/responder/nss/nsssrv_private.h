/*
    SSSD

    nsssrv_private.h

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#ifndef NSSSRV_PRIVATE_H_
#define NSSSRV_PRIVATE_H_

#include "dhash.h"

struct nss_cmd_ctx {
    struct cli_ctx *cctx;
    char *name;
    uint32_t id;

    bool immediate;
    bool check_next;
    bool enum_cached;

    int saved_dom_idx;
    int saved_cur;
};

struct dom_ctx {
    struct sss_domain_info *domain;
    struct ldb_result *res;
};

struct getent_ctx {
    struct dom_ctx *doms;
    int num;
    bool ready;
    struct setent_req_list *reqs;

    /* Netgroup-specific */
    hash_table_t *lookup_table;
    struct sysdb_netgroup_ctx **entries;
    char *name;
    char *domain;
    bool found;
};

struct nss_dom_ctx {
    struct nss_cmd_ctx *cmdctx;
    struct sss_domain_info *domain;

    /* For a case when we are discovering subdomains */
    const char *rawname;

    bool check_provider;

    /* cache results */
    struct ldb_result *res;

    /* Netgroup-specific */
    struct getent_ctx *netgr;

    /* Service-specific */
    const char *protocol;
};

struct setent_step_ctx {
    struct nss_ctx *nctx;
    struct nss_dom_ctx *dctx;
    struct getent_ctx *getent_ctx;
    struct resp_ctx *rctx;
    struct cli_ctx *cctx;
    bool check_next;

    bool returned_to_mainloop;

    /* Netgroup-specific */
    char *name;
};

#define NSS_CMD_FATAL_ERROR(cctx) do { \
    DEBUG(1,("Fatal error, killing connection!\n")); \
    talloc_free(cctx); \
    return; \
} while(0)

#define NSS_CMD_FATAL_ERROR_CODE(cctx, ret) do { \
    DEBUG(1,("Fatal error, killing connection!\n")); \
    talloc_free(cctx); \
    return ret; \
} while(0)

/* Finish the request */
int nss_cmd_done(struct nss_cmd_ctx *cmdctx, int ret);

errno_t nss_setent_add_ref(TALLOC_CTX *memctx,
                           struct getent_ctx *getent_ctx,
                           struct tevent_req *req);

void nss_setent_notify_error(struct getent_ctx *getent_ctx, errno_t ret);
void nss_setent_notify_done(struct getent_ctx *getent_ctx);

errno_t check_cache(struct nss_dom_ctx *dctx,
                    struct nss_ctx *nctx,
                    struct ldb_result *res,
                    int req_type,
                    const char *opt_name,
                    uint32_t opt_id,
                    sss_dp_callback_t callback,
                    void *pvt);

#endif /* NSSSRV_PRIVATE_H_ */
