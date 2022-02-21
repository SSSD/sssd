/*
    SSSD

    Proxy provider, private header file

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef __PROXY_H__
#define __PROXY_H__

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/nss_dl_load.h"
#include "providers/backend.h"
#include "db/sysdb.h"
#include <dhash.h>
#include "sss_iface/sss_iface_async.h"

#define PROXY_CHILD_PATH "/org/freedesktop/sssd/proxychild"

struct authtok_conv {
    struct sss_auth_token *authtok;
    struct sss_auth_token *newauthtok;

    bool sent_old;
};

struct proxy_id_ctx {
    struct be_ctx *be;
    bool fast_alias;
    struct sss_nss_ops ops;
};

struct proxy_auth_ctx {
    struct be_ctx *be;
    char *pam_target;

    uint32_t max_children;
    uint32_t running;
    uint32_t next_id;
    hash_table_t *request_table;
    int timeout_ms;
};

struct proxy_resolver_ctx {
    struct sss_nss_ops ops;
};

struct proxy_module_ctx {
    struct proxy_id_ctx *id_ctx;
    struct proxy_auth_ctx *auth_ctx;
    struct proxy_resolver_ctx *resolver_ctx;
};

struct proxy_child_ctx {
    struct proxy_auth_ctx *auth_ctx;
    struct be_req *be_req;
    struct pam_data *pd;

    uint32_t id;
    pid_t pid;
    bool running;

    struct sbus_connection *conn;
    struct tevent_timer *timer;

    struct tevent_req *init_req;
};

struct pc_init_ctx {
    char *command;
    pid_t pid;
    struct tevent_timer *timeout;
    struct tevent_signal *sige;
    struct proxy_child_ctx *child_ctx;
    struct sbus_connection *conn;
};

#define PROXY_CHILD_PIPE "private/proxy_child"
#define DEFAULT_BUFSIZE 4096
#define MAX_BUF_SIZE 1024*1024 /* max 1MiB */

/* From proxy_id.c */
struct tevent_req *
proxy_account_info_handler_send(TALLOC_CTX *mem_ctx,
                               struct proxy_id_ctx *id_ctx,
                               struct dp_id_data *data,
                               struct dp_req_params *params);

errno_t proxy_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       struct dp_reply_std *data);

/* From proxy_auth.c */
struct tevent_req *
proxy_pam_handler_send(TALLOC_CTX *mem_ctx,
                      struct proxy_auth_ctx *proxy_auth_ctx,
                      struct pam_data *pd,
                      struct dp_req_params *params);

errno_t
proxy_pam_handler_recv(TALLOC_CTX *mem_ctx,
                      struct tevent_req *req,
                      struct pam_data **_data);

/* From proxy_netgroup.c */
errno_t get_netgroup(struct proxy_id_ctx *ctx,
                     struct sss_domain_info *dom,
                     const char *name);

errno_t get_serv_byname(struct proxy_id_ctx *ctx,
                        struct sss_domain_info *dom,
                        const char *name,
                        const char *protocol);

errno_t
get_serv_byport(struct proxy_id_ctx *ctx,
                struct sss_domain_info *dom,
                const char *be_filter,
                const char *protocol);

errno_t enum_services(struct proxy_id_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom);

/* From proxy_hosts.c */
struct tevent_req *
proxy_hosts_handler_send(TALLOC_CTX *mem_ctx,
                      struct proxy_resolver_ctx *proxy_resolver_ctx,
                      struct dp_resolver_data *resolver_data,
                      struct dp_req_params *params);

errno_t
proxy_hosts_handler_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct dp_reply_std *data);

/* From proxy_ipnetworks.c */
struct tevent_req *
proxy_nets_handler_send(TALLOC_CTX *mem_ctx,
                        struct proxy_resolver_ctx *proxy_resolver_ctx,
                        struct dp_resolver_data *resolver_data,
                        struct dp_req_params *params);

errno_t
proxy_nets_handler_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        struct dp_reply_std *data);

errno_t
proxy_client_init(struct sbus_connection *conn,
                  struct proxy_auth_ctx *auth_ctx);

#endif /* __PROXY_H__ */
