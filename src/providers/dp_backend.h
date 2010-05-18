/*
   SSSD

   Data Provider, private header file

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#ifndef __DP_BACKEND_H__
#define __DP_BACKEND_H__

#include "providers/data_provider.h"
#include "providers/fail_over.h"
#include "db/sysdb.h"

/* a special token, if used in place of the hostname, denotes that real
 * hostnames should be looked up from DNS using SRV requests
 */
#define BE_SRV_IDENTIFIER  "_srv_"

struct be_ctx;
struct bet_ops;
struct be_req;

typedef int (*bet_init_fn_t)(TALLOC_CTX *, struct bet_ops **, void **);
typedef void (*be_shutdown_fn)(void *);
typedef void (*be_req_fn_t)(struct be_req *);
typedef void (*be_async_callback_t)(struct be_req *, int, int, const char *);

typedef void (*be_callback_t)(void *);

enum bet_type {
    BET_NULL = 0,
    BET_ID,
    BET_AUTH,
    BET_ACCESS,
    BET_CHPASS,
    BET_MAX
};

struct bet_data {
    enum bet_type bet_type;
    const char *option_name;
    const char *mod_init_fn_name_fmt;
};

struct loaded_be {
    char *be_name;
    void *handle;
};

struct bet_info {
    enum bet_type bet_type;
    struct bet_ops *bet_ops;
    void *pvt_bet_data;
    char *mod_name;
};

struct be_offline_status {
    time_t went_offline;
    bool offline;
};

struct be_client {
    struct be_ctx *bectx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
    bool initialized;
};

struct be_failover_ctx;

struct be_cb;

struct be_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    const char *identity;
    const char *conf_path;
    struct be_failover_ctx *be_fo;

    /* Functions to be invoked when the
     * backend goes online or offline
     */
    struct be_cb *online_cb_list;
    bool run_online_cb;
    struct be_cb *offline_cb_list;

    struct be_offline_status offstat;

    struct sbus_connection *mon_conn;
    struct sbus_connection *sbus_srv;

    struct be_client *nss_cli;
    struct be_client *pam_cli;

    struct loaded_be loaded_be[BET_MAX];
    struct bet_info bet_info[BET_MAX];
};

struct bet_ops {
    be_req_fn_t check_online;
    be_req_fn_t handler;
    be_req_fn_t finalize;
};

#define MAX_BE_REQ_RESTARTS 2

struct be_req {
    struct be_client *becli;
    struct be_ctx *be_ctx;
    void *req_data;

    be_async_callback_t fn;
    void *pvt;

    int restarts;
};

struct be_acct_req {
    int entry_type;
    int attr_type;
    int filter_type;
    char *filter_value;
};

bool be_is_offline(struct be_ctx *ctx);
void be_mark_offline(struct be_ctx *ctx);

int be_add_online_cb(TALLOC_CTX *mem_ctx,
                     struct be_ctx *ctx,
                     be_callback_t cb,
                     void *pvt,
                     struct be_cb **online_cb);
void be_run_online_cb(struct be_ctx *be);

int be_add_offline_cb(TALLOC_CTX *mem_ctx,
                     struct be_ctx *ctx,
                     be_callback_t cb,
                     void *pvt,
                     struct be_cb **online_cb);
void be_run_offline_cb(struct be_ctx *be);

/* from data_provider_fo.c */
typedef void (be_svc_callback_fn_t)(void *, struct fo_server *);

int be_init_failover(struct be_ctx *ctx);
int be_fo_is_srv_identifier(const char *server);
int be_fo_add_service(struct be_ctx *ctx, const char *service_name);
int be_fo_service_add_callback(TALLOC_CTX *memctx,
                               struct be_ctx *ctx, const char *service_name,
                               be_svc_callback_fn_t *fn, void *private_data);
int be_fo_add_srv_server(struct be_ctx *ctx, const char *service_name,
                         const char *query_service, const char *proto,
                         const char *domain, void *user_data);
int be_fo_add_server(struct be_ctx *ctx, const char *service_name,
                     const char *server, int port, void *user_data);

struct tevent_req *be_resolve_server_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct be_ctx *ctx,
                                          const char *service_name);
int be_resolve_server_recv(struct tevent_req *req, struct fo_server **srv);

int be_fo_run_callbacks_at_next_request(struct be_ctx *ctx,
                                        const char *service_name);
#endif /* __DP_BACKEND_H___ */
