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
#include "providers/be_netlink.h"
#include "providers/be_refresh.h"
#include "providers/data_provider/dp.h"
#include "util/child_common.h"
#include "util/session_recording.h"
#include "db/sysdb.h"

/* a special token, if used in place of the hostname, denotes that real
 * hostnames should be looked up from DNS using SRV requests
 */
#define BE_SRV_IDENTIFIER  "_srv_"

struct be_ctx;

typedef void (*be_callback_t)(void *);

struct be_resolv_ctx {
    struct resolv_ctx *resolv;
    struct dp_option *opts;

    enum restrict_family family_order;
};

struct be_svc_data {
    struct be_svc_data *prev;
    struct be_svc_data *next;

    const char *name;
    struct fo_service *fo_service;

    char *last_good_srv;
    int last_good_port;
    time_t last_status_change;
    bool run_callbacks;

    struct be_svc_callback *callbacks;
    struct fo_server *first_resolved;
};

struct be_failover_ctx {
    struct fo_ctx *fo_ctx;
    struct be_resolv_ctx *be_res;

    struct be_svc_data *svcs;
    struct tevent_timer *primary_server_handler;
};

struct be_cb;

struct be_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    struct sss_domain_info *domain;
    const char *identity;
    const char *conf_path;
    const char *sbus_name;
    char override_space;
    struct session_recording_conf sr_conf;
    struct be_failover_ctx *be_fo;
    struct be_resolv_ctx *be_res;
    struct file_watch_ctx *file_ctx;

    /* Functions to be invoked when the
     * backend goes online or offline
     */
    struct be_cb *online_cb_list;
    bool run_online_cb;
    struct be_cb *offline_cb_list;
    bool run_offline_cb;
    struct be_cb *reconnect_cb_list;
    /* In contrast to online_cb_list which are only run if the backend is
     * offline the unconditional_online_cb_list should be run whenever the
     * backend receives a request to go online. The typical use case is to
     * reset timers independently of the state of the backend. */
    struct be_cb *unconditional_online_cb_list;

    bool offline;
    /* Periodically check if we can go online. */
    struct be_ptask *check_if_online_ptask;

    struct be_refresh_ctx *refresh_ctx;
    struct be_netlink_ctx *nlctx;

    size_t check_online_ref_count;
    int check_online_retry_delay;

    struct data_provider *provider;
    struct sbus_connection *conn;

    /* Indicates whether the last state of the DP that has been logged is
     * DP_ERR_OK or DP_ERR_OFFLINE. The only usage of this var, so far, is
     * to log the DP status without spamming the syslog/journal. */
    int last_dp_state;

    /* List of periodic tasks */
    struct be_ptask *tasks;
};

bool be_is_offline(struct be_ctx *ctx);
void be_mark_offline(struct be_ctx *ctx);
void be_mark_dom_offline(struct sss_domain_info *dom, struct be_ctx *ctx);

int be_add_reconnect_cb(TALLOC_CTX *mem_ctx,
                        struct be_ctx *ctx,
                        be_callback_t cb,
                        void *pvt,
                        struct be_cb **reconnect_cb);
void be_run_reconnect_cb(struct be_ctx *be);

int be_add_online_cb(TALLOC_CTX *mem_ctx,
                     struct be_ctx *ctx,
                     be_callback_t cb,
                     void *pvt,
                     struct be_cb **online_cb);
void be_run_online_cb(struct be_ctx *be);
int be_add_unconditional_online_cb(TALLOC_CTX *mem_ctx, struct be_ctx *ctx,
                                   be_callback_t cb, void *pvt,
                                   struct be_cb **unconditional_online_cb);
void be_run_unconditional_online_cb(struct be_ctx *be);

int be_add_offline_cb(TALLOC_CTX *mem_ctx,
                     struct be_ctx *ctx,
                     be_callback_t cb,
                     void *pvt,
                     struct be_cb **online_cb);
void be_run_offline_cb(struct be_ctx *be);

/* from data_provider_fo.c */
enum be_fo_protocol {
    BE_FO_PROTO_TCP,
    BE_FO_PROTO_UDP,
    BE_FO_PROTO_SENTINEL
};

typedef void (be_svc_callback_fn_t)(void *, struct fo_server *);

int be_init_failover(struct be_ctx *ctx);
int be_fo_is_srv_identifier(const char *server);
int be_fo_add_service(struct be_ctx *ctx, const char *service_name,
                      datacmp_fn user_data_cmp);
int be_fo_service_add_callback(TALLOC_CTX *memctx,
                               struct be_ctx *ctx, const char *service_name,
                               be_svc_callback_fn_t *fn, void *private_data);
int be_fo_get_server_count(struct be_ctx *ctx, const char *service_name);

void be_fo_set_srv_lookup_plugin(struct be_ctx *ctx,
                                 fo_srv_lookup_plugin_send_t send_fn,
                                 fo_srv_lookup_plugin_recv_t recv_fn,
                                 void *pvt,
                                 const char *plugin_name);

errno_t be_fo_set_dns_srv_lookup_plugin(struct be_ctx *be_ctx,
                                        const char *hostname);

int be_fo_add_srv_server(struct be_ctx *ctx,
                         const char *service_name,
                         const char *query_service,
                         const char *default_discovery_domain,
                         enum be_fo_protocol proto,
                         bool proto_fallback, void *user_data);
int be_fo_add_server(struct be_ctx *ctx, const char *service_name,
                     const char *server, int port, void *user_data,
                     bool primary);

struct tevent_req *be_resolve_server_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct be_ctx *ctx,
                                          const char *service_name,
                                          bool first_try);
int be_resolve_server_recv(struct tevent_req *req,
                           TALLOC_CTX *ref_ctx,
                           struct fo_server **srv);

#define be_fo_set_port_status(ctx, service_name, server, status) \
    _be_fo_set_port_status(ctx, service_name, server, status, \
                           __LINE__, __FILE__, __FUNCTION__)

void _be_fo_set_port_status(struct be_ctx *ctx,
                            const char *service_name,
                            struct fo_server *server,
                            enum port_status status,
                            int line,
                            const char *file,
                            const char *function);

/*
 * Instruct fail-over to try next server on the next connect attempt.
 * Should be used after connection to service was unexpectedly dropped
 * but there is no authoritative information on whether active server is down.
 */
void be_fo_try_next_server(struct be_ctx *ctx, const char *service_name);

int be_fo_run_callbacks_at_next_request(struct be_ctx *ctx,
                                        const char *service_name);

void reset_fo(struct be_ctx *be_ctx);
void be_fo_reset_svc(struct be_ctx *be_ctx, const char *svc_name);

const char *be_fo_get_active_server_name(struct be_ctx *ctx,
                                         const char *service_name);

errno_t be_res_init(struct be_ctx *ctx);

#endif /* __DP_BACKEND_H___ */
