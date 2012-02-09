/*
   SSSD

   SSS Client Responder, header file

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

#ifndef __SSS_RESPONDER_H__
#define __SSS_RESPONDER_H__

#include <stdint.h>
#include <sys/un.h>
#include <pcre.h>
#include "config.h"
#include "talloc.h"
#include "tevent.h"
#include "ldb.h"
#include "dhash.h"
#include "sbus/sssd_dbus.h"
#include "sss_client/sss_cli.h"

extern hash_table_t *dp_requests;

/* if there is a provider other than the special local */
#define NEED_CHECK_PROVIDER(provider) \
    (provider != NULL && strcmp(provider, "local") != 0)

/* needed until nsssrv.h is updated */
struct cli_request {

    /* original request from the wire */
    struct sss_packet *in;

    /* reply data */
    struct sss_packet *out;
};

struct cli_protocol_version {
    uint32_t version;
    const char *date;
    const char *description;
};

struct be_conn {
    struct be_conn *next;
    struct be_conn *prev;

    const char *cli_name;
    struct sss_domain_info *domain;

    char *sbus_address;
    struct sbus_interface *intf;
    struct sbus_connection *conn;
};

struct resp_ctx {
    struct tevent_context *ev;
    struct tevent_fd *lfde;
    int lfd;
    struct tevent_fd *priv_lfde;
    int priv_lfd;
    struct confdb_ctx *cdb;
    const char *sock_name;
    const char *priv_sock_name;

    struct sbus_connection *mon_conn;
    struct be_conn *be_conns;

    struct sss_domain_info *domains;
    struct sysdb_ctx_list *db_list;

    struct sss_cmd_table *sss_cmds;
    const char *sss_pipe_name;
    const char *confdb_service_path;

    struct sss_names_ctx *names;

    hash_table_t *dp_request_table;

    void *pvt_ctx;
};

struct cli_ctx {
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    int cfd;
    struct tevent_fd *cfde;
    struct sockaddr_un addr;
    struct cli_request *creq;
    struct cli_protocol_version *cli_protocol_version;
    int priv;
    int32_t client_euid;
    int32_t client_egid;
    int32_t client_pid;

    int pwent_dom_idx;
    int pwent_cur;

    int grent_dom_idx;
    int grent_cur;

    int svc_dom_idx;
    int svcent_cur;

    char *netgr_name;
    int netgrent_cur;

    char *automntmap_name;
};

struct sss_cmd_table {
    enum sss_cli_command cmd;
    int (*fn)(struct cli_ctx *cctx);
};

/* responder_common.c */
int sss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb,
                     struct sss_cmd_table sss_cmds[],
                     const char *sss_pipe_name,
                     const char *sss_priv_pipe_name,
                     const char *confdb_service_path,
                     const char *svc_name,
                     uint16_t svc_version,
                     struct sbus_interface *monitor_intf,
                     const char *cli_name,
                     struct sbus_interface *dp_intf,
                     struct resp_ctx **responder_ctx);

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **domain, char **name);

int sss_dp_get_domain_conn(struct resp_ctx *rctx, const char *domain,
                           struct be_conn **_conn);
struct sss_domain_info *
responder_get_domain(struct sss_domain_info *doms, const char *domain);

/* responder_cmd.c */
int sss_cmd_empty_packet(struct sss_packet *packet);
int sss_cmd_send_empty(struct cli_ctx *cctx, TALLOC_CTX *freectx);
int sss_cmd_send_error(struct cli_ctx *cctx, int err);
int sss_cmd_execute(struct cli_ctx *cctx, struct sss_cmd_table *sss_cmds);
void sss_cmd_done(struct cli_ctx *cctx, void *freectx);
int sss_cmd_get_version(struct cli_ctx *cctx);
struct cli_protocol_version *register_cli_protocol_version(void);

struct setent_req_list;

/* A facility for notifying setent requests */
struct tevent_req *setent_get_req(struct setent_req_list *sl);
errno_t setent_add_ref(TALLOC_CTX *memctx,
                       void *pvt,
                       struct setent_req_list **list,
                       struct tevent_req *req);
void setent_notify(struct setent_req_list **list, errno_t err);
void setent_notify_done(struct setent_req_list **list);

errno_t
sss_cmd_check_cache(struct ldb_message *msg,
                    int cache_refresh_percent,
                    uint64_t cache_expire);

typedef void (*sss_dp_callback_t)(uint16_t err_maj, uint32_t err_min,
                                  const char *err_msg, void *ptr);

struct dp_callback_ctx {
    sss_dp_callback_t callback;
    void *ptr;

    void *mem_ctx;
    struct cli_ctx *cctx;
};

void handle_requests_after_reconnect(void);

int responder_logrotate(DBusMessage *message,
                        struct sbus_connection *conn);

/* Each responder-specific request must create a constructor
 * function that creates a DBus Message that would be sent to
 * the back end
 */
typedef DBusMessage * (dbus_msg_constructor)(void *);

/*
 * This function is indended for consumption by responders to create
 * responder-specific requests such as sss_dp_get_account_send for
 * downloading account data.
 *
 * Issues a new back end request based on strkey if not already running
 * or registers a callback that is called when an existing request finishes.
 */
errno_t
sss_dp_issue_request(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                     const char *strkey, struct sss_domain_info *dom,
                     dbus_msg_constructor msg_create, void *pvt,
                     struct tevent_req *nreq);

/* Every provider specific request uses this structure as the tevent_req
 * "state" structure.
 */
struct sss_dp_req_state {
    dbus_uint16_t dp_err;
    dbus_uint32_t dp_ret;
    char *err_msg;
};

/* The _recv functions of provider specific requests usually need to
 * only call sss_dp_req_recv() to get return codes from back end
 */
errno_t
sss_dp_req_recv(TALLOC_CTX *mem_ctx,
                struct tevent_req *sidereq,
                dbus_uint16_t *dp_err,
                dbus_uint32_t *dp_ret,
                char **err_msg);

/* Send a request to the data provider
 * Once this function is called, the communication
 * with the data provider will always run to
 * completion. Freeing the returned tevent_req will
 * cancel the notification of completion, but not
 * the data provider action.
 */

enum sss_dp_acct_type {
    SSS_DP_USER = 1,
    SSS_DP_GROUP,
    SSS_DP_INITGROUPS,
    SSS_DP_NETGR,
    SSS_DP_SERVICES,
    SSS_DP_HOST
};

struct tevent_req *
sss_dp_get_account_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        enum sss_dp_acct_type type,
                        const char *opt_name,
                        uint32_t opt_id,
                        const char *extra);
errno_t
sss_dp_get_account_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *err_maj,
                        dbus_uint32_t *err_min,
                        char **err_msg);

bool sss_utf8_check(const uint8_t *s, size_t n);

#endif /* __SSS_RESPONDER_H__ */
