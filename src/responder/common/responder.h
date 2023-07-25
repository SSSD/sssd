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

#include "config.h"

#include <stdint.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <dhash.h>

#include "util/sss_regexp.h"
#include "sss_iface/sss_iface_async.h"
#include "responder/common/negcache.h"
#include "sss_client/sss_cli.h"
#include "responder/common/cache_req/cache_req_domain.h"
#include "util/session_recording.h"

extern hash_table_t *dp_requests;

/* we want default permissions on created files to be very strict,
 * so set our umask to 0177 */
#define DFL_RSP_UMASK SSS_DFL_UMASK

/* Public sockets must be readable and writable by anybody on the system.
 * So we set umask to 0111. */
#define SCKT_RSP_UMASK 0111

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

struct cli_protocol {
    struct cli_request *creq;
    struct cli_protocol_version *cli_protocol_version;
};

struct resp_ctx;

struct be_conn {
    struct be_conn *next;
    struct be_conn *prev;

    struct resp_ctx *rctx;

    const char *cli_name;
    struct sss_domain_info *domain;

    char *bus_name;
    char *sbus_address;
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

    struct sss_nc_ctx *ncache;
    struct sss_names_ctx *global_names;

    struct sbus_connection *mon_conn;
    struct be_conn *be_conns;

    struct sss_domain_info *domains;
    int domains_timeout;
    int client_idle_timeout;

    struct cache_req_domain *cr_domains;
    const char *domain_resolution_order;

    time_t last_request_time;
    int idle_timeout;
    struct tevent_timer *idle;

    struct sss_cmd_table *sss_cmds;
    const char *sss_pipe_name;
    const char *confdb_service_path;

    struct timeval get_domains_last_call;

    size_t allowed_uids_count;
    uid_t *allowed_uids;

    char *default_domain;
    char override_space;

    char **allowed_shells;
    char *override_shell;
    char **vetoed_shells;
    char **etc_shells;
    char *shell_fallback;
    char *default_shell;

    struct session_recording_conf sr_conf;

    uint32_t cache_req_num;
    uint32_t client_id_num;

    void *pvt_ctx;

    bool shutting_down;
    bool socket_activated;
    bool dbus_activated;
    bool cache_first;
    bool enumeration_warn_logged;
};

struct cli_creds;

struct cli_ctx {
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    int cfd;
    struct tevent_fd *cfde;
    tevent_fd_handler_t cfd_handler;
    struct sockaddr_un addr;
    int priv;

    struct cli_creds *creds;
    char *cmd_line;

    void *protocol_ctx;
    void *state_ctx;

    struct tevent_timer *idle;
    time_t last_request_time;
    uint32_t client_id_num;
};

struct sss_cmd_table {
    enum sss_cli_command cmd;
    int (*fn)(struct cli_ctx *cctx);
};

/* from generated code */
struct mon_cli_iface;

/*
 * responder_common.c
 *
 */

typedef int (*connection_setup_t)(struct cli_ctx *cctx);

int sss_connection_setup(struct cli_ctx *cctx);

void sss_client_fd_handler(void *ptr,
                           void (*recv_fn) (struct cli_ctx *cctx),
                           void (*send_fn) (struct cli_ctx *cctx),
                           uint16_t flags);

int sss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb,
                     struct sss_cmd_table sss_cmds[],
                     const char *sss_pipe_name,
                     int pipe_fd,
                     const char *sss_priv_pipe_name,
                     int priv_pipe_fd,
                     const char *confdb_service_path,
                     const char *conn_name,
                     const char *svc_name,
                     connection_setup_t conn_setup,
                     struct resp_ctx **responder_ctx);

int sss_dp_get_domain_conn(struct resp_ctx *rctx, const char *domain,
                           struct be_conn **_conn);
struct sss_domain_info *
responder_get_domain(struct resp_ctx *rctx, const char *domain);

errno_t responder_get_domain_by_id(struct resp_ctx *rctx, const char *id,
                                   struct sss_domain_info **_ret_dom);

int create_pipe_fd(const char *sock_name, int *_fd, mode_t umaskval);
int activate_unix_sockets(struct resp_ctx *rctx,
                          connection_setup_t conn_setup);

/* responder_cmd.c */
int sss_cmd_empty_packet(struct sss_packet *packet);
int sss_cmd_send_empty(struct cli_ctx *cctx);
int sss_cmd_send_error(struct cli_ctx *cctx, int err);
void sss_cmd_done(struct cli_ctx *cctx, void *freectx);
int sss_cmd_get_version(struct cli_ctx *cctx);
int sss_cmd_execute(struct cli_ctx *cctx,
                    enum sss_cli_command cmd,
                    struct sss_cmd_table *sss_cmds);
struct cli_protocol_version *register_cli_protocol_version(void);

struct setent_req_list;

/* A facility for notifying setent requests */
struct tevent_req *setent_get_req(struct setent_req_list *sl);
errno_t setent_add_ref(TALLOC_CTX *memctx,
                       struct setent_req_list **list,
                       struct tevent_req *req);
void setent_notify(struct setent_req_list **list, errno_t err);
void setent_notify_done(struct setent_req_list **list);

errno_t
sss_cmd_check_cache(struct ldb_message *msg,
                    int cache_refresh_percent,
                    uint64_t cache_expire);

void handle_requests_after_reconnect(struct resp_ctx *rctx);

errno_t
responder_logrotate(TALLOC_CTX *mem_ctx,
                    struct sbus_request *sbus_req,
                    struct resp_ctx *rctx);

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
    SSS_DP_SUBID_RANGES,
    SSS_DP_NETGR,
    SSS_DP_SERVICES,
    SSS_DP_SECID,
    SSS_DP_USER_AND_GROUP,
    SSS_DP_CERT,
    SSS_DP_WILDCARD_USER,
    SSS_DP_WILDCARD_GROUP,
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
                        uint16_t *_dp_error,
                        uint32_t *_error,
                        const char **_error_message);

struct tevent_req *
sss_dp_resolver_get_send(TALLOC_CTX *mem_ctx,
                         struct resp_ctx *rctx,
                         struct sss_domain_info *dom,
                         bool fast_reply,
                         uint32_t entry_type,
                         uint32_t filter_type,
                         const char *filter_value);

errno_t
sss_dp_resolver_get_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         uint16_t *_dp_error,
                         uint32_t *_error,
                         const char **_error_message);

bool sss_utf8_check(const uint8_t *s, size_t n);

void responder_set_fd_limit(rlim_t fd_limit);

errno_t reset_client_idle_timer(struct cli_ctx *cctx);

errno_t responder_setup_idle_timeout_config(struct resp_ctx *rctx);

#define GET_DOMAINS_DEFAULT_TIMEOUT 60

struct tevent_req *sss_dp_get_domains_send(TALLOC_CTX *mem_ctx,
                                           struct resp_ctx *rctx,
                                           bool force,
                                           const char *hint);

errno_t sss_dp_get_domains_recv(struct tevent_req *req);

/*
 * Call a getAccountDomain request
 *
 * Only requests by ID are supported.
 *
 * @param   mem_ctx     Parent memory context
 * @param   rctx        Responder context
 * @param   domain      The SSSD domain we're querying. The response can
 *                      be either NULL or come from any of domain's subdomains
 *                      or domain itself
 * @param   type        Either SSS_DP_USER, SSS_DP_GROUP or SSS_DP_SECID, other
 *                      types  are not supported at the moment
 * @param   opt_id      The ID number we're trying to locate
 * @param   opt_str     The SID number we're trying to locate
 *
 * @return  A tevent request or NULL if allocating the request fails.
 */
struct tevent_req *sss_dp_get_account_domain_send(TALLOC_CTX *mem_ctx,
                                                  struct resp_ctx *rctx,
                                                  struct sss_domain_info *domain,
                                                  bool fast_reply,
                                                  enum sss_dp_acct_type type,
                                                  uint32_t opt_id,
                                                  const char *opt_str);

/* Receive a getAccountDomain request result
 *
 * @param   mem_ctx     The memory context that will own the contents of _domain
 * @param   req         The request that had finished
 * @para    _domain     Either NULL (the request did not match any domain) or
 *                      a string that corresponds to either the input domain
 *                      or any of its subdomains
 *
 * @return EOK on success, errno otherwise
 */
errno_t sss_dp_get_account_domain_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       char **_domain);

typedef void (get_domains_callback_fn_t)(void *);
errno_t schedule_get_domains_task(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *optional_ncache,
                                  get_domains_callback_fn_t *callback,
                                  void *callback_pvt);

errno_t csv_string_to_uid_array(TALLOC_CTX *mem_ctx, const char *csv_string,
                                size_t *_uid_count, uid_t **_uids);

uid_t client_euid(struct cli_creds *creds);
errno_t check_allowed_uids(uid_t uid, size_t allowed_uids_count,
                           const uid_t *allowed_uids);

struct tevent_req *
sss_parse_inp_send(TALLOC_CTX *mem_ctx,
                   struct resp_ctx *rctx,
                   const char *default_domain,
                   const char *rawinp);

errno_t sss_parse_inp_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           char **_name, char **_domname);

const char **parse_attr_list_ex(TALLOC_CTX *mem_ctx, const char *conf_str,
                                const char **defaults);

char *sss_resp_create_fqname(TALLOC_CTX *mem_ctx,
                             struct resp_ctx *rctx,
                             struct sss_domain_info *dom,
                             bool name_is_upn,
                             const char *orig_name);

errno_t sss_resp_populate_cr_domains(struct resp_ctx *rctx);

const char *
sss_resp_get_shell_override(struct ldb_message *msg,
                            struct resp_ctx *rctx,
                            struct sss_domain_info *domain);

/**
 * Helper functions to format output names
 */

/* Format orig_name into a sized_string in output format as prescribed
 * by the name_dom domain
 */
int sized_output_name(TALLOC_CTX *mem_ctx,
                      struct resp_ctx *rctx,
                      const char *orig_name,
                      struct sss_domain_info *name_dom,
                      struct sized_string **_name);

/* Format orig_name into a sized_string in output format as prescribed
 * by the domain read from the fully qualified name.
 */
int sized_domain_name(TALLOC_CTX *mem_ctx,
                      struct resp_ctx *rctx,
                      const char *member_name,
                      struct sized_string **_name);

/* Given a ldb_result structure that contains a result of sysdb_initgroups
 * where some groups might be just 'stubs' that don't have a name, but only
 * a SID and a GID, resolve those incomplete groups into full group objects
 */
struct tevent_req *resp_resolve_group_names_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct resp_ctx *rctx,
                                                 struct sss_domain_info *dom,
                                                 struct ldb_result *initgr_res);

int resp_resolve_group_names_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  struct ldb_result **_initgr_named_res);

/**
 * Register common responder sbus interface on connection.
 */
errno_t
sss_resp_register_sbus_iface(struct sbus_connection *conn,
                             struct resp_ctx *rctx);

/**
 * Register common service sbus interface on monitor connection.
 */
errno_t
sss_resp_register_service_iface(struct resp_ctx *rctx);

#endif /* __SSS_RESPONDER_H__ */
