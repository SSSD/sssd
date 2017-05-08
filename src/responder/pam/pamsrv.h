/*
    Authors:
        Simo Sorce <ssorce@redhat.com>
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#ifndef __PAMSRV_H__
#define __PAMSRV_H__

#include <security/pam_appl.h>
#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"

struct pam_auth_req;

typedef void (pam_dp_callback_t)(struct pam_auth_req *preq);

struct pam_ctx {
    struct resp_ctx *rctx;
    time_t id_timeout;
    hash_table_t *id_table;
    size_t trusted_uids_count;
    uid_t *trusted_uids;

    /* List of domains that are accessible even for untrusted users. */
    char **public_domains;
    int public_domains_count;

    /* What services are permitted to access application domains */
    char **app_services;

    bool cert_auth;
    int p11_child_debug_fd;
    char *nss_db;
};

struct pam_auth_dp_req {
    struct pam_auth_req *preq;
};

struct pam_auth_req {
    struct cli_ctx *cctx;
    struct sss_domain_info *domain;
    enum cache_req_dom_type req_dom_type;

    struct pam_data *pd;

    pam_dp_callback_t *callback;

    bool is_uid_trusted;
    void *data;
    bool use_cached_auth;
    /* whether cached authentication was tried and failed */
    bool cached_auth_failed;

    struct pam_auth_dp_req *dpreq_spy;

    struct ldb_message *user_obj;
    struct ldb_result *cert_user_objs;
    char *token_name;
    char *module_name;
    char *key_id;
    bool cert_auth_local;
};

struct sss_cmd_table *get_pam_cmds(void);

int pam_dp_send_req(struct pam_auth_req *preq, int timeout);

int LOCAL_pam_handler(struct pam_auth_req *preq);

errno_t p11_child_init(struct pam_ctx *pctx);

struct tevent_req *pam_check_cert_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       int child_debug_fd,
                                       const char *nss_db,
                                       time_t timeout,
                                       const char *verify_opts,
                                       struct pam_data *pd);
errno_t pam_check_cert_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            char **cert, char **token_name, char **module_name,
                            char **key_id);

errno_t add_pam_cert_response(struct pam_data *pd, const char *user,
                              const char *token_name, const char *module_name,
                              const char *key_id, enum response_type type);

bool may_do_cert_auth(struct pam_ctx *pctx, struct pam_data *pd);

errno_t
pam_set_last_online_auth_with_curr_token(struct sss_domain_info *domain,
                                         const char *username,
                                         uint64_t value);

errno_t filter_responses(struct confdb_ctx *cdb,
                         struct response_data *resp_list,
                         struct pam_data *pd);
#endif /* __PAMSRV_H__ */
