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
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "lib/certmap/sss_certmap.h"

#define PROMPT_CONFIG_FIRST     1
#define PROMPT_CONFIG_SECOND    2

struct pam_auth_req;

typedef void (pam_dp_callback_t)(struct pam_auth_req *preq);

enum pam_initgroups_scheme {
    PAM_INITGR_NEVER,
    PAM_INITGR_NO_SESSION,
    PAM_INITGR_ALWAYS,
    PAM_INITGR_INVALID
};

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
    char *ca_db;
    struct sss_certmap_ctx *sss_certmap_ctx;
    char **smartcard_services;

    /* parsed list of pam_response_filter option */
    char **pam_filter_opts;

    char **prompting_config_sections;
    int num_prompting_config_sections;

    enum pam_initgroups_scheme initgroups_scheme;

    /* List of PAM services that are allowed to authenticate with GSSAPI. */
    char **gssapi_services;
    /* List of authentication indicators associated with a PAM service */
    char **gssapi_indicators_map;
    bool gssapi_check_upn;
    bool passkey_auth;
    struct pam_passkey_table_data *pk_table_data;
    char **json_services;
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

    struct ldb_message *user_obj;
    struct cert_auth_info *cert_list;
    struct cert_auth_info *current_cert;
    /* Switched to 'true' if the backend indicates that it cannot handle
     * Smartcard authentication, but Smartcard authentication is
     * possible and local Smartcard authentication is allowed. */
    bool cert_auth_local;
    /* Switched to 'true' if authentication (not pre-authentication) was
     * started without a login name and the name had to be lookup up with the
     * certificate used for authentication. Since reading the certificate from
     * the Smartcard already involves the PIN validation in this case there
     * would be no need for an additional Smartcard interaction if only local
     * Smartcard authentication is possible. */
    bool initial_cert_auth_successful;

    bool passkey_data_exists;
    uint32_t client_id_num;
};

struct pam_resp_auth_type {
    bool password_auth;
    bool otp_auth;
    bool cert_auth;
    bool passkey_auth;
    bool backend_returned_no_auth_type;
};

struct sss_cmd_table *get_pam_cmds(void);

errno_t
pam_dp_send_req(struct pam_auth_req *preq);

int pam_check_user_search(struct pam_auth_req *preq);
int pam_check_user_done(struct pam_auth_req *preq, int ret);
void pam_reply(struct pam_auth_req *preq);

errno_t p11_child_init(struct pam_ctx *pctx);

struct cert_auth_info;
const char *sss_cai_get_cert(struct cert_auth_info *i);
const char *sss_cai_get_token_name(struct cert_auth_info *i);
const char *sss_cai_get_module_name(struct cert_auth_info *i);
const char *sss_cai_get_key_id(struct cert_auth_info *i);
const char *sss_cai_get_label(struct cert_auth_info *i);
struct cert_auth_info *sss_cai_get_next(struct cert_auth_info *i);
struct ldb_result *sss_cai_get_cert_user_objs(struct cert_auth_info *i);
void sss_cai_set_cert_user_objs(struct cert_auth_info *i,
                                struct ldb_result *cert_user_objs);
void sss_cai_check_users(struct cert_auth_info **list, size_t *_cert_count,
                         size_t *_cert_user_count);

struct tevent_req *pam_check_cert_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       const char *ca_db,
                                       time_t timeout,
                                       const char *verify_opts,
                                       struct sss_certmap_ctx *sss_certmap_ctx,
                                       const char *uri,
                                       struct pam_data *pd);
errno_t pam_check_cert_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            struct cert_auth_info **cert_list);

errno_t add_pam_cert_response(struct pam_data *pd, struct sss_domain_info *dom,
                              const char *sysdb_username,
                              struct cert_auth_info *cert_info,
                              enum response_type type);

bool may_do_cert_auth(struct pam_ctx *pctx, struct pam_data *pd);

errno_t p11_refresh_certmap_ctx(struct pam_ctx *pctx,
                                struct sss_domain_info *domains);

errno_t
pam_set_last_online_auth_with_curr_token(struct sss_domain_info *domain,
                                         const char *username,
                                         uint64_t value);

errno_t filter_responses(struct pam_ctx *pctx,
                         struct response_data *resp_list,
                         struct pam_data *pd);

errno_t pam_get_auth_types(struct pam_data *pd,
                           struct pam_resp_auth_type *_auth_types);
errno_t pam_eval_prompting_config(struct pam_ctx *pctx, struct pam_data *pd,
                                  struct prompt_config ***_pc_list);

enum pam_initgroups_scheme pam_initgroups_string_to_enum(const char *str);
const char *pam_initgroup_enum_to_string(enum pam_initgroups_scheme scheme);

int pam_cmd_gssapi_init(struct cli_ctx *cli_ctx);
int pam_cmd_gssapi_sec_ctx(struct cli_ctx *cctx);

#endif /* __PAMSRV_H__ */
