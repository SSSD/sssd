/*
    SSSD

    Kerberos Backend, private header file

    Authors:
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

#ifndef __KRB5_AUTH_H__
#define __KRB5_AUTH_H__


#include "util/sss_regexp.h"
#include "util/sss_krb5.h"
#include "providers/backend.h"
#include "util/child_common.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_ccache.h"

#define CCACHE_ENV_NAME "KRB5CCNAME"

#define ILLEGAL_PATH_PATTERN "//|/\\./|/\\.\\./"

#define CHILD_OPT_FAST_CCACHE_UID "fast-ccache-uid"
#define CHILD_OPT_FAST_CCACHE_GID "fast-ccache-gid"
#define CHILD_OPT_FAST_USE_ANONYMOUS_PKINIT "fast-use-anonymous-pkinit"
#define CHILD_OPT_REALM "realm"
#define CHILD_OPT_LIFETIME "lifetime"
#define CHILD_OPT_RENEWABLE_LIFETIME "renewable-lifetime"
#define CHILD_OPT_USE_FAST "use-fast"
#define CHILD_OPT_FAST_PRINCIPAL "fast-principal"
#define CHILD_OPT_CANONICALIZE "canonicalize"
#define CHILD_OPT_SSS_CREDS_PASSWORD "sss-creds-password"
#define CHILD_OPT_CHAIN_ID "chain-id"
#define CHILD_OPT_CHECK_PAC "check-pac"

struct krb5child_req {
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    struct sss_domain_info *dom;

    const char *ccname;
    const char *old_ccname;
    const char *homedir;
    char *upn;
    uid_t uid;
    gid_t gid;
    bool is_offline;
    struct fo_server *srv;
    struct fo_server *kpasswd_srv;
    bool active_ccache;
    bool valid_tgt;
    bool upn_from_different_realm;
    bool send_pac;

    const char *user;
    const char *kuserok_user;
};

errno_t krb5_setup(TALLOC_CTX *mem_ctx,
                   struct pam_data *pd,
                   struct sss_domain_info *dom,
                   struct krb5_ctx *krb5_ctx,
                   struct krb5child_req **_krb5_req);

struct tevent_req *
krb5_pam_handler_send(TALLOC_CTX *mem_ctx,
                      struct krb5_ctx *krb5_ctx,
                      struct pam_data *pd,
                      struct dp_req_params *params);

errno_t
krb5_pam_handler_recv(TALLOC_CTX *mem_ctx,
                      struct tevent_req *req,
                      struct pam_data **_data);

/* Please use krb5_auth_send/recv *only* if you're certain there can't
 * be concurrent logins happening. With some ccache back ends, the ccache
 * files might clobber one another. Please use krb5_auth_queue_send()
 * instead that queues the requests
 */
struct tevent_req *krb5_auth_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct pam_data *pd,
                                  struct krb5_ctx *krb5_ctx);
int krb5_auth_recv(struct tevent_req *req, int *pam_status, int *dp_err);

struct tevent_req *handle_child_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct krb5child_req *kr);
int handle_child_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                      uint8_t **buf, ssize_t *len);

struct krb5_child_response {
    int32_t msg_status;
    struct tgt_times tgtt;
    char *ccname;
    char *correct_upn;
    bool otp;
};

errno_t
parse_krb5_child_response(TALLOC_CTX *mem_ctx, uint8_t *buf, ssize_t len,
                          struct pam_data *pd, int pwd_exp_warning,
                          struct krb5_child_response **_res);

errno_t add_user_to_delayed_online_authentication(struct krb5_ctx *krb5_ctx,
                                                  struct sss_domain_info *domain,
                                                  struct pam_data *pd,
                                                  uid_t uid);
errno_t init_delayed_online_authentication(struct krb5_ctx *krb5_ctx,
                                           struct be_ctx *be_ctx,
                                           struct tevent_context *ev);

errno_t init_renew_tgt(struct krb5_ctx *krb5_ctx, struct be_ctx *be_ctx,
                       struct tevent_context *ev, time_t renew_intv);
errno_t add_tgt_to_renew_table(struct krb5_ctx *krb5_ctx, const char *ccfile,
                               struct tgt_times *tgtt, struct pam_data *pd,
                               const char *upn);
errno_t soft_terminate_krb5_child(TALLOC_CTX *mem_ctx,
                                  struct pam_data *pd,
                                  struct krb5_ctx *krb5_ctx);

/* krb5_access.c */
struct tevent_req *krb5_access_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct be_ctx *be_ctx,
                                    struct pam_data *pd,
                                    struct krb5_ctx *krb5_ctx);
int krb5_access_recv(struct tevent_req *req, bool *access_allowed);

/* krb5_wait_queue.c */
struct tevent_req *krb5_auth_queue_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct be_ctx *be_ctx,
                                        struct pam_data *pd,
                                        struct krb5_ctx *krb5_ctx);

int krb5_auth_queue_recv(struct tevent_req *req,
                         int *_pam_status,
                         int *_dp_err);

#endif /* __KRB5_AUTH_H__ */
