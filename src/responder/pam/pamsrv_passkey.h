/*
    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2022 Red Hat

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

#ifndef __PAMSRV_PASSKEY_H__
#define __PAMSRV_PASSKEY_H__

#include <security/pam_appl.h>
#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/pam/pamsrv.h"
#include "lib/certmap/sss_certmap.h"

enum passkey_user_verification {
    PAM_PASSKEY_VERIFICATION_ON,
    PAM_PASSKEY_VERIFICATION_OFF,
    PAM_PASSKEY_VERIFICATION_OMIT,
    PAM_PASSKEY_VERIFICATION_INVALID
};

/* Operations when calling passkey child */
enum passkey_child_op {
    PAM_PASSKEY_OP_PREFLIGHT,
    PAM_PASSKEY_OP_KERBEROS_AUTH,
    PAM_PASSKEY_OP_LOCAL_AUTH,
    PAM_PASSKEY_OP_INVALID
};

struct pam_preflight_data {
    int attempts;
    bool pin_required;
    bool obtained;
};

struct pk_child_user_data {
    /* Both Kerberos and non-kerberos */
    const char *domain;
    size_t num_credentials;
    const char *user_verification;
    const char **key_handles;
    /* Kerberos PA only */
    const char *crypto_challenge;
    /* Non-kerberos only */
    const char *user;
    const char **public_keys;
};

errno_t passkey_child_execute(TALLOC_CTX *mem_ctx,
                               struct cli_ctx *cli_ctx,
                               struct tevent_context *ev,
                               struct pam_auth_req *pam_req,
                               struct pam_ctx *pam_ctx,
                               struct pam_data *pd,
                               enum passkey_child_op op);

errno_t read_passkey_conf_verification(TALLOC_CTX *mem_ctx,
                                       const char *verify_opts,
                                       enum passkey_user_verification *_user_verification);

void pam_forwarder_passkey_cb(struct tevent_req *req);
struct tevent_req *pam_passkey_auth_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       int timeout,
                                       bool debug_libfido2,
                                       enum passkey_user_verification verification,
                                       struct pam_data *pd,
                                       struct pk_child_user_data *pk_data,
                                       enum passkey_child_op op);
errno_t pam_passkey_auth_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              int *child_status,
                              uint8_t **read_buf,
                              ssize_t *read_buf_len);
errno_t pam_eval_passkey_response(struct pam_ctx *pctx,
                                  struct pam_data *pd,
                                  struct pam_auth_req *preq,
                                  bool *_pk_preauth_done);
errno_t process_passkey_data(TALLOC_CTX *mem_ctx,
                             struct ldb_message *user_mesg,
                             const char *domain,
                             struct pk_child_user_data *_data);
errno_t passkey_local_verification(struct confdb_ctx *cdb,
                                   struct sysdb_ctx *sysdb,
                                   const char *domain_name,
                                   enum passkey_user_verification *_user_verification,
                                   bool *_debug_libfido2);
bool may_do_passkey_auth(struct pam_ctx *pctx,
                         struct pam_data *pd);

#endif /* __PAMSRV_PASSKEY_H__ */
