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
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "lib/certmap/sss_certmap.h"

enum passkey_user_verification {
    PAM_PASSKEY_VERIFICATION_ON,
    PAM_PASSKEY_VERIFICATION_OFF,
    PAM_PASSKEY_VERIFICATION_OMIT,
    PAM_PASSKEY_VERIFICATION_INVALID
};

struct passkey_auth_data {
    char *key;
    char *name;
};

errno_t check_passkey(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct pam_ctx *pam_ctx,
                             struct pam_auth_req *preq,
                             struct pam_data *pd);

struct pk_child_user_data {
    const char *user;
    const char *domain;
    int num_passkeys;
    const char **public_keys;
    const char **key_handles;
    const char *user_verification;
};

struct tevent_req *pam_passkey_auth_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       int timeout,
                                       bool debug_libfido2,
                                       enum passkey_user_verification verification,
                                       struct pam_data *pd,
                                       struct pk_child_user_data *pk_data);
errno_t pam_passkey_auth_recv(struct tevent_req *req,
                            int *child_status);
bool may_do_passkey_auth(struct pam_ctx *pctx,
                         struct pam_data *pd);

#endif /* __PAMSRV_PASSKEY_H__ */
