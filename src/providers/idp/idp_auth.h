/*
    SSSD

    IdP Backend Module -- Authentication

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

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

#ifndef _IDP_AUTH_H_
#define _IDP_AUTH_H_

#include "providers/backend.h"
#include "providers/idp/idp_common.h"
#include "util/sss_ptr_hash.h"

struct idp_auth_ctx {
    struct be_ctx *be_ctx;
    struct idp_init_ctx *init_ctx;
    struct dp_option *idp_options;
    hash_table_t *open_request_table;

    const char *idp_type;
    const char *client_id;
    const char *client_secret;
    const char *token_endpoint;
    const char *device_auth_endpoint;
    const char *userinfo_endpoint;
    const char *scope;
};

struct tevent_req *
idp_pam_auth_handler_send(TALLOC_CTX *mem_ctx,
                          struct idp_auth_ctx *auth_ctx,
                          struct pam_data *pd,
                          struct dp_req_params *params);

errno_t
idp_pam_auth_handler_recv(TALLOC_CTX *mem_ctx,
                          struct tevent_req *req,
                          struct pam_data **_data);
#endif /* _IDP_AUTH_H_ */
