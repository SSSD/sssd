/*
    SSSD

    IdP Backend, common header file

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

#ifndef __IDP_COMMON_H__
#define __IDP_COMMON_H__

#include "config.h"
#include <stdbool.h>

#include "providers/backend.h"
#include "util/util.h"

enum idp_opts {
    IDP_REQ_TIMEOUT = 0,
    IDP_TYPE,
    IDP_CLIENT_ID,
    IDP_CLIENT_SECRET,
    IDP_TOKEN_ENDPOINT,
    IDP_DEVICE_AUTH_ENDPOINT,
    IDP_USERINFO_ENDPOINT,
    IDP_ID_SCOPE,
    IDP_AUTH_SCOPE,
    IDMAP_LOWER,
    IDMAP_UPPER,
    IDMAP_RANGESIZE,

    IDP_OPTS
};

struct idp_id_ctx;

struct idp_req {
    struct dp_option *idp_options;
    const char **oidc_child_extra_args;
    struct io_buffer *send_buffer;
};


struct tevent_req *
idp_online_check_handler_send(TALLOC_CTX *mem_ctx,
                              struct idp_id_ctx *id_ctx,
                              void *data,
                              struct dp_req_params *params);

errno_t idp_online_check_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data);

/* oidc_child_handler.c */
struct tevent_req *handle_oidc_child_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct idp_req *idp_req,
                                          struct io_buffer *send_buffer);

int handle_oidc_child_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           uint8_t **buf, ssize_t *len);

errno_t set_oidc_common_args(const char **extra_args, size_t *c,
                             const char *idp_type,
                             const char *client_id,
                             const char *client_secret,
                             const char *token_endpoint,
                             const char *scope);
#endif /* __IDP_COMMON_H__ */
