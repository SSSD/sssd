/*
    SSSD

    Helper child for OIDC and OAuth 2.0 Device Authorization Grant

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef __OIDC_CHILD_UTIL_H__
#define __OIDC_CHILD_UTIL_H__

#include <jansson.h>
#include "util/util.h"

struct token_data {
    json_t *result;
    json_t *access_token;
    json_t *access_token_payload;
    char *access_token_str;
    json_t *id_token;
    json_t *id_token_payload;
    char *id_token_str;
    json_t *userinfo;
};

struct devicecode_ctx {
    bool libcurl_debug;
    const char *ca_db;
    const char *device_authorization_endpoint;
    const char *token_endpoint;
    const char *userinfo_endpoint;
    const char *jwks_uri;
    const char *scope;

    char *http_data;
    char *user_code;
    char *device_code;
    char *verification_uri;
    char *verification_uri_complete;
    char *message;
    int interval;
    int expires_in;

    struct token_data *td;
};

/* oidc_child_curl.c */
char *url_encode_string(TALLOC_CTX *mem_ctx, const char *inp);

errno_t init_curl(void *p);

void clean_http_data(struct devicecode_ctx *dc_ctx);

errno_t get_openid_configuration(struct devicecode_ctx *dc_ctx,
                                        const char *issuer_url);

errno_t get_jwks(struct devicecode_ctx *dc_ctx);

errno_t get_devicecode(struct devicecode_ctx *dc_ctx,
                       const char *client_id, const char *client_secret);

errno_t get_token(TALLOC_CTX *mem_ctx,
                  struct devicecode_ctx *dc_ctx, const char *client_id,
                  const char *client_secret,
                  bool get_device_code);

errno_t get_userinfo(struct devicecode_ctx *dc_ctx);


/* oidc_child_json.c */
errno_t parse_openid_configuration(struct devicecode_ctx *dc_ctx);

errno_t parse_result(struct devicecode_ctx *dc_ctx);

errno_t parse_token_result(struct devicecode_ctx *dc_ctx,
                           char **error_description);

errno_t verify_token(struct devicecode_ctx *dc_ctx);

const char *get_user_identifier(TALLOC_CTX *mem_ctx, json_t *userinfo,
                                const char *user_identifier_attr);

#endif /* __OIDC_CHILD_UTIL_H__ */
