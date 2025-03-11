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

enum oidc_cmd {
    NO_CMD = 0,
    GET_DEVICE_CODE,
    GET_ACCESS_TOKEN,
    GET_USER,
    GET_USER_GROUPS,
    GET_GROUP,
    GET_GROUP_MEMBERS,
    CMD_SENTINEL
};

enum search_str_type {
    TYPE_NAME = 1,
    TYPE_OBJECT_ID = 2
};

struct rest_ctx;

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
    struct rest_ctx *rest_ctx;
    const char *device_authorization_endpoint;
    const char *token_endpoint;
    const char *userinfo_endpoint;
    const char *jwks_uri;
    const char *scope;

    char *user_code;
    char *device_code;
    char *verification_uri;
    char *verification_uri_complete;
    char *message;
    int interval;
    int expires_in;

    struct token_data *td;
};

struct name_and_type_identifier {
    const char *user_identifier_attr;
    const char *group_identifier_attr;
    const char *user_name_attr;
    const char *group_name_attr;
};

/* oidc_child_curl.c */
struct rest_ctx *get_rest_ctx(TALLOC_CTX *mem_ctx, bool libcurl_debug,
                              const char *ca_db);

const char *get_http_data(struct rest_ctx *rest_ctx);

errno_t set_http_data(struct rest_ctx *rest_ctx, const char *str);

char *url_encode_string(TALLOC_CTX *mem_ctx, const char *inp);

errno_t init_curl(void *p);

void clean_http_data(struct rest_ctx *rest_ctx);

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


errno_t client_credentials_grant(struct rest_ctx *rest_ctx,
                                 const char *token_endpoint,
                                 const char *client_id,
                                 const char *client_secret,
                                 const char *scope);

errno_t do_http_request(struct rest_ctx *rest_ctx, const char *uri,
                        const char *post_data, const char *token);

errno_t do_http_request_json_data(struct rest_ctx *rest_ctx, const char *uri,
                                  const char *post_data, const char *token);

/* oidc_child_json.c */
errno_t parse_openid_configuration(struct devicecode_ctx *dc_ctx);

errno_t parse_result(struct devicecode_ctx *dc_ctx);

errno_t parse_token_result(struct devicecode_ctx *dc_ctx,
                           char **error_description);

errno_t decode_token(struct devicecode_ctx *dc_ctx, bool verify);

const char *get_user_identifier(TALLOC_CTX *mem_ctx, json_t *userinfo,
                                const char *user_identifier_attr,
                                const char *user_info_type);

const char *get_bearer_token(TALLOC_CTX *mem_ctx, const char *json_inp);

const char *get_str_attr_from_json_string(TALLOC_CTX *mem_ctx,
                                          const char *json_str,
                                          const char *attr_name);

const char *get_str_attr_from_json_array_string(TALLOC_CTX *mem_ctx,
                                                const char *json_str,
                                                const char *attr_name);

const char *get_str_attr_from_embed_json_string(TALLOC_CTX *mem_ctx,
                                                const char *json_str,
                                                const char *embed_attr_name,
                                                const char *attr_name);

const char **get_str_list_from_json_string(TALLOC_CTX *mem_ctx,
                                           const char *json_str,
                                           const char *attr_name);

char *get_json_string_array_from_json_string(TALLOC_CTX *mem_ctx,
                                             const char *json_str,
                                             const char *attr_name);

char *get_json_string_array_by_id_list(TALLOC_CTX *mem_ctx,
                                       struct rest_ctx *rest_ctx,
                                       const char *bearer_token,
                                       const char **id_list);

errno_t add_posix_to_json_string_array(TALLOC_CTX *mem_ctx,
                                       struct name_and_type_identifier *map,
                                       char domain_seperator,
                                       const char *in,
                                       char **out);

/* oidc_child_id.c */
errno_t oidc_get_id(TALLOC_CTX *mem_ctx, enum oidc_cmd oidc_cmd,
                    char *idp_type,
                    char *input, enum search_str_type input_type,
                    bool libcurl_debug, const char *ca_db,
                    const char *client_id, const char *client_secret,
                    const char *token_endpoint, const char *scope, char **out);

#endif /* __OIDC_CHILD_UTIL_H__ */
