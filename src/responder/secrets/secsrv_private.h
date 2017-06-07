/*
   SSSD

   Secrets Responder, private header file

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016

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

#ifndef __SECSRV_PRIVATE_H__
#define __SECSRV_PRIVATE_H__

#include "config.h"
#include "responder/common/responder.h"
#include "responder/secrets/secsrv.h"
#include "util/sss_iobuf.h"
#include <http_parser.h>

struct sec_kvp {
    char *name;
    char *value;
};

struct sec_data {
    char *data;
    size_t length;
};

enum sec_http_status_codes {
    STATUS_200 = 0,
    STATUS_400,
    STATUS_401,
    STATUS_403,
    STATUS_404,
    STATUS_405,
    STATUS_406,
    STATUS_409,
    STATUS_413,
    STATUS_500,
    STATUS_504,
    STATUS_507,
};

struct sec_proto_ctx {
    http_parser_settings callbacks;
    http_parser parser;
};

struct sec_url {
    char *schema;
    char *host;
    int port;
    char *path;
    char *query;
    char *fragment;
    char *userinfo;
};

struct sec_req_ctx {
    struct cli_ctx *cctx;
    const char *base_path;
    const char *cfg_section;
    bool complete;

    size_t total_size;
    size_t max_payload_size;

    char *request_url;
    char *mapped_path;

    enum http_method method;
    struct sec_url parsed_url;
    struct sec_kvp *headers;
    int num_headers;
    struct sec_data body;

    struct sec_data reply;
};

typedef struct tevent_req *(*sec_provider_req_t)(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 void *provider_ctx,
                                                 struct sec_req_ctx *secreq);

struct provider_handle {
    const char *name;
    sec_provider_req_t fn;
    void *context;
};
int sec_get_provider(struct sec_ctx *sctx, const char *name,
                     struct provider_handle **out_handle);
int sec_add_provider(struct sec_ctx *sctx, struct provider_handle *handle);

#define SEC_BASEPATH            "/secrets/"
#define SEC_KCM_BASEPATH        "/kcm/"

/* The KCM responder must "impersonate" the owner of the credentials.
 * Only a trusted UID can do that -- root by default, but unit
 * tests might choose otherwise */
#ifndef KCM_PEER_UID
#define KCM_PEER_UID            0
#endif /* KCM_PEER_UID */

/* providers.c */
int sec_req_routing(TALLOC_CTX *mem_ctx, struct sec_req_ctx *secreq,
                    struct provider_handle **handle);
int sec_provider_recv(struct tevent_req *subreq);

int sec_http_append_header(TALLOC_CTX *mem_ctx, char **dest,
                           char *field, char *value);

int sec_http_status_reply(TALLOC_CTX *mem_ctx, struct sec_data *reply,
                          enum sec_http_status_codes code);
int sec_http_reply_with_body(TALLOC_CTX *mem_ctx, struct sec_data *reply,
                             enum sec_http_status_codes code,
                             const char *content_type,
                             struct sec_data *body);
int sec_http_reply_with_headers(TALLOC_CTX *mem_ctx, struct sec_data *reply,
                                int status_code, const char *reason,
                                struct sec_kvp *headers, int num_headers,
                                struct sec_data *body);
errno_t sec_http_reply_iobuf(TALLOC_CTX *mem_ctx,
                             struct sec_data *reply,
                             int response_code,
                             struct sss_iobuf *response);
enum sec_http_status_codes sec_errno_to_http_status(errno_t err);

int sec_json_to_simple_secret(TALLOC_CTX *mem_ctx,
                              const char *input,
                              char **secret);
int sec_simple_secret_to_json(TALLOC_CTX *mem_ctx,
                              const char *secret,
                              char **output);

int sec_array_to_json(TALLOC_CTX *mem_ctx,
                      char **array, int count,
                      char **output);

bool sec_req_has_header(struct sec_req_ctx *req,
                        const char *name, const char *value);

/* secsrv_cmd.c */
#define SEC_PACKET_MAX_RECV_SIZE 8192

int sec_send_data(int fd, struct sec_data *data);
int sec_recv_data(int fd, struct sec_data *data);

#endif /* __SECSRV_PRIVATE_H__ */
