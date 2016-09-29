/*
   SSSD

   Secrets Responder

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

#include "responder/secrets/secsrv_private.h"
#include "util/crypto/sss_crypto.h"
#include "resolv/async_resolv.h"
#include "util/sss_sockets.h"

struct proxy_context {
    struct resolv_ctx *resctx;
    struct confdb_ctx *cdb;
};

enum proxy_auth_type {
    PAT_NONE = 0,
    PAT_BASIC_AUTH = 1,
    PAT_HEADER = 2,
};

struct pat_basic_auth {
    char *username;
    char *password;
};

struct pat_header {
    char *name;
    char *value;
};

struct proxy_cfg {
    char *url;
    char **fwd_headers;
    int num_headers;
    enum proxy_auth_type auth_type;
    union {
        struct pat_basic_auth basic;
        struct pat_header header;
    } auth;
};

static int proxy_get_config_string(struct proxy_context *pctx,
                                   TALLOC_CTX *ctx, bool not_null,
                                   struct sec_req_ctx *secreq,
                                   const char *name, char **value)
{
    int ret;

    ret = confdb_get_string(pctx->cdb, ctx,
                            secreq->cfg_section, name, NULL, value);
    if (not_null && (ret == 0) && (*value == NULL)) ret = EINVAL;
    return ret;
}

static int proxy_sec_get_cfg(struct proxy_context *pctx,
                             TALLOC_CTX *mem_ctx,
                             struct sec_req_ctx *secreq,
                             struct proxy_cfg **target)
{
    struct proxy_cfg *cfg;
    char *auth_type;
    int ret;

    /* find matching remote and build the URI */
    cfg = talloc_zero(mem_ctx, struct proxy_cfg);
    if (!cfg) return ENOMEM;

    ret = proxy_get_config_string(pctx, cfg, true, secreq,
                                  "proxy_url", &cfg->url);
    if (ret) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS, "proxy_url: %s\n", cfg->url);

    ret = proxy_get_config_string(pctx, cfg, false, secreq,
                                  "auth_type", &auth_type);
    if (ret) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS, "auth_type: %s\n", auth_type);

    if (auth_type) {
        if (strcmp(auth_type, "basic_auth") == 0) {
            cfg->auth_type = PAT_BASIC_AUTH;
            ret = proxy_get_config_string(pctx, cfg, true, secreq, "username",
                                          &cfg->auth.basic.username);
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "username: %s\n", cfg->auth.basic.username);

            if (ret) goto done;
            ret = proxy_get_config_string(pctx, cfg, true, secreq, "password",
                                          &cfg->auth.basic.password);
            if (ret) goto done;
        } else if (strcmp(auth_type, "header") == 0) {
            cfg->auth_type = PAT_HEADER;
            ret = proxy_get_config_string(pctx, cfg, true, secreq,
                                          "auth_header_name",
                                          &cfg->auth.header.name);
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "auth_header_name: %s\n", cfg->auth.basic.username);

            if (ret) goto done;
            ret = proxy_get_config_string(pctx, cfg, true, secreq,
                                          "auth_header_value",
                                          &cfg->auth.header.value);
            if (ret) goto done;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknown auth type!\n");
            ret = EINVAL;
            goto done;
        }
    }

    ret = confdb_get_string_as_list(pctx->cdb, cfg, secreq->cfg_section,
                                    "forward_headers", &cfg->fwd_headers);
    if ((ret != 0) && (ret != ENOENT)) goto done;

    while (cfg->fwd_headers && cfg->fwd_headers[cfg->num_headers]) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Forwarding header: %s\n", cfg->fwd_headers[cfg->num_headers]);
        cfg->num_headers++;
    }

    /* Always whitelist Content-Type and Content-Length */
    cfg->fwd_headers = talloc_realloc(cfg, cfg->fwd_headers, char *,
                                     cfg->num_headers + 3);
    if (!cfg->fwd_headers) {
        ret = ENOMEM;
        goto done;
    }
    cfg->fwd_headers[cfg->num_headers] = talloc_strdup(cfg, "Content-Type");
    if (!cfg->fwd_headers[cfg->num_headers]) {
        ret = ENOMEM;
        goto done;
    }
    cfg->num_headers++;
    cfg->fwd_headers[cfg->num_headers] = talloc_strdup(cfg, "Content-Length");
    if (!cfg->fwd_headers[cfg->num_headers]) {
        ret = ENOMEM;
        goto done;
    }
    cfg->num_headers++;
    cfg->fwd_headers[cfg->num_headers] = NULL;
    ret = EOK;

done:
    if (ret) talloc_free(cfg);
    else *target = cfg;
    return ret;
}

#define REQ_HAS_SCHEMA(secreq) ((secreq)->parsed_url.schema != NULL)
#define REQ_HAS_HOST(secreq) ((secreq)->parsed_url.host != NULL)
#define REQ_HAS_PORT(secreq) ((secreq)->parsed_url.port != 0)
#define REQ_HAS_PATH(secreq) ((secreq)->parsed_url.path != NULL)
#define REQ_HAS_QUERY(secreq) ((secreq)->parsed_url.query != NULL)
#define REQ_HAS_FRAGMENT(secreq) ((secreq)->parsed_url.fragment != NULL)
#define REQ_HAS_USERINFO(secreq) ((secreq)->parsed_url.userinfo != NULL)

#define SECREQ_HAS_PORT(secreq) ((secreq)->parsed_url.port != 0)
#define SECREQ_PORT(secreq) ((secreq)->parsed_url.port)

#define SECREQ_HAS_PART(secreq, part) ((secreq)->parsed_url.part != NULL)
#define SECREQ_PART(secreq, part) \
    ((secreq)->parsed_url.part ? (secreq)->parsed_url.part : "")

int proxy_sec_map_url(TALLOC_CTX *mem_ctx, struct sec_req_ctx *secreq,
                      struct proxy_cfg *pcfg, char **req_url)
{
    char port[6] = { 0 };
    char *url;
    int blen;
    int ret;

    if (SECREQ_HAS_PORT(secreq)) {
        ret = snprintf(port, 6, "%d", SECREQ_PORT(secreq));
        if (ret < 1 || ret > 5) {
            DEBUG(SSSDBG_CRIT_FAILURE, "snprintf failed\n");
            return EINVAL;
        }
    }

    blen = strlen(secreq->base_path);

    url = talloc_asprintf(mem_ctx, "%s%s%s%s%s%s%s%s/%s%s%s%s%s",
                          SECREQ_PART(secreq, schema),
                          SECREQ_HAS_PART(secreq, schema) ? "://" : "",
                          SECREQ_PART(secreq, userinfo),
                          SECREQ_HAS_PART(secreq, userinfo) ? "@" : "",
                          SECREQ_PART(secreq, host),
                          SECREQ_HAS_PORT(secreq) ? ":" : "",
                          SECREQ_HAS_PORT(secreq) ? port : "",
                          pcfg->url, &secreq->mapped_path[blen],
                          SECREQ_HAS_PART(secreq, query) ? "?" :"",
                          SECREQ_PART(secreq, query),
                          SECREQ_HAS_PART(secreq, fragment) ? "?" :"",
                          SECREQ_PART(secreq, fragment));
    if (!url) return ENOMEM;

    DEBUG(SSSDBG_TRACE_INTERNAL, "URL: %s\n", url);

    *req_url = url;
    return EOK;
}

int proxy_sec_map_headers(TALLOC_CTX *mem_ctx, struct sec_req_ctx *secreq,
                          struct proxy_cfg *pcfg, char **req_headers)
{
    int ret;

    for (int i = 0; i < secreq->num_headers; i++) {
        bool forward = false;
        for (int j = 0; pcfg->fwd_headers[j]; j++) {
            if (strcasecmp(secreq->headers[i].name,
                           pcfg->fwd_headers[j]) == 0) {
                forward = true;
                break;
            }
        }
        if (forward) {
            DEBUG(SSSDBG_TRACE_LIBS, "Forwarding header %s:%s\n",
                  secreq->headers[i].name, secreq->headers[i].value);

            ret = sec_http_append_header(mem_ctx, req_headers,
                                         secreq->headers[i].name,
                                         secreq->headers[i].value);
            if (ret) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Couldn't append header %s\n", secreq->headers[i].name);
                return ret;
            }
        }
    }

    if (pcfg->auth_type == PAT_HEADER) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Forwarding header %s\n", pcfg->auth.header.name);

        ret = sec_http_append_header(mem_ctx, req_headers,
                                     pcfg->auth.header.name,
                                     pcfg->auth.header.value);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Couldn't append header %s\n", pcfg->auth.header.name);
            return ret;
        }
    }

    return EOK;
}

static int proxy_http_create_request(TALLOC_CTX *mem_ctx,
                                     struct sec_req_ctx *secreq,
                                     struct proxy_cfg *pcfg,
                                     const char *http_uri,
                                     struct sec_data **http_req)
{
    struct sec_data *req;
    int ret;

    req = talloc_zero(mem_ctx, struct sec_data);
    if (!req) return ENOMEM;

    /* Request-Line */
    req->data = talloc_asprintf(req, "%s %s HTTP/1.1\r\n",
                                http_method_str(secreq->method), http_uri);
    if (!req->data) {
        ret = ENOMEM;
        goto done;
    }

    /* Headers */
    ret = proxy_sec_map_headers(req, secreq, pcfg, &req->data);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Couldn't map headers\n");
        goto done;
    }

    /* CRLF separator before body */
    req->data = talloc_strdup_append_buffer(req->data, "\r\n");

    req->length = strlen(req->data);

    /* Message-Body */
    if (secreq->body.length > 0) {
        req->data = talloc_realloc_size(req, req->data,
                                        req->length + secreq->body.length);
        if (!req->data) {
            ret = ENOMEM;
            goto done;
        }

        memcpy(&req->data[req->length],
               secreq->body.data, secreq->body.length);
        req->length += secreq->body.length;
    }

    *http_req = req;
    ret = EOK;

done:
    if (ret) talloc_free(req);
    return ret;
}

struct proxy_http_request {
    struct sec_data *data;
    size_t written;
};

struct proxy_http_reply {
    http_parser parser;
    bool complete;

    int status_code;
    char *reason_phrase;
    struct sec_kvp *headers;
    int num_headers;
    struct sec_data body;

    size_t received;
};

struct proxy_http_req_state {
    struct tevent_context *ev;

    char *proxyname;
    int port;

    struct resolv_hostent *hostent;
    int hostidx;

    int sd;
    struct tevent_fd *fde;

    struct proxy_http_request request;
    struct proxy_http_reply *reply;
};

static int proxy_http_req_state_destroy(void *data);
static void proxy_http_req_gethostname_done(struct tevent_req *subreq);
static void proxy_http_req_connect_step(struct tevent_req *req);
static void proxy_http_req_connect_done(struct tevent_req *subreq);
static void proxy_fd_handler(struct tevent_context *ev, struct tevent_fd *fde,
                             uint16_t flags, void *ptr);

struct tevent_req *proxy_http_req_send(struct proxy_context *pctx,
                                       TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sec_req_ctx *secreq,
                                       const char *http_uri,
                                       struct sec_data *http_req)
{
    struct proxy_http_req_state *state;
    struct http_parser_url parsed;
    struct tevent_req *req, *subreq;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct proxy_http_req_state);
    if (!req) return NULL;

    state->ev = ev;
    state->request.data = http_req;
    state->sd = -1;
    talloc_set_destructor((TALLOC_CTX *)state,
                          proxy_http_req_state_destroy);

    /* STEP1: reparse URL to get hostname and port */
    ret = http_parser_parse_url(http_uri, strlen(http_uri), 0, &parsed);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse URL [%s]: %d: %s\n",
                                   http_uri, ret, sss_strerror(ret));
        goto done;
    }

    if (!(parsed.field_set & (1 << UF_HOST))) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No UF_HOST flag found\n");
        ret = EINVAL;
        goto done;
    }
    state->proxyname =
        talloc_strndup(state,
                       &http_uri[parsed.field_data[UF_HOST].off],
                       parsed.field_data[UF_HOST].len);
    if (!state->proxyname) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "proxy name: %s\n", state->proxyname);

    if (parsed.field_set & (1 << UF_PORT)) {
        state->port = parsed.port;
    } else if (parsed.field_set & (1 << UF_SCHEMA)) {
        uint16_t off = parsed.field_data[UF_SCHEMA].off;
        uint16_t len = parsed.field_data[UF_SCHEMA].len;

        if ((len == 5) &&
            (strncmp("https", &http_uri[off], len) == 0)) {
            state->port = 443;
        } else if ((len == 4) &&
                   (strncmp("http", &http_uri[off], len) == 0)) {
            state->port = 80;
        }
    }
    DEBUG(SSSDBG_TRACE_LIBS, "proxy port: %d\n", state->port);

    /* STEP2: resolve hostname first */
    subreq = resolv_gethostbyname_send(state, ev, pctx->resctx,
                                       state->proxyname, IPV4_FIRST,
                                       default_host_dbs);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, proxy_http_req_gethostname_done, req);

    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void proxy_http_req_gethostname_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct proxy_http_req_state *state;
    int resolv_status;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct proxy_http_req_state);

    ret = resolv_gethostbyname_recv(subreq, state, &resolv_status, NULL,
                                    &state->hostent);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* Empty result, just quit */
            DEBUG(SSSDBG_TRACE_INTERNAL, "No hostent found\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not resolve fqdn for this machine, error [%d]: %s, "
                  "resolver returned: [%d]: %s\n", ret, strerror(ret),
                  resolv_status, resolv_strerror(resolv_status));
        }
        goto done;
    }

    /* EOK */
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found fqdn: %s\n", state->hostent->name);

    /* STEP3: connect to one of the servers */
    proxy_http_req_connect_step(req);
    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static void proxy_http_req_connect_step(struct tevent_req *req)
{
    struct proxy_http_req_state *state;
    struct sockaddr_storage *sockaddr;
    char *ipaddr;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct proxy_http_req_state);

    if (!state->hostent->addr_list[state->hostidx]) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No more addresses to try.\n");
        ret = ENXIO;
        goto done;
    }

    sockaddr = resolv_get_sockaddr_address_index(state, state->hostent,
                                                 state->port, state->hostidx);
    if (sockaddr == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "resolv_get_sockaddr_address() failed\n");
        ret = EIO;
        goto done;
    }

    if (DEBUG_IS_SET(SSSDBG_TRACE_FUNC)) {
        ipaddr = resolv_get_string_address_index(state, state->hostent,
                                                 state->hostidx);
        if (!ipaddr) {
            ret = EFAULT;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Connecting to %s:%d\n",
              ipaddr, state->port);
    }

    /* increase idx for next attempt */
    state->hostidx++;

    subreq = sssd_async_socket_init_send(state, state->ev, sockaddr,
                                         sizeof(struct sockaddr_storage),
                                         SEC_NET_TIMEOUT);
    if (!subreq) {
        ret = EIO;
        goto done;
    }
    tevent_req_set_callback(subreq, proxy_http_req_connect_done, req);
    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static void proxy_http_req_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct proxy_http_req_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct proxy_http_req_state);

    ret = sssd_async_socket_init_recv(subreq, &state->sd);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sssd_async_socket_init request failed: [%d]: %s.\n",
              ret, sss_strerror(ret));

        /* try next server if any */
        proxy_http_req_connect_step(req);
        return;
    }

    /* EOK */
    DEBUG(SSSDBG_TRACE_FUNC, "Connected to %s\n", state->hostent->name);

    state->fde = tevent_add_fd(state->ev, state, state->sd,
                               TEVENT_FD_WRITE, proxy_fd_handler,
                               req);
    if (!state->fde) {
        ret = EIO;
        goto done;
    }

    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}


int proxy_http_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                        struct proxy_http_reply **reply)
{
    struct proxy_http_req_state *state =
                tevent_req_data(req, struct proxy_http_req_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply = talloc_move(mem_ctx, &state->reply);

    return EOK;
}

static int proxy_http_req_state_destroy(void *data)
{
    struct proxy_http_req_state *state =
        talloc_get_type(data, struct proxy_http_req_state);

    if (!state) return 0;

    if (state->sd != -1) {
        DEBUG(SSSDBG_TRACE_FUNC, "closing socket [%d]\n", state->sd);
        close(state->sd);
        state->sd = -1;
    }

    return 0;
}

static int proxy_wire_send(int fd, struct proxy_http_request *req)
{
    struct sec_data data;
    int ret;

    data.data = req->data->data + req->written;
    data.length = req->data->length - req->written;

    ret = sec_send_data(fd, &data);
    if (ret != EOK && ret != EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sec_send_data failed [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    req->written = req->data->length - data.length;
    return ret;
}

static void proxy_fd_send(void *data)
{
    struct proxy_http_req_state *state;
    struct tevent_req * req;
    int ret;

    req = talloc_get_type(data, struct tevent_req);
    state = tevent_req_data(req, struct proxy_http_req_state);

    ret = proxy_wire_send(state->sd, &state->request);
    if (ret == EAGAIN) {
        /* not all data was sent, loop again */
        return;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to send data, aborting!\n");
        tevent_req_error(req, ret);
        return;
    }

    /* ok all sent, wait for reply now */
    TEVENT_FD_NOT_WRITEABLE(state->fde);
    TEVENT_FD_READABLE(state->fde);
    return;
}

static bool ph_received_data(struct proxy_http_reply *reply, size_t length)
{
    reply->received += length;
    if (reply->received > SEC_REQUEST_MAX_SIZE) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Request too big, aborting!\n");
        return true;
    }
    return false;
}

static void ph_append_string(TALLOC_CTX *memctx, char **dest,
                             const char *src, size_t len)
{
    if (*dest) {
        *dest = talloc_strndup_append_buffer(*dest, src, len);
    } else {
        *dest = talloc_strndup(memctx, src, len);
    }
}

static int ph_on_message_begin(http_parser *parser)
{
    DEBUG(SSSDBG_TRACE_INTERNAL, "HTTP Message parsing begins\n");
    return 0;
}

#if ((HTTP_PARSER_VERSION_MAJOR >= 2) && (HTTP_PARSER_VERSION_MINOR >= 2))
static int ph_on_status(http_parser *parser, const char *at, size_t length)
{
    struct proxy_http_reply *reply =
        talloc_get_type(parser->data, struct proxy_http_reply);

    if (ph_received_data(reply, length)) return -1;

    ph_append_string(reply, &reply->reason_phrase, at, length);
    if (!reply->reason_phrase) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store reason phrase, aborting client!\n");
        return -1;
    }

    return 0;
}
#endif

static int ph_on_header_field(http_parser *parser,
                              const char *at, size_t length)
{
    struct proxy_http_reply *reply =
        talloc_get_type(parser->data, struct proxy_http_reply);
    int n = reply->num_headers;

    if (ph_received_data(reply, length)) return -1;

    if (!reply->headers) {
        reply->headers = talloc_zero_array(reply, struct sec_kvp, 10);
    } else if ((n % 10 == 0) &&
               (reply->headers[n - 1].value)) {
        reply->headers = talloc_realloc(reply, reply->headers,
                                        struct sec_kvp, n + 10);
        if (reply->headers) {
            memset(&reply->headers[n], 0, sizeof(struct sec_kvp) * 10);
        }
    }
    if (!reply->headers) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store headers, aborting client!\n");
        return -1;
    }

    if (!n || reply->headers[n - 1].value) {
        /* new field */
        n++;
    }
    ph_append_string(reply->headers, &reply->headers[n - 1].name, at, length);
    if (!reply->headers[n - 1].name) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store header name, aborting client!\n");
        return -1;
    }

    return 0;
}

static int ph_on_header_value(http_parser *parser,
                              const char *at, size_t length)
{
    struct proxy_http_reply *reply =
        talloc_get_type(parser->data, struct proxy_http_reply);
    int n = reply->num_headers;

    if (ph_received_data(reply, length)) return -1;

    if (!reply->headers) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid headers pointer, aborting client!\n");
        return -1;
    }

    if (reply->headers[n].name && !reply->headers[n].value) {
        /* we increment on new value */
        n = ++reply->num_headers;
    }

    ph_append_string(reply->headers, &reply->headers[n - 1].value, at, length);
    if (!reply->headers[n - 1].value) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store header value, aborting client!\n");
        return -1;
    }

    return 0;
}

static int ph_on_headers_complete(http_parser *parser)
{
    /* TODO: if message has no body we should return 1 */
    return 0;
}

static int ph_on_body(http_parser *parser, const char *at, size_t length)
{
    struct proxy_http_reply *reply =
        talloc_get_type(parser->data, struct proxy_http_reply);

    if (ph_received_data(reply, length)) return -1;

    /* FIXME: body may be binary */
    ph_append_string(reply, &reply->body.data, at, length);
    if (!reply->body.data) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store body, aborting!\n");
        return -1;
    }
    reply->body.length += length;

    return 0;
}

static int ph_on_message_complete(http_parser *parser)
{
    struct proxy_http_reply *reply =
        talloc_get_type(parser->data, struct proxy_http_reply);

    reply->status_code = parser->status_code;
    reply->complete = true;

    return 0;
}

static http_parser_settings ph_callbacks = {
    .on_message_begin = ph_on_message_begin,
#if ((HTTP_PARSER_VERSION_MAJOR >= 2) && (HTTP_PARSER_VERSION_MINOR >= 2))
    .on_status = ph_on_status,
#endif
    .on_header_field = ph_on_header_field,
    .on_header_value = ph_on_header_value,
    .on_headers_complete = ph_on_headers_complete,
    .on_body = ph_on_body,
    .on_message_complete = ph_on_message_complete
};

static void proxy_fd_recv(void *data)
{
    char buffer[SEC_PACKET_MAX_RECV_SIZE];
    struct sec_data packet = { buffer,
                               SEC_PACKET_MAX_RECV_SIZE };
    struct proxy_http_req_state *state;
    struct tevent_req *req;
    bool must_complete = false;
    int ret;

    req = talloc_get_type(data, struct tevent_req);
    state = tevent_req_data(req, struct proxy_http_req_state);

    if (!state->reply) {
        /* A new reply */
        state->reply = talloc_zero(state, struct proxy_http_reply);
        if (!state->reply) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to allocate reply, aborting!\n");
            tevent_req_error(req, ENOMEM);
            return;
        }
        http_parser_init(&state->reply->parser, HTTP_RESPONSE);
        state->reply->parser.data = state->reply;
    }

    ret = sec_recv_data(state->sd, &packet);
    switch (ret) {
    case ENODATA:
        DEBUG(SSSDBG_TRACE_ALL, "Server closed connection.\n");
        /* if we got no content length and the request is not complete,
         * then 0 length will indicate EOF to the parser, otherwise we
         * have an error */
        must_complete = true;
        break;
    case EAGAIN:
        DEBUG(SSSDBG_TRACE_ALL,
              "Interrupted before any data could be read, retry later\n");
        return;
    case EOK:
        /* all fine */
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to receive data (%d, %s), aborting\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, EIO);
        return;
    }

    ret = http_parser_execute(&state->reply->parser, &ph_callbacks,
                              packet.data, packet.length);
    if (ret != packet.length) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to parse request, aborting!\n");
        tevent_req_error(req, EIO);
        return;
    }

    if (!state->reply->complete) {
        if (must_complete) {
            tevent_req_error(req, EIO);
        }
        return;
    }

    /* do not read anymore, server is done sending */
    TEVENT_FD_NOT_READABLE(state->fde);
    tevent_req_done(req);
}

static void proxy_fd_handler(struct tevent_context *ev, struct tevent_fd *fde,
                             uint16_t flags, void *data)
{
    if (flags & TEVENT_FD_READ) {
        proxy_fd_recv(data);
    } else if (flags & TEVENT_FD_WRITE) {
        proxy_fd_send(data);
    }
}

struct proxy_secret_state {
    struct tevent_context *ev;
    struct sec_req_ctx *secreq;
    struct proxy_cfg *pcfg;
};
static void proxy_secret_req_done(struct tevent_req *subreq);

struct tevent_req *proxy_secret_req(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    void *provider_ctx,
                                    struct sec_req_ctx *secreq)
{
    struct tevent_req *req, *subreq;
    struct proxy_secret_state *state;
    struct proxy_context *pctx;
    struct sec_data *http_req;
    char *http_uri;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct proxy_secret_state);
    if (!req) return NULL;

    state->ev = ev;
    state->secreq = secreq;

    pctx = talloc_get_type(provider_ctx, struct proxy_context);
    if (!pctx) {
        ret = EIO;
        goto done;
    }

    ret = proxy_sec_get_cfg(pctx, state, state->secreq, &state->pcfg);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "proxy_sec_get_cfg failed [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = proxy_sec_map_url(state, secreq, state->pcfg, &http_uri);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "proxy_sec_map_url failed [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }


    ret = proxy_http_create_request(state, state->secreq, state->pcfg,
                                    http_uri, &http_req);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "proxy_http_create_request failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }


    subreq = proxy_http_req_send(pctx, state, ev, state->secreq,
                                 http_uri, http_req);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, proxy_secret_req_done, req);

    return req;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        /* shortcircuit the request here as all called functions are
         * synchronous and final and no further subrequests have been
         * made if we get here */
        tevent_req_done(req);
    }

    return tevent_req_post(req, ev);
}

static void proxy_secret_req_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct proxy_secret_state *state;
    struct proxy_http_reply *reply = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct proxy_secret_state);

    ret = proxy_http_req_recv(subreq, state, &reply);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "proxy_http request failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = sec_http_reply_with_headers(state->secreq, &state->secreq->reply,
                                      reply->status_code, reply->reason_phrase,
                                      reply->headers, reply->num_headers,
                                      &reply->body);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "sec_http_reply_with_headers request failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
    }
}

struct provider_handle proxy_secrets_handle = {
    .fn = proxy_secret_req,
    .context = NULL,
};

int proxy_secrets_provider_handle(struct sec_ctx *sctx,
                                  struct provider_handle **out_handle)
{
    struct provider_handle *handle;
    struct proxy_context *pctx;

    handle = talloc_zero(sctx, struct provider_handle);
    if (!handle) return ENOMEM;

    handle->name = "PROXY";
    handle->fn = proxy_secret_req;

    pctx = talloc(handle, struct proxy_context);
    if (!pctx) return ENOMEM;

    pctx->resctx = sctx->resctx;
    pctx->cdb = sctx->rctx->cdb;

    handle->context = pctx;

    *out_handle = handle;
    return EOK;
}
