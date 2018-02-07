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

#include "config.h"
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/secrets/secsrv.h"
#include "responder/secrets/secsrv_private.h"


/* ##### Request Handling ##### */

struct sec_http_request_state {
    struct tevent_context *ev;
    struct sec_req_ctx *secreq;
};
static void sec_http_request_pipeline_done(struct tevent_req *subreq);

static struct tevent_req *sec_http_request_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct sec_req_ctx *secreq)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sec_http_request_state *state;
    struct provider_handle *provider_handle;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sec_http_request_state);
    if (!req) return NULL;

    state->ev = ev;
    state->secreq = secreq;

    /* Go through the pipeline */

    /* 1. mapping and path conversion */
    ret = sec_req_routing(state, secreq, &provider_handle);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sec_req_routing failed [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* 2. backend invocation */
    subreq = provider_handle->fn(state, state->ev,
                                 provider_handle->context, secreq);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sec_http_request_pipeline_done, req);
    return req;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    return tevent_req_post(req, state->ev);
}

static void sec_http_request_pipeline_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    /* 3. reply construction */
    ret = sec_provider_recv(subreq);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS, "Did not find the requested data\n");
        tevent_req_error(req, ret);
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sec request failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, "sec request done\n");
        tevent_req_done(req);
    }
}

static int sec_http_request_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* --- */

static void
sec_http_request_done(struct tevent_req *req)
{
    struct sec_req_ctx *secreq;
    struct cli_ctx *cctx;
    int ret;

    secreq = tevent_req_callback_data(req, struct sec_req_ctx);
    cctx = secreq->cctx;

    ret = sec_http_request_recv(req);

    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_LIBS, "Did not find the requested data\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sec_http_request_recv failed [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
        /* Always return an error if we get here */
        ret = sec_http_status_reply(secreq, &secreq->reply,
                                    sec_errno_to_http_status(ret));
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to find reply, aborting client!\n");
        talloc_free(cctx);
        return;
    }

    /* Turn writable on so we can write back the reply */
    TEVENT_FD_WRITEABLE(cctx->cfde);
}

static void sec_cmd_execute(struct cli_ctx *cctx)
{
    struct sec_req_ctx *secreq;
    struct tevent_req *req;

    secreq = talloc_get_type(cctx->state_ctx, struct sec_req_ctx);

    req = sec_http_request_send(secreq, cctx->ev, secreq);
    if (!req) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to schedule secret retrieval\n.");
        talloc_free(cctx);
        return;
    }
    tevent_req_set_callback(req, sec_http_request_done, secreq);
}


/* ##### HTTP Parsing Callbacks ##### */

static void sec_append_string(TALLOC_CTX *memctx, char **dest,
                              const char *src, size_t len)
{
    if (*dest) {
        *dest = talloc_strndup_append_buffer(*dest, src, len);
    } else {
        *dest = talloc_strndup(memctx, src, len);
    }
}

static bool sec_too_much_data(struct sec_req_ctx *req, size_t length)
{
    req->total_size += length;
    if (req->max_payload_size > 0
            && req->total_size > req->max_payload_size) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Request too big, aborting client!\n");
        return true;
    }
    return false;
}

static int sec_on_message_begin(http_parser *parser)
{
    DEBUG(SSSDBG_TRACE_INTERNAL, "HTTP Message parsing begins\n");

    return 0;
}

static int sec_on_url(http_parser *parser,
                      const char *at, size_t length)
{
    struct sec_req_ctx *req =
        talloc_get_type(parser->data, struct sec_req_ctx);

    if (sec_too_much_data(req, length)) return -1;

    sec_append_string(req, &req->request_url, at, length);
    if (!req->request_url) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store URL, aborting client!\n");
        return -1;
    }
    return 0;
}

static int sec_on_header_field(http_parser *parser,
                               const char *at, size_t length)
{
    struct sec_req_ctx *req =
        talloc_get_type(parser->data, struct sec_req_ctx);
    int n = req->num_headers;

    if (sec_too_much_data(req, length)) return -1;

    if (!req->headers) {
        req->headers = talloc_zero_array(req, struct sec_kvp, 10);
    } else if ((n % 10 == 0) &&
               (req->headers[n - 1].value)) {
        req->headers = talloc_realloc(req, req->headers,
                                      struct sec_kvp, n + 10);
        if (req->headers) {
            memset(&req->headers[n], 0, sizeof(struct sec_kvp) * 10);
        }
    }
    if (!req->headers) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store headers, aborting client!\n");
        return -1;
    }

    if (!n || req->headers[n - 1].value) {
        /* new field */
        n++;
    }
    sec_append_string(req->headers, &req->headers[n - 1].name, at, length);
    if (!req->headers[n - 1].name) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store header name, aborting client!\n");
        return -1;
    }

    return 0;
}

static int sec_on_header_value(http_parser *parser,
                               const char *at, size_t length)
{
    struct sec_req_ctx *req =
        talloc_get_type(parser->data, struct sec_req_ctx);
    int n = req->num_headers;

    if (sec_too_much_data(req, length)) return -1;

    if (!req->headers) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid headers pointer, aborting client!\n");
        return -1;
    }

    if (req->headers[n].name && !req->headers[n].value) {
        /* we increment on new value */
        n = ++req->num_headers;
    }

    sec_append_string(req->headers, &req->headers[n - 1].value, at, length);
    if (!req->headers[n - 1].value) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store header value, aborting client!\n");
        return -1;
    }

    return 0;
}

static int sec_on_headers_complete(http_parser *parser)
{
    /* TODO: if message has no body we should return 1 */
    return 0;
}

static int sec_on_body(http_parser *parser,
                       const char *at, size_t length)
{
    struct sec_req_ctx *req =
        talloc_get_type(parser->data, struct sec_req_ctx);

    if (sec_too_much_data(req, length)) return -1;

    sec_append_string(req, &req->body.data, at, length);
    if (!req->body.data) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to store body, aborting client!\n");
        return -1;
    }
    req->body.length += length;

    return 0;
}

static int sec_get_parsed_field(TALLOC_CTX *mem_ctx, int field,
                                struct http_parser_url *parsed,
                                char *source_buf,
                                char **dest)
{
    uint16_t off = parsed->field_data[field].off;
    uint16_t len = parsed->field_data[field].len;
    *dest = talloc_strndup(mem_ctx, &source_buf[off], len);
    if (!*dest) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to parse url, aborting client!\n");
        return ENOMEM;
    }
    return EOK;
}

static int sec_on_message_complete(http_parser *parser)
{
    struct sec_req_ctx *req =
        talloc_get_type(parser->data, struct sec_req_ctx);
    struct http_parser_url parsed;
    int ret;

    /* parse url as well */
    ret = http_parser_parse_url(req->request_url,
                                strlen(req->request_url),
                                0, &parsed);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse URL %s\n", req->request_url);
        return ret;
    }

    if (parsed.field_set & (1 << UF_SCHEMA)) {
        ret = sec_get_parsed_field(req, UF_SCHEMA, &parsed,
                                   req->request_url,
                                   &req->parsed_url.schema);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to retrieve schema from %s\n", req->request_url);
            return -1;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "schema: %s\n", req->parsed_url.schema);
    }

    if (parsed.field_set & (1 << UF_HOST)) {
        ret = sec_get_parsed_field(req, UF_HOST, &parsed,
                                   req->request_url,
                                   &req->parsed_url.host);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to retrieve host from %s\n", req->request_url);
            return -1;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "host: %s\n", req->parsed_url.host);
    }

    if (parsed.field_set & (1 << UF_PORT)) {
        req->parsed_url.port = parsed.port;
        DEBUG(SSSDBG_TRACE_INTERNAL, "port: %d\n", req->parsed_url.port);
    }

    if (parsed.field_set & (1 << UF_PATH)) {
        ret = sec_get_parsed_field(req, UF_PATH, &parsed,
                                   req->request_url,
                                   &req->parsed_url.path);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to retrieve path from %s\n", req->request_url);
            return -1;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "path: %s\n", req->parsed_url.path);
    }

    if (parsed.field_set & (1 << UF_QUERY)) {
        ret = sec_get_parsed_field(req, UF_QUERY, &parsed,
                                   req->request_url,
                                   &req->parsed_url.query);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to retrieve query from %s\n", req->request_url);
            return -1;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "query: %s\n", req->parsed_url.query);
    }

    if (parsed.field_set & (1 << UF_FRAGMENT)) {
        ret = sec_get_parsed_field(req, UF_FRAGMENT, &parsed,
                                   req->request_url,
                                   &req->parsed_url.fragment);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to retrieve fragment from %s\n", req->request_url);
            return -1;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "fragment: %s\n", req->parsed_url.fragment);
    }

    if (parsed.field_set & (1 << UF_USERINFO)) {
        ret = sec_get_parsed_field(req, UF_USERINFO, &parsed,
                                   req->request_url,
                                   &req->parsed_url.userinfo);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to retrieve userinfo from %s\n", req->request_url);
            return -1;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "userinfo: %s\n", req->parsed_url.userinfo);
    }

    req->method = parser->method;

    req->complete = true;
    DEBUG(SSSDBG_TRACE_INTERNAL, "parsing complete\n");

    return 0;
}


/* ##### Communications ##### */

int sec_send_data(int fd, struct sec_data *data)
{
    ssize_t len;
    errno_t ret;

    errno = 0;
    len = send(fd, data->data, data->length, 0);
    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return EAGAIN;
        } else {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "send failed [%d]: %s\n", ret, strerror(ret));
            return ret;
        }
    }

    if (len == 0) {
        return EIO;
    }

    data->length -= len;
    data->data += len;
    DEBUG(SSSDBG_TRACE_INTERNAL, "sent %zu bytes, %zu bytes remaining\n",
          len, data->length);
    return EOK;
}

static void sec_send(struct cli_ctx *cctx)
{
    struct sec_req_ctx *req;
    int ret;

    req = talloc_get_type(cctx->state_ctx, struct sec_req_ctx);

    ret = sec_send_data(cctx->cfd, &req->reply);
    if (ret == EAGAIN) {
        /* not all data was sent, loop again */
        return;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to send data, aborting client!\n");
        talloc_free(cctx);
        return;
    }

    /* ok all sent */
    TEVENT_FD_NOT_WRITEABLE(cctx->cfde);
    TEVENT_FD_READABLE(cctx->cfde);
    talloc_zfree(cctx->state_ctx);
    return;
}

int sec_recv_data(int fd, struct sec_data *data)
{
    ssize_t len;
    errno_t ret;

    errno = 0;
    len = recv(fd, data->data, data->length, 0);
    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return EAGAIN;
        } else {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "send failed [%d]: %s\n", ret, strerror(ret));
            return ret;
        }
    }

    if (len == 0) {
        data->length = 0;
        return ENODATA;
    }

    data->length = len;
    DEBUG(SSSDBG_TRACE_INTERNAL, "received %zu bytes\n", data->length);
    return EOK;
}

static void sec_recv(struct cli_ctx *cctx)
{
    struct sec_proto_ctx *prctx;
    struct sec_req_ctx *req;
    struct sec_ctx *sec_ctx = talloc_get_type(cctx->rctx->pvt_ctx,
                                              struct sec_ctx);
    char buffer[SEC_PACKET_MAX_RECV_SIZE];
    struct sec_data data = { buffer,
                             SEC_PACKET_MAX_RECV_SIZE };
    size_t len;
    int ret;

    prctx = talloc_get_type(cctx->protocol_ctx, struct sec_proto_ctx);
    req = talloc_get_type(cctx->state_ctx, struct sec_req_ctx);
    if (!req) {
        /* A new request comes in, setup data structures */
        req = talloc_zero(cctx, struct sec_req_ctx);
        if (!req) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to setup request handlers, aborting client\n");
            talloc_free(cctx);
            return;
        }
        req->cctx = cctx;
        req->max_payload_size = sec_ctx->max_payload_size;
        cctx->state_ctx = req;
        http_parser_init(&prctx->parser, HTTP_REQUEST);
        prctx->parser.data = req;
    }

    ret = sec_recv_data(cctx->cfd, &data);
    switch (ret) {
    case ENODATA:
        DEBUG(SSSDBG_TRACE_ALL,
              "Client closed connection.\n");
        talloc_free(cctx);
        return;
    case EAGAIN:
        DEBUG(SSSDBG_TRACE_ALL,
              "Interrupted before any data could be read, retry later\n");
        return;
    case EOK:
        /* all fine */
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to receive data (%d, %s), aborting client\n",
              ret, sss_strerror(ret));
        talloc_free(cctx);
        return;
    }

    len = http_parser_execute(&prctx->parser, &prctx->callbacks,
                              data.data, data.length);
    if (len != data.length) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to parse request, aborting client!\n");
        talloc_free(cctx);
        return;
    }

    if (!req->complete) {
        return;
    }

    /* do not read anymore, client is done sending */
    TEVENT_FD_NOT_READABLE(cctx->cfde);

    sec_cmd_execute(cctx);
}

static void sec_fd_handler(struct tevent_context *ev,
                           struct tevent_fd *fde,
                           uint16_t flags, void *ptr)
{
    sss_client_fd_handler(ptr, sec_recv, sec_send, flags);
}

static http_parser_settings sec_callbacks = {
    .on_message_begin = sec_on_message_begin,
    .on_url = sec_on_url,
    .on_header_field = sec_on_header_field,
    .on_header_value = sec_on_header_value,
    .on_headers_complete = sec_on_headers_complete,
    .on_body = sec_on_body,
    .on_message_complete = sec_on_message_complete
};

int sec_connection_setup(struct cli_ctx *cctx)
{
    struct sec_proto_ctx *protocol_ctx;

    protocol_ctx = talloc_zero(cctx, struct sec_proto_ctx);
    if (!protocol_ctx) return ENOMEM;
    protocol_ctx->callbacks = sec_callbacks;

    cctx->protocol_ctx = protocol_ctx;
    cctx->cfd_handler = sec_fd_handler;
    return EOK;
}

/* Dummy, not used here but required to link to other responder files */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    return NULL;
}
