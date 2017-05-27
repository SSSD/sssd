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
#include "util/sss_iobuf.h"
#include "util/tev_curl.h"

#define SEC_PROXY_TIMEOUT 5

struct proxy_context {
    struct resolv_ctx *resctx;
    struct confdb_ctx *cdb;
    struct tcurl_ctx *tcurl;
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

    char *key;
    char *cert;
    char *cacert;
    char *capath;
    bool verify_peer;
    bool verify_host;
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

    ret = confdb_get_bool(pctx->cdb, secreq->cfg_section, "verify_peer",
                          true, &cfg->verify_peer);
    if (ret) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS, "verify_peer: %s\n",
          cfg->verify_peer ? "true" : "false");

    ret = confdb_get_bool(pctx->cdb, secreq->cfg_section, "verify_host",
                          true, &cfg->verify_host);
    if (ret) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS, "verify_host: %s\n",
          cfg->verify_host ? "true" : "false");

    ret = proxy_get_config_string(pctx, cfg, false, secreq,
                                  "capath", &cfg->capath);
    if (ret) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS, "capath: %s\n", cfg->capath);

    ret = proxy_get_config_string(pctx, cfg, false, secreq,
                                  "cacert", &cfg->cacert);
    if (ret) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS, "cacert: %s\n", cfg->cacert);

    ret = proxy_get_config_string(pctx, cfg, false, secreq,
                                  "cert", &cfg->cert);
    if (ret) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS, "cert: %s\n", cfg->cert);

    ret = proxy_get_config_string(pctx, cfg, false, secreq,
                                  "key", &cfg->key);
    if (ret) goto done;
    DEBUG(SSSDBG_CONF_SETTINGS, "key: %s\n", cfg->key);

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

static errno_t proxy_http_append_header(TALLOC_CTX *mem_ctx,
                                        const char *name,
                                        const char *value,
                                        const char ***_headers,
                                        size_t *_num_headers)
{
    const char **headers = *_headers;
    size_t num_headers = *_num_headers;

    num_headers++;
    headers = talloc_realloc(mem_ctx, headers, const char *,
                             num_headers + 1);
    if (headers == NULL) {
        return ENOMEM;
    }

    headers[num_headers - 1] = talloc_asprintf(headers, "%s: %s", name, value);
    if (headers[num_headers - 1] == NULL) {
        return ENOMEM;
    }

    headers[num_headers] = NULL;

    *_headers = headers;
    *_num_headers = num_headers;

    return EOK;
}

static const char **
proxy_http_create_headers(TALLOC_CTX *mem_ctx,
                          struct sec_req_ctx *secreq,
                          struct proxy_cfg *pcfg)
{
    TALLOC_CTX *tmp_ctx;
    const char **headers;
    size_t num_headers;
    errno_t ret;
    int i, j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return NULL;
    }

    headers = talloc_zero_array(tmp_ctx, const char *, 1);
    if (headers == NULL) {
        ret = ENOMEM;
        goto done;
    }

    num_headers = 0;
    for (i = 0; i < secreq->num_headers; i++) {
        for (j = 0; pcfg->fwd_headers[j]; j++) {
            if (strcasecmp(secreq->headers[i].name, pcfg->fwd_headers[j]) == 0) {
                DEBUG(SSSDBG_TRACE_LIBS, "Forwarding header %s: %s\n",
                      secreq->headers[i].name, secreq->headers[i].value);

                ret = proxy_http_append_header(tmp_ctx, secreq->headers[i].name,
                                               secreq->headers[i].value,
                                               &headers, &num_headers);
                if (ret != EOK) {
                    goto done;
                }

                break;
            }
        }
    }

    if (pcfg->auth_type == PAT_HEADER) {
        DEBUG(SSSDBG_TRACE_LIBS, "Forwarding header %s\n",
              pcfg->auth.header.name);

        ret = proxy_http_append_header(tmp_ctx, pcfg->auth.header.name,
                                       pcfg->auth.header.value,
                                       &headers, &num_headers);
        if (ret != EOK) {
            goto done;
        }
    }

    talloc_steal(mem_ctx, headers);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        return NULL;
    }

    return headers;
}

static errno_t proxy_http_create_request(TALLOC_CTX *mem_ctx,
                                         struct sec_req_ctx *secreq,
                                         struct proxy_cfg *pcfg,
                                         const char *url,
                                         struct tcurl_request **_tcurl_req)
{
    TALLOC_CTX *tmp_ctx;
    struct tcurl_request *tcurl_req;
    enum tcurl_http_method method;
    struct sss_iobuf *body;
    const char **headers;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    headers = proxy_http_create_headers(tmp_ctx, secreq, pcfg);
    if (headers == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to construct HTTP headers!\n");
        ret = ENOMEM;
        goto done;
    }

    body = sss_iobuf_init_readonly(tmp_ctx, (uint8_t *)secreq->body.data,
                                   secreq->body.length);
    if (body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create HTTP body!\n");
        ret = ENOMEM;
        goto done;
    }

    switch (secreq->method) {
    case HTTP_GET:
        method = TCURL_HTTP_GET;
        break;
    case HTTP_PUT:
        method = TCURL_HTTP_PUT;
        break;
    case HTTP_POST:
        method = TCURL_HTTP_POST;
        break;
    case HTTP_DELETE:
        method = TCURL_HTTP_DELETE;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected HTTP method: %d\n",
              secreq->method);
        ret = EINVAL;
        goto done;
    }

    tcurl_req = tcurl_http(tmp_ctx, method, NULL, url, headers, body);
    if (tcurl_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create TCURL request!\n");
        ret = ENOMEM;
        goto done;
    }

    /* TCURL will return response buffer also with headers. */
    ret = tcurl_req_enable_rawoutput(tcurl_req);
    if (ret != EOK) {
        goto done;
    }

    /* Set TLS settings to verify peer.
     * This has no effect for HTTP protocol so we can set it anyway. */
    ret = tcurl_req_verify_peer(tcurl_req, pcfg->capath, pcfg->cacert,
                                pcfg->verify_peer, pcfg->verify_host);
    if (ret != EOK) {
        goto done;
    }

    /* Set client's certificate if required. */
    if (pcfg->cert != NULL) {
        ret = tcurl_req_set_client_cert(tcurl_req, pcfg->cert, pcfg->key);
        if (ret != EOK) {
            goto done;
        }
    }

    /* Set basic authentication if required. */
    if (pcfg->auth_type == PAT_BASIC_AUTH) {
        ret = tcurl_req_http_basic_auth(tcurl_req, pcfg->auth.basic.username,
                                        pcfg->auth.basic.password);
        if (ret != EOK) {
            goto done;
        }
    }

    talloc_steal(tcurl_req, body);
    *_tcurl_req = talloc_steal(mem_ctx, tcurl_req);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
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
    struct tcurl_request *tcurl_req;
    struct proxy_context *pctx;
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
                                    http_uri, &tcurl_req);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "proxy_http_create_request failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    subreq = tcurl_request_send(mem_ctx, ev, pctx->tcurl, tcurl_req,
                                SEC_PROXY_TIMEOUT);
    if (subreq == NULL) {
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
    struct sss_iobuf *response;
    int http_code;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct proxy_secret_state);

    ret = tcurl_request_recv(state, subreq, &response, &http_code);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "proxy_http request failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = sec_http_reply_iobuf(state->secreq, &state->secreq->reply,
                               http_code, response);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "sec_http_reply_iobuf request failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
    }
}

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
    pctx->tcurl = tcurl_init(pctx, sctx->rctx->ev);
    if (pctx->tcurl == NULL) {
        talloc_free(pctx);
        return ENOMEM;
    }

    handle->context = pctx;

    *out_handle = handle;
    return EOK;
}
