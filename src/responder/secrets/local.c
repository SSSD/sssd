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

#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ldb.h>

#include "db/sysdb.h"
#include "responder/secrets/secsrv_private.h"
#include "util/crypto/sss_crypto.h"
#include "util/secrets/secrets.h"

struct local_secret_state {
    struct tevent_context *ev;
    struct sec_req_ctx *secreq;
};

static struct tevent_req *local_secret_req(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           void *provider_ctx,
                                           struct sec_req_ctx *secreq)
{
    struct tevent_req *req;
    struct local_secret_state *state;
    struct sss_sec_ctx *sec_ctx;
    struct sec_data body = { 0 };
    const char *content_type;
    bool body_is_json;
    struct sss_sec_req *ssec_req;
    char *secret;
    char **keys;
    size_t nkeys;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct local_secret_state);
    if (!req) return NULL;

    state->ev = ev;
    state->secreq = secreq;

    sec_ctx = talloc_get_type(provider_ctx, struct sss_sec_ctx);
    if (!sec_ctx) {
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Received a local secrets request\n");

    if (sec_req_has_header(secreq, "Content-Type",
                                  "application/json")) {
        body_is_json = true;
        content_type = "application/json";
    } else if (sec_req_has_header(secreq, "Content-Type",
                           "application/octet-stream")) {
        body_is_json = false;
        content_type = "application/octet-stream";
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "No or unknown Content-Type\n");
        ret = EINVAL;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Content-Type: %s\n", content_type);

    /* be strict for now */
    if (secreq->parsed_url.fragment != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unrecognized URI fragments: [%s]\n",
              secreq->parsed_url.fragment);
        ret = EINVAL;
        goto done;
    }

    if (secreq->parsed_url.userinfo != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unrecognized URI userinfo: [%s]\n",
              secreq->parsed_url.userinfo);
        ret = EINVAL;
        goto done;
    }

    /* only type simple for now */
    if (secreq->parsed_url.query != NULL) {
        ret = strcmp(secreq->parsed_url.query, "type=simple");
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid URI query: [%s]\n",
                  secreq->parsed_url.query);
            ret = EINVAL;
            goto done;
        }
    }

    ret = sss_sec_new_req(state,
                          sec_ctx,
                          secreq->parsed_url.path,
                          client_euid(secreq->cctx->creds),
                          &ssec_req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot create libsecret request [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    switch (secreq->method) {
    case HTTP_GET:
        DEBUG(SSSDBG_TRACE_LIBS, "Processing HTTP GET\n"); /* todo: make sure the library prints the path */
        if (sss_sec_req_is_list(ssec_req)) {
            ret = sss_sec_list(state, ssec_req, &keys, &nkeys);
            if (ret) goto done;

            ret = sec_array_to_json(state, keys, nkeys, &body.data);
            if (ret) goto done;

            body.length = strlen(body.data);
            break;
        }

        ret = sss_sec_get(state, ssec_req, &secret, NULL);
        if (ret) goto done;

        if (body_is_json) {
            ret = sec_simple_secret_to_json(state, secret, &body.data);
            if (ret) goto done;

            body.length = strlen(body.data);
        } else {
            body.data = (void *)sss_base64_decode(state, secret, &body.length);
            ret = body.data ? EOK : ENOMEM;
        }
        if (ret) goto done;

        break;

    case HTTP_PUT:
        if (secreq->body.length == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "PUT with no data\n");
            ret = EINVAL;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Processing HTTP PUT\n"); /* todo path */
        if (body_is_json) {
            ret = sec_json_to_simple_secret(state, secreq->body.data,
                                            &secret);
        } else {
            secret = sss_base64_encode(state, (uint8_t *)secreq->body.data,
                                       secreq->body.length);
            ret = secret ? EOK : ENOMEM;
        }
        if (ret) goto done;

        ret = sss_sec_put(ssec_req, secret, SSS_SEC_MASTERKEY, "simple");
        if (ret) goto done;
        break;

    case HTTP_DELETE:
        ret = sss_sec_delete(ssec_req);
        if (ret) goto done;
        break;

    case HTTP_POST:
        DEBUG(SSSDBG_TRACE_LIBS, "Processing HTTP POST\n"); /* todo */
        ret = sss_sec_create_container(ssec_req);
        if (ret) goto done;
        break;

    default:
        ret = EINVAL;
        goto done;
    }

    if (body.data) {
        ret = sec_http_reply_with_body(secreq, &secreq->reply, STATUS_200,
                                       content_type, &body);
    } else {
        ret = sec_http_status_reply(secreq, &secreq->reply, STATUS_200);
    }

done:
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_LIBS, "Did not find the requested data\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Local secrets request error [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
        tevent_req_error(req, ret);
    } else {
        /* shortcircuit the request here as all called functions are
         * synchronous and final and no further subrequests are made */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Local secrets request done\n");
        tevent_req_done(req);
    }
    return tevent_req_post(req, state->ev);
}

int local_secrets_provider_handle(struct sec_ctx *sctx,
                                  struct provider_handle **out_handle)
{
    struct provider_handle *handle;
    struct sss_sec_ctx *ss_ctx;
    int ret;
    struct sss_sec_hive_config **hive_config;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Creating a local provider handle\n");

    handle = talloc_zero(sctx, struct provider_handle);
    if (!handle) return ENOMEM;

    handle->name = "LOCAL";
    handle->fn = local_secret_req;

    hive_config = talloc_zero_array(handle, struct sss_sec_hive_config *, 3);
    if (hive_config == NULL) {
        talloc_free(handle);
        return ENOMEM;
    }
    hive_config[0] = &sctx->sec_config;
    hive_config[1] = &sctx->kcm_config;
    hive_config[2] = NULL;

    ret = sss_sec_init(handle, hive_config, &ss_ctx);
    if (ret != EOK) {
        talloc_free(handle);
        return ret;
    }

    handle->context = ss_ctx;

    *out_handle = handle;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Local provider handle created\n");
    return EOK;
}
