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
#include "responder/secrets/secsrv_local.h"
#include "responder/secrets/secsrv_proxy.h"
#include "util/sss_iobuf.h"
#include <jansson.h>

typedef int (*url_mapper_fn)(struct sec_req_ctx *secreq,
                             char **mapped_path);

struct url_pfx_router {
    const char *prefix;
    url_mapper_fn mapper_fn;
};

static int sec_map_url_to_user_path(struct sec_req_ctx *secreq,
                                    char **mapped_path)
{
    uid_t c_euid;

    c_euid = client_euid(secreq->cctx->creds);

    /* change path to be user specific */
    *mapped_path =
        talloc_asprintf(secreq, SEC_BASEPATH"users/%"SPRIuid"/%s",
                        c_euid,
                        &secreq->parsed_url.path[sizeof(SEC_BASEPATH) - 1]);
    if (!*mapped_path) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to user specific url\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "User-specific secrets path is [%s]\n", *mapped_path);
    return EOK;
}

static int kcm_map_url_to_path(struct sec_req_ctx *secreq,
                               char **mapped_path)
{
    uid_t c_euid;

    c_euid = client_euid(secreq->cctx->creds);
    if (c_euid != KCM_PEER_UID) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "UID %"SPRIuid" is not allowed to access "
              "the "SEC_KCM_BASEPATH" hive\n",
              c_euid);
        return EPERM;
    }

    *mapped_path = talloc_strdup(secreq, secreq->parsed_url.path );
    if (!*mapped_path) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to user specific url\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "User-specific KCM path is [%s]\n", *mapped_path);
    return EOK;
}

static struct url_pfx_router secrets_url_mapping[] = {
    { SEC_BASEPATH, sec_map_url_to_user_path },
    { SEC_KCM_BASEPATH, kcm_map_url_to_path },
    { NULL, NULL },
};

int sec_req_routing(TALLOC_CTX *mem_ctx, struct sec_req_ctx *secreq,
                    struct provider_handle **handle)
{
    struct sec_ctx *sctx;
    char **sections;
    char *def_provider;
    char *provider;
    int num_sections;
    int ret;
    url_mapper_fn mapper_fn = NULL;

    sctx = talloc_get_type(secreq->cctx->rctx->pvt_ctx, struct sec_ctx);

    for (int i = 0; secrets_url_mapping[i].prefix != NULL; i++) {
        if (strncasecmp(secreq->parsed_url.path,
                        secrets_url_mapping[i].prefix,
                        strlen(secrets_url_mapping[i].prefix)) == 0) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Mapping prefix %s\n", secrets_url_mapping[i].prefix);
            mapper_fn = secrets_url_mapping[i].mapper_fn;
            break;
        }
    }

    if (mapper_fn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Path [%s] does not start with any allowed prefix\n",
              secreq->parsed_url.path);
        return EPERM;
    }

    ret = mapper_fn(secreq, &secreq->mapped_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map the user path [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    /* source default provider */
    ret = confdb_get_string(secreq->cctx->rctx->cdb, mem_ctx,
                            CONFDB_SEC_CONF_ENTRY, "provider", "LOCAL",
                            &def_provider);
    if (ret) return EIO;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "The default provider is '%s'\n", def_provider);

    ret = confdb_get_sub_sections(mem_ctx, secreq->cctx->rctx->cdb,
                                  CONFDB_SEC_CONF_ENTRY, &sections,
                                  &num_sections);
    if (ret != EOK) return ret;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "confdb section %s has %d sub-sections\n",
          CONFDB_SEC_CONF_ENTRY, num_sections);

    provider = def_provider;

    // TODO order by length?
    for (int i = 0; i < num_sections; i++) {
        int slen;

        secreq->base_path = talloc_asprintf(secreq, SEC_BASEPATH"%s/", sections[i]);
        if (!secreq->base_path) return ENOMEM;
        slen = strlen(secreq->base_path);

        DEBUG(SSSDBG_TRACE_INTERNAL,
              "matching subsection [%s]\n", sections[i]);

        if (strncmp(secreq->base_path, secreq->mapped_path, slen) == 0) {
            char *secname;

            secname = talloc_asprintf(mem_ctx, CONFDB_SEC_CONF_ENTRY"/%s",
                                      sections[i]);
            if (!secname) return ENOMEM;

            provider = NULL;
            ret = confdb_get_string(secreq->cctx->rctx->cdb, mem_ctx,
                                    secname, "provider", def_provider,
                                    &provider);
            if (ret || !provider) return EIO;

            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "matched subsection %s with provider %s\n",
                  sections[i], provider);

            secreq->cfg_section = talloc_steal(secreq, secname);
            if (!secreq->cfg_section) return ENOMEM;
            break;
        }
        talloc_zfree(secreq->base_path);
    }

    if (!secreq->base_path) secreq->base_path = SEC_BASEPATH;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Request base path is [%s]\n", secreq->base_path);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Request provider is [%s]\n", provider);

    ret = sec_get_provider(sctx, provider, handle);
    if (ret == ENOENT) {
        if (strcasecmp(provider, "LOCAL") == 0) {
            ret = local_secrets_provider_handle(sctx, handle);
        } else if (strcasecmp(provider, "PROXY") == 0) {
            ret = proxy_secrets_provider_handle(sctx, handle);
        } else {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unknown provider type: %s\n", provider);
            ret = EIO;
        }
        if (ret == EOK) {
            ret = sec_add_provider(sctx, *handle);
        }
    }

    return ret;
}

int sec_provider_recv(struct tevent_req *req) {
    TEVENT_REQ_RETURN_ON_ERROR(req);
    DEBUG(SSSDBG_TRACE_INTERNAL, "Request finished\n");
    return EOK;
}

static struct sec_http_status_format_table {
    int status;
    const char *text;
    const char *description;
} sec_http_status_format_table[] = {
    { 200, "OK", "Success" },
    { 400, "Bad Request",
      "The request format is invalid." },
    { 401, "Unauthorized",
      "Access to the requested resource requires authentication." },
    { 403, "Forbidden",
      "Access to the requested resource is forbidden." },
    { 404, "Not Found",
      "The requested resource was not found." },
    { 405, "Method Not Allowed",
      "Request method not allowed for this resource." },
    { 406, "Not Acceptable",
      "The request cannot be accepted." },
    { 409, "Conflict",
      "The requested resource already exists." },
    { 413, "Payload Too Large",
      "The secret payload is too large." },
    { 500, "Internal Server Error",
      "The server encountered an internal error." },
    { 504, "Gateway timeout",
      "No response from a proxy server." },
    { 507, "Insufficient Storage",
      "The server is unable to store the resource needed to complete the request." },
};

int sec_http_status_reply(TALLOC_CTX *mem_ctx, struct sec_data *reply,
                          enum sec_http_status_codes code)
{
    char *body = talloc_asprintf(mem_ctx,
                        "<html>\r\n"
                            "<head>\r\n<title>%d %s</title></head>\r\n"
                        "<body>\r\n"
                            "<h1>%s</h1>\r\n"
                            "<p>%s</p>\r\n"
                        "</body>",
                        sec_http_status_format_table[code].status,
                        sec_http_status_format_table[code].text,
                        sec_http_status_format_table[code].text,
                        sec_http_status_format_table[code].description);
    if (!body) return ENOMEM;

    reply->data = talloc_asprintf(mem_ctx,
                        "HTTP/1.1 %d %s\r\n"
                        "Content-Length: %u\r\n"
                        "Content-Type: text/html\r\n"
                        "\r\n"
                        "%s",
                        sec_http_status_format_table[code].status,
                        sec_http_status_format_table[code].text,
                        (unsigned)strlen(body), body);
    talloc_free(body);
    if (!reply->data) return ENOMEM;

    reply->length = strlen(reply->data);

    DEBUG(SSSDBG_TRACE_LIBS,
          "HTTP reply %d: %s\n",
          sec_http_status_format_table[code].status,
          sec_http_status_format_table[code].text);

    return EOK;
}

int sec_http_reply_with_body(TALLOC_CTX *mem_ctx, struct sec_data *reply,
                             enum sec_http_status_codes code,
                             const char *content_type,
                             struct sec_data *body)
{
    int head_size;

    reply->data = talloc_asprintf(mem_ctx,
                        "HTTP/1.1 %d %s\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %zu\r\n"
                        "\r\n",
                        sec_http_status_format_table[code].status,
                        sec_http_status_format_table[code].text,
                        content_type, body->length);
    if (!reply->data) return ENOMEM;

    head_size = strlen(reply->data);

    reply->data = talloc_realloc(mem_ctx, reply->data, char,
                                 head_size + body->length);
    if (!reply->data) return ENOMEM;

    memcpy(&reply->data[head_size], body->data, body->length);
    reply->length = head_size + body->length;

    DEBUG(SSSDBG_TRACE_LIBS,
          "HTTP reply %d: %s\n",
          sec_http_status_format_table[code].status,
          sec_http_status_format_table[code].text);

    return EOK;
}

int sec_http_append_header(TALLOC_CTX *mem_ctx, char **dest,
                           char *field, char *value)
{
    if (*dest == NULL) {
        *dest = talloc_asprintf(mem_ctx, "%s: %s\r\n", field, value);
    } else {
        *dest = talloc_asprintf_append_buffer(*dest, "%s: %s\r\n",
                                              field, value);
    }
    if (!*dest) return ENOMEM;

    return EOK;
}

int sec_http_reply_with_headers(TALLOC_CTX *mem_ctx, struct sec_data *reply,
                                int status_code, const char *reason,
                                struct sec_kvp *headers, int num_headers,
                                struct sec_data *body)
{
    const char *reason_phrase = reason ? reason : "";
    bool add_content_length = true;
    bool has_content_type = false;
    int ret;

    /* Status-Line */
    reply->data = talloc_asprintf(mem_ctx, "HTTP/1.1 %d %s\r\n",
                                  status_code, reason_phrase);
    if (!reply->data) return ENOMEM;

    DEBUG(SSSDBG_TRACE_LIBS, "HTTP reply %d: %s\n", status_code, reason_phrase);

    /* Headers */
    for (int i = 0; i < num_headers; i++) {
        if (strcasecmp(headers[i].name, "Content-Length") == 0) {
            add_content_length = false;
        } else if (strcasecmp(headers[i].name, "Content-Type") == 0) {
            has_content_type = true;
        }
        ret = sec_http_append_header(mem_ctx, &reply->data,
                                     headers[i].name, headers[i].value);
        if (ret) return ret;
    }

    if (!has_content_type) {
        DEBUG(SSSDBG_OP_FAILURE, "No Content-Type header\n");
        return EINVAL;
    }

    if (add_content_length) {
        reply->data = talloc_asprintf_append_buffer(reply->data,
                            "Content-Length: %u\r\n", (unsigned)body->length);
        if (!reply->data) return ENOMEM;
    }

    /* CRLF separator before body */
    reply->data = talloc_strdup_append_buffer(reply->data, "\r\n");

    reply->length = strlen(reply->data);

    /* Message-Body */
    if (body && body->length) {
        reply->data = talloc_realloc(mem_ctx, reply->data, char,
                                     reply->length + body->length);
        if (!reply->data) return ENOMEM;

        memcpy(&reply->data[reply->length], body->data, body->length);
        reply->length += body->length;
    }

    return EOK;
}

static errno_t
sec_http_iobuf_split(struct sss_iobuf *response,
                     const char **headers,
                     const char **body)
{
    const char *data = (const char *)sss_iobuf_get_data(response);
    char *delim;

    /* The last header ends with \r\n and then comes \r\n again as a separator
     * of body from headers. We can use this to find this point. */
    delim = strstr(data, "\r\n\r\n");
    if (delim == NULL) {
        return EINVAL;
    }

    /* Skip to the body delimiter. */
    delim = delim + sizeof("\r\n") - 1;

    /* Replace \r\n with zeros turning data into:
     * from HEADER\r\nBODY into HEADER\0\0BODY format. */
    delim[0] = '\0';
    delim[1] = '\0';

    /* Split the buffer. */
    *headers = data;
    *body = delim + 2;

    return 0;
}

static const char *
sec_http_iobuf_add_content_length(TALLOC_CTX *mem_ctx,
                                  const char *headers,
                                  size_t body_len)
{
    /* If Content-Length is already present we do nothing. */
    if (strstr(headers, "Content-Length:") != NULL) {
        return headers;
    }

    return talloc_asprintf(mem_ctx, "%sContent-Length: %zu\r\n",
                           headers, body_len);
}

errno_t sec_http_reply_iobuf(TALLOC_CTX *mem_ctx,
                             struct sec_data *reply,
                             int response_code,
                             struct sss_iobuf *response)
{
    const char *headers;
    const char *body;
    size_t body_len;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_LIBS, "HTTP reply %d\n", response_code);

    ret = sec_http_iobuf_split(response, &headers, &body);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unexpected HTTP reply, returning what we got from server\n");
        reply->data = (char *)sss_iobuf_get_data(response);
        reply->length = sss_iobuf_get_len(response);

        return EOK;
    }

    /* Add Content-Length header if not present so client does not await
     * not-existing incoming data. */
    body_len = strlen(body);
    headers = sec_http_iobuf_add_content_length(mem_ctx, headers, body_len);
    if (headers == NULL) {
        return ENOMEM;
    }

    reply->length = strlen(headers) + sizeof("\r\n") - 1 + body_len;
    reply->data = talloc_asprintf(mem_ctx, "%s\r\n%s", headers, body);
    if (reply->data == NULL) {
        return ENOMEM;
    }

    return EOK;
}

enum sec_http_status_codes sec_errno_to_http_status(errno_t err)
{
    DEBUG(SSSDBG_TRACE_LIBS, "Request errno: %d\n", err);

    switch (err) {
    case EOK:
        return STATUS_200;
    case EINVAL:
        return STATUS_400;
    case EACCES:
        return STATUS_401;
    case EPERM:
        return STATUS_403;
    case ENOENT:
        return STATUS_404;
    case EISDIR:
        return STATUS_405;
    case EMEDIUMTYPE:
    case ERR_SEC_INVALID_CONTAINERS_NEST_LEVEL:
        return STATUS_406;
    case EEXIST:
        return STATUS_409;
    case ERR_SEC_PAYLOAD_SIZE_IS_TOO_LARGE:
        return STATUS_413;
    case ERR_SEC_NO_PROXY:
        return STATUS_504;
    case ERR_SEC_INVALID_TOO_MANY_SECRETS:
        return STATUS_507;
    default:
        return STATUS_500;
    }
}

int sec_json_to_simple_secret(TALLOC_CTX *mem_ctx,
                              const char *input,
                              char **secret)
{
    json_t *root;
    json_t *element;
    json_error_t error;
    int ret;

    root = json_loads(input, 0, &error);
    if (!root) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse JSON payload on line %d: %s\n",
              error.line, error.text);
        return EINVAL;
    }

    if (!json_is_object(root)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json data is not an object.\n");
        ret = EINVAL;
        goto done;
    }

    element = json_object_get(root, "type");
    if (!element) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json data key 'type' not found.\n");
        ret = EINVAL;
        goto done;
    }
    if (!json_is_string(element)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json object 'type' is not a string.\n");
        ret = EINVAL;
        goto done;
    }
    if (strcmp(json_string_value(element), "simple") != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Token type is not 'simple'.\n");
        ret = EMEDIUMTYPE;
        goto done;
    }

    element = json_object_get(root, "value");
    if (!element) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json key 'value' not found.\n");
        ret = EINVAL;
        goto done;
    }
    if (!json_is_string(element)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json object 'value' is not a string.\n");
        ret = EINVAL;
        goto done;
    }

    *secret = talloc_strdup(mem_ctx, json_string_value(element));
    if (!*secret) {
        ret = ENOMEM;
    } else {
        ret = EOK;
    }

done:
    json_decref(root);
    return ret;
}

int sec_simple_secret_to_json(TALLOC_CTX *mem_ctx,
                              const char *secret,
                              char **output)
{
    char *jsonized = NULL;
    json_t *root;
    int ret;

    root = json_pack("{s:s, s:s}", "type", "simple", "value", secret);
    if (!root) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to pack Json object\n");
        return ENOMEM;
    }

    jsonized = json_dumps(root, JSON_INDENT(4));
    if (!jsonized) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to dump Json object\n");
        ret = ENOMEM;
        goto done;
    }

    *output = talloc_strdup(mem_ctx, jsonized);
    if (!*output) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    json_decref(root);
    free(jsonized);
    return ret;
}

int sec_array_to_json(TALLOC_CTX *mem_ctx,
                      char **array, int count,
                      char **output)
{
    char *jsonized = NULL;
    json_t *root;
    int ret;

    root = json_array();
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create Json array\n");
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; i < count; i++) {
        // FIXME: json_string mem leak?
        // FIXME: Error checking
        json_array_append_new(root, json_string(array[i]));
    }

    jsonized = json_dumps(root, JSON_INDENT(4));
    if (!jsonized) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to dump Json object\n");
        ret = ENOMEM;
        goto done;
    }

    *output = talloc_strdup(mem_ctx, jsonized);
    if (!*output) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    json_decref(root);
    free(jsonized);
    return ret;
}

int sec_get_provider(struct sec_ctx *sctx, const char *name,
                     struct provider_handle **out_handle)
{
    struct provider_handle *handle;

    for (int i = 0; sctx->providers && sctx->providers[i]; i++) {
        handle = sctx->providers[i];
        if (strcasecmp(handle->name, name) != 0) {
            continue;
        }
        *out_handle = handle;
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "No handle for provider %s\n", name);
    return ENOENT;
}

int sec_add_provider(struct sec_ctx *sctx, struct provider_handle *handle)
{
    int c;

    for (c = 0; sctx->providers && sctx->providers[c]; c++)
        continue;

    sctx->providers = talloc_realloc(sctx, sctx->providers,
                                     struct provider_handle *, c + 2);
    if (!sctx->providers) return ENOMEM;

    sctx->providers[c] = talloc_steal(sctx, handle);
    sctx->providers[c + 1] = NULL;

    return EOK;
}

bool sec_req_has_header(struct sec_req_ctx *req,
                        const char *name, const char *value)
{
    for (int i = 0; i < req->num_headers; i++) {
        if (strcasecmp(name, req->headers[i].name) == 0) {
            if (value == NULL) return true;
            return (strcasecmp(value, req->headers[i].value) == 0);
        }
    }
    return false;
}
