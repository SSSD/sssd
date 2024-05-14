/*
    SSSD

    Helper child for OIDC and OAuth 2.0 Device Authorization Grant
    Curl based HTTP access

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

#include <curl/curl.h>
#include "oidc_child/oidc_child_util.h"

char *url_encode_string(TALLOC_CTX *mem_ctx, const char *inp)
{
    CURL *curl_ctx = NULL;
    char *tmp;
    char *out = NULL;

    if (inp == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Empty input.\n");
        return NULL;
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        return NULL;
    }

    tmp = curl_easy_escape(curl_ctx, inp, 0);
    if (tmp == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "curl_easy_escape failed for [%s].\n", inp);
        goto done;
    }

    out = talloc_strdup(mem_ctx, tmp);
    curl_free(tmp);
    if (out == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "talloc_strdup failed.\n");
        goto done;
    }

done:
    curl_easy_cleanup(curl_ctx);
    return (out);
}

/* The curl write_callback will always append the received data. To start a
 * new string call clean_http_data() before the curl request.*/
void clean_http_data(struct devicecode_ctx *dc_ctx)
{
    talloc_free(dc_ctx->http_data);
    dc_ctx->http_data = NULL;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb,
                             void *userdata)
{
    size_t realsize = size * nmemb;
    struct devicecode_ctx *dc_ctx = (struct devicecode_ctx *) userdata;
    char *tmp = NULL;

    DEBUG(SSSDBG_TRACE_ALL, "%.*s\n", (int) realsize, ptr);

    tmp = talloc_asprintf(dc_ctx, "%s%.*s",
                          dc_ctx->http_data == NULL ? "" : dc_ctx->http_data,
                          (int) realsize, ptr);
    talloc_free(dc_ctx->http_data);
    explicit_bzero(ptr, realsize);
    dc_ctx->http_data = tmp;
    if (dc_ctx->http_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy received data.\n");
        return 0;
    }
    talloc_set_destructor((void *) dc_ctx->http_data,
                          sss_erase_talloc_mem_securely);

    return realsize;
}

static int libcurl_debug_callback(CURL *curl_ctx, curl_infotype type,
                                  char *data, size_t size, void *userptr)
{
    static const char prefix[CURLINFO_END][3] = {
                                     "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };

    switch (type) {
    case CURLINFO_TEXT:
    case CURLINFO_HEADER_IN:
    case CURLINFO_HEADER_OUT:
        sss_debug_fn(__FILE__, __LINE__, __FUNCTION__, SSSDBG_TRACE_ALL,
                     "libcurl: %s%.*s", prefix[type], (int) size, data);
        break;
    default:
        break;
    }

    return 0;
}

static errno_t set_http_opts(CURL *curl_ctx, struct devicecode_ctx *dc_ctx,
                             const char *uri, const char *post_data,
                             const char *token, struct curl_slist *headers)
{
    CURLcode res;
    int ret;

    /* Only allow https */
    res = curl_easy_setopt(curl_ctx, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to enforce HTTPS.\n");
        ret = EIO;
        goto done;
    }

    if (dc_ctx->ca_db != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_CAINFO, dc_ctx->ca_db);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set CA DB path.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_URL, uri);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set URL.\n");
        ret = EIO;
        goto done;
    }

    if (dc_ctx->libcurl_debug) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_VERBOSE, 1L);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set verbose option.\n");
            ret = EIO;
            goto done;
        }
        res = curl_easy_setopt(curl_ctx, CURLOPT_DEBUGFUNCTION,
                               libcurl_debug_callback);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set debug callback.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_USERAGENT, "SSSD oidc_child/0.0");
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set useragent option.\n");
        ret = EIO;
        goto done;
    }

    if (headers != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_HTTPHEADER, headers);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add header to POST request.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_WRITEFUNCTION, write_callback);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add write callback.\n");
        ret = EIO;
        goto done;
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_WRITEDATA, dc_ctx);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add write callback data.\n");
        ret = EIO;
        goto done;
    }

    if (post_data != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "POST data: [%s].\n", post_data);
        res = curl_easy_setopt(curl_ctx, CURLOPT_POSTFIELDS, post_data);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add data to POST request.\n");
            ret = EIO;
            goto done;
        }
    }

    if (token != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set HTTP auth.\n");
            ret = EIO;
            goto done;
        }
        res = curl_easy_setopt(curl_ctx, CURLOPT_XOAUTH2_BEARER, token);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add token.\n");
            ret = EIO;
            goto done;
        }
    }

    ret = EOK;
done:

    return ret;
}

#define ACCEPT_JSON "Accept: application/json"

static errno_t do_http_request(struct devicecode_ctx *dc_ctx, const char *uri,
                               const char *post_data, const char *token)
{
    CURL *curl_ctx = NULL;
    CURLcode res;
    int ret;
    long resp_code;
    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, ACCEPT_JSON);
    if (headers == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create Accept header, trying without.\n");
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        ret = EIO;
        goto done;
    }

    ret = set_http_opts(curl_ctx, dc_ctx, uri, post_data, token, headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set http options.\n");
        goto done;
    }

    res = curl_easy_perform(curl_ctx);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send request.\n");
        ret = EIO;
        goto done;
    }

    res = curl_easy_getinfo(curl_ctx, CURLINFO_RESPONSE_CODE, &resp_code);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get response code.\n");
        ret = EIO;
        goto done;
    }

    if (resp_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "Request failed, response code is [%ld].\n",
                                 resp_code);
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_ctx);
    return ret;
}

#define AZURE_EXPECT_CODE "The request body must contain the following parameter: 'code'."

errno_t get_token(TALLOC_CTX *mem_ctx,
                  struct devicecode_ctx *dc_ctx, const char *client_id,
                  const char *client_secret,
                  bool get_device_code)
{
    CURL *curl_ctx = NULL;
    CURLcode res;
    int ret;
    size_t waiting_time = 0;
    char *error_description = NULL;
    char *post_data = NULL;
    const char *post_data_tmpl = "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&%s=%s";
    struct curl_slist *headers = NULL;
    bool azure_fallback = false;

    headers = curl_slist_append(headers, ACCEPT_JSON);
    if (headers == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create Accept header, trying without.\n");
    }

    post_data = talloc_asprintf(mem_ctx, post_data_tmpl, client_id, "device_code",
                                                         dc_ctx->device_code);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    if (client_secret != NULL) {
        post_data = talloc_asprintf_append(post_data, "&client_secret=%s",
                                           client_secret);
        if (post_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add client secret to POST data.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        ret = EIO;
        goto done;
    }

    ret = set_http_opts(curl_ctx, dc_ctx, dc_ctx->token_endpoint, post_data,
                        NULL, headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set http options.\n");
        goto done;
    }

    do {
        clean_http_data(dc_ctx);

        res = curl_easy_perform(curl_ctx);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to send token request.\n");
            ret = EIO;
            goto done;
        }

        talloc_zfree(error_description);
        ret = parse_token_result(dc_ctx, &error_description);
        if (ret != EAGAIN) {
            if (ret == EIO && !azure_fallback && error_description != NULL
                    && strstr(error_description, AZURE_EXPECT_CODE) != NULL) {
                /* Older Azure AD v1 endpoints expect 'code' instead of the RFC
                 * conforming 'device_code', see e.g.
                 * https://docs.microsoft.com/de-de/archive/blogs/azuredev/assisted-login-using-the-oauth-deviceprofile-flow
                 * and search for 'request_content' in the code example. */
                talloc_free(post_data);
                post_data = talloc_asprintf(mem_ctx, post_data_tmpl, client_id, "code",
                                                                     dc_ctx->device_code);
                if (post_data == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "Failed to generate POST data.\n");
                    ret = ENOMEM;
                    goto done;
                }
                azure_fallback = true;
                continue;
            }
            break;
        }

        /* only run once after getting the device code to tell the IdP we are
         * expecting that the user will connect */
        if (get_device_code) {
            if (ret == EAGAIN) {
                ret = EOK;
            }
            break;
        }

        waiting_time += dc_ctx->interval;
        if (waiting_time >= dc_ctx->expires_in) {
            /* Next sleep will end after the request is expired on the
             * server side, so we can just error out now. */
            ret = ETIMEDOUT;
            break;
        }
        sleep(dc_ctx->interval);
    } while (waiting_time < dc_ctx->expires_in);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get token.\n");
    }

done:
    talloc_free(post_data);
    talloc_free(error_description);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_ctx);
    return ret;
}

errno_t get_openid_configuration(struct devicecode_ctx *dc_ctx,
                                 const char *issuer_url)
{
    int ret;
    char *uri = NULL;
    bool has_slash = false;

    if (issuer_url[strlen(issuer_url) - 1] == '/') {
        has_slash = true;
    }

    uri = talloc_asprintf(dc_ctx, "%s%s.well-known/openid-configuration",
                                   issuer_url, has_slash ? "" : "/");
    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for config url.\n");
        ret = ENOMEM;
        goto done;
    }

    clean_http_data(dc_ctx);
    ret = do_http_request(dc_ctx, uri, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "http request failed.\n");
    }

done:
    talloc_free(uri);

    return ret;
}

#define DEFAULT_SCOPE "user"

errno_t get_devicecode(struct devicecode_ctx *dc_ctx,
                       const char *client_id, const char *client_secret)
{
    int ret;

    char *post_data = NULL;

    post_data  = talloc_asprintf(dc_ctx, "client_id=%s&scope=%s",
                                 client_id,
                                 dc_ctx->scope != NULL ? dc_ctx->scope
                                                       : DEFAULT_SCOPE);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for POST data.\n");
        return ENOMEM;
    }

    if (client_secret != NULL) {
        post_data = talloc_asprintf_append(post_data, "&client_secret=%s",
                                           client_secret);
        if (post_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add client secret to POST data.\n");
            return ENOMEM;
        }
    }

    clean_http_data(dc_ctx);
    ret = do_http_request(dc_ctx, dc_ctx->device_authorization_endpoint,
                          post_data, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send device code request.\n");
    }

    talloc_free(post_data);
    return ret;
}

errno_t get_userinfo(struct devicecode_ctx *dc_ctx)
{
    int ret;

    clean_http_data(dc_ctx);
    ret = do_http_request(dc_ctx, dc_ctx->userinfo_endpoint, NULL,
                          dc_ctx->td->access_token_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send userinfo request.\n");
    }

    return ret;
}

errno_t get_jwks(struct devicecode_ctx *dc_ctx)
{
    int ret;

    clean_http_data(dc_ctx);
    ret = do_http_request(dc_ctx, dc_ctx->jwks_uri, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read jwks file [%s].\n",
                                 dc_ctx->jwks_uri);
    }

    return ret;

}

static int cleanup_curl(void *p)
{
    curl_global_cleanup();

    return 0;
}

errno_t init_curl(void *p)
{
    CURLcode res;

    res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize libcurl.\n");
        return EIO;
    }

    if (p != NULL) {
        talloc_set_destructor(p, cleanup_curl);
    }

    return EOK;
}
