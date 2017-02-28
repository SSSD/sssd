/*
   SSSD

   libcurl tevent integration

   Copyright (C) Red Hat, 2016

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

#ifndef __TEV_CURL_H
#define __TEV_CURL_H

#include <talloc.h>
#include <tevent.h>

#include "util/sss_iobuf.h"

struct tcurl_request;

/**
 * @brief Supported HTTP methods
 */
enum tcurl_http_method {
    TCURL_HTTP_GET,
    TCURL_HTTP_PUT,
    TCURL_HTTP_POST,
    TCURL_HTTP_DELETE,
};

/**
 * @brief Initialize the tcurl tevent wrapper.
 *
 * @returns the opaque context or NULL on error
 */
struct tcurl_ctx *tcurl_init(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev);

/**
 * @brief Run a single asynchronous TCURL request.
 *
 * If the libcurl processing succeeds but we obtain a protocol error we still
 * mark the tevent request as successful. The protocol error is return from
 * @tcurl_request_recv as an output parameter.
 *
 * @param[in]  mem_ctx      The talloc context that owns the request
 * @param[in]  ev           Event loop context
 * @param[in]  tctx         Use tcurl_init to get this context
 * @param[in]  tcurl_req    TCURL request
 * @param[in]  timeout      The request timeout in seconds. Use 0 if you want
 *                          to use the default libcurl timeout.
 *
 * @returns A tevent request or NULL on allocation error. On other errors, we
 * try to set the errno as event error code and run it to completion so that
 * the programmer can use tcurl_request_recv to read the error code.
 *
 * @see tcurl_init
 * @see tcurl_http
 * @see tcurl_request_recv
 */
struct tevent_req *
tcurl_request_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct tcurl_ctx *tcurl_ctx,
                   struct tcurl_request *tcurl_req,
                   long int timeout);

/**
 * @brief Receive a result of a single asynchronous TCURL request.
 *
 * @param[in]  mem_ctx         The talloc context that owns the response
 * @param[in]  req             The request previously obtained with tcurl_request_send
 * @param[out] _response       Response to the request
 * @param[out] _response_code  Protocol response code (may indicate a protocl error)
 *
 * @returns The error code of the curl request (not the HTTP code!)
 */
errno_t tcurl_request_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct sss_iobuf **_response,
                           int *_response_code);

/**
 * @brief Create a HTTP request.
 *
 * Use this if you need better control over the request options.
 *
 * Headers are a NULL-terminated array of strings such as:
 *   static const char *headers[] = {
 *       "Content-type: application/octet-stream",
 *       NULL,
 *   };
 *
 * @param[in]  mem_ctx      The talloc context that owns the tcurl_request
 * @param[in]  method       TCURL HTTP method
 * @param[in]  socket_path  The path to the UNIX socket to forward the
 *                          request to, may be NULL.
 * @param[in]  url          The request URL, cannot be NULL.
 * @param[in]  headers      A NULL-terminated array of strings to use
 *                          as additional HTTP headers. Pass NULL if you
 *                          don't need any additional headers.
 * @param[in]  body         The HTTP request input data. For some request
 *                          types like DELETE, this is OK to leave as NULL.
 *
 * @returns A tcurl_request that can be later started with tcurl_request_send
 * or NULL on error.
 *
 * @see tcurl_init
 * @see tcurl_request_send
 * @see tcurl_request_recv
 */
struct tcurl_request *tcurl_http(TALLOC_CTX *mem_ctx,
                                 enum tcurl_http_method method,
                                 const char *socket_path,
                                 const char *url,
                                 const char **headers,
                                 struct sss_iobuf *body);

/**
 * @brief Run a single asynchronous HTTP request.
 *
 * Use this if you do not need control over additional request options.
 *
 * If the request runs into completion, but reports a failure with HTTP return
 * code, the request will be marked as done. Only if the request cannot run at
 * all (if e.g. the socket is unreachable), the request will fail completely.
 *
 * Headers are a NULL-terminated array of strings such as:
 *   static const char *headers[] = {
 *       "Content-type: application/octet-stream",
 *       NULL,
 *   };
 *
 * @param[in]  mem_ctx      The talloc context that owns the iobuf
 * @param[in]  ev           Event loop context
 * @param[in]  tcurl_ctx    Use tcurl_init to get this context
 * @param[in]  method       HTTP method
 * @param[in]  socket_path  The path to the UNIX socket to forward the
 *                          request to, may be NULL.
 * @param[in]  url          The request URL, cannot be NULL.
 * @param[in]  headers      A NULL-terminated array of strings to use
 *                          as additional HTTP headers. Pass NULL if you
 *                          don't need any additional headers.
 * @param[in]  body         The HTTP request input data. For some request
 *                          types like DELETE, this is OK to leave as NULL.
 * @param[in]  timeout      The request timeout in seconds. Use 0 if you want
 *                          to use the default libcurl timeout.
 *
 * @returns A tevent request or NULL on allocation error. On other errors, we
 * try to set the errno as event error code and run it to completion so that
 * the programmer can use tcurl_http_recv to read the error code.
 *
 * @see tcurl_init
 * @see tcurl_http_recv
 */
struct tevent_req *tcurl_http_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct tcurl_ctx *tcurl_ctx,
                                   enum tcurl_http_method method,
                                   const char *socket_path,
                                   const char *url,
                                   const char **headers,
                                   struct sss_iobuf *body,
                                   int timeout);

/**
 * @brief Receive a result of a single asynchronous HTTP request.
 *
 * @param[in]  mem_ctx      The talloc context that owns the outbuf
 * @param[in]  req          The request previously obtained with
 *                          tcurl_http_send
 * @param[out] _http_code   The HTTP code that the transfer ended with
 * @param[out] _outbuf      The raw data the HTTP request returned
 *
 * @returns The error code of the curl request (not the HTTP code!)
 */
errno_t tcurl_http_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        int *_http_code,
                        struct sss_iobuf **_response);

/**
 * @brief We are usually interested only in the reply body without protocol
 * headers. Call this function on tcurl_request, if you want to include
 * complete protocol response in the output buffer.
 *
 * @param[in]  tcurl_request
 *
 * @returns errno code
 *
 * @see tcurl_http
 */
errno_t tcurl_req_enable_rawoutput(struct tcurl_request *tcurl_req);

/**
 * @brief TLS is enabled automatically by providing an URL that points to
 * TLS-enabled protocol such as https. If you want to provide different
 * path to CA directory or disable peer/hostname check explicitly, use
 * this function on tcurl_request.
 *
 * @param[in]  tcurl_request
 * @param[in]  capath        Path to directory containing installed CA certificates.
 *                           If not set, libcurl default is used.
 * @param[ing  cacert        CA certificate. If NULL it is found in @capath.
 * @param[in]  verify_peer   If false, the peer certificate is not verified.
 * @param[in]  verify_host   If false, the host name provided in remote
 *                           certificate may differ from the actual host name.
 *
 * @returns errno code
 *
 * @see tcurl_http
 */
errno_t tcurl_req_verify_peer(struct tcurl_request *tcurl_req,
                              const char *capath,
                              const char *cacert,
                              bool verify_peer,
                              bool verify_host);
/**
 * @brief Some server require client verification during TLS setup. You can
 * provide path to client's certificate file. If this file does not contain
 * private key, you can specify a different file the holds the private key.
 *
 * @param[in]  tcurl_request
 * @param[in]  cert          Path to client's certificate.
 * @param[in]  key           Path to client's private key.
 *
 * @returns errno code
 *
 * @see tcurl_http
 */
errno_t tcurl_req_set_client_cert(struct tcurl_request *tcurl_req,
                                  const char *cert,
                                  const char *key);

/**
 * @brief Force HTTP basic authentication with @username and @password.
 *
 * @param[in]  tcurl_request
 * @param[in]  username
 * @param[in]  password
 *
 * @returns errno code
 *
 * @see tcurl_http
 */
errno_t tcurl_req_http_basic_auth(struct tcurl_request *tcurl_req,
                                  const char *username,
                                  const char *password);

#endif /* __TEV_CURL_H */
