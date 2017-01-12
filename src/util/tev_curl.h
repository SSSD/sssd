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

/**
 * @brief Supported HTTP requests
 */
enum tcurl_http_request {
    TCURL_HTTP_GET,
    TCURL_HTTP_PUT,
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
 * @brief Run a single asynchronous HTTP request.
 *
 * Currently only UNIX sockets at socket_path are supported.
 *
 * If the request runs into completion, but reports a failure with HTTP return
 * code, the request will be marked as done. Only if the request cannot run at
 * all (if e.g. the socket is unreachable), the request will fail completely.
 *
 * Headers are a NULL-terminated
 * array of strings such as:
 *   static const char *headers[] = {
 *       "Content-type: application/octet-stream",
 *       NULL,
 *   };
 *
 * @param[in]  mem_ctx      The talloc context that owns the iobuf
 * @param[in]  ev           Event loop context
 * @param[in]  tctx         Use tcurl_init to get this context
 * @param[in]  req_type     The request type
 * @param[in]  socket_path  The path to the UNIX socket to forward the
 *                          request to
 * @param[in]  url          The request URL
 * @param[in]  headers      A NULL-terminated array of strings to use
 *                          as additional HTTP headers. Pass NULL if you
 *                          don't need any additional headers.
 * @param[in]  req_data     The HTTP request input data. For some request
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
                                   struct tcurl_ctx *tctx,
                                   enum tcurl_http_request req_type,
                                   const char *socket_path,
                                   const char *url,
                                   const char *headers[],
                                   struct sss_iobuf *req_data,
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
int tcurl_http_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    int *_http_code,
                    struct sss_iobuf **_outbuf);

#endif /* __TEV_CURL_H */
