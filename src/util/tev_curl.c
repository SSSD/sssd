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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include <talloc.h>
#include <tevent.h>

#include <curl/curl.h>

#include "util/util.h"
#include "util/tev_curl.h"

#define IOBUF_CHUNK   1024
#define IOBUF_MAX     4096

static bool global_is_curl_initialized;

/**
 * @brief The main structure of the tcurl module.
 *
 * Use tcurl_init() to initialize it, then pass to the request.
 * Should be kept opaque in the future.
 *
 * @see tcurl_init()
 */
struct tcurl_ctx {
    struct tevent_context *ev;
    /* See where we set CURLMOPT_TIMERFUNCTION */
    struct tevent_timer *process_timer;

    /* Since we want the API to be non-blocking, all the transfers use
     * the curl's multi interface:
     *  https://ec.haxx.se/libcurl-drive-multi.html
     * and then each transfer also uses an easy interface instance for
     * the transfer's private data
     */
    CURLM *multi_handle;
};

/**
 * @brief A tevent wrapper around curl socket
 */
struct tcurl_sock {
    struct tcurl_ctx *tctx;     /* Backchannel to the main context */

    curl_socket_t sockfd;       /* curl socket is an int typedef on Unix */
    struct tevent_fd *fde;      /* tevent tracker of the fd events */
};

/**
 * @brief A state of one curl transfer
 *
 * Intentionally breaking the tevent coding style here and making the struct available
 * in the whole module so that the structure is available to curl callbacks that
 * need to access the state of the transfer.
 *
 * @see handle_curlmsg_done()
 */
struct tcurl_http_state {
    /* Input parameters */
    struct tcurl_ctx *tctx;
    const char *socket_path;
    const char *url;
    int timeout;
    struct sss_iobuf *inbuf;

    /* Internal state */
    CURL *http_handle;
    struct curl_slist *curl_headers;

    /* Output data */
    struct sss_iobuf *outbuf;
    long http_code;
};

static errno_t curl_code2errno(CURLcode crv)
{
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "curl error %d: %s\n", crv, curl_easy_strerror(crv));
    }

    switch (crv) {
    /* HTTP error does not fail the whole request, just returns the error
     * separately
     */
    case CURLE_HTTP_RETURNED_ERROR:
    case CURLE_OK:
        return EOK;
    case CURLE_URL_MALFORMAT:
        return EBADMSG;
    case CURLE_COULDNT_CONNECT:
        return EHOSTUNREACH;
    case CURLE_REMOTE_ACCESS_DENIED:
        return EACCES;
    case CURLE_OUT_OF_MEMORY:
        return ENOMEM;
    case CURLE_OPERATION_TIMEDOUT:
        return ETIMEDOUT;
    default:
        break;
    }

    return EIO;
}

static errno_t tcurl_global_init(void)
{
    errno_t ret;

    if (global_is_curl_initialized == false) {
        ret = curl_global_init(CURL_GLOBAL_ALL);
        if (ret != CURLE_OK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot initialize global curl options [%d]\n", ret);
            return EIO;
        }
    }

    global_is_curl_initialized = true;
    return EOK;
}

static const char *http_req2str(enum tcurl_http_request req)
{
    switch (req) {
    case TCURL_HTTP_GET:
        return "GET";
    case TCURL_HTTP_PUT:
        return "PUT";
    case TCURL_HTTP_DELETE:
        return "DELETE";
    }

    return "Uknown request type";
}

static int curl2tev_flags(int curlflags)
{
    int flags = 0;

    switch (curlflags) {
    case CURL_POLL_IN:
        flags |= TEVENT_FD_READ;
        break;
    case CURL_POLL_OUT:
        flags |= TEVENT_FD_WRITE;
        break;
    case CURL_POLL_INOUT:
        flags |= (TEVENT_FD_READ | TEVENT_FD_WRITE);
        break;
    }

    return flags;
}

static void handle_curlmsg_done(CURLMsg *message)
{
    CURL *easy_handle;
    CURLcode crv;
    struct tevent_req *req;
    char *done_url;
    errno_t ret;
    struct tcurl_http_state *state;

    easy_handle = message->easy_handle;
    if (easy_handle == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: NULL handle for message %p\n", message);
        return;
    }

    if (DEBUG_IS_SET(SSSDBG_TRACE_FUNC)) {
        crv = curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &done_url);
        if (crv != CURLE_OK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot get CURLINFO_EFFECTIVE_URL [%d]: %s\n",
                  crv, curl_easy_strerror(crv));
            /* not fatal since we need this only for debugging */
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Handled %s\n", done_url);
        }
    }

    crv = curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, (void *) &req);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot get CURLINFO_PRIVATE [%d]: %s\n",
              crv, curl_easy_strerror(crv));
        return;
    }

    state = tevent_req_data(req, struct tcurl_http_state);
    if (state == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: request has no state\n");
        tevent_req_error(req, EFAULT);
        return;
    }

    ret = curl_code2errno(message->data.result);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "curl operation failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* If there was no fatal error, let's read the HTTP error code and mark
     * the request as done
     */
    crv = curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &state->http_code);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get HTTP status code\n");
        tevent_req_error(req, EFAULT);
        return;
    }

    tevent_req_done(req);
}

static void process_curl_activity(struct tcurl_ctx *tctx)
{
    CURLMsg *message;
    int pending;

    while ((message = curl_multi_info_read(tctx->multi_handle, &pending))) {
        switch (message->msg) {
        case CURLMSG_DONE:
            handle_curlmsg_done(message);
            break;
        default:
            DEBUG(SSSDBG_TRACE_LIBS,
                  "noop for curl msg %d\n", message->msg);
            break;
        }
    }
}

static void tcurlsock_input_available(struct tevent_context *ev,
                                      struct tevent_fd *fde,
                                      uint16_t flags,
                                      void *data)
{
    struct tcurl_ctx *tctx;
    struct tcurl_sock *tcs = NULL;
    int curl_flags = 0;
    int running_handles;

    tcs = talloc_get_type(data, struct tcurl_sock);
    if (tcs == NULL) {
        return;
    }

    if (flags & TEVENT_FD_READ) {
        curl_flags |= CURL_CSELECT_IN;
    }
    if (flags & TEVENT_FD_WRITE) {
        curl_flags |= CURL_CSELECT_OUT;
    }

    /* multi_socket_action might invalidate tcs when the transfer ends,
     * so we need to store tctx separately
     */
    tctx = tcs->tctx;

    /* https://ec.haxx.se/libcurl-drive-multi-socket.html */
    curl_multi_socket_action(tcs->tctx->multi_handle,
                             tcs->sockfd,
                             curl_flags,
                             &running_handles);

    process_curl_activity(tctx);
}

/**
 * @brief Registers a curl's socket with tevent
 *
 * Creates a private structure, registers the socket with tevent and finally
 * registers the tcurl_sock structure as a private pointer for the curl
 * socket for later
 */
static struct tcurl_sock *register_curl_socket(struct tcurl_ctx *tctx,
                                               curl_socket_t sockfd,
                                               int flags)
{
    struct tcurl_sock *tcs;

    tcs = talloc_zero(tctx, struct tcurl_sock);
    if (tcs == NULL) {
        return NULL;
    }
    tcs->sockfd = sockfd;
    tcs->tctx = tctx;

    tcs->fde = tevent_add_fd(tctx->ev, tcs, sockfd, flags,
                             tcurlsock_input_available, tcs);
    if (tcs->fde == NULL) {
        talloc_free(tcs);
        return NULL;
    }

    curl_multi_assign(tctx->multi_handle, sockfd, (void *) tcs);
    return tcs;
}

/* libcurl informs the application about socket activity to wait for with
 * this callback */
static int handle_socket(CURL *easy,
                         curl_socket_t s,
                         int action,
                         void *userp,
                         void *socketp)
{
    struct tcurl_ctx *tctx = NULL;
    struct tcurl_sock *tcsock;
    int flags = 0;

    tctx = talloc_get_type(userp, struct tcurl_ctx);
    if (tctx == NULL) {
        return 1;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Activity on curl socket %d socket data %p\n", s, socketp);

    switch (action) {
    case CURL_POLL_IN:
    case CURL_POLL_OUT:
    case CURL_POLL_INOUT:
        /* There is some activity on a socket */

        flags = curl2tev_flags(action);

        if (socketp == NULL) {
            /* If this socket doesn't have private data, it must be a new one,
             * let's start tracking it with tevent
             */
            tcsock = register_curl_socket(tctx, s, flags);
            if (tcsock == NULL) {
                return 1;
            }
        } else {
            /* If we are already tracking this socket, just set the correct
             * flags for tevent and pass the control to tevent
             */
            tcsock = talloc_get_type(socketp, struct tcurl_sock);
            if (tcsock == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "BUG: No private data for socket %d\n", s);
                return 1;
            }
            tevent_fd_set_flags(tcsock->fde, flags);
        }
        break;

    case CURL_POLL_REMOVE:
        /* This socket is being closed by curl, so we need to.. */
        tcsock = talloc_get_type(socketp, struct tcurl_sock);
        if (tcsock == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "BUG: Trying to remove an untracked socket %d\n", s);
        }
        /* ..stop tracking the socket with the multi handle.. */
        curl_multi_assign(tctx->multi_handle, s, NULL);
        /* ..and stop tracking the fd with tevent */
        talloc_free(tcsock);
        break;

    default:
        return 1;
    }

    return 0;
}

static void check_curl_timeouts(struct tcurl_ctx *tctx)
{
    int running_handles;

    curl_multi_socket_action(tctx->multi_handle,
                             CURL_SOCKET_TIMEOUT,
                             0,
                             &running_handles);
    DEBUG(SSSDBG_TRACE_ALL,
          "Still tracking %d outstanding requests\n", running_handles);

    /* https://ec.haxx.se/libcurl-drive-multi-socket.html */
    process_curl_activity(tctx);
}

static void check_fd_activity(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval current_time,
                              void *private_data)
{
    struct tcurl_ctx *tctx = talloc_get_type(private_data, struct tcurl_ctx);
    check_curl_timeouts(tctx);
}

static int schedule_fd_processing(CURLM *multi,
                                  long timeout_ms,
                                  void *userp)
{
    struct timeval tv = { 0, 0 };
    struct tcurl_ctx *tctx = talloc_get_type(userp, struct tcurl_ctx);

    DEBUG(SSSDBG_TRACE_INTERNAL, "timeout_ms: %ld\n", timeout_ms);

    if (timeout_ms == -1) {
        /* man curlmopt_timerfunction(3) says:
         *  A timeout_ms value of -1 means you should delete your timer.
         */
        talloc_zfree(tctx->process_timer);
        check_curl_timeouts(tctx);
        return 0;
    }

    tv = tevent_timeval_current_ofs(0, timeout_ms * 1000);

    /* There is only one timer per multi handle, so it makes sense to cancel
     * the previous one.
     *
     * From https://ec.haxx.se/libcurl-drive-multi-socket.html:
     * There is only one timeout for the application to handle for the
     * entire multi handle, no matter how many individual easy handles
     * that have been added or transfers that are in progress. The timer
     * callback will be updated with the current nearest-in-time period to
     * wait.
     */
    talloc_zfree(tctx->process_timer);
    tctx->process_timer = tevent_add_timer(tctx->ev, tctx, tv,
                                           check_fd_activity, tctx);
    if (tctx->process_timer == NULL) {
        return -1;
    }

    return 0;
}

static int tcurl_ctx_destroy(struct tcurl_ctx *ctx)
{
    if (ctx == NULL) {
        return 0;
    }

    curl_multi_cleanup(ctx->multi_handle);
    return 0;
}

struct tcurl_ctx *tcurl_init(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev)
{
    errno_t ret;
    struct tcurl_ctx *tctx = NULL;
    CURLMcode cmret;

    /* Per the manpage it is safe to call the initialization multiple
     * times, as long as this is done before any other curl calls to
     * make sure we don't mangle the global curl environment
     */
    ret = tcurl_global_init();
    if (ret != EOK) {
        goto fail;
    }

    tctx = talloc_zero(mem_ctx, struct tcurl_ctx);
    if (tctx == NULL) {
        goto fail;
    }
    tctx->ev = ev;

    tctx->multi_handle = curl_multi_init();
    if (tctx->multi_handle == NULL) {
        goto fail;
    }
    talloc_set_destructor(tctx, tcurl_ctx_destroy);

    cmret = curl_multi_setopt(tctx->multi_handle,
                              CURLMOPT_SOCKETDATA, tctx);
    if (cmret != CURLM_OK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot set CURLMOPT_SOCKETDATA [%d]: %s\n",
              cmret, curl_multi_strerror(cmret));
        goto fail;
    }

    /*
     * When there is some activity on a socket associated with the multi
     * handle, then the handle_socket() function will be called with the
     * global context as private data
     */
    cmret = curl_multi_setopt(tctx->multi_handle,
                              CURLMOPT_SOCKETFUNCTION, handle_socket);
    if (cmret != CURLM_OK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot set CURLMOPT_SOCKETFUNCTION [%d]: %s\n",
              cmret, curl_multi_strerror(cmret));
        goto fail;
    }

    /* When integrated in a mainloop, the curl multi interface must
     * kick off the communication in another eventloop tick. Similar
     * to the handle_socet function, the tcurl context is passed in
     * as private data
     */
    cmret = curl_multi_setopt(tctx->multi_handle,
                              CURLMOPT_TIMERFUNCTION, schedule_fd_processing);
    if (cmret != CURLM_OK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot set CURLMOPT_TIMERFUNCTION [%d]: %s\n",
              cmret, curl_multi_strerror(cmret));
        goto fail;
    }

    cmret = curl_multi_setopt(tctx->multi_handle, CURLMOPT_TIMERDATA, tctx);
    if (cmret != CURLM_OK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot set CURLMOPT_TIMERDATA [%d]: %s\n",
              cmret, curl_multi_strerror(cmret));
    }

    return tctx;

fail:
    talloc_free(tctx);
    return NULL;
}

static errno_t tcurl_add_headers(struct tcurl_http_state *state,
                                 const char *headers[]);

static errno_t tcurl_set_options(struct tcurl_http_state *state,
                                 struct tevent_req *req,
                                 enum tcurl_http_request req_type);

static int tcurl_http_cleanup_handle(TALLOC_CTX *ptr);

static size_t tcurl_http_write_data(char *ptr,
                                    size_t size,
                                    size_t nmemb,
                                    void *userdata);

static size_t tcurl_http_read_data(void *ptr,
                                   size_t size,
                                   size_t nmemb,
                                   void *userdata);

struct tevent_req *tcurl_http_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct tcurl_ctx *tctx,
                                   enum tcurl_http_request req_type,
                                   const char *socket_path,
                                   const char *url,
                                   const char *headers[],
                                   struct sss_iobuf *req_data,
                                   int timeout)
{
    errno_t ret;
    struct tevent_req *req;
    struct tcurl_http_state *state;

    req = tevent_req_create(mem_ctx, &state, struct tcurl_http_state);
    if (req == NULL) {
        return NULL;
    }

    state->tctx = tctx;
    state->socket_path = socket_path;
    state->url = url;
    state->inbuf = req_data;
    state->timeout = timeout;

    state->outbuf = sss_iobuf_init_empty(state, IOBUF_CHUNK, IOBUF_MAX);
    if (state->outbuf == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "HTTP request %s for URL %s\n", http_req2str(req_type), url);
    talloc_set_destructor((TALLOC_CTX *) state, tcurl_http_cleanup_handle);

    /* All transfer share the same multi handle, but each trasfer has its own
     * easy handle we can use to set per-transfer options
     */
    state->http_handle = curl_easy_init();
    if (state->http_handle == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "curl_easy_init failed\n");
        ret = EIO;
        goto fail;
    }

    ret = tcurl_add_headers(state, headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set CURL headers [%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    ret = tcurl_set_options(state, req, req_type);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set CURL options [%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    /* Pass control to the curl handling which will mark the request as
     * done
     */
    curl_multi_add_handle(tctx->multi_handle, state->http_handle);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static int tcurl_http_cleanup_handle(TALLOC_CTX *ptr)
{
    struct tcurl_http_state *state = talloc_get_type(ptr, struct tcurl_http_state);

    if (state == NULL) {
        return 0;
    }

    /* it is safe to pass NULL here */
    curl_multi_remove_handle(state->tctx->multi_handle, state->http_handle);
    curl_slist_free_all(state->curl_headers);
    curl_easy_cleanup(state->http_handle);
    return 0;
}

static errno_t tcurl_add_headers(struct tcurl_http_state *state,
                                 const char *headers[])
{
    if (headers == NULL) {
        return EOK;
    }

    /* The headers will be freed later in tcurl_http_cleanup_handle */
    for (int i = 0; headers[i] != NULL; i++) {
        state->curl_headers = curl_slist_append(state->curl_headers, headers[i]);
        if (state->curl_headers == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot add header %s\n", headers[i]);
            return ENOMEM;
        }
    }

    /* Add a dummy header to suppress libcurl adding Expect 100-continue which
     * was causing libcurl to always wait for the internal timeout when sending
     * a PUT/PATCH request
     */
    state->curl_headers = curl_slist_append(state->curl_headers, "Expect:");
    if (state->curl_headers == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot add the dummy expect header\n");
        return ENOMEM;
    }

    return EOK;
}

static errno_t tcurl_set_common_options(struct tcurl_http_state *state,
                                        struct tevent_req *req)
{
    CURLcode crv;

    crv = curl_easy_setopt(state->http_handle,
                           CURLOPT_HTTPHEADER,
                           state->curl_headers);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set HTTP headers [%d]: %s\n",
              crv, curl_easy_strerror(crv));
        return EIO;
    }

    crv = curl_easy_setopt(state->http_handle,
                           CURLOPT_UNIX_SOCKET_PATH,
                           state->socket_path);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set UNIX socket path %s [%d]: %s\n",
              state->socket_path, crv, curl_easy_strerror(crv));
        return EIO;
    }

    crv = curl_easy_setopt(state->http_handle, CURLOPT_URL, state->url);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set URL %s [%d]: %s\n",
              state->url, crv, curl_easy_strerror(crv));
        return EIO;
    }

    crv = curl_easy_setopt(state->http_handle, CURLOPT_PRIVATE, req);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set private data [%d]: %s\n",
              crv, curl_easy_strerror(crv));
        return EIO;
    }

    if (state->timeout > 0) {
        crv = curl_easy_setopt(state->http_handle,
                               CURLOPT_TIMEOUT,
                               state->timeout);
        if (crv != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to set timeout [%d]: %s\n",
                  crv, curl_easy_strerror(crv));
            return EIO;
        }
    }

    return EOK;
}

static errno_t tcurl_set_write_options(struct tcurl_http_state *state)
{
    CURLcode crv;

    crv = curl_easy_setopt(state->http_handle,
                           CURLOPT_WRITEFUNCTION,
                           tcurl_http_write_data);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set write function [%d]: %s\n",
              crv, curl_easy_strerror(crv));
        return EIO;
    }

    crv = curl_easy_setopt(state->http_handle,
                           CURLOPT_WRITEDATA,
                           state->outbuf);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set write data [%d]: %s\n",
              crv, curl_easy_strerror(crv));
        return EIO;
    }

    return EOK;
}

static errno_t tcurl_set_read_options(struct tcurl_http_state *state)
{
    CURLcode crv;

    crv = curl_easy_setopt(state->http_handle,
                           CURLOPT_READFUNCTION,
                           tcurl_http_read_data);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set read function [%d]: %s\n",
              crv, curl_easy_strerror(crv));
        return EIO;
    }

    crv = curl_easy_setopt(state->http_handle,
                           CURLOPT_READDATA,
                           state->inbuf);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set read data [%d]: %s\n",
              crv, curl_easy_strerror(crv));
        return EIO;
    }

    return EOK;
}

static errno_t tcurl_set_options(struct tcurl_http_state *state,
                                 struct tevent_req *req,
                                 enum tcurl_http_request req_type)
{
    CURLcode crv;
    errno_t ret;

    ret = tcurl_set_common_options(state, req);
    if (ret != EOK) {
        return ret;
    }

    ret = tcurl_set_write_options(state);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set write callbacks [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    switch (req_type) {
    case TCURL_HTTP_PUT:
        /* CURLOPT_UPLOAD enables HTTP_PUT */
        crv = curl_easy_setopt(state->http_handle,
                               CURLOPT_UPLOAD,
                               1L);
        if (crv != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to set the uplodad option [%d]: %s\n",
                  crv, curl_easy_strerror(crv));
            return EIO;
        }

        /* Causes libcurl to add a sane Content-Length header */
        crv = curl_easy_setopt(state->http_handle,
                               CURLOPT_INFILESIZE_LARGE,
                               (curl_off_t) sss_iobuf_get_size(state->inbuf));
        if (crv != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to set CURLOPT_INFILESIZE_LARGE [%d]: %s\n",
                  crv, curl_easy_strerror(crv));
            return EIO;
        }

        ret = tcurl_set_read_options(state);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to set write callbacks [%d]: %s\n",
                  ret, sss_strerror(ret));
            return ret;
        }
        break;
    case TCURL_HTTP_GET:
        /* GET just needs the write callbacks, nothing to do here.. */
        break;
    case TCURL_HTTP_DELETE:
        crv = curl_easy_setopt(state->http_handle,
                               CURLOPT_CUSTOMREQUEST,
                               "DELETE");
        if (crv != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to set the uplodad option [%d]: %s\n",
                  crv, curl_easy_strerror(crv));
            return EIO;
        }
        break;
    default:
        return EFAULT;
    }

    return EOK;
}

static size_t tcurl_http_write_data(char *ptr,
                                    size_t size,
                                    size_t nmemb,
                                    void *userdata)
{
    errno_t ret;
    size_t realsize = size * nmemb;
    struct sss_iobuf *outbuf = talloc_get_type(userdata, struct sss_iobuf);

    DEBUG(SSSDBG_TRACE_INTERNAL, "---> begin libcurl data\n");
    DEBUG(SSSDBG_TRACE_INTERNAL, "%s\n", ptr);
    DEBUG(SSSDBG_TRACE_INTERNAL, "<--- end libcurl data\n");

    ret = sss_iobuf_write_len(outbuf, (uint8_t *) ptr, realsize);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to write data to buffer [%d]: %s\n", ret, sss_strerror(ret));
        /* zero signifies an EOF */
        return 0;
    }

    return realsize;
}

static size_t tcurl_http_read_data(void *ptr,
                                   size_t size,
                                   size_t nmemb,
                                   void *userdata)
{
    errno_t ret;
    size_t readbytes;
    struct sss_iobuf *inbuf = (struct sss_iobuf *) userdata;

    if (inbuf == NULL) {
        return CURL_READFUNC_ABORT;
    }

    ret = sss_iobuf_read(inbuf, size * nmemb, ptr, &readbytes);
    if (ret != EOK) {
        return CURL_READFUNC_ABORT;
    }

    return readbytes;
}

int tcurl_http_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    int *_http_code,
                    struct sss_iobuf **_outbuf)
{
    struct tcurl_http_state *state = tevent_req_data(req, struct tcurl_http_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_http_code != NULL) {
        *_http_code = state->http_code;
    }

    if (_outbuf != NULL) {
        *_outbuf = talloc_steal(mem_ctx, state->outbuf);
    }

    return 0;
}
