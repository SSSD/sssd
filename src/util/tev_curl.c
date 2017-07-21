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

#define TCURL_IOBUF_CHUNK   1024
#define TCURL_IOBUF_MAX    16384

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

static void tcurl_request_done(struct tevent_req *req,
                               errno_t process_error,
                               int response_code);

static errno_t curl_code2errno(CURLcode crv)
{
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
    case CURLE_SSL_ISSUER_ERROR:
    case CURLE_SSL_CACERT_BADFILE:
    case CURLE_SSL_CACERT:
    case CURLE_SSL_CERTPROBLEM:
        return ERR_INVALID_CERT;

    case CURLE_SSL_CRL_BADFILE:
    case CURLE_SSL_SHUTDOWN_FAILED:
    case CURLE_SSL_ENGINE_INITFAILED:
    case CURLE_USE_SSL_FAILED:
    case CURLE_SSL_CIPHER:
    case CURLE_SSL_ENGINE_SETFAILED:
    case CURLE_SSL_ENGINE_NOTFOUND:
    case CURLE_SSL_CONNECT_ERROR:
        return ERR_SSL_FAILURE;
    case CURLE_PEER_FAILED_VERIFICATION:
        return ERR_UNABLE_TO_VERIFY_PEER;
    case CURLE_COULDNT_RESOLVE_HOST:
        return ERR_UNABLE_TO_RESOLVE_HOST;
    default:
        break;
    }

    return EIO;
}

static errno_t curlm_code2errno(CURLcode crv)
{
    switch (crv) {
    case CURLM_OK:
        return EOK;
    case CURLM_BAD_SOCKET:
        return EPIPE;
    case CURLM_OUT_OF_MEMORY:
        return ENOMEM;
    case CURLM_BAD_HANDLE:
    case CURLM_BAD_EASY_HANDLE:
    case CURLM_UNKNOWN_OPTION:
        return EINVAL;
    case CURLM_INTERNAL_ERROR:
        return ERR_INTERNAL;
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
    long response_code = 0;
    char *done_url;
    errno_t ret;

    easy_handle = message->easy_handle;
    if (easy_handle == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: NULL handle for message %p\n", message);
        return;
    }

    if (DEBUG_IS_SET(SSSDBG_TRACE_FUNC)) {
        crv = curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &done_url);
        if (crv != CURLE_OK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot get CURLINFO_EFFECTIVE_URL "
                  "[%d]: %s\n", crv, curl_easy_strerror(crv));
            /* not fatal since we need this only for debugging */
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Handled %s\n", done_url);
        }
    }

    crv = curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, (void *) &req);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get CURLINFO_PRIVATE [%d]: %s\n",
              crv, curl_easy_strerror(crv));
        ret = curl_code2errno(crv);
        goto done;
    }

    ret = curl_code2errno(message->data.result);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "CURL operation failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* If there was no fatal error, let's read the response code
     * and mark the request as done */
    crv = curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &response_code);
    if (crv != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get response code\n");
        ret = curl_code2errno(crv);
        goto done;
    }

    ret = EOK;

done:
    tcurl_request_done(req, ret, response_code);
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

#define tcurl_set_option(tcurl_req, option, value)                          \
({                                                                          \
    CURLcode __curl_code;                                                   \
    errno_t __ret;                                                          \
                                                                            \
    __curl_code = curl_easy_setopt((tcurl_req)->curl_easy_handle,           \
                                   (option), (value));                      \
    if (__curl_code == CURLE_OK) {                                          \
        __ret = EOK;                                                        \
    } else {                                                                \
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set CURL option %s [%d]: %s\n", \
              #option, __curl_code, curl_easy_strerror(__curl_code));       \
        __ret = curl_code2errno(__curl_code);                               \
    }                                                                       \
    __ret;                                                                  \
})

static size_t tcurl_write_data(char *ptr,
                               size_t size,
                               size_t nmemb,
                               void *userdata)
{
    errno_t ret;
    size_t realsize = size * nmemb;
    struct sss_iobuf *outbuf;

    outbuf = talloc_get_type(userdata, struct sss_iobuf);

    DEBUG(SSSDBG_TRACE_INTERNAL, "---> begin libcurl data\n");
    DEBUG(SSSDBG_TRACE_INTERNAL, "%s\n", ptr);
    DEBUG(SSSDBG_TRACE_INTERNAL, "<--- end libcurl data\n");

    ret = sss_iobuf_write_len(outbuf, (uint8_t *)ptr, realsize);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to write data to buffer [%d]: %s\n",
              ret, sss_strerror(ret));
        /* zero signifies an EOF */
        return 0;
    }

    return realsize;
}

static size_t tcurl_read_data(void *ptr,
                              size_t size,
                              size_t nmemb,
                              void *userdata)
{
    errno_t ret;
    size_t readbytes;
    struct sss_iobuf *inbuf;

    inbuf = talloc_get_type(userdata, struct sss_iobuf);

    if (inbuf == NULL) {
        return CURL_READFUNC_ABORT;
    }

    ret = sss_iobuf_read(inbuf, size * nmemb, ptr, &readbytes);
    if (ret != EOK) {
        return CURL_READFUNC_ABORT;
    }

    return readbytes;
}


struct tcurl_request {
    CURL *curl_easy_handle;

    struct sss_iobuf *body;
    struct curl_slist *headers;

    const char *url;
    const char *socket;

    /* Associated tcurl context if this request is in progress. */
    struct tcurl_ctx *tcurl_ctx;
};

struct tcurl_request_state {
    struct tcurl_request *tcurl_req;
    struct sss_iobuf *response;
    int response_code;
};

struct tevent_req *
tcurl_request_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct tcurl_ctx *tcurl_ctx,
                   struct tcurl_request *tcurl_req,
                   long int timeout)
{
    struct tcurl_request_state *state;
    struct tevent_req *req;
    CURLMcode curl_code;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct tcurl_request_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Sending TCURL request for %s, at socket %s\n",
          tcurl_req->url == NULL ? "<none>" : tcurl_req->url,
          tcurl_req->socket == NULL ? "<none>" : tcurl_req->socket);

    state->tcurl_req = talloc_steal(state, tcurl_req);

    state->response = sss_iobuf_init_empty(state, TCURL_IOBUF_CHUNK, TCURL_IOBUF_MAX);
    if (state->response == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = tcurl_set_option(tcurl_req, CURLOPT_PRIVATE, req);
    if (ret != EOK) {
        goto done;
    }

    ret = tcurl_set_option(tcurl_req, CURLOPT_TIMEOUT, timeout);
    if (ret != EOK) {
        goto done;
    }

    ret = tcurl_set_option(tcurl_req, CURLOPT_WRITEFUNCTION, tcurl_write_data);
    if (ret != EOK) {
        goto done;
    }

    ret = tcurl_set_option(tcurl_req, CURLOPT_WRITEDATA, state->response);
    if (ret != EOK) {
        goto done;
    }

    if (tcurl_req->body != NULL) {
        ret = tcurl_set_option(tcurl_req, CURLOPT_READFUNCTION, tcurl_read_data);
        if (ret != EOK) {
            goto done;
        }

        ret = tcurl_set_option(tcurl_req, CURLOPT_READDATA, tcurl_req->body);
        if (ret != EOK) {
            goto done;
        }
    }

    curl_code = curl_multi_add_handle(tcurl_ctx->multi_handle,
                                      tcurl_req->curl_easy_handle);
    if (curl_code != CURLM_OK) {
        ret = curlm_code2errno(curl_code);
        goto done;
    }

    tcurl_req->tcurl_ctx = tcurl_ctx;

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void tcurl_request_done(struct tevent_req *req,
                               errno_t process_error,
                               int response_code)
{
    struct tcurl_request_state *state;

    DEBUG(SSSDBG_TRACE_FUNC, "TCURL request finished [%d]: %s\n",
          process_error, sss_strerror(process_error));

    if (req == NULL) {
        /* To handle case where we fail to obtain request from private data. */
        DEBUG(SSSDBG_MINOR_FAILURE, "No tevent request provided!\n");
        return;
    }

    state = tevent_req_data(req, struct tcurl_request_state);

    curl_multi_remove_handle(state->tcurl_req->tcurl_ctx->multi_handle,
                             state->tcurl_req->curl_easy_handle);

    /* This request is no longer associated with tcurl context. */
    state->tcurl_req->tcurl_ctx = NULL;

    if (process_error != EOK) {
        tevent_req_error(req, process_error);
        return;
    }

    state->response_code = response_code;

    tevent_req_done(req);
    return;
}

errno_t tcurl_request_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct sss_iobuf **_response,
                           int *_response_code)
{
    struct tcurl_request_state *state;
    state = tevent_req_data(req, struct tcurl_request_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_response != NULL) {
        *_response = talloc_steal(mem_ctx, state->response);
    }

    if (_response_code != NULL) {
        *_response_code = state->response_code;
    }

    return EOK;
}

static struct curl_slist *
tcurl_add_header(struct curl_slist *slist, const char *header)
{
    struct curl_slist *new;

    new = curl_slist_append(slist, header);
    if (new == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot add header %s\n", header);
        if (slist != NULL) {
            curl_slist_free_all(slist);
        }

        return NULL;
    }

    return new;
}

static errno_t
tcurl_construct_headers(const char **headers,
                        struct curl_slist **_slist)
{
    struct curl_slist *slist = NULL;
    int i;

    if (headers == NULL || headers[0] == NULL) {
        *_slist = NULL;
        return EOK;
    }

    for (i = 0; headers[i] != NULL; i++) {
        slist = tcurl_add_header(slist, headers[i]);
        if (slist == NULL) {
            return ENOMEM;
        }
    }

    /* Add a dummy header to suppress libcurl adding Expect 100-continue which
     * was causing libcurl to always wait for the internal timeout when sending
     * a PUT/POST request because secrets responder does not implement this.
     */
    slist = tcurl_add_header(slist, "Expect: ");
    if (slist == NULL) {
        return ENOMEM;
    }

    *_slist = slist;

    return EOK;
}

static int
tcurl_request_destructor(struct tcurl_request *tcurl_req)
{
    if (tcurl_req->tcurl_ctx != NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Terminating TCURL request...\n");
        curl_multi_remove_handle(tcurl_req->tcurl_ctx->multi_handle,
                                 tcurl_req->curl_easy_handle);
    }

    if (tcurl_req->headers != NULL) {
        curl_slist_free_all(tcurl_req->headers);
    }

    if (tcurl_req->curl_easy_handle != NULL) {
        curl_easy_cleanup(tcurl_req->curl_easy_handle);
    }

    return 0;
}

static struct tcurl_request *
tcurl_request_create(TALLOC_CTX *mem_ctx,
                     const char *socket_path,
                     const char *url,
                     const char **headers,
                     struct sss_iobuf *body)
{
    struct tcurl_request *tcurl_req;
    errno_t ret;

    tcurl_req = talloc_zero(mem_ctx, struct tcurl_request);
    if (tcurl_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    if (url == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "URL cannot be NULL!\n");
        ret = EINVAL;
        goto done;
    }

    /* Setup a curl easy handle. This handle contains state for the request
     * and is later associated with curl multi handle which performs
     * asynchronous processing. */
    tcurl_req->curl_easy_handle = curl_easy_init();
    if (tcurl_req->curl_easy_handle == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize curl easy handle!\n");
        ret = ENOMEM;
        goto done;
    }

    tcurl_req->url = talloc_strdup(tcurl_req, url);
    if (tcurl_req->url == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    if (socket_path != NULL) {
        tcurl_req->socket = talloc_strdup(tcurl_req, socket_path);
        if (tcurl_req->socket == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = tcurl_construct_headers(headers, &tcurl_req->headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to construct headers [%d]: %s\n",
              ret, sss_strerror(ret));
        ret = ENOMEM;
        goto done;
    }

    tcurl_req->body = body;

    talloc_set_destructor(tcurl_req, tcurl_request_destructor);

    ret = tcurl_set_option(tcurl_req, CURLOPT_URL, url);
    if (ret != EOK) {
        goto done;
    }

    if (socket_path != NULL) {
        ret = tcurl_set_option(tcurl_req, CURLOPT_UNIX_SOCKET_PATH, socket_path);
        if (ret != EOK) {
            goto done;
        }
    }

    if (body != NULL) {
        /* Curl will tell the underlying protocol about incoming data length.
         * In case of HTTP it will add a sane Content-Length header. */
        ret = tcurl_set_option(tcurl_req, CURLOPT_INFILESIZE_LARGE,
                               (curl_off_t)sss_iobuf_get_size(body));
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(tcurl_req);
        return NULL;
    }

    return tcurl_req;
}

struct tcurl_request *tcurl_http(TALLOC_CTX *mem_ctx,
                                 enum tcurl_http_method method,
                                 const char *socket_path,
                                 const char *url,
                                 const char **headers,
                                 struct sss_iobuf *body)
{
    struct tcurl_request *tcurl_req;
    errno_t ret;

    tcurl_req = tcurl_request_create(mem_ctx, socket_path, url, headers, body);
    if (tcurl_req == NULL) {
        return NULL;
    }

    /* Set HTTP specific options. */

    ret = tcurl_set_option(tcurl_req, CURLOPT_HTTPHEADER, tcurl_req->headers);
    if (ret != EOK) {
        goto done;
    }

    switch (method) {
    case TCURL_HTTP_GET:
        /* Nothing to do here. GET is default. */
        break;
    case TCURL_HTTP_PUT:
        ret = tcurl_set_option(tcurl_req, CURLOPT_UPLOAD, 1L);
        if (ret != EOK) {
            goto done;
        }
        break;
    case TCURL_HTTP_POST:
        ret = tcurl_set_option(tcurl_req, CURLOPT_CUSTOMREQUEST, "POST");
        if (ret != EOK) {
            goto done;
        }
        break;
    case TCURL_HTTP_DELETE:
        ret = tcurl_set_option(tcurl_req, CURLOPT_CUSTOMREQUEST, "DELETE");
        if (ret != EOK) {
            goto done;
        }
        break;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(tcurl_req);
        return NULL;
    }

    return tcurl_req;
}

struct tevent_req *tcurl_http_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct tcurl_ctx *tcurl_ctx,
                                   enum tcurl_http_method method,
                                   const char *socket_path,
                                   const char *url,
                                   const char **headers,
                                   struct sss_iobuf *body,
                                   int timeout)
{
    struct tcurl_request *tcurl_req;
    struct tevent_req *req;

    tcurl_req = tcurl_http(mem_ctx, method, socket_path, url, headers, body);
    if (tcurl_req == NULL) {
        return NULL;
    }

    req = tcurl_request_send(mem_ctx, ev, tcurl_ctx, tcurl_req, timeout);
    if (req == NULL) {
        talloc_free(tcurl_req);
    }

    return req;
}

errno_t tcurl_http_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        int *_http_code,
                        struct sss_iobuf **_response)
{
    return tcurl_request_recv(mem_ctx, req, _response, _http_code);
}

errno_t tcurl_req_enable_rawoutput(struct tcurl_request *tcurl_req)
{
    return tcurl_set_option(tcurl_req, CURLOPT_HEADER, 1L);
}

errno_t tcurl_req_verify_peer(struct tcurl_request *tcurl_req,
                              const char *capath,
                              const char *cacert,
                              bool verify_peer,
                              bool verify_host)
{
    errno_t ret;

    long peer = verify_peer ? 1L : 0L;
    long host = verify_host ? 2L : 0L;

    ret = tcurl_set_option(tcurl_req, CURLOPT_SSL_VERIFYPEER, peer);
    if (ret != EOK) {
        return ret;
    }

    ret = tcurl_set_option(tcurl_req, CURLOPT_SSL_VERIFYHOST, host);
    if (ret != EOK) {
        return ret;
    }

    if (capath != NULL) {
        ret = tcurl_set_option(tcurl_req, CURLOPT_CAPATH, capath);
        if (ret != EOK) {
            return ret;
        }
    }

    if (cacert != NULL) {
        ret = tcurl_set_option(tcurl_req, CURLOPT_CAINFO, cacert);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

errno_t tcurl_req_set_client_cert(struct tcurl_request *tcurl_req,
                                  const char *cert,
                                  const char *key)
{
    errno_t ret;

    if (cert == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "You must specify client certificate!\n");
        return EINVAL;
    }

    ret = tcurl_set_option(tcurl_req, CURLOPT_SSLCERT, cert);
    if (ret != EOK) {
        return ret;
    }

    if (key != NULL) {
        /* If client's private key is in separate file. */
        ret = tcurl_set_option(tcurl_req, CURLOPT_SSLKEY, key);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

errno_t tcurl_req_http_basic_auth(struct tcurl_request *tcurl_req,
                                  const char *username,
                                  const char *password)
{
    errno_t ret;

    ret = tcurl_set_option(tcurl_req, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    if (ret != EOK) {
        return ret;
    }

    ret = tcurl_set_option(tcurl_req, CURLOPT_USERNAME, username);
    if (ret != EOK) {
        return ret;
    }

    ret = tcurl_set_option(tcurl_req, CURLOPT_PASSWORD, password);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}
