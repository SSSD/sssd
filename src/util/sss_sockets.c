/*
   SSSD

   Socket utils

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016
   Copyright (C) Sumit Bose <sbose@redhat.com> 2009

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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "util/util.h"


static errno_t set_fcntl_flags(int fd, int fd_flags, int fl_flags)
{
    int ret;
    int cur_flags;

    ret = fcntl(fd, F_GETFD, 0);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fcntl F_GETFD failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }
    cur_flags = ret;

    ret = fcntl(fd, F_SETFD, cur_flags | fd_flags);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fcntl F_SETFD failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    ret = fcntl(fd, F_GETFL, 0);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fcntl F_GETFD failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }
    cur_flags = ret;

    ret = fcntl(fd, F_SETFL, cur_flags | fl_flags);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fcntl F_SETFD failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    return EOK;
}

errno_t set_fd_common_opts(int fd, int timeout)
{
    int dummy = 1;
    int ret;
    struct timeval tv;
    unsigned int milli;
    int domain;
    int type;
    socklen_t optlen = sizeof(int);

    /* Get protocol domain. */
    ret = getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &optlen);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_FUNC_DATA, "Unable to get socket domain [%d]: %s.\n",
              ret, strerror(ret));
        /* Assume IPV6. */
        domain = AF_INET6;
    }

    /* Get protocol type. */
    ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_FUNC_DATA, "Unable to get socket type [%d]: %s.\n",
              ret, strerror(ret));
        /* Assume TCP. */
        type = SOCK_STREAM;
    }

    /* SO_KEEPALIVE and TCP_NODELAY are set by OpenLDAP client libraries but
     * failures are ignored.*/
    if (domain != AF_UNIX && type == SOCK_STREAM) {

        ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &dummy, sizeof(dummy));
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_FUNC_DATA,
                  "setsockopt SO_KEEPALIVE failed.[%d][%s].\n", ret,
                      strerror(ret));
        }

        ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &dummy, sizeof(dummy));
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_FUNC_DATA,
                "setsockopt TCP_NODELAY failed.[%d][%s].\n", ret,
                    strerror(ret));
        }
    }

    if (timeout > 0) {
        /* Set socket read & write timeout */
        tv = tevent_timeval_set(timeout, 0);

        ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_FUNC_DATA,
                  "setsockopt SO_RCVTIMEO failed.[%d][%s].\n", ret,
                  strerror(ret));
        }

        ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_FUNC_DATA,
                  "setsockopt SO_SNDTIMEO failed.[%d][%s].\n", ret,
                  strerror(ret));
        }

        if (domain != AF_UNIX && type == SOCK_STREAM) {
            milli = timeout * 1000; /* timeout in milliseconds */
            ret = setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &milli,
                            sizeof(milli));
            if (ret != 0) {
                ret = errno;
                DEBUG(SSSDBG_FUNC_DATA,
                    "setsockopt TCP_USER_TIMEOUT failed.[%d][%s].\n", ret,
                    strerror(ret));
            }
        }
    }

    return EOK;
}


struct sssd_async_connect_state {
    struct tevent_fd *fde;
    int fd;
    socklen_t addr_len;
    struct sockaddr_storage addr;
};

static void sssd_async_connect_done(struct tevent_context *ev,
                                    struct tevent_fd *fde, uint16_t flags,
                                    void *priv);

struct tevent_req *sssd_async_connect_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           int fd,
                                           const struct sockaddr *addr,
                                           socklen_t addr_len)
{
    struct tevent_req *req;
    struct sssd_async_connect_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sssd_async_connect_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->fd = fd;
    state->addr_len = addr_len;
    memcpy(&state->addr, addr, addr_len);

    ret = connect(fd, addr, addr_len);
    if (ret == EOK) {
        goto done;
    }

    ret = errno;
    switch (ret) {
    case EINPROGRESS:
    case EINTR:

        /* Despite the connect() man page says waiting on a non-blocking
         * connect should be done by checking for writability, we need to check
         * also for readability.
         * With TEVENT_FD_READ, connect fails much faster in offline mode with
         * errno 113/No route to host.
         */
        state->fde = tevent_add_fd(ev, state, fd,
                                   TEVENT_FD_READ | TEVENT_FD_WRITE,
                                   sssd_async_connect_done, req);
        if (state->fde == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_fd failed.\n");
            ret = ENOMEM;
            goto done;
        }

        return req;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "connect failed [%d][%s].\n", ret, strerror(ret));
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, ev);
    return req;
}

static void sssd_async_connect_done(struct tevent_context *ev,
                                    struct tevent_fd *fde, uint16_t flags,
                                    void *priv)
{
    struct tevent_req *req = talloc_get_type(priv, struct tevent_req);
    struct sssd_async_connect_state *state =
                tevent_req_data(req, struct sssd_async_connect_state);
    int ret;

    errno = 0;
    ret = connect(state->fd, (struct sockaddr *) &state->addr,
                  state->addr_len);
    if (ret == -1) {
        ret = errno;
        if (ret == EALREADY || ret == EINPROGRESS || ret == EINTR) {
            return; /* Try again later */
        }
    }

    talloc_zfree(fde);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "connect failed [%d][%s].\n", ret, strerror(ret));
        tevent_req_error(req, ret);
    }
}

int sssd_async_connect_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


static void sssd_async_connect_timeout(struct tevent_context *ev,
                                       struct tevent_timer *te,
                                       struct timeval tv, void *pvt)
{
    struct tevent_req *connection_request;

    DEBUG(SSSDBG_CONF_SETTINGS,
          "The connection timed out [ldap_network_timeout]\n");

    connection_request = talloc_get_type(pvt, struct tevent_req);
    tevent_req_error(connection_request, ETIMEDOUT);
}


struct sssd_async_socket_state {
    struct tevent_timer *connect_timeout;
    int sd;
};

static int sssd_async_socket_state_destructor(void *data);
static void sssd_async_socket_init_done(struct tevent_req *subreq);

struct tevent_req *sssd_async_socket_init_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               bool use_udp,
                                               struct sockaddr *addr,
                                               socklen_t addr_len, int timeout)
{
    struct sssd_async_socket_state *state;
    struct tevent_req *req, *subreq;
    struct timeval tv;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sssd_async_socket_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }
    state->sd = -1;

    talloc_set_destructor((TALLOC_CTX *)state,
                          sssd_async_socket_state_destructor);

    state->sd = socket(addr->sa_family, use_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (state->sd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "socket failed [%d][%s].\n", ret, strerror(ret));
        goto fail;
    }

    ret = set_fd_common_opts(state->sd, timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "set_fd_common_opts failed.\n");
        goto fail;
    }

    ret = set_fcntl_flags(state->sd, FD_CLOEXEC, O_NONBLOCK);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "setting fd flags failed.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Using file descriptor [%d] for the connection.\n", state->sd);

    subreq = sssd_async_connect_send(state, ev, state->sd,
                                     (struct sockaddr *) addr, addr_len);
    if (subreq == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "sssd_async_connect_send failed.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Setting %d seconds timeout [ldap_network_timeout] for connecting\n",
          timeout);
    tv = tevent_timeval_current_ofs(timeout, 0);

    state->connect_timeout = tevent_add_timer(ev, subreq, tv,
                                              sssd_async_connect_timeout,
                                              subreq);
    if (state->connect_timeout == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, sssd_async_socket_init_done, req);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sssd_async_socket_init_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
                tevent_req_callback_data(subreq, struct tevent_req);
    struct sssd_async_socket_state *state =
                tevent_req_data(req, struct sssd_async_socket_state);
    int ret;

    /* kill the timeout handler now that we got a reply */
    talloc_zfree(state->connect_timeout);

    ret = sssd_async_connect_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (ret == ETIMEDOUT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_async_sys_connect request failed: [%d]: %s "
                  "[ldap_network_timeout].\n",
                  ret, sss_strerror(ret));
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_async_sys_connect request failed: [%d]: %s.\n",
                  ret, sss_strerror(ret));
        }
        goto fail;
    }

    tevent_req_done(req);
    return;

fail:
    tevent_req_error(req, ret);
}

int sssd_async_socket_init_recv(struct tevent_req *req, int *sd)
{
    struct sssd_async_socket_state *state =
                tevent_req_data(req, struct sssd_async_socket_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    /* steal the sd and neutralize destructor actions */
    *sd = state->sd;
    state->sd = -1;

    return EOK;
}

static int sssd_async_socket_state_destructor(void *data)
{
    struct sssd_async_socket_state *state =
        talloc_get_type(data, struct sssd_async_socket_state);

    if (state->sd != -1) {
        DEBUG(SSSDBG_TRACE_FUNC, "closing socket [%d]\n", state->sd);
        close(state->sd);
        state->sd = -1;
    }

    return 0;
}
