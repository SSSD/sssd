/*
    SSSD

    Common helper functions to be used in child processes

    Authors:
        Sumit Bose   <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <sys/types.h>
#include <fcntl.h>
#include <tevent.h>
#include <sys/wait.h>

#include "util/util.h"
#include "util/find_uid.h"
#include "db/sysdb.h"
#include "providers/child_common.h"

uint8_t *copy_buffer_and_add_zero(TALLOC_CTX *mem_ctx,
                                  const uint8_t *src, size_t len)
{
    uint8_t *str;

    str = talloc_size(mem_ctx, len + 1);
    if (str == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        return NULL;
    }
    memcpy(str, src, len);
    str[len] = '\0';

    return str;
}

/* Async communication with the child process via a pipe */

struct read_pipe_state {
    int fd;
    uint8_t *buf;
    size_t len;
};

static void read_pipe_done(struct tevent_context *ev,
                           struct tevent_fd *fde,
                           uint16_t flags, void *pvt);

struct tevent_req *read_pipe_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev, int fd)
{
    struct tevent_req *req;
    struct read_pipe_state *state;
    struct tevent_fd *fde;

    req = tevent_req_create(mem_ctx, &state, struct read_pipe_state);
    if (req == NULL) return NULL;

    state->fd = fd;
    state->buf = talloc_array(state, uint8_t, MAX_CHILD_MSG_SIZE);
    state->len = 0;
    if (state->buf == NULL) goto fail;

    fde = tevent_add_fd(ev, state, fd, TEVENT_FD_READ,
                        read_pipe_done, req);
    if (fde == NULL) {
        DEBUG(1, ("tevent_add_fd failed.\n"));
        goto fail;
    }

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void read_pipe_done(struct tevent_context *ev,
                           struct tevent_fd *fde,
                           uint16_t flags, void *pvt)
{
    ssize_t size;
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct read_pipe_state *state = tevent_req_data(req, struct read_pipe_state);

    if (flags & TEVENT_FD_WRITE) {
        DEBUG(1, ("read_pipe_done called with TEVENT_FD_WRITE, this should not happen.\n"));
        tevent_req_error(req, EINVAL);
        return;
    }

    size = read(state->fd, state->buf + state->len, talloc_get_size(state->buf) - state->len);
    if (size == -1) {
        if (errno == EAGAIN || errno == EINTR) return;
        DEBUG(1, ("read failed [%d][%s].\n", errno, strerror(errno)));
        tevent_req_error(req, errno);
        return;
    } else if (size > 0) {
        state->len += size;
        if (state->len > talloc_get_size(state->buf)) {
            DEBUG(1, ("read to much, this should never happen.\n"));
            tevent_req_error(req, EINVAL);
            return;
        }
        return;
    } else if (size == 0) {
        tevent_req_done(req);
        return;
    } else {
        DEBUG(1, ("unexpected return value of read [%d].\n", size));
        tevent_req_error(req, EINVAL);
        return;
    }
}

int read_pipe_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                   uint8_t **buf, ssize_t *len)
{
    struct read_pipe_state *state = tevent_req_data(req,
                                                    struct read_pipe_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *buf = talloc_move(mem_ctx, &state->buf);
    *len = state->len;

    return EOK;
}

/* The pipes to communicate with the child must be nonblocking */
void fd_nonblocking(int fd)
{
    int flags;
    int ret;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        ret = errno;
        DEBUG(1, ("F_GETFL failed [%d][%s].\n", ret, strerror(ret)));
        return;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        ret = errno;
        DEBUG(1, ("F_SETFL failed [%d][%s].\n", ret, strerror(ret)));
    }

    return;
}

void child_sig_handler(struct tevent_context *ev,
                       struct tevent_signal *sige, int signum,
                       int count, void *__siginfo, void *pvt)
{
    int ret;
    int child_status;

    DEBUG(7, ("Waiting for [%d] childeren.\n", count));
    do {
        errno = 0;
        ret = waitpid(-1, &child_status, WNOHANG);

        if (ret == -1) {
            DEBUG(1, ("waitpid failed [%d][%s].\n", errno, strerror(errno)));
        } else if (ret == 0) {
            DEBUG(1, ("waitpid did not found a child with changed status.\n"));
        } else  {
            if (WEXITSTATUS(child_status) != 0) {
                DEBUG(1, ("child [%d] failed with status [%d].\n", ret,
                          child_status));
            } else {
                DEBUG(4, ("child [%d] finished successful.\n", ret));
            }
        }

        --count;
    } while (count < 0);

    return;
}

