/*
    SSSD

    Async communication with the child process via a pipe.

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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <talloc.h>
#include <tevent.h>

#include "util/util_errors.h"
#include "util/debug.h"
#include "util/util.h"
#include "util/child_common.h"

#define CHILD_MSG_CHUNK     1024

struct _write_pipe_state {
    int fd;
    uint8_t *buf;
    size_t len;
    bool safe;
    ssize_t written;
};

static void _write_pipe_handler(struct tevent_context *ev,
                                struct tevent_fd *fde,
                                uint16_t flags,
                                void *pvt);

static struct tevent_req *_write_pipe_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           uint8_t *buf,
                                           size_t len,
                                           bool safe,
                                           int fd)
{
    struct tevent_req *req;
    struct _write_pipe_state *state;
    struct tevent_fd *fde;

    req = tevent_req_create(mem_ctx, &state, struct _write_pipe_state);
    if (req == NULL) return NULL;

    state->fd = fd;
    state->buf = buf;
    state->len = len;
    state->safe = safe;
    state->written = 0;

    fde = tevent_add_fd(ev, state, fd, TEVENT_FD_WRITE,
                        _write_pipe_handler, req);
    if (fde == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_fd failed.\n");
        goto fail;
    }

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void _write_pipe_handler(struct tevent_context *ev,
                                struct tevent_fd *fde,
                                uint16_t flags,
                                void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct _write_pipe_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct _write_pipe_state);

    if (flags & TEVENT_FD_READ) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "_write_pipe_done called with TEVENT_FD_READ,"
              " this should not happen.\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    errno = 0;
    if (state->safe) {
        state->written = sss_atomic_write_safe_s(state->fd, state->buf, state->len);
    } else {
        state->written = sss_atomic_write_s(state->fd, state->buf, state->len);
    }
    if (state->written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
            "write failed [%d][%s].\n", ret, strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->len != state->written) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Wrote %zd bytes, expected %zu\n",
              state->written, state->len);
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "All data has been sent!\n");
    tevent_req_done(req);
    return;
}

static int _write_pipe_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct tevent_req *write_pipe_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   uint8_t *buf,
                                   size_t len,
                                   int fd)
{
    return _write_pipe_send(mem_ctx, ev, buf, len, false, fd);
}

int write_pipe_recv(struct tevent_req *req)
{
    return _write_pipe_recv(req);
}

struct tevent_req *write_pipe_safe_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        uint8_t *buf,
                                        size_t len,
                                        int fd)
{
    return _write_pipe_send(mem_ctx, ev, buf, len, true, fd);
}

int write_pipe_safe_recv(struct tevent_req *req)
{
    return _write_pipe_recv(req);
}

struct _read_pipe_state {
    int fd;
    uint8_t *buf;
    size_t len;
    bool safe;
    bool non_blocking;
};

static void _read_pipe_handler(struct tevent_context *ev,
                               struct tevent_fd *fde,
                               uint16_t flags,
                               void *pvt);

static struct tevent_req *_read_pipe_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          bool safe,
                                          bool non_blocking,
                                          int fd)
{
    struct tevent_req *req;
    struct _read_pipe_state *state;
    struct tevent_fd *fde;

    req = tevent_req_create(mem_ctx, &state, struct _read_pipe_state);
    if (req == NULL) return NULL;

    state->fd = fd;
    state->buf = NULL;
    state->len = 0;

    if (safe && non_blocking) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Both flags 'safe' and 'non_blocking' are set to 'true', this is "
              "most probably an error in the SSSD code which should be fixed. "
              "Continue by setting 'non_blocking' to 'false'.");
        non_blocking = false;
    }
    state->safe = safe;
    state->non_blocking = non_blocking;

    fde = tevent_add_fd(ev, state, fd, TEVENT_FD_READ,
                        _read_pipe_handler, req);
    if (fde == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_fd failed.\n");
        goto fail;
    }

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void _read_pipe_handler(struct tevent_context *ev,
                               struct tevent_fd *fde,
                               uint16_t flags,
                               void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct _read_pipe_state *state;
    ssize_t size;
    errno_t err;
    uint8_t *buf;
    size_t len = 0;

    state = tevent_req_data(req, struct _read_pipe_state);

    if (flags & TEVENT_FD_WRITE) {
        DEBUG(SSSDBG_CRIT_FAILURE, "_read_pipe_done called with "
              "TEVENT_FD_WRITE, this should not happen.\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    buf = talloc_array(state, uint8_t, CHILD_MSG_CHUNK);
    if (buf == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    if (state->safe) {
        size = sss_atomic_read_safe_s(state->fd, buf, CHILD_MSG_CHUNK, &len);
        if (size == -1 && errno == ERANGE) {
            buf = talloc_realloc(state, buf, uint8_t, len);
            if(!buf) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            size = sss_atomic_read_s(state->fd, buf, len);
        }
    } else {
        if (state->non_blocking) {
            size = read(state->fd, buf, CHILD_MSG_CHUNK);
            if (size == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Waiting for more data to read, returning the event loop. "
                      "Current size [%zu]\n", state->len);
                return;
            }
        } else {
            size = sss_atomic_read_s(state->fd, buf, CHILD_MSG_CHUNK);
        }
    }
    if (size == -1) {
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "read failed [%d][%s].\n", err, strerror(err));

        tevent_req_error(req, err);
        return;
    } else if (size > 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Adding [%zd] bytes of data.\n", size);
        state->buf = talloc_realloc(state, state->buf, uint8_t,
                                    state->len + size);
        if(!state->buf) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        safealign_memcpy(&state->buf[state->len], buf,
                         size, &state->len);

        if (state->len == len) {
            DEBUG(SSSDBG_TRACE_FUNC, "All data received\n");
            tevent_req_done(req);
        }
        return;

    } else if (size == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "EOF received, client finished\n");
        tevent_req_done(req);
        return;

    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "unexpected return value of read [%zd].\n", size);
        tevent_req_error(req, EINVAL);
        return;
    }
}

static errno_t _read_pipe_recv(struct tevent_req *req,
                               TALLOC_CTX *mem_ctx,
                               uint8_t **buf,
                               ssize_t *len)
{
    struct _read_pipe_state *state;
    state = tevent_req_data(req, struct _read_pipe_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *buf = talloc_steal(mem_ctx, state->buf);
    *len = state->len;

    return EOK;
}

struct tevent_req *read_pipe_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  int fd)
{
    return _read_pipe_send(mem_ctx, ev, false, false, fd);
}

struct tevent_req *read_pipe_non_blocking_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               int fd)
{
    return _read_pipe_send(mem_ctx, ev, false, true, fd);
}

errno_t read_pipe_recv(struct tevent_req *req,
                       TALLOC_CTX *mem_ctx,
                       uint8_t **_buf,
                       ssize_t *_len)
{
    return _read_pipe_recv(req, mem_ctx, _buf, _len);
}

struct tevent_req *read_pipe_safe_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       int fd)
{
    return _read_pipe_send(mem_ctx, ev, true, false, fd);
}

errno_t read_pipe_safe_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            uint8_t **_buf,
                            ssize_t *_len)
{
    return _read_pipe_recv(req, mem_ctx, _buf, _len);
}
