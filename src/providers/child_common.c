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
#include <errno.h>

#include "util/util.h"
#include "util/find_uid.h"
#include "db/sysdb.h"
#include "providers/child_common.h"

struct sss_child_ctx {
    struct tevent_signal *sige;
    pid_t pid;
    int child_status;
    sss_child_callback_t cb;
    void *pvt;
};

int child_handler_setup(struct tevent_context *ev, int pid,
                        sss_child_callback_t cb, void *pvt)
{
    struct sss_child_ctx *child_ctx;

    DEBUG(8, ("Setting up signal handler up for pid [%d]\n", pid));

    child_ctx = talloc_zero(ev, struct sss_child_ctx);
    if (child_ctx == NULL) {
        return ENOMEM;
    }

    child_ctx->sige = tevent_add_signal(ev, child_ctx, SIGCHLD, SA_SIGINFO,
                                        child_sig_handler, child_ctx);
    if(!child_ctx->sige) {
        /* Error setting up signal handler */
        talloc_free(child_ctx);
        return ENOMEM;
    }

    child_ctx->pid = pid;
    child_ctx->cb = cb;
    child_ctx->pvt = pvt;

    DEBUG(8, ("Signal handler set up for pid [%d]\n", pid));
    return EOK;
}

/* Async communication with the child process via a pipe */

struct write_pipe_state {
    int fd;
    uint8_t *buf;
    size_t len;
    size_t written;
};

static void write_pipe_handler(struct tevent_context *ev,
                               struct tevent_fd *fde,
                               uint16_t flags, void *pvt);

struct tevent_req *write_pipe_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   uint8_t *buf, size_t len, int fd)
{
    struct tevent_req *req;
    struct write_pipe_state *state;
    struct tevent_fd *fde;

    req = tevent_req_create(mem_ctx, &state, struct write_pipe_state);
    if (req == NULL) return NULL;

    state->fd = fd;
    state->buf = buf;
    state->len = len;
    state->written = 0;

    fde = tevent_add_fd(ev, state, fd, TEVENT_FD_WRITE,
                        write_pipe_handler, req);
    if (fde == NULL) {
        DEBUG(1, ("tevent_add_fd failed.\n"));
        goto fail;
    }

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void write_pipe_handler(struct tevent_context *ev,
                               struct tevent_fd *fde,
                               uint16_t flags, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct write_pipe_state *state = tevent_req_data(req,
                                                     struct write_pipe_state);
    ssize_t size;

    if (flags & TEVENT_FD_READ) {
        DEBUG(1, ("write_pipe_done called with TEVENT_FD_READ,"
                  " this should not happen.\n"));
        tevent_req_error(req, EINVAL);
        return;
    }

    size = write(state->fd,
                 state->buf + state->written,
                 state->len - state->written);
    if (size == -1) {
        if (errno == EAGAIN || errno == EINTR) return;
        DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
        tevent_req_error(req, errno);
        return;

    } else if (size >= 0) {
        state->written += size;
        if (state->written > state->len) {
            DEBUG(1, ("write to much, this should never happen.\n"));
            tevent_req_error(req, EINVAL);
            return;
        }
    } else {
        DEBUG(1, ("unexpected return value of write [%d].\n", size));
        tevent_req_error(req, EINVAL);
        return;
    }

    if (state->len == state->written) {
        DEBUG(6, ("All data has been sent!\n"));
        tevent_req_done(req);
        return;
    }
}

int write_pipe_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct read_pipe_state {
    int fd;
    uint8_t *buf;
    size_t len;
};

static void read_pipe_handler(struct tevent_context *ev,
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
    state->buf = NULL;
    state->len = 0;

    fde = tevent_add_fd(ev, state, fd, TEVENT_FD_READ,
                        read_pipe_handler, req);
    if (fde == NULL) {
        DEBUG(1, ("tevent_add_fd failed.\n"));
        goto fail;
    }

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static void read_pipe_handler(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct read_pipe_state *state = tevent_req_data(req,
                                                    struct read_pipe_state);
    ssize_t size;
    errno_t err;
    uint8_t buf[CHILD_MSG_CHUNK];

    if (flags & TEVENT_FD_WRITE) {
        DEBUG(1, ("read_pipe_done called with TEVENT_FD_WRITE,"
                  " this should not happen.\n"));
        tevent_req_error(req, EINVAL);
        return;
    }

    size = read(state->fd,
                buf,
                CHILD_MSG_CHUNK);
    if (size == -1) {
        err = errno;
        if (err == EAGAIN || err == EINTR) {
            return;
        }

        DEBUG(1, ("read failed [%d][%s].\n", err, strerror(err)));
        tevent_req_error(req, err);
        return;

    } else if (size > 0) {
        state->buf = talloc_realloc(state, state->buf, uint8_t,
                                    state->len + size);
        if(!state->buf) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        safealign_memcpy(&state->buf[state->len], buf,
                         size, &state->len);
        return;

    } else if (size == 0) {
        DEBUG(6, ("EOF received, client finished\n"));
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
    struct read_pipe_state *state;
    state = tevent_req_data(req, struct read_pipe_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *buf = talloc_steal(mem_ctx, state->buf);
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

static void child_invoke_callback(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt);
void child_sig_handler(struct tevent_context *ev,
                       struct tevent_signal *sige, int signum,
                       int count, void *__siginfo, void *pvt)
{
    int ret, err;
    struct sss_child_ctx *child_ctx;
    struct tevent_immediate *imm;

    if (count <= 0) {
        DEBUG(0, ("SIGCHLD handler called with invalid child count\n"));
        return;
    }

    child_ctx = talloc_get_type(pvt, struct sss_child_ctx);
    DEBUG(7, ("Waiting for child [%d].\n", child_ctx->pid));

    errno = 0;
    ret = waitpid(child_ctx->pid, &child_ctx->child_status, WNOHANG);

    if (ret == -1) {
        err = errno;
        DEBUG(1, ("waitpid failed [%d][%s].\n", err, strerror(err)));
    } else if (ret == 0) {
        DEBUG(1, ("waitpid did not found a child with changed status.\n"));
    } else {
        if WIFEXITED(child_ctx->child_status) {
            if (WEXITSTATUS(child_ctx->child_status) != 0) {
                DEBUG(1, ("child [%d] failed with status [%d].\n", ret,
                          WEXITSTATUS(child_ctx->child_status)));
            } else {
                DEBUG(4, ("child [%d] finished successfully.\n", ret));
            }
        } else if WIFSIGNALED(child_ctx->child_status) {
            DEBUG(1, ("child [%d] was terminated by signal [%d].\n", ret,
                      WTERMSIG(child_ctx->child_status)));
        } else {
            if WIFSTOPPED(child_ctx->child_status) {
                DEBUG(7, ("child [%d] was stopped by signal [%d].\n", ret,
                          WSTOPSIG(child_ctx->child_status)));
            }
            if WIFCONTINUED(child_ctx->child_status) {
                DEBUG(7, ("child [%d] was resumed by delivery of SIGCONT.\n",
                          ret));
            }

            return;
        }

        /* Invoke the callback in a tevent_immediate handler
         * so that it is safe to free the tevent_signal *
         */
        imm = tevent_create_immediate(ev);
        if (imm == NULL) {
            DEBUG(0, ("Out of memory invoking sig handler callback\n"));
            return;
        }

        tevent_schedule_immediate(imm, ev,child_invoke_callback,
                                  child_ctx);
    }

    return;
}

static void child_invoke_callback(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt)
{
    struct sss_child_ctx *child_ctx =
            talloc_get_type(pvt, struct sss_child_ctx);
    if (child_ctx->cb) {
        child_ctx->cb(child_ctx->child_status, child_ctx->sige, child_ctx->pvt);
    }

    /* Stop monitoring for this child */
    talloc_free(child_ctx);
}

static errno_t prepare_child_argv(TALLOC_CTX *mem_ctx,
                                  int child_debug_fd,
                                  const char *binary,
                                  char ***_argv)
{
    uint_t argc = 3; /* program name, debug_level and NULL */
    char ** argv;
    errno_t ret = EINVAL;

    /* Save the current state in case an interrupt changes it */
    bool child_debug_to_file = debug_to_file;
    bool child_debug_timestamps = debug_timestamps;

    if (child_debug_to_file) argc++;
    if (!child_debug_timestamps) argc++;

    /* program name, debug_level,
     * debug_to_file, debug_timestamps
     * and NULL */
    argv  = talloc_array(mem_ctx, char *, argc);
    if (argv == NULL) {
        DEBUG(1, ("talloc_array failed.\n"));
        return ENOMEM;
    }

    argv[--argc] = NULL;

    argv[--argc] = talloc_asprintf(argv, "--debug-level=%d",
                              debug_level);
    if (argv[argc] == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    if (child_debug_to_file) {
        argv[--argc] = talloc_asprintf(argv, "--debug-fd=%d",
                                       child_debug_fd);
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (!child_debug_timestamps) {
        argv[--argc] = talloc_strdup(argv, "--debug-timestamps=0");
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    argv[--argc] = talloc_strdup(argv, binary);
    if (argv[argc] == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    if (argc != 0) {
        ret = EINVAL;
        goto fail;
    }

    *_argv = argv;

    return EOK;

fail:
    talloc_free(argv);
    return ret;
}

errno_t exec_child(TALLOC_CTX *mem_ctx,
                   int *pipefd_to_child, int *pipefd_from_child,
                   const char *binary, int debug_fd)
{
    int ret;
    errno_t err;
    char **argv;

    close(pipefd_to_child[1]);
    ret = dup2(pipefd_to_child[0], STDIN_FILENO);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("dup2 failed [%d][%s].\n", err, strerror(err)));
        return err;
    }

    close(pipefd_from_child[0]);
    ret = dup2(pipefd_from_child[1], STDOUT_FILENO);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("dup2 failed [%d][%s].\n", err, strerror(err)));
        return err;
    }

    ret = prepare_child_argv(mem_ctx, debug_fd,
                             binary, &argv);
    if (ret != EOK) {
        DEBUG(1, ("prepare_child_argv.\n"));
        return ret;
    }

    ret = execv(binary, argv);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("execv failed [%d][%s].\n", err, strerror(err)));
        return err;
    }

    return EOK;
}

void child_cleanup(int readfd, int writefd)
{
    int ret;

    if (readfd != -1) {
        ret = close(readfd);
        if (ret != EOK) {
            ret = errno;
            DEBUG(1, ("close failed [%d][%s].\n", errno, strerror(errno)));
        }
    }
    if (writefd != -1) {
        ret = close(writefd);
        if (ret != EOK) {
            ret = errno;
            DEBUG(1, ("close failed [%d][%s].\n", errno, strerror(errno)));
        }
    }
}
