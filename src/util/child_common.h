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

#ifndef __CHILD_COMMON_H__
#define __CHILD_COMMON_H__

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <tevent.h>

#include "util/util.h"

#define IN_BUF_SIZE         2048
#define CHILD_MSG_CHUNK     1024

#define SIGTERM_TO_SIGKILL_TIME 2

struct response {
    uint8_t *buf;
    size_t size;
};

struct io_buffer {
    uint8_t *data;
    size_t size;
};

struct child_io_fds {
    int read_from_child_fd;
    int write_to_child_fd;
    pid_t pid;
    bool child_exited;
    bool in_use;
};

/* COMMON SIGCHLD HANDLING */
typedef void (*sss_child_fn_t)(int pid, int wait_status, void *pvt);

struct sss_sigchild_ctx;
struct sss_child_ctx;

/* Create a new child context to manage callbacks */
errno_t sss_sigchld_init(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sss_sigchild_ctx **child_ctx);

errno_t sss_child_register(TALLOC_CTX *mem_ctx,
                           struct sss_sigchild_ctx *sigchld_ctx,
                           pid_t pid,
                           sss_child_fn_t cb,
                           void *pvt,
                           struct sss_child_ctx **child_ctx);

/* Callback to be invoked when a sigchld handler is called.
 * The tevent_signal * associated with the handler will be
 * freed automatically when this function returns.
 */
typedef void (*sss_child_callback_t)(int child_status,
                                     struct tevent_signal *sige,
                                     void *pvt);

struct sss_child_ctx_old;

/* Set up child termination signal handler */
int child_handler_setup(struct tevent_context *ev, int pid,
                        sss_child_callback_t cb, void *pvt,
                        struct sss_child_ctx_old **_child_ctx);

/* Destroy child termination signal handler */
void child_handler_destroy(struct sss_child_ctx_old *ctx);

/* Async communication with the child process via a pipe */
struct tevent_req *write_pipe_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   uint8_t *buf,
                                   size_t len,
                                   int fd);
int write_pipe_recv(struct tevent_req *req);

struct tevent_req *read_pipe_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  int fd);
errno_t read_pipe_recv(struct tevent_req *req,
                       TALLOC_CTX *mem_ctx,
                       uint8_t **_buf,
                       ssize_t *_len);

/* Include buffer length in a message header, read does not wait for EOF. */
struct tevent_req *write_pipe_safe_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        uint8_t *buf,
                                        size_t len,
                                        int fd);
int write_pipe_safe_recv(struct tevent_req *req);

struct tevent_req *read_pipe_safe_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       int fd);
errno_t read_pipe_safe_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            uint8_t **_buf,
                            ssize_t *_len);

/* The pipes to communicate with the child must be nonblocking */
void fd_nonblocking(int fd);

/* Never returns EOK, ether returns an error, or doesn't return on success */
void exec_child_ex(TALLOC_CTX *mem_ctx,
                   int *pipefd_to_child, int *pipefd_from_child,
                   const char *binary, const char *logfile,
                   const char *extra_argv[], bool extra_args_only,
                   int child_in_fd, int child_out_fd);

/* Same as exec_child_ex() except child_in_fd is set to STDIN_FILENO and
 * child_out_fd is set to STDOUT_FILENO and extra_argv is always NULL.
 */
void exec_child(TALLOC_CTX *mem_ctx,
                int *pipefd_to_child, int *pipefd_from_child,
                const char *binary, const char *logfile);

int child_io_destructor(void *ptr);

#endif /* __CHILD_COMMON_H__ */
