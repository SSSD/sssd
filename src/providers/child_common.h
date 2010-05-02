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

#define IN_BUF_SIZE         512
#define CHILD_MSG_CHUNK     256

struct response {
    uint8_t *buf;
    size_t size;
};

struct io_buffer {
    uint8_t *data;
    size_t size;
};

/* Callback to be invoked when a sigchld handler is called.
 * The tevent_signal * associated with the handler will be
 * freed automatically when this function returns.
 */
typedef void (*sss_child_callback_t)(int child_status,
                                     struct tevent_signal *sige,
                                     void *pvt);

/* Set up child termination signal handler */
int child_handler_setup(struct tevent_context *ev, int pid,
                        sss_child_callback_t cb, void *pvt);

/* Async communication with the child process via a pipe */
struct tevent_req *write_pipe_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   uint8_t *buf, size_t len, int fd);
int write_pipe_recv(struct tevent_req *req);

struct tevent_req *read_pipe_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev, int fd);
int read_pipe_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                   uint8_t **buf, ssize_t *len);

/* The pipes to communicate with the child must be nonblocking */
void fd_nonblocking(int fd);

void child_sig_handler(struct tevent_context *ev,
                       struct tevent_signal *sige, int signum,
                       int count, void *__siginfo, void *pvt);

errno_t exec_child(TALLOC_CTX *mem_ctx,
                   int *pipefd_to_child, int *pipefd_from_child,
                   const char *binary, int debug_fd);

void child_cleanup(int readfd, int writefd);

#endif /* __CHILD_COMMON_H__ */
