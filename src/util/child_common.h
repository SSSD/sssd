/*
    SSSD

    Common helper functions to handle child processes

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
#include <stdbool.h>
#include <sys/types.h>
#include <tevent.h>

#include "shared/io.h"
#include "util/util.h"

/* **********   Child process handling helpers (child_common.c)   ********** */

struct child_io_fds {
    int read_from_child_fd;
    int write_to_child_fd;
    pid_t pid;
    struct tevent_timer *timeout_handler;

    /* Following two fields are kind of "user payload":
     * not handled by general child helpers internally;
     * currently used by krb5/oidc only as those have
     * specific requirements (single process for multiple
     * tevent reqs).
     */
    bool child_exited;
    bool in_use;
};

/* Callback to be invoked when a sigchld handler is called.
 * The tevent_signal * associated with the handler will be
 * freed automatically when this function returns.
 */
typedef void (*sss_child_sigchld_callback_t)(int child_status,
                                             struct tevent_signal *sige,
                                             void *pvt);

/* A note about callbacks.
 * Typically user wants only one of callbacks - either sigchld or timeout -
 * whatever happens first (or even none if req is done once response is read).
 *
 * It is expected that executing any of those callbacks will destroy 'mem_ctx'
 * (typically a request or its state) - this will cancel 'timeout_cb', whose
 * timer is attached to 'mem_ctx' (if it didn't fire yet).
 *
 * There is also a watch attached to SIGCHLD 'pvt' so callback won't be called
 * if 'pvt' was freed. But basic handling - waitpid() - is still performed
 * automatically.
 */
errno_t sss_child_start(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        const char *binary,
                        const char *extra_args[], bool extra_args_only,
                        const char *logfile,
                        int child_out_fd,  /* FD that binary uses to write response to */
                        sss_child_sigchld_callback_t cb,  /* SIGCHLD handler */
                        void *pvt,  /* SIGCHLD callback context, NULL means `*_io` */
                        unsigned timeout,  /* timeout to invoke timeout_cb, 0 means no timeout */
                        tevent_timer_handler_t timeout_cb,
                        void *timeout_pvt,  /* timeout callback context */
                        bool auto_terminate, /* send SIGKILL after execution of timeout_cb */
                        struct child_io_fds **_io /* can be NULL */);

/* Standard implementation of sss_child_sigchld_callback_t used by krb5/oidc */
void sss_child_handle_exited(int child_status, struct tevent_signal *sige, void *pvt);

/* Simple helper that sends SIGKILL if (pid != 0) */
void sss_child_terminate(pid_t pid);

/* **************************   IPC (child_io.c)   ************************* */

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
struct tevent_req *read_pipe_non_blocking_send(TALLOC_CTX *mem_ctx,
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

#endif /* __CHILD_COMMON_H__ */
