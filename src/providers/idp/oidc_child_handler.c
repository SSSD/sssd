/*
    SSSD

    IdP Backend Module - Manage oidc_child

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

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

#include "providers/idp/idp_common.h"

#define OIDC_CHILD SSSD_LIBEXEC_PATH"/oidc_child"
#define OIDC_CHILD_LOG_FILE "oidc_child"

struct handle_oidc_child_state {
    struct tevent_context *ev;
    struct idp_req *idp_req;
    uint8_t *buf;
    ssize_t len;

    struct tevent_timer *timeout_handler;
    pid_t child_pid;

    struct child_io_fds *io;
};

/* TODO: krb5_child_handler.c is using similar */
static void oidc_child_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct handle_oidc_child_state *state = tevent_req_data(req,
                                                     struct handle_oidc_child_state);

    if (state->timeout_handler == NULL) {
        return;
    }

    /* No I/O expected anymore, make sure sockets are closed properly */
    state->io->in_use = false;

    DEBUG(SSSDBG_IMPORTANT_INFO,
          "Timeout for child [%d] reached. In case IdP is distant or network "
          "is slow you may consider increasing value of idp_request_timeout.\n",
          state->child_pid);

    child_terminate(state->child_pid);

    tevent_req_error(req, ETIMEDOUT);
}

static errno_t fork_child(struct tevent_context *ev,
                          struct idp_req *idp_req,
                          pid_t *_child_pid,
                          struct child_io_fds **_io)
{
    TALLOC_CTX *tmp_ctx;
    int pipefd_to_child[2] = PIPE_INIT;
    int pipefd_from_child[2] = PIPE_INIT;
    struct child_io_fds *io;
    pid_t pid = 0;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe (from) failed [%d][%s].\n", errno, strerror(errno));
        goto done;
    }

    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe (to) failed [%d][%s].\n", errno, strerror(errno));
        goto done;
    }

    pid = fork();

    if (pid == 0) { /* child */
        exec_child_ex(tmp_ctx,
                      pipefd_to_child, pipefd_from_child,
                      OIDC_CHILD, OIDC_CHILD_LOG_FILE,
                      idp_req->oidc_child_extra_args, false,
                      STDIN_FILENO, STDOUT_FILENO);

        /* We should never get here */
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Could not exec OIDC child\n");
        ret = ERR_INTERNAL;
        goto done;
    } else if (pid < 0) { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "fork failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    /* parent */

    io = talloc_zero(tmp_ctx, struct child_io_fds);
    if (io == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto done;
    }
    talloc_set_destructor((void*)io, child_io_destructor);

    io->pid = pid;

    /* Set file descriptors. */
    io->read_from_child_fd = pipefd_from_child[0];
    io->write_to_child_fd = pipefd_to_child[1];
    PIPE_FD_CLOSE(pipefd_from_child[1]);
    PIPE_FD_CLOSE(pipefd_to_child[0]);
    sss_fd_nonblocking(io->read_from_child_fd);
    sss_fd_nonblocking(io->write_to_child_fd);

    /* Setup the child handler. It will free io and remove it from the hash
     * table when it exits. */
    ret = child_handler_setup(ev, pid, child_exited, io, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up child signal handler "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Steal the io pair so it can outlive this request if needed. */
    talloc_steal(idp_req->idp_options, io);

    *_child_pid = pid;
    *_io = io;

    ret = EOK;

done:
    if (ret != EOK) {
        PIPE_CLOSE(pipefd_from_child);
        PIPE_CLOSE(pipefd_to_child);
        child_terminate(pid);
    }

    talloc_free(tmp_ctx);
    return ret;
}

static errno_t create_send_buffer(struct idp_req *idp_req,
                                  struct io_buffer **io_buf)
{
    struct io_buffer *buf = NULL;
    const char *client_secret;
    int ret;

    buf = talloc_zero(idp_req, struct io_buffer);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    client_secret = dp_opt_get_cstring(idp_req->idp_options,
                                       IDP_CLIENT_SECRET);
    if (client_secret == NULL || *client_secret == '\0') {
        ret = EOK;
        goto done;
    }

    buf->size = strlen(client_secret);
    buf->data = talloc_size(buf, buf->size);
    if (buf->data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        talloc_free(buf);
        return ENOMEM;
    }

    safealign_memcpy(buf->data, client_secret, strlen(client_secret), NULL);

    ret = EOK;

done:
    if (ret == EOK) {
        *io_buf = buf;
    }

    return ret;
}

static void handle_oidc_child_send_done(struct tevent_req *subreq);
static void handle_oidc_child_done(struct tevent_req *subreq);

struct tevent_req *handle_oidc_child_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct idp_req *idp_req,
                                         struct io_buffer *send_buffer)
{
    struct tevent_req *req, *subreq;
    struct handle_oidc_child_state *state;
    int ret;
    struct io_buffer *buf = NULL;

    req = tevent_req_create(mem_ctx, &state, struct handle_oidc_child_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->idp_req = idp_req;
    state->buf = NULL;
    state->len = 0;
    state->child_pid = -1;
    state->timeout_handler = NULL;

    if (send_buffer == NULL) {
        ret = create_send_buffer(idp_req, &buf);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "create_send_buffer failed.\n");
            goto fail;
        }
    } else {
        buf = send_buffer;
    }

    /* Create new child. */
    ret = fork_child(ev, idp_req, &state->child_pid, &state->io);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "fork_child failed.\n");
        goto fail;
    }

    /* Setup timeout. If failed, terminate the child process. */
    state->timeout_handler =  activate_child_timeout_handler(state, req, ev,
                                            oidc_child_timeout,
                                            dp_opt_get_int(idp_req->idp_options,
                                                           IDP_REQ_TIMEOUT));
    if (state->timeout_handler == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup child timeout "
              "[%d]: %s\n", ret, sss_strerror(ret));
        child_terminate(state->child_pid);
        goto fail;
    }

    state->io->in_use = true;
    subreq = write_pipe_send(state, ev, buf->data, buf->size,
                             state->io->write_to_child_fd);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, handle_oidc_child_send_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void handle_oidc_child_send_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct handle_oidc_child_state *state = tevent_req_data(req,
                                                struct handle_oidc_child_state);
    int ret;

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    PIPE_FD_CLOSE(state->io->write_to_child_fd);

    subreq = read_pipe_send(state, state->ev,
                            state->io->read_from_child_fd);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, handle_oidc_child_done, req);

done:
    if (ret != EOK) {
        state->io->in_use = false;
        if (state->io->child_exited) {
            talloc_free(state->io);
        }

        tevent_req_error(req, ret);
    }
}

static void handle_oidc_child_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct handle_oidc_child_state *state = tevent_req_data(req,
                                                struct handle_oidc_child_state);
    int ret;

    talloc_zfree(state->timeout_handler);

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    state->io->in_use = false;
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

done:
    state->io->in_use = false;
    if (state->io->child_exited) {
        talloc_free(state->io);
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int handle_oidc_child_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           uint8_t **buf, ssize_t *len)
{
    struct handle_oidc_child_state *state = tevent_req_data(req,
                                                struct handle_oidc_child_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *buf = talloc_move(mem_ctx, &state->buf);
    *len = state->len;

    return EOK;
}

errno_t set_oidc_common_args(const char **extra_args, size_t *c,
                             const char *idp_type,
                             const char *client_id,
                             const char *client_secret,
                             const char *token_endpoint,
                             const char *scope)
{
    int ret;

    if (idp_type != NULL) {
        extra_args[*c] = talloc_asprintf(extra_args,
                                         "--idp-type=%s", idp_type);
        if (extra_args[*c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
        (*c)++;
    }

    extra_args[*c] = talloc_asprintf(extra_args,
                                     "--client-id=%s", client_id);
    if (extra_args[*c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    (*c)++;

    if (client_secret != NULL) {
        extra_args[*c] = talloc_strdup(extra_args,
                                       "--client-secret-stdin");
        if (extra_args[*c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
        (*c)++;
    }

    extra_args[*c] = talloc_asprintf(extra_args,
                                     "--token-endpoint=%s", token_endpoint);
    if (extra_args[*c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    (*c)++;

    extra_args[*c] = talloc_asprintf(extra_args,
                                     "--scope=%s", scope);
    if (extra_args[*c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    (*c)++;

    ret = EOK;
done:

    return ret;
}
