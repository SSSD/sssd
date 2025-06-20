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

#include "util/child_common.h"
#include "providers/idp/idp_common.h"

#define OIDC_CHILD SSSD_LIBEXEC_PATH"/oidc_child"
#define OIDC_CHILD_LOG_FILE "oidc_child"

struct handle_oidc_child_state {
    struct tevent_context *ev;
    struct idp_req *idp_req;
    uint8_t *buf;
    ssize_t len;

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

    /* No I/O expected anymore, make sure sockets are closed properly */
    state->io->in_use = false;

    DEBUG(SSSDBG_IMPORTANT_INFO,
          "Timeout for child [%d] reached. In case IdP is distant or network "
          "is slow you may consider increasing value of idp_request_timeout.\n",
          state->child_pid);

    tevent_req_error(req, ETIMEDOUT);
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
    ret = sss_child_start(state, ev,
                          OIDC_CHILD, idp_req->oidc_child_extra_args, false,
                          OIDC_CHILD_LOG_FILE, STDOUT_FILENO,
                          sss_child_handle_exited, NULL,
                          dp_opt_get_int(idp_req->idp_options, IDP_REQ_TIMEOUT),
                          oidc_child_timeout, req, true,
                          &(state->io));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_child_start() failed.\n");
        goto fail;
    }

    /* Steal the io pair so it can outlive this request if needed. */
    talloc_steal(idp_req->idp_options, state->io);
    state->child_pid = state->io->pid;
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

    FD_CLOSE(state->io->write_to_child_fd);

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

    talloc_zfree(state->io->timeout_handler);

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
