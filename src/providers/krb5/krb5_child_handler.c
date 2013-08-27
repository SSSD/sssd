/*
    SSSD

    Kerberos 5 Backend Module - Manage krb5_child

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "util/util.h"
#include "providers/child_common.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_auth.h"
#include "src/providers/krb5/krb5_utils.h"

#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#else
#define KRB5_CHILD SSSD_LIBEXEC_PATH"/krb5_child"
#endif

struct io {
    int read_from_child_fd;
    int write_to_child_fd;
};

struct handle_child_state {
    struct tevent_context *ev;
    struct krb5child_req *kr;
    uint8_t *buf;
    ssize_t len;

    struct tevent_timer *timeout_handler;
    pid_t child_pid;

    struct io *io;
};

static int child_io_destructor(void *ptr)
{
    int ret;
    struct io *io = talloc_get_type(ptr, struct io);
    if (io == NULL) return EOK;

    if (io->write_to_child_fd != -1) {
        ret = close(io->write_to_child_fd);
        io->write_to_child_fd = -1;
        if (ret != EOK) {
            ret = errno;
            DEBUG(1, ("close failed [%d][%s].\n", ret, strerror(ret)));
        }
    }

    if (io->read_from_child_fd != -1) {
        ret = close(io->read_from_child_fd);
        io->read_from_child_fd = -1;
        if (ret != EOK) {
            ret = errno;
            DEBUG(1, ("close failed [%d][%s].\n", ret, strerror(ret)));
        }
    }

    return EOK;
}

static errno_t create_send_buffer(struct krb5child_req *kr,
                                  struct io_buffer **io_buf)
{
    struct io_buffer *buf;
    size_t rp;
    const char *keytab;
    uint32_t validate;
    size_t username_len;

    keytab = dp_opt_get_cstring(kr->krb5_ctx->opts, KRB5_KEYTAB);
    if (keytab == NULL) {
        DEBUG(1, ("Missing keytab option.\n"));
        return EINVAL;
    }

    validate = dp_opt_get_bool(kr->krb5_ctx->opts, KRB5_VALIDATE) ? 1 : 0;

    buf = talloc(kr, struct io_buffer);
    if (buf == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }

    buf->size = 6*sizeof(uint32_t) + strlen(kr->upn);

    if (kr->pd->cmd == SSS_PAM_AUTHENTICATE ||
        kr->pd->cmd == SSS_CMD_RENEW ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        buf->size += 4*sizeof(uint32_t) + strlen(kr->ccname) + strlen(keytab) +
                     kr->pd->authtok_size;
    }

    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        buf->size += 2*sizeof(uint32_t) + kr->pd->newauthtok_size;
    }

    if (kr->pd->cmd == SSS_PAM_ACCT_MGMT) {
        username_len = strlen(kr->pd->user);
        buf->size += sizeof(uint32_t) + username_len;
    }

    buf->data = talloc_size(kr, buf->size);
    if (buf->data == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        talloc_free(buf);
        return ENOMEM;
    }

    rp = 0;
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->pd->cmd, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->uid, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->gid, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &validate, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->is_offline, &rp);

    SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(kr->upn), &rp);
    safealign_memcpy(&buf->data[rp], kr->upn, strlen(kr->upn), &rp);

    if (kr->pd->cmd == SSS_PAM_AUTHENTICATE ||
        kr->pd->cmd == SSS_CMD_RENEW ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(kr->ccname), &rp);
        safealign_memcpy(&buf->data[rp], kr->ccname, strlen(kr->ccname), &rp);

        SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(keytab), &rp);
        safealign_memcpy(&buf->data[rp], keytab, strlen(keytab), &rp);

        SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->pd->authtok_type, &rp);
        SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->pd->authtok_size, &rp);
        safealign_memcpy(&buf->data[rp], kr->pd->authtok,
                         kr->pd->authtok_size, &rp);
    }

    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->pd->newauthtok_type, &rp);
        SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->pd->newauthtok_size, &rp);
        safealign_memcpy(&buf->data[rp], kr->pd->newauthtok,
                         kr->pd->newauthtok_size, &rp);
    }

    if (kr->pd->cmd == SSS_PAM_ACCT_MGMT) {
        SAFEALIGN_SET_UINT32(&buf->data[rp], username_len, &rp);
        safealign_memcpy(&buf->data[rp], kr->pd->user, username_len, &rp);
    }

    *io_buf = buf;

    return EOK;
}


static void krb5_child_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct handle_child_state *state = tevent_req_data(req,
                                                     struct handle_child_state);
    int ret;

    if (state->timeout_handler == NULL) {
        return;
    }

    DEBUG(9, ("timeout for child [%d] reached.\n", state->child_pid));

    ret = kill(state->child_pid, SIGKILL);
    if (ret == -1) {
        DEBUG(1, ("kill failed [%d][%s].\n", errno, strerror(errno)));
    }

    tevent_req_error(req, ETIMEDOUT);
}

static errno_t activate_child_timeout_handler(struct tevent_req *req,
                                              struct tevent_context *ev,
                                              const uint32_t timeout_seconds)
{
    struct timeval tv;
    struct handle_child_state *state = tevent_req_data(req,
                                                     struct handle_child_state);

    tv = tevent_timeval_current();
    tv = tevent_timeval_add(&tv, timeout_seconds, 0);
    state->timeout_handler = tevent_add_timer(ev, state, tv,
                                           krb5_child_timeout, req);
    if (state->timeout_handler == NULL) {
        DEBUG(1, ("tevent_add_timer failed.\n"));
        return ENOMEM;
    }

    return EOK;
}

static errno_t fork_child(struct tevent_req *req)
{
    int pipefd_to_child[2];
    int pipefd_from_child[2];
    pid_t pid;
    int ret;
    errno_t err;
    struct handle_child_state *state = tevent_req_data(req,
                                                     struct handle_child_state);

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("pipe failed [%d][%s].\n", errno, strerror(errno)));
        return err;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("pipe failed [%d][%s].\n", errno, strerror(errno)));
        return err;
    }

    pid = fork();

    if (pid == 0) { /* child */
        if (state->kr->run_as_user) {
            ret = become_user(state->kr->uid, state->kr->gid);
            if (ret != EOK) {
                DEBUG(1, ("become_user failed.\n"));
                return ret;
            }
        }

        err = exec_child(state,
                         pipefd_to_child, pipefd_from_child,
                         KRB5_CHILD, state->kr->krb5_ctx->child_debug_fd);
        if (err != EOK) {
            DEBUG(1, ("Could not exec KRB5 child: [%d][%s].\n",
                      err, strerror(err)));
            return err;
        }
    } else if (pid > 0) { /* parent */
        state->child_pid = pid;
        state->io->read_from_child_fd = pipefd_from_child[0];
        close(pipefd_from_child[1]);
        state->io->write_to_child_fd = pipefd_to_child[1];
        close(pipefd_to_child[0]);
        fd_nonblocking(state->io->read_from_child_fd);
        fd_nonblocking(state->io->write_to_child_fd);

        ret = child_handler_setup(state->ev, pid, NULL, NULL, NULL);
        if (ret != EOK) {
            DEBUG(1, ("Could not set up child signal handler\n"));
            return ret;
        }

        err = activate_child_timeout_handler(req, state->ev,
                  dp_opt_get_int(state->kr->krb5_ctx->opts, KRB5_AUTH_TIMEOUT));
        if (err != EOK) {
            DEBUG(1, ("activate_child_timeout_handler failed.\n"));
        }

    } else { /* error */
        err = errno;
        DEBUG(1, ("fork failed [%d][%s].\n", errno, strerror(errno)));
        return err;
    }

    return EOK;
}

static void handle_child_step(struct tevent_req *subreq);
static void handle_child_done(struct tevent_req *subreq);

struct tevent_req *handle_child_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct krb5child_req *kr)
{
    struct tevent_req *req, *subreq;
    struct handle_child_state *state;
    int ret;
    struct io_buffer *buf;

    req = tevent_req_create(mem_ctx, &state, struct handle_child_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->kr = kr;
    state->buf = NULL;
    state->len = 0;
    state->child_pid = -1;
    state->timeout_handler = NULL;

    state->io = talloc(state, struct io);
    if (state->io == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    state->io->write_to_child_fd = -1;
    state->io->read_from_child_fd = -1;
    talloc_set_destructor((void *) state->io, child_io_destructor);

    ret = create_send_buffer(kr, &buf);
    if (ret != EOK) {
        DEBUG(1, ("create_send_buffer failed.\n"));
        goto fail;
    }

    ret = fork_child(req);
    if (ret != EOK) {
        DEBUG(1, ("fork_child failed.\n"));
        goto fail;
    }

    subreq = write_pipe_send(state, ev, buf->data, buf->size,
                             state->io->write_to_child_fd);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, handle_child_step, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void handle_child_step(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct handle_child_state *state = tevent_req_data(req,
                                                    struct handle_child_state);
    int ret;

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    close(state->io->write_to_child_fd);
    state->io->write_to_child_fd = -1;

    subreq = read_pipe_send(state, state->ev, state->io->read_from_child_fd);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, handle_child_done, req);
}

static void handle_child_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct handle_child_state *state = tevent_req_data(req,
                                                    struct handle_child_state);
    int ret;

    talloc_zfree(state->timeout_handler);

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    close(state->io->read_from_child_fd);
    state->io->read_from_child_fd = -1;

    tevent_req_done(req);
    return;
}

int handle_child_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                      uint8_t **buf, ssize_t *len)
{
    struct handle_child_state *state = tevent_req_data(req,
                                                    struct handle_child_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *buf = talloc_move(mem_ctx, &state->buf);
    *len = state->len;

    return EOK;
}
