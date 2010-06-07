/*
    SSSD

    LDAP Backend Module -- child helpers

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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
#include <sys/wait.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>

#include "util/util.h"
#include "providers/ldap/ldap_common.h"
#include "providers/child_common.h"

#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#else
#define LDAP_CHILD SSSD_LIBEXEC_PATH"/ldap_child"
#endif

#ifndef LDAP_CHILD_USER
#define LDAP_CHILD_USER  "nobody"
#endif

struct sdap_child {
    /* child info */
    pid_t pid;
    int read_from_child_fd;
    int write_to_child_fd;
};

static void sdap_close_fd(int *fd)
{
    int ret;

    if (*fd == -1) {
        DEBUG(6, ("fd already closed\n"));
        return;
    }

    ret = close(*fd);
    if (ret) {
        ret = errno;
        DEBUG(2, ("Closing fd %d, return error %d (%s)\n",
                  *fd, ret, strerror(ret)));
    }

    *fd = -1;
}

static int sdap_child_destructor(void *ptr)
{
    struct sdap_child *child = talloc_get_type(ptr, struct sdap_child);

    child_cleanup(child->read_from_child_fd, child->write_to_child_fd);

    return 0;
}

static errno_t sdap_fork_child(struct tevent_context *ev,
                               struct sdap_child *child)
{
    int pipefd_to_child[2];
    int pipefd_from_child[2];
    pid_t pid;
    int ret;
    errno_t err;

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("pipe failed [%d][%s].\n", err, strerror(err)));
        return err;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("pipe failed [%d][%s].\n", err, strerror(err)));
        return err;
    }

    pid = fork();

    if (pid == 0) { /* child */
        err = exec_child(child,
                         pipefd_to_child, pipefd_from_child,
                         LDAP_CHILD, ldap_child_debug_fd);
        if (err != EOK) {
            DEBUG(1, ("Could not exec LDAP child: [%d][%s].\n",
                      err, strerror(err)));
            return err;
        }
    } else if (pid > 0) { /* parent */
        child->pid = pid;
        child->read_from_child_fd = pipefd_from_child[0];
        close(pipefd_from_child[1]);
        child->write_to_child_fd = pipefd_to_child[1];
        close(pipefd_to_child[0]);
        fd_nonblocking(child->read_from_child_fd);
        fd_nonblocking(child->write_to_child_fd);

        ret = child_handler_setup(ev, pid, NULL, NULL);
        if (ret != EOK) {
            return ret;
        }

    } else { /* error */
        err = errno;
        DEBUG(1, ("fork failed [%d][%s].\n", err, strerror(err)));
        return err;
    }

    return EOK;
}

static errno_t create_tgt_req_send_buffer(TALLOC_CTX *mem_ctx,
                                          const char *realm_str,
                                          const char *princ_str,
                                          const char *keytab_name,
                                          int32_t lifetime,
                                          struct io_buffer **io_buf)
{
    struct io_buffer *buf;
    size_t rp;

    buf = talloc(mem_ctx, struct io_buffer);
    if (buf == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }

    buf->size = 4 * sizeof(uint32_t);
    if (realm_str) {
        buf->size += strlen(realm_str);
    }
    if (princ_str) {
        buf->size += strlen(princ_str);
    }
    if (keytab_name) {
        buf->size += strlen(keytab_name);
    }

    DEBUG(7, ("buffer size: %d\n", buf->size));

    buf->data = talloc_size(buf, buf->size);
    if (buf->data == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        talloc_free(buf);
        return ENOMEM;
    }

    rp = 0;

    /* realm */
    if (realm_str) {
        SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(realm_str), &rp);
        safealign_memcpy(&buf->data[rp], realm_str, strlen(realm_str), &rp);
    } else {
        SAFEALIGN_SET_UINT32(&buf->data[rp], 0, &rp);
    }

    /* principal */
    if (princ_str) {
        SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(princ_str), &rp);
        safealign_memcpy(&buf->data[rp], princ_str, strlen(princ_str), &rp);
    } else {
        SAFEALIGN_SET_UINT32(&buf->data[rp], 0, &rp);
    }

    /* keytab */
    if (keytab_name) {
        SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(keytab_name), &rp);
        safealign_memcpy(&buf->data[rp], keytab_name, strlen(keytab_name), &rp);
    } else {
        SAFEALIGN_SET_UINT32(&buf->data[rp], 0, &rp);
    }

    /* lifetime */
    SAFEALIGN_SET_UINT32(&buf->data[rp], lifetime, &rp);

    *io_buf = buf;
    return EOK;
}

static int parse_child_response(TALLOC_CTX *mem_ctx,
                                uint8_t *buf, ssize_t size,
                                int  *result, char **ccache)
{
    size_t p = 0;
    uint32_t len;
    uint32_t res;
    char *ccn;

    /* operation result code */
    SAFEALIGN_COPY_UINT32_CHECK(&res, buf + p, size, &p);

    /* ccache name size */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    if ((p + len ) > size) return EINVAL;

    ccn = talloc_size(mem_ctx, sizeof(char) * (len + 1));
    if (ccn == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        return ENOMEM;
    }
    memcpy(ccn, buf+p, sizeof(char) * (len + 1));
    ccn[len] = '\0';

    *result = res;
    *ccache = ccn;
    return EOK;
}

/* ==The-public-async-interface============================================*/

struct sdap_get_tgt_state {
    struct tevent_context *ev;
    struct sdap_child *child;
    ssize_t len;
    uint8_t *buf;
};

static errno_t set_tgt_child_timeout(struct tevent_req *req,
                                     struct tevent_context *ev,
                                     int timeout);
static void sdap_get_tgt_step(struct tevent_req *subreq);
static void sdap_get_tgt_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_tgt_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     const char *realm_str,
                                     const char *princ_str,
                                     const char *keytab_name,
                                     int32_t lifetime,
                                     int timeout)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_tgt_state *state;
    struct io_buffer *buf;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_get_tgt_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;

    state->child = talloc_zero(state, struct sdap_child);
    if (!state->child) {
        ret = ENOMEM;
        goto fail;
    }

    state->child->read_from_child_fd = -1;
    state->child->write_to_child_fd = -1;
    talloc_set_destructor((TALLOC_CTX *)state->child, sdap_child_destructor);

    /* prepare the data to pass to child */
    ret = create_tgt_req_send_buffer(state,
                                     realm_str, princ_str, keytab_name, lifetime,
                                     &buf);
    if (ret != EOK) {
        DEBUG(1, ("create_tgt_req_send_buffer failed.\n"));
        goto fail;
    }

    ret = sdap_fork_child(state->ev, state->child);
    if (ret != EOK) {
        DEBUG(1, ("sdap_fork_child failed.\n"));
        goto fail;
    }

    ret = set_tgt_child_timeout(req, ev, timeout);
    if (ret != EOK) {
        DEBUG(1, ("activate_child_timeout_handler failed.\n"));
        goto fail;
    }

    subreq = write_pipe_send(state, ev, buf->data, buf->size,
                             state->child->write_to_child_fd);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_get_tgt_step, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_get_tgt_step(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_tgt_state *state = tevent_req_data(req,
                                                  struct sdap_get_tgt_state);
    int ret;

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    sdap_close_fd(&state->child->write_to_child_fd);

    subreq = read_pipe_send(state, state->ev,
                            state->child->read_from_child_fd);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_tgt_done, req);
}

static void sdap_get_tgt_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_tgt_state *state = tevent_req_data(req,
                                                  struct sdap_get_tgt_state);
    int ret;

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    sdap_close_fd(&state->child->read_from_child_fd);

    tevent_req_done(req);
}

int sdap_get_tgt_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           int  *result,
                           char **ccname)
{
    struct sdap_get_tgt_state *state = tevent_req_data(req,
                                             struct sdap_get_tgt_state);
    char *ccn;
    int  res;
    int ret;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ret = parse_child_response(mem_ctx, state->buf, state->len, &res, &ccn);
    if (ret != EOK) {
        DEBUG(1, ("Cannot parse child response: [%d][%s]\n", ret, strerror(ret)));
        return ret;
    }

    DEBUG(6, ("Child responded: %d [%s]\n", res, ccn));
    *result = res;
    *ccname = ccn;
    return EOK;
}



static void get_tgt_timeout_handler(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_tgt_state *state = tevent_req_data(req,
                                            struct sdap_get_tgt_state);
    int ret;

    DEBUG(9, ("timeout for tgt child [%d] reached.\n", state->child->pid));

    ret = kill(state->child->pid, SIGKILL);
    if (ret == -1) {
        DEBUG(1, ("kill failed [%d][%s].\n", errno, strerror(errno)));
    }

    tevent_req_error(req, ETIMEDOUT);
}

static errno_t set_tgt_child_timeout(struct tevent_req *req,
                                     struct tevent_context *ev,
                                     int timeout)
{
    struct tevent_timer *te;
    struct timeval tv;

    DEBUG(6, ("Setting %d seconds timeout for tgt child\n", timeout));

    tv = tevent_timeval_current_ofs(timeout, 0);

    te = tevent_add_timer(ev, req, tv, get_tgt_timeout_handler, req);
    if (te == NULL) {
        DEBUG(1, ("tevent_add_timer failed.\n"));
        return ENOMEM;
    }

    return EOK;
}



/* Setup child logging */
int setup_child(struct sdap_id_ctx *ctx)
{
    int ret;
    const char *mech;
    unsigned v;
    FILE *debug_filep;

    mech = dp_opt_get_string(ctx->opts->basic,
                             SDAP_SASL_MECH);
    if (!mech) {
        return EOK;
    }

    if (debug_to_file != 0 && ldap_child_debug_fd == -1) {
        ret = open_debug_file_ex("ldap_child", &debug_filep);
        if (ret != EOK) {
            DEBUG(0, ("Error setting up logging (%d) [%s]\n",
                        ret, strerror(ret)));
            return ret;
        }

        ldap_child_debug_fd = fileno(debug_filep);
        if (ldap_child_debug_fd == -1) {
            DEBUG(0, ("fileno failed [%d][%s]\n", errno, strerror(errno)));
            ret = errno;
            return ret;
        }

        v = fcntl(ldap_child_debug_fd, F_GETFD, 0);
        fcntl(ldap_child_debug_fd, F_SETFD, v & ~FD_CLOEXEC);
    }

    return EOK;
}
