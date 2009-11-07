/*
    SSSD

    Kerberos 5 Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include <errno.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"

#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#else
#define KRB5_CHILD SSSD_LIBEXEC_PATH"/krb5_child"
#endif

static errno_t become_user(uid_t uid, gid_t gid)
{
    int ret;
    ret = setgid(gid);
    if (ret == -1) {
        DEBUG(1, ("setgid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = setuid(uid);
    if (ret == -1) {
        DEBUG(1, ("setuid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = setegid(gid);
    if (ret == -1) {
        DEBUG(1, ("setegid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = seteuid(uid);
    if (ret == -1) {
        DEBUG(1, ("seteuid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    return EOK;
}

struct io_buffer {
    uint8_t *data;
    size_t size;
};

errno_t create_send_buffer(struct krb5child_req *kr, struct io_buffer **io_buf)
{
    struct io_buffer *buf;
    size_t rp;

    buf = talloc(kr, struct io_buffer);
    if (buf == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }

    buf->size = 4*sizeof(int) + strlen(kr->pd->upn) + strlen(kr->ccname) +
                kr->pd->authtok_size;
    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        buf->size += sizeof(int) + kr->pd->newauthtok_size;
    }

    buf->data = talloc_size(kr, buf->size);
    if (buf->data == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        talloc_free(buf);
        return ENOMEM;
    }

    rp = 0;
    ((uint32_t *)(&buf->data[rp]))[0] = kr->pd->cmd;
    rp += sizeof(uint32_t);

    ((uint32_t *)(&buf->data[rp]))[0] = (uint32_t) strlen(kr->pd->upn);
    rp += sizeof(uint32_t);

    memcpy(&buf->data[rp], kr->pd->upn, strlen(kr->pd->upn));
    rp += strlen(kr->pd->upn);

    ((uint32_t *)(&buf->data[rp]))[0] = (uint32_t) strlen(kr->ccname);
    rp += sizeof(uint32_t);

    memcpy(&buf->data[rp], kr->ccname, strlen(kr->ccname));
    rp += strlen(kr->ccname);

    ((uint32_t *)(&buf->data[rp]))[0] = kr->pd->authtok_size;
    rp += sizeof(uint32_t);

    memcpy(&buf->data[rp], kr->pd->authtok, kr->pd->authtok_size);
    rp += kr->pd->authtok_size;

    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        ((uint32_t *)(&buf->data[rp]))[0] = kr->pd->newauthtok_size;
        rp += sizeof(uint32_t);

        memcpy(&buf->data[rp], kr->pd->newauthtok, kr->pd->newauthtok_size);
        rp += kr->pd->newauthtok_size;
    }

    *io_buf = buf;

    return EOK;
}

static struct krb5_ctx *get_krb5_ctx(struct be_req *be_req)
{
    struct pam_data *pd;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            return talloc_get_type(be_req->be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                                       struct krb5_ctx);
            break;
        case SSS_PAM_CHAUTHTOK:
            return talloc_get_type(be_req->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                                       struct krb5_ctx);
            break;
        default:
            DEBUG(1, ("Unsupported PAM task.\n"));
            return NULL;
    }
}

static void fd_nonblocking(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        DEBUG(1, ("F_GETFL failed [%d][%s].\n", errno, strerror(errno)));
        return;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        DEBUG(1, ("F_SETFL failed [%d][%s].\n", errno, strerror(errno)));
    }

    return;
}

static void krb_reply(struct be_req *req, int dp_err, int result);

static void krb5_child_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv, void *pvt)
{
    struct krb5child_req *kr = talloc_get_type(pvt, struct krb5child_req);
    struct be_req *be_req = kr->req;
    struct pam_data *pd = kr->pd;
    int ret;

    if (kr->timeout_handler == NULL) {
        return;
    }

    DEBUG(9, ("timeout for child [%d] reached.\n", kr->child_pid));

    ret = kill(kr->child_pid, SIGKILL);
    if (ret == -1) {
        DEBUG(1, ("kill failed [%d][%s].\n", errno, strerror(errno)));
    }

    talloc_zfree(kr);

    pd->pam_status = PAM_AUTHINFO_UNAVAIL;
    be_mark_offline(be_req->be_ctx);

    krb_reply(be_req, DP_ERR_OFFLINE, pd->pam_status);
}

static errno_t activate_child_timeout_handler(struct krb5child_req *kr)
{
    struct timeval tv;

    tv = tevent_timeval_current();
    tv = tevent_timeval_add(&tv,
                            dp_opt_get_int(kr->krb5_ctx->opts,
                                           KRB5_AUTH_TIMEOUT),
                            0);
    kr->timeout_handler = tevent_add_timer(kr->req->be_ctx->ev, kr, tv,
                                           krb5_child_timeout, kr);
    if (kr->timeout_handler == NULL) {
        DEBUG(1, ("tevent_add_timer failed.\n"));
        return ENOMEM;
    }

    return EOK;
}

static int krb5_cleanup(void *ptr)
{
    int ret;
    struct krb5child_req *kr = talloc_get_type(ptr, struct krb5child_req);

    if (kr == NULL) return EOK;

    if (kr->read_from_child_fd != -1) {
        ret = close(kr->read_from_child_fd);
        if (ret != EOK) {
            DEBUG(1, ("close failed [%d][%s].\n", errno, strerror(errno)));
        }
    }
    if (kr->write_to_child_fd != -1) {
        ret = close(kr->write_to_child_fd);
        if (ret != EOK) {
            DEBUG(1, ("close failed [%d][%s].\n", errno, strerror(errno)));
        }
    }

    memset(kr, 0, sizeof(struct krb5child_req));

    return EOK;
}

static errno_t krb5_setup(struct be_req *req, struct krb5child_req **krb5_req,
                          const char *homedir)
{
    struct krb5child_req *kr = NULL;
    struct krb5_ctx *krb5_ctx;
    struct pam_data *pd;
    errno_t err;

    pd = talloc_get_type(req->req_data, struct pam_data);

    krb5_ctx = get_krb5_ctx(req);
    if (krb5_ctx == NULL) {
        DEBUG(1, ("Kerberos context not available.\n"));
        err = EINVAL;
        goto failed;
    }

    kr = talloc_zero(req, struct krb5child_req);
    if (kr == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        err = ENOMEM;
        goto failed;
    }
    kr->read_from_child_fd = -1;
    kr->write_to_child_fd = -1;
    talloc_set_destructor((TALLOC_CTX *) kr, krb5_cleanup);

    kr->pd = pd;
    kr->req = req;
    kr->krb5_ctx = krb5_ctx;
    kr->homedir = homedir;

    kr->ccname = expand_ccname_template(kr, kr,
                                        dp_opt_get_cstring(krb5_ctx->opts,
                                                           KRB5_CCNAME_TMPL)
                                        );
    if (kr->ccname == NULL) {
        DEBUG(1, ("expand_ccname_template failed.\n"));
        err = EINVAL;
        goto failed;
    }

    *krb5_req = kr;

    return EOK;

failed:
    talloc_zfree(kr);

    return err;
}

void krb5_child_sig_handler(struct tevent_context *ev,
                            struct tevent_signal *sige, int signum,
                            int count, void *__siginfo, void *pvt)
{
    int ret;
    int child_status;
    siginfo_t *siginfo = (siginfo_t *)__siginfo;

    errno = 0;
    do {
        ret = waitpid(siginfo->si_pid, &child_status, WNOHANG);
    } while (ret == -1 && errno == EINTR);
    if (ret == siginfo->si_pid) {
        DEBUG(4, ("child status [%d].\n", child_status));
        if (WEXITSTATUS(child_status) != 0) {
            DEBUG(1, ("child failed.\n"));
        }
    } else if (ret == 0) {
        DEBUG(1, ("waitpid did not found a child with changed status.\n", ret));
    } else if (ret >= 0 && ret != siginfo->si_pid) {
        DEBUG(1, ("waitpid returned wrong child pid [%d], continue waiting.\n", ret));
    } else if (ret == -1 && errno == ECHILD) {
        DEBUG(1, ("no child with pid [%d].\n", siginfo->si_pid));
    } else {
        DEBUG(1, ("waitpid failed [%s].\n", strerror(errno)));
    }

    return;
}

static errno_t prepare_child_argv(TALLOC_CTX *mem_ctx,
                                  struct krb5child_req *kr,
                                  char ***_argv)
{
    uint_t argc = 3; /* program name, debug_level and NULL */
    char ** argv;
    errno_t ret = EINVAL;

    /* Save the current state in case an interrupt changes it */
    bool child_debug_to_file = debug_to_file;
    bool child_debug_timestamps = debug_timestamps;

    if (child_debug_to_file) argc++;
    if (child_debug_timestamps) argc++;

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
                                  kr->krb5_ctx->child_debug_fd);
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    if (child_debug_timestamps) {
        argv[--argc] = talloc_strdup(argv, "--debug-timestamps");
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    argv[--argc] = talloc_strdup(argv, KRB5_CHILD);
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

static errno_t fork_child(struct krb5child_req *kr)
{
    int pipefd_to_child[2];
    int pipefd_from_child[2];
    pid_t pid;
    int ret;
    errno_t err;
    char **argv;

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
        //talloc_free(kr->req->be_ctx->ev);

        ret = chdir("/tmp");
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("chdir failed [%d][%s].\n", errno, strerror(errno)));
            return err;
        }

        ret = become_user(kr->pd->pw_uid, kr->pd->gr_gid);
        if (ret != EOK) {
            DEBUG(1, ("become_user failed.\n"));
            return ret;
        }


        close(pipefd_to_child[1]);
        ret = dup2(pipefd_to_child[0],STDIN_FILENO);
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("dup2 failed [%d][%s].\n", errno, strerror(errno)));
            return err;
        }

        close(pipefd_from_child[0]);
        ret = dup2(pipefd_from_child[1],STDOUT_FILENO);
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("dup2 failed [%d][%s].\n", errno, strerror(errno)));
            return err;
        }

        ret = prepare_child_argv(kr, kr, &argv);
        if (ret != EOK) {
            DEBUG(1, ("prepare_child_argv.\n"));
            return ret;
        }

        ret = execv(KRB5_CHILD, argv);
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("execv failed [%d][%s].\n", errno, strerror(errno)));
            return err;
        }
    } else if (pid > 0) { /* parent */
        kr->child_pid = pid;
        kr->read_from_child_fd = pipefd_from_child[0];
        close(pipefd_from_child[1]);
        kr->write_to_child_fd = pipefd_to_child[1];
        close(pipefd_to_child[0]);
        fd_nonblocking(kr->read_from_child_fd);
        fd_nonblocking(kr->write_to_child_fd);

        err = activate_child_timeout_handler(kr);
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


struct read_pipe_state {
    int fd;
    uint8_t *buf;
    size_t len;
};

static void read_pipe_done(struct tevent_context *ev,
                           struct tevent_fd *fde,
                           uint16_t flags, void *pvt);

static struct tevent_req *read_pipe_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev, int fd)
{
    struct tevent_req *req;
    struct read_pipe_state *state;
    struct tevent_fd *fde;


    req = tevent_req_create(memctx, &state, struct read_pipe_state);
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

static int read_pipe_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                          uint8_t **buf, ssize_t *len)
{
    struct read_pipe_state *state = tevent_req_data(req,
                                                    struct read_pipe_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *buf = talloc_move(mem_ctx, &state->buf);
    *len = state->len;

    return EOK;
}

struct handle_child_state {
    struct krb5child_req *kr;
    ssize_t len;
    uint8_t *buf;
};

static void handle_child_done(struct tevent_req *subreq);

static struct tevent_req *handle_child_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct krb5child_req *kr)
{
    int ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct handle_child_state *state;
    struct io_buffer *buf;

    ret = create_send_buffer(kr, &buf);
    if (ret != EOK) {
        DEBUG(1, ("create_send_buffer failed.\n"));
        return NULL;
    }

    ret = fork_child(kr);
    if (ret != EOK) {
        DEBUG(1, ("fork_child failed.\n"));
        return NULL;
    }

    ret = write(kr->write_to_child_fd, buf->data, buf->size);
    close(kr->write_to_child_fd);
    kr->write_to_child_fd = -1;
    if (ret == -1) {
        DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct handle_child_state);
    if (req == NULL) {
        return NULL;
    }

    state->kr = kr;

    subreq = read_pipe_send(state, ev, kr->read_from_child_fd);
    if (tevent_req_nomem(subreq, req)) {
        return tevent_req_post(req, ev);
    }
    tevent_req_set_callback(subreq, handle_child_done, req);
    return req;
}

static void handle_child_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct handle_child_state *state = tevent_req_data(req,
                                                    struct handle_child_state);
    int ret;

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    talloc_zfree(subreq);
    talloc_zfree(state->kr->timeout_handler);
    close(state->kr->read_from_child_fd);
    state->kr->read_from_child_fd = -1;
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static int handle_child_recv(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             uint8_t **buf, ssize_t *len)
{
    struct handle_child_state *state = tevent_req_data(req,
                                                    struct handle_child_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *buf = talloc_move(mem_ctx, &state->buf);
    *len = state->len;

    return EOK;
}

static void get_user_upn_done(void *pvt, int err, struct ldb_result *res);
static void krb5_pam_handler_done(struct tevent_req *req);
static void krb5_pam_handler_cache_done(struct tevent_req *treq);

void krb5_pam_handler(struct be_req *be_req)
{
    struct pam_data *pd;
    const char **attrs;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err = DP_ERR_FATAL;
    int ret;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    if (be_is_offline(be_req->be_ctx)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        pam_status = PAM_AUTHINFO_UNAVAIL;
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    if (pd->cmd != SSS_PAM_AUTHENTICATE && pd->cmd != SSS_PAM_CHAUTHTOK) {
        DEBUG(4, ("krb5 does not handles pam task %d.\n", pd->cmd));
        pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        goto done;
    }

    attrs = talloc_array(be_req, const char *, 3);
    if (attrs == NULL) {
        goto done;
    }

    attrs[0] = SYSDB_UPN;
    attrs[1] = SYSDB_HOMEDIR;
    attrs[2] = NULL;

    ret = sysdb_get_user_attr(be_req, be_req->be_ctx->sysdb,
                              be_req->be_ctx->domain, pd->user, attrs,
                              get_user_upn_done, be_req);

    if (ret) {
        goto done;
    }

    return;

done:
    pd->pam_status = pam_status;

    krb_reply(be_req, dp_err, pd->pam_status);
}

static void get_user_upn_done(void *pvt, int err, struct ldb_result *res)
{
    struct be_req *be_req = talloc_get_type(pvt, struct be_req);
    struct krb5_ctx *krb5_ctx;
    struct krb5child_req *kr = NULL;
    struct tevent_req *req;
    int ret;
    struct pam_data *pd;
    int pam_status=PAM_SYSTEM_ERR;
    const char *homedir = NULL;
    const char *dummy;

    pd = talloc_get_type(be_req->req_data, struct pam_data);
    krb5_ctx = get_krb5_ctx(be_req);
    if (krb5_ctx == NULL) {
        DEBUG(1, ("Kerberos context not available.\n"));
        err = EINVAL;
        goto failed;
    }


    if (err != LDB_SUCCESS) {
        DEBUG(5, ("sysdb search for upn of user [%s] failed.\n", pd->user));
        goto failed;
    }

    switch (res->count) {
    case 0:
        DEBUG(5, ("No upn for user [%s] found.\n", pd->user));
        break;

    case 1:
        pd->upn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_UPN, NULL);
        if (pd->upn == NULL) {
            /* NOTE: this is a hack, works only in some environments */
            dummy = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
            if (dummy != NULL) {
                pd->upn = talloc_asprintf(be_req, "%s@%s", pd->user, dummy);
                if (pd->upn == NULL) {
                    DEBUG(1, ("failed to build simple upn.\n"));
                }
                DEBUG(9, ("Using simple UPN [%s].\n", pd->upn));
            }
        }

        homedir = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_HOMEDIR,
                                              NULL);
        if (homedir == NULL) {
            DEBUG(4, ("Home directory for user [%s] not known.\n", pd->user));
        }
        break;

    default:
        DEBUG(1, ("A user search by name (%s) returned > 1 results!\n",
                  pd->user));
        break;
    }

    if (pd->upn == NULL) {
        DEBUG(1, ("Cannot set UPN.\n"));
        goto failed;
    }

    ret = krb5_setup(be_req, &kr, homedir);
    if (ret != EOK) {
        DEBUG(1, ("krb5_setup failed.\n"));
        goto failed;
    }

    req = handle_child_send(be_req, be_req->be_ctx->ev, kr);
    if (req == NULL) {
        DEBUG(1, ("handle_child_send failed.\n"));
        goto failed;
    }

    tevent_req_set_callback(req, krb5_pam_handler_done, kr);
    return;

failed:
    talloc_free(kr);

    pd->pam_status = pam_status;
    krb_reply(be_req, DP_ERR_FATAL, pd->pam_status);
}

static void krb5_pam_handler_done(struct tevent_req *req)
{
    struct krb5child_req *kr = tevent_req_callback_data(req,
                                                        struct krb5child_req);
    struct pam_data *pd = kr->pd;
    struct be_req *be_req = kr->req;
    struct krb5_ctx *krb5_ctx = kr->krb5_ctx;
    int ret;
    uint8_t *buf;
    ssize_t len;
    int p;
    int32_t *msg_status;
    int32_t *msg_type;
    int32_t *msg_len;
    struct tevent_req *subreq = NULL;
    char *password = NULL;
    char *env = NULL;
    int dp_err = DP_ERR_FATAL;
    const char *dummy;

    pd->pam_status = PAM_SYSTEM_ERR;
    talloc_free(kr);

    ret = handle_child_recv(req, pd, &buf, &len);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("child failed (%d [%s])\n", ret, strerror(ret)));
        goto done;
    }

    if ((size_t) len < 3*sizeof(int32_t)) {
        DEBUG(1, ("message too short.\n"));
        goto done;
    }

    p=0;
    msg_status = ((int32_t *)(buf+p));
    p += sizeof(int32_t);

    msg_type = ((int32_t *)(buf+p));
    p += sizeof(int32_t);

    msg_len = ((int32_t *)(buf+p));
    p += sizeof(int32_t);

    DEBUG(4, ("child response [%d][%d][%d].\n", *msg_status, *msg_type,
                                                *msg_len));

    if ((p + *msg_len) != len) {
        DEBUG(1, ("message format error.\n"));
        goto done;
    }

    ret = pam_add_response(pd, *msg_type, *msg_len, &buf[p]);
    if (ret != EOK) {
        DEBUG(1, ("pam_add_response failed.\n"));
        goto done;
    }

    if (*msg_status == PAM_AUTHINFO_UNAVAIL) {
        be_mark_offline(be_req->be_ctx);
        pd->pam_status = *msg_status;
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    if (*msg_status == PAM_SUCCESS && pd->cmd == SSS_PAM_AUTHENTICATE) {
        dummy = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
        if (dummy != NULL) {
            env = talloc_asprintf(pd, "%s=%s", SSSD_KRB5_REALM, dummy);
            if (env == NULL) {
                DEBUG(1, ("talloc_asprintf failed.\n"));
                goto done;
            }
            ret = pam_add_response(pd, PAM_ENV_ITEM, strlen(env)+1,
                                   (uint8_t *) env);
            if (ret != EOK) {
                DEBUG(1, ("pam_add_response failed.\n"));
                goto done;
            }
        }

        dummy = dp_opt_get_cstring(krb5_ctx->opts, KRB5_KDC);
        if (dummy != NULL) {
            env = talloc_asprintf(pd, "%s=%s", SSSD_KRB5_KDC, dummy);
            if (env == NULL) {
                DEBUG(1, ("talloc_asprintf failed.\n"));
                goto done;
            }
            ret = pam_add_response(pd, PAM_ENV_ITEM, strlen(env)+1,
                                   (uint8_t *) env);
            if (ret != EOK) {
                DEBUG(1, ("pam_add_response failed.\n"));
                goto done;
            }
        }
    }

    pd->pam_status = *msg_status;
    dp_err = DP_ERR_OK;

    if (pd->pam_status == PAM_SUCCESS &&
        be_req->be_ctx->domain->cache_credentials == TRUE) {

        switch(pd->cmd) {
            case SSS_PAM_AUTHENTICATE:
                password = talloc_size(be_req, pd->authtok_size + 1);
                if (password != NULL) {
                    memcpy(password, pd->authtok, pd->authtok_size);
                    password[pd->authtok_size] = '\0';
                }
                break;
            case SSS_PAM_CHAUTHTOK:
                password = talloc_size(be_req, pd->newauthtok_size + 1);
                if (password != NULL) {
                    memcpy(password, pd->newauthtok, pd->newauthtok_size);
                    password[pd->newauthtok_size] = '\0';
                }
                break;
            default:
                DEBUG(0, ("unsupported PAM command [%d].\n", pd->cmd));
        }

        if (password == NULL) {
            DEBUG(0, ("password not available, offline auth may not work.\n"));
            goto done;
        }

        talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

        subreq = sysdb_cache_password_send(be_req, be_req->be_ctx->ev,
                                           be_req->be_ctx->sysdb, NULL,
                                           be_req->be_ctx->domain, pd->user,
                                           password);
        if (subreq == NULL) {
            DEBUG(2, ("cache_password_send failed, offline auth may not work.\n"));
            goto done;
        }
        tevent_req_set_callback(subreq, krb5_pam_handler_cache_done, be_req);
        return;
    }

done:
    krb_reply(be_req, dp_err, pd->pam_status);
}

static void krb5_pam_handler_cache_done(struct tevent_req *subreq)
{
    struct be_req *be_req = tevent_req_callback_data(subreq, struct be_req);
    int ret;

    /* password caching failures are not fatal errors */
    ret = sysdb_cache_password_recv(subreq);
    talloc_zfree(subreq);

    /* so we just log it any return */
    if (ret) {
        DEBUG(2, ("Failed to cache password (%d)[%s]!?\n",
                  ret, strerror(ret)));
    }

    krb_reply(be_req, DP_ERR_OK, PAM_SUCCESS);
}

static void krb_reply(struct be_req *req, int dp_err, int result)
{
    req->fn(req, dp_err, result, NULL);
}

