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
#include <krb5/krb5.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "db/sysdb.h"
#include "../sss_client/sss_cli.h"
#include "krb5_plugin/sssd_krb5_locator_plugin.h"
#include "providers/krb5/krb5_auth.h"

static void fd_nonblocking(int fd) {
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

static void krb5_cleanup(struct krb5_req *kr)
{
    if (kr == NULL) return;

    /* FIXME: is it safe to drop the "!= NULL" checks? */
    if (kr->options != NULL)
        krb5_get_init_creds_opt_free(kr->ctx, kr->options);
    if (kr->creds != NULL)
        krb5_free_cred_contents(kr->ctx, kr->creds);
    if (kr->name != NULL)
        krb5_free_unparsed_name(kr->ctx, kr->name);
    if (kr->princ != NULL)
        krb5_free_principal(kr->ctx, kr->princ);
    if (kr->cc != NULL)
        krb5_cc_close(kr->ctx, kr->cc);
    if (kr->ctx != NULL)
        krb5_free_context(kr->ctx);

    talloc_free(kr);
}

static int krb5_setup(struct be_req *req, struct krb5_req **krb5_req)
{
    struct krb5_req *kr = NULL;
    struct krb5_ctx *krb5_ctx;
    struct pam_data *pd;
    krb5_error_code kerr = 0;
    char *user_princ_str = NULL;

    pd = talloc_get_type(req->req_data, struct pam_data);

    krb5_ctx = talloc_get_type(req->be_ctx->pvt_auth_data, struct krb5_ctx);

    kr = talloc_zero(req, struct krb5_req);
    if (kr == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        kerr = ENOMEM;
        goto failed;
    }

    kr->pd = pd;
    kr->req = req;

    kerr = krb5_init_context(&kr->ctx);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

/* TODO: try to read user principal from id backend, use user + realm as a
   fallback */
    if (kr->pd->user != NULL && krb5_ctx->realm != NULL) {
        user_princ_str = talloc_asprintf(kr, "%s@%s", kr->pd->user,
                                                      krb5_ctx->realm);
    }
    if (user_princ_str == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        kerr = ENOMEM;
        goto failed;
    }

    kerr = krb5_parse_name(kr->ctx, user_princ_str, &kr->princ);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

    kerr = krb5_unparse_name(kr->ctx, kr->princ, &kr->name);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

    kr->creds = talloc_zero(kr, krb5_creds);
    if (kr->creds == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        kerr = ENOMEM;
        goto failed;
    }

    kerr = krb5_get_init_creds_opt_alloc(kr->ctx, &kr->options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

/* TODO: set options, e.g.
 *  krb5_get_init_creds_opt_set_tkt_life
 *  krb5_get_init_creds_opt_set_renew_life
 *  krb5_get_init_creds_opt_set_forwardable
 *  krb5_get_init_creds_opt_set_proxiable
 *  krb5_get_init_creds_opt_set_etype_list
 *  krb5_get_init_creds_opt_set_address_list
 *  krb5_get_init_creds_opt_set_preauth_list
 *  krb5_get_init_creds_opt_set_salt
 *  krb5_get_init_creds_opt_set_change_password_prompt
 *  krb5_get_init_creds_opt_set_pa
 */

    *krb5_req = kr;
    return EOK;

failed:
    krb5_cleanup(kr);

    return kerr;
}

/* TODO: remove later
 * These functions are available in the latest tevent and are the ones that
 * should be used as tevent_req is rightfully opaque there */
#ifndef tevent_req_data
#define tevent_req_data(req, type) ((type *)req->private_state)
#endif

#ifndef tevent_req_set_callback
#define tevent_req_set_callback(req, func, data) \
    do { req->async.fn = func; req->async.private_data = data; } while(0)
#endif

#ifndef tevent_req_callback_data
#define tevent_req_callback_data(req, type) ((type *)req->async.private_data)
#endif

static void wait_for_child_handler(struct tevent_context *ev,
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

static int fork_tgt_req_child(struct krb5_req *kr)
{
    int pipefd[2];
    pid_t pid;
    int ret;

    ret = pipe(pipefd);
    if (ret == -1) {
        DEBUG(1, ("pipe failed [%d][%s].\n", errno, strerror(errno)));
        return -1;
    }
    pid = fork();

    if (pid == 0) { /* child */
        close(pipefd[0]);
        tgt_req_child(pipefd[1], kr);
    } else if (pid > 0) { /* parent */
        kr->child_pid = pid;
        kr->fd = pipefd[0];
        close(pipefd[1]);

        fd_nonblocking(kr->fd);

    } else { /* error */
        DEBUG(1, ("fork failed [%d][%s].\n", errno, strerror(errno)));
        return -1;
    }

    return EOK;
}


struct read_pipe_state {
    int fd;
    uint8_t *buf;
    size_t len;
};

static void read_pipe_done(struct tevent_context *ev, struct tevent_fd *fde,
                         uint16_t flags, void *pvt);

static struct tevent_req *read_pipe_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       int fd)
{
    struct tevent_req *req;
    struct read_pipe_state *state;
    struct tevent_fd *fde;


    req = tevent_req_create(memctx, &state, struct read_pipe_state);
    if (req == NULL) return NULL;

    state->fd = fd;
    state->buf = talloc_array(state, uint8_t, MAX_CHILD_MSG_SIZE);
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

static void read_pipe_done(struct tevent_context *ev, struct tevent_fd *fde,
                         uint16_t flags, void *pvt)
{
    ssize_t size;
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct read_pipe_state *state = tevent_req_data(req, struct read_pipe_state);

    if (flags & TEVENT_FD_WRITE) {
        DEBUG(1, ("client_response_handler called with TEVENT_FD_WRITE, this should not happen.\n"));
        tevent_req_error(req, EINVAL);
        return;
    }

    size = read(state->fd, state->buf, talloc_get_size(state->buf));
    if (size == -1) {
        if (errno == EAGAIN || errno == EINTR) return;
        DEBUG(1, ("read failed [%d][%s].\n", errno, strerror(errno)));
        tevent_req_error(req, errno);
        return;
    }
    state->len = size;

    tevent_req_done(req);
    return;
}

static ssize_t read_pipe_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                        uint8_t **buf, uint64_t *error) {
    struct read_pipe_state *state = tevent_req_data(req,
                                                    struct read_pipe_state);
    enum tevent_req_state tstate;

    if (tevent_req_is_error(req, &tstate, error)) {
        return -1;
    }

    *buf = talloc_move(mem_ctx, &state->buf);
    return state->len;
}

struct tgt_req_state {
    struct krb5_req *kr;
    ssize_t len;
    uint8_t *buf;
};

static void tgt_req_done(struct tevent_req *subreq);

static struct tevent_req *tgt_req_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                        struct krb5_req *kr)
{
    int ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct tgt_req_state *state;

    ret = fork_tgt_req_child(kr);
    if (ret != EOK) {
        DEBUG(1, ("fork_tgt_req_child failed.\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct tgt_req_state);
    if (req == NULL) {
        return NULL;
    }

    state->kr = kr;

    subreq = read_pipe_send(state, ev, kr->fd);
    if (tevent_req_nomem(subreq, req)) {
        return tevent_req_post(req, ev);
    }
    tevent_req_set_callback(subreq, tgt_req_done, req);
    return req;
}

static void tgt_req_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct tgt_req_state *state = tevent_req_data(req, struct tgt_req_state);
    uint64_t error;

    state->len = read_pipe_recv(subreq, state, &state->buf, &error);
    talloc_zfree(subreq);
    close(state->kr->fd);
    if (state->len == -1) {
        tevent_req_error(req, error);
        return;
    }

    tevent_req_done(req);
    return;
}

static ssize_t tgt_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                     uint8_t **buf, uint64_t *error) {
    struct tgt_req_state *state = tevent_req_data(req, struct tgt_req_state);
    enum tevent_req_state tstate;

    if (tevent_req_is_error(req, &tstate, error)) {
        return -1;
    }

    *buf = talloc_move(mem_ctx, &state->buf);
    return state->len;
}

static void krb5_pam_handler_done(struct tevent_req *req);

static void krb5_pam_handler(struct be_req *be_req)
{
    struct krb5_req *kr = NULL;
    struct tevent_req *req;
    int ret;
    struct pam_data *pd;
    int pam_status=PAM_SYSTEM_ERR;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    if (pd->cmd != SSS_PAM_AUTHENTICATE) {
        DEBUG(4, ("krb5 does not handles pam task %d.\n", pd->cmd));
        pam_status = PAM_SUCCESS;
        goto done;
    }

    ret = krb5_setup(be_req, &kr);
    if (ret != EOK) {
        DEBUG(1, ("krb5_setup failed.\n"));
        goto done;
    }

    req = tgt_req_send(be_req, be_req->be_ctx->ev, kr);
    if (req == NULL) {
        DEBUG(1, ("tgt_req_send failed.\n"));
        goto done;
    }

    tevent_req_set_callback(req, krb5_pam_handler_done, kr);
    return;

done:
    krb5_cleanup(kr);

    pd->pam_status = pam_status;

    be_req->fn(be_req, pam_status, NULL);
}

static void krb5_pam_handler_done(struct tevent_req *req)
{
    struct krb5_req *kr = tevent_req_callback_data(req, struct krb5_req);
    struct pam_data *pd = kr->pd;
    struct be_req *be_req = kr->req;
    struct tgt_req_state *state = tevent_req_data(req, struct tgt_req_state);
    int ret;
    uint8_t *buf;
    ssize_t len;
    uint64_t error;
    int p;
    int32_t *msg_status;
    int32_t *msg_type;
    int32_t *msg_len;

    pd->pam_status = PAM_SYSTEM_ERR;
    krb5_cleanup(kr);

    len = tgt_req_recv(req, state, &buf, &error);
    talloc_zfree(req);
    if (len == -1) {
        DEBUG(1, ("tgt_req request failed\n"));
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

    ret=pam_add_response(kr->pd, *msg_type, *msg_len, &buf[p]);
    if (ret != EOK) {
        DEBUG(1, ("pam_add_response failed.\n"));
        goto done;
    }

    pd->pam_status = *msg_status;

done:
    be_req->fn(be_req, pd->pam_status, NULL);
}


struct be_auth_ops krb5_auth_ops = {
    .pam_handler = krb5_pam_handler,
    .finalize = NULL,
};


int sssm_krb5_auth_init(struct be_ctx *bectx, struct be_auth_ops **ops,
                   void **pvt_auth_data)
{
    struct krb5_ctx *ctx = NULL;
    char *value = NULL;
    int ret;
    struct tevent_signal *sige;

    ctx = talloc_zero(bectx, struct krb5_ctx);
    if (!ctx) {
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }

    ctx->action = INIT_PW;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            "krb5KDCIP", NULL, &value);
    if (ret != EOK) goto fail;
    if (value == NULL) {
        DEBUG(2, ("Missing krb5KDCIP, authentication might fail.\n"));
    } else {
        ret = setenv(SSSD_KDC, value, 1);
        if (ret != EOK) {
            DEBUG(2, ("setenv %s failed, authentication might fail.\n",
                      SSSD_KDC));
        }
    }
    ctx->kdcip = value;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                            "krb5REALM", NULL, &value);
    if (ret != EOK) goto fail;
    if (value == NULL) {
        DEBUG(4, ("Missing krb5REALM authentication might fail.\n"));
    } else {
        ret = setenv(SSSD_REALM, value, 1);
        if (ret != EOK) {
            DEBUG(2, ("setenv %s failed, authentication might fail.\n",
                      SSSD_REALM));
        }
    }
    ctx->realm = value;

/* TODO: set options */

    sige = tevent_add_signal(bectx->ev, ctx, SIGCHLD, SA_SIGINFO,
                       wait_for_child_handler, NULL);
    if (sige == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        ret = ENOMEM;
        goto fail;
    }


    *ops = &krb5_auth_ops;
    *pvt_auth_data = ctx;
    return EOK;

fail:
    talloc_free(ctx);
    return ret;
}
