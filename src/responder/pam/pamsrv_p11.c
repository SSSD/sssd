/*
   SSSD

   PAM Responder - certificate realted requests

   Copyright (C) Sumit Bose <sbose@redhat.com> 2015

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

#include <time.h>

#include "util/util.h"
#include "providers/data_provider.h"
#include "util/child_common.h"
#include "util/strtonum.h"
#include "responder/pam/pamsrv.h"


#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#endif  /* SSSD_LIBEXEC_PATH */

#define P11_CHILD_LOG_FILE "p11_child"
#define P11_CHILD_PATH SSSD_LIBEXEC_PATH"/p11_child"

errno_t p11_child_init(struct pam_ctx *pctx)
{
    return child_debug_init(P11_CHILD_LOG_FILE, &pctx->p11_child_debug_fd);
}

bool may_do_cert_auth(struct pam_ctx *pctx, struct pam_data *pd)
{
    size_t c;
    const char *sc_services[] = { "login", "su", "su-l", "gdm-smartcard",
                                  "gdm-password", "kdm", "sudo", "sudo-i",
                                  NULL };
    if (!pctx->cert_auth) {
        return false;
    }

    if (pd->cmd != SSS_PAM_PREAUTH && pd->cmd != SSS_PAM_AUTHENTICATE) {
        return false;
    }

    if (pd->cmd == SSS_PAM_AUTHENTICATE
           && sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_SC_PIN
           && sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_SC_KEYPAD) {
        return false;
    }

    /* TODO: make services configurable */
    if (pd->service == NULL || *pd->service == '\0') {
        return false;
    }
    for (c = 0; sc_services[c] != NULL; c++) {
        if (strcmp(pd->service, sc_services[c]) == 0) {
            break;
        }
    }
    if  (sc_services[c] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Smartcard authentication for service [%s] not supported.\n",
              pd->service);
        return false;
    }

    return true;
}

static errno_t get_p11_child_write_buffer(TALLOC_CTX *mem_ctx,
                                          struct pam_data *pd,
                                          uint8_t **_buf, size_t *_len)
{
    int ret;
    uint8_t *buf;
    size_t len;
    const char *pin = NULL;

    if (pd == NULL || pd->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing authtok.\n");
        return EINVAL;
    }

    switch (sss_authtok_get_type(pd->authtok)) {
    case SSS_AUTHTOK_TYPE_SC_PIN:
        ret = sss_authtok_get_sc_pin(pd->authtok, &pin, &len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_sc_pin failed.\n");
            return ret;
        }
        if (pin == NULL || len == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing PIN.\n");
            return EINVAL;
        }

        buf = talloc_size(mem_ctx, len);
        if (buf == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
            return ENOMEM;
        }

        safealign_memcpy(buf, pin, len, NULL);

        break;
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
        /* Nothing to send */
        len = 0;
        buf = NULL;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported authtok type [%d].\n",
                                   sss_authtok_get_type(pd->authtok));
        return EINVAL;
    }

    *_len = len;
    *_buf = buf;

    return EOK;
}

static errno_t parse_p11_child_response(TALLOC_CTX *mem_ctx, uint8_t *buf,
                                        ssize_t buf_len, char **_cert,
                                        char **_token_name)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    uint8_t *p;
    uint8_t *pn;
    char *cert = NULL;
    char *token_name = NULL;

    if (buf_len < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error occured while reading data from p11_child.\n");
        return EIO;
    }

    if (buf_len == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "No certificate found.\n");
        ret = EOK;
        goto done;
    }

    p = memchr(buf, '\n', buf_len);
    if (p == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing new-line in p11_child response.\n");
        return EINVAL;
    }
    if (p == buf) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing counter in p11_child response.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    token_name = talloc_strndup(tmp_ctx, (char*) buf, (p - buf));
    if (token_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    p++;
    pn = memchr(p, '\n', buf_len - (p - buf));
    if (pn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Missing new-line in p11_child response.\n");
        ret = EINVAL;
        goto done;
    }

    if (pn == p) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing cert in p11_child response.\n");
        ret = EINVAL;
        goto done;
    }

    cert = talloc_strndup(tmp_ctx, (char *) p, (pn - p));
    if(cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL, "Found cert [%s].\n", cert);

    ret = EOK;

done:
    if (ret == EOK) {
        *_token_name = talloc_steal(mem_ctx, token_name);
        *_cert = talloc_steal(mem_ctx, cert);
    }

    talloc_free(tmp_ctx);

    return ret;
}

struct pam_check_cert_state {
    int child_status;
    struct sss_child_ctx_old *child_ctx;
    struct tevent_timer *timeout_handler;
    struct tevent_context *ev;

    int write_to_child_fd;
    int read_from_child_fd;
    char *cert;
    char *token_name;
};

static void p11_child_write_done(struct tevent_req *subreq);
static void p11_child_done(struct tevent_req *subreq);
static void p11_child_timeout(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval tv, void *pvt);

struct tevent_req *pam_check_cert_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       int child_debug_fd,
                                       const char *nss_db,
                                       time_t timeout,
                                       const char *verify_opts,
                                       struct pam_data *pd)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct pam_check_cert_state *state;
    pid_t child_pid;
    struct timeval tv;
    int pipefd_to_child[2];
    int pipefd_from_child[2];
    const char *extra_args[7] = { NULL };
    uint8_t *write_buf = NULL;
    size_t write_buf_len = 0;
    size_t arg_c;

    req = tevent_req_create(mem_ctx, &state, struct pam_check_cert_state);
    if (req == NULL) {
        return NULL;
    }

    if (nss_db == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing NSS DB.\n");
        ret = EINVAL;
        goto done;
    }

    /* extra_args are added in revers order */
    arg_c = 0;
    extra_args[arg_c++] = nss_db;
    extra_args[arg_c++] = "--nssdb";
    if (verify_opts != NULL) {
        extra_args[arg_c++] = verify_opts;
        extra_args[arg_c++] = "--verify";
    }
    if (pd->cmd == SSS_PAM_AUTHENTICATE) {
        extra_args[arg_c++] = "--auth";
        switch (sss_authtok_get_type(pd->authtok)) {
        case SSS_AUTHTOK_TYPE_SC_PIN:
            extra_args[arg_c++] = "--pin";
            break;
        case SSS_AUTHTOK_TYPE_SC_KEYPAD:
            extra_args[arg_c++] = "--keypad";
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unsupported authtok type.\n");
            ret = EINVAL;
            goto done;
        }
    } else if (pd->cmd == SSS_PAM_PREAUTH) {
        extra_args[arg_c++] = "--pre";
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected PAM command [%d}.\n", pd->cmd);
        ret = EINVAL;
        goto done;
    }

    state->ev = ev;
    state->child_status = EFAULT;
    state->read_from_child_fd = -1;
    state->write_to_child_fd = -1;
    state->cert = NULL;
    state->token_name = NULL;

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    if (child_debug_fd == -1) {
        child_debug_fd = STDERR_FILENO;
    }

    child_pid = fork();
    if (child_pid == 0) { /* child */
        ret = exec_child_ex(state, pipefd_to_child, pipefd_from_child,
                            P11_CHILD_PATH, child_debug_fd, extra_args, false,
                            STDIN_FILENO, STDOUT_FILENO);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not exec p11 child: [%d][%s].\n",
                                       ret, strerror(ret));
            goto done;
        }
    } else if (child_pid > 0) { /* parent */

        state->read_from_child_fd = pipefd_from_child[0];
        close(pipefd_from_child[1]);
        sss_fd_nonblocking(state->read_from_child_fd);

        state->write_to_child_fd = pipefd_to_child[1];
        close(pipefd_to_child[0]);
        sss_fd_nonblocking(state->write_to_child_fd);

        /* Set up SIGCHLD handler */
        ret = child_handler_setup(ev, child_pid, NULL, NULL, &state->child_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not set up child handlers [%d]: %s\n",
                ret, sss_strerror(ret));
            ret = ERR_P11_CHILD;
            goto done;
        }

        /* Set up timeout handler */
        tv = tevent_timeval_current_ofs(timeout, 0);
        state->timeout_handler = tevent_add_timer(ev, req, tv,
                                                  p11_child_timeout, req);
        if(state->timeout_handler == NULL) {
            ret = ERR_P11_CHILD;
            goto done;
        }

        if (pd->cmd == SSS_PAM_AUTHENTICATE) {
            ret = get_p11_child_write_buffer(state, pd, &write_buf,
                                             &write_buf_len);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "get_p11_child_write_buffer failed.\n");
                goto done;
            }
        }

        if (write_buf_len != 0) {
            subreq = write_pipe_send(state, ev, write_buf, write_buf_len,
                                     state->write_to_child_fd);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "write_pipe_send failed.\n");
                ret = ERR_P11_CHILD;
                goto done;
            }
            tevent_req_set_callback(subreq, p11_child_write_done, req);
        } else {
            subreq = read_pipe_send(state, ev, state->read_from_child_fd);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "read_pipe_send failed.\n");
                ret = ERR_P11_CHILD;
                goto done;
            }
            tevent_req_set_callback(subreq, p11_child_done, req);
        }

        /* Now either wait for the timeout to fire or the child
         * to finish
         */
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "fork failed [%d][%s].\n",
                                   ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void p11_child_write_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct pam_check_cert_state *state = tevent_req_data(req,
                                                   struct pam_check_cert_state);
    int ret;

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    close(state->write_to_child_fd);
    state->write_to_child_fd = -1;

    subreq = read_pipe_send(state, state->ev, state->read_from_child_fd);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, p11_child_done, req);
}

static void p11_child_done(struct tevent_req *subreq)
{
    uint8_t *buf;
    ssize_t buf_len;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct pam_check_cert_state *state = tevent_req_data(req,
                                                   struct pam_check_cert_state);
    int ret;

    talloc_zfree(state->timeout_handler);

    ret = read_pipe_recv(subreq, state, &buf, &buf_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    close(state->read_from_child_fd);
    state->read_from_child_fd = -1;

    ret = parse_p11_child_response(state, buf, buf_len, &state->cert,
                                   &state->token_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "parse_p11_child_respose failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static void p11_child_timeout(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct pam_check_cert_state *state =
                              tevent_req_data(req, struct pam_check_cert_state);

    DEBUG(SSSDBG_CRIT_FAILURE, "Timeout reached for p11_child.\n");
    child_handler_destroy(state->child_ctx);
    state->child_ctx = NULL;
    state->child_status = ETIMEDOUT;
    tevent_req_error(req, ERR_P11_CHILD);
}

errno_t pam_check_cert_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            char **cert, char **token_name)
{
    struct pam_check_cert_state *state =
                              tevent_req_data(req, struct pam_check_cert_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (cert != NULL) {
        *cert = talloc_steal(mem_ctx, state->cert);
    }

    if (token_name != NULL) {
        *token_name = talloc_steal(mem_ctx, state->token_name);
    }

    return EOK;
}

errno_t add_pam_cert_response(struct pam_data *pd, const char *user,
                              const char *token_name)
{
    uint8_t *msg = NULL;
    size_t user_len;
    size_t msg_len;
    size_t slot_len;
    int ret;

    if (user == NULL || token_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing mandatory user or slot name.\n");
        return EINVAL;
    }

    user_len = strlen(user) + 1;
    slot_len = strlen(token_name) + 1;
    msg_len = user_len + slot_len;

    msg = talloc_zero_size(pd, msg_len);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_size failed.\n");
        return ENOMEM;
    }

    memcpy(msg, user, user_len);
    memcpy(msg + user_len, token_name, slot_len);

    ret = pam_add_response(pd, SSS_PAM_CERT_INFO, msg_len, msg);
    talloc_free(msg);

    return ret;
}
