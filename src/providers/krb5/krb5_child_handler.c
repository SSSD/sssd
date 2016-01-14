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
#include "util/child_common.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_auth.h"
#include "src/providers/krb5/krb5_utils.h"

#ifndef KRB5_CHILD_DIR
#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#endif  /* SSSD_LIBEXEC_PATH */

#define KRB5_CHILD_DIR SSSD_LIBEXEC_PATH
#endif /* KRB5_CHILD_DIR */

#define KRB5_CHILD KRB5_CHILD_DIR"/krb5_child"

#define TIME_T_MAX LONG_MAX
#define int64_to_time_t(val) ((time_t)((val) < TIME_T_MAX ? val : TIME_T_MAX))

struct handle_child_state {
    struct tevent_context *ev;
    struct krb5child_req *kr;
    uint8_t *buf;
    ssize_t len;

    struct tevent_timer *timeout_handler;
    pid_t child_pid;

    struct child_io_fds *io;
};

static errno_t pack_authtok(struct io_buffer *buf, size_t *rp,
                            struct sss_auth_token *tok)
{
    uint32_t auth_token_type;
    uint32_t auth_token_length = 0;
    const char *data;
    size_t len;
    errno_t ret = EOK;

    auth_token_type = sss_authtok_get_type(tok);

    switch (auth_token_type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        auth_token_length = 0;
        data = "";
        break;
    case SSS_AUTHTOK_TYPE_PASSWORD:
        ret = sss_authtok_get_password(tok, &data, &len);
        auth_token_length = len + 1;
        break;
    case SSS_AUTHTOK_TYPE_CCFILE:
        ret = sss_authtok_get_ccfile(tok, &data, &len);
        auth_token_length = len + 1;
        break;
    case SSS_AUTHTOK_TYPE_2FA:
        data = (char *) sss_authtok_get_data(tok);
        auth_token_length = sss_authtok_get_size(tok);
        break;
    default:
        ret = EINVAL;
    }

    if (ret == EOK) {
        SAFEALIGN_COPY_UINT32(&buf->data[*rp], &auth_token_type, rp);
        SAFEALIGN_COPY_UINT32(&buf->data[*rp], &auth_token_length, rp);
        safealign_memcpy(&buf->data[*rp], data, auth_token_length, rp);
    }

    return ret;
}

static errno_t create_send_buffer(struct krb5child_req *kr,
                                  struct io_buffer **io_buf)
{
    struct io_buffer *buf;
    size_t rp;
    const char *keytab;
    uint32_t validate;
    uint32_t send_pac;
    uint32_t use_enterprise_principal;
    size_t username_len = 0;
    errno_t ret;

    keytab = dp_opt_get_cstring(kr->krb5_ctx->opts, KRB5_KEYTAB);
    if (keytab == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing keytab option.\n");
        return EINVAL;
    }

    validate = dp_opt_get_bool(kr->krb5_ctx->opts, KRB5_VALIDATE) ? 1 : 0;

    /* Always send PAC except for local IPA users and IPA server mode */
    switch (kr->krb5_ctx->config_type) {
        case K5C_IPA_CLIENT:
            send_pac = kr->upn_from_different_realm ? 1 : 0;
            break;
        case K5C_IPA_SERVER:
            send_pac = 0;
            break;
        default:
            send_pac = 1;
            break;
    }

    if (kr->pd->cmd == SSS_CMD_RENEW || kr->is_offline) {
        use_enterprise_principal = false;
    } else {
        use_enterprise_principal = dp_opt_get_bool(kr->krb5_ctx->opts,
                                         KRB5_USE_ENTERPRISE_PRINCIPAL) ? 1 : 0;
    }

    buf = talloc(kr, struct io_buffer);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    buf->size = 8*sizeof(uint32_t) + strlen(kr->upn);

    if (kr->pd->cmd == SSS_PAM_AUTHENTICATE ||
        kr->pd->cmd == SSS_CMD_RENEW ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        buf->size += 4*sizeof(uint32_t) + strlen(kr->ccname) + strlen(keytab) +
                     sss_authtok_get_size(kr->pd->authtok);

        buf->size += sizeof(uint32_t);
        if (kr->old_ccname) {
            buf->size += strlen(kr->old_ccname);
        }
    }

    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        buf->size += 2*sizeof(uint32_t) +
                     sss_authtok_get_size(kr->pd->newauthtok);
    }

    if (kr->pd->cmd == SSS_PAM_ACCT_MGMT) {
        username_len = strlen(kr->pd->user);
        buf->size += sizeof(uint32_t) + username_len;
    }

    buf->data = talloc_size(kr, buf->size);
    if (buf->data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        talloc_free(buf);
        return ENOMEM;
    }

    rp = 0;
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->pd->cmd, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->uid, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->gid, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &validate, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &kr->is_offline, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &send_pac, &rp);
    SAFEALIGN_COPY_UINT32(&buf->data[rp], &use_enterprise_principal, &rp);

    SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(kr->upn), &rp);
    safealign_memcpy(&buf->data[rp], kr->upn, strlen(kr->upn), &rp);

    if (kr->pd->cmd == SSS_PAM_AUTHENTICATE ||
        kr->pd->cmd == SSS_CMD_RENEW ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(kr->ccname), &rp);
        safealign_memcpy(&buf->data[rp], kr->ccname, strlen(kr->ccname), &rp);

        if (kr->old_ccname) {
            SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(kr->old_ccname), &rp);
            safealign_memcpy(&buf->data[rp], kr->old_ccname,
                             strlen(kr->old_ccname), &rp);
        } else {
            SAFEALIGN_SET_UINT32(&buf->data[rp], 0, &rp);
        }

        SAFEALIGN_SET_UINT32(&buf->data[rp], strlen(keytab), &rp);
        safealign_memcpy(&buf->data[rp], keytab, strlen(keytab), &rp);

        ret = pack_authtok(buf, &rp, kr->pd->authtok);
        if (ret) {
            return ret;
        }
    }

    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        ret = pack_authtok(buf, &rp, kr->pd->newauthtok);
        if (ret) {
            return ret;
        }
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

    DEBUG(SSSDBG_IMPORTANT_INFO,
          "Timeout for child [%d] reached. In case KDC is distant or network "
           "is slow you may consider increasing value of krb5_auth_timeout.\n",
           state->child_pid);

    ret = kill(state->child_pid, SIGKILL);
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "kill failed [%d][%s].\n", errno, strerror(errno));
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
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
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
    const char *k5c_extra_args[3];

    k5c_extra_args[0] = talloc_asprintf(state, "--fast-ccache-uid=%"SPRIuid, getuid());
    k5c_extra_args[1] = talloc_asprintf(state, "--fast-ccache-gid=%"SPRIgid, getgid());
    k5c_extra_args[2] = NULL;
    if (k5c_extra_args[0] == NULL || k5c_extra_args[1] == NULL) {
        return ENOMEM;
    }

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", errno, strerror(errno));
        return err;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", errno, strerror(errno));
        return err;
    }

    pid = fork();

    if (pid == 0) { /* child */
        err = exec_child_ex(state,
                            pipefd_to_child, pipefd_from_child,
                            KRB5_CHILD, state->kr->krb5_ctx->child_debug_fd,
                            k5c_extra_args, false, STDIN_FILENO, STDOUT_FILENO);
        if (err != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not exec KRB5 child: [%d][%s].\n",
                      err, strerror(err));
            return err;
        }
    } else if (pid > 0) { /* parent */
        state->child_pid = pid;
        state->io->read_from_child_fd = pipefd_from_child[0];
        close(pipefd_from_child[1]);
        state->io->write_to_child_fd = pipefd_to_child[1];
        close(pipefd_to_child[0]);
        sss_fd_nonblocking(state->io->read_from_child_fd);
        sss_fd_nonblocking(state->io->write_to_child_fd);

        ret = child_handler_setup(state->ev, pid, NULL, NULL, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not set up child signal handler\n");
            return ret;
        }

        err = activate_child_timeout_handler(req, state->ev,
                  dp_opt_get_int(state->kr->krb5_ctx->opts, KRB5_AUTH_TIMEOUT));
        if (err != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "activate_child_timeout_handler failed.\n");
        }

    } else { /* error */
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fork failed [%d][%s].\n", errno, strerror(errno));
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
    struct io_buffer *buf = NULL;

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

    state->io = talloc(state, struct child_io_fds);
    if (state->io == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    state->io->write_to_child_fd = -1;
    state->io->read_from_child_fd = -1;
    talloc_set_destructor((void *) state->io, child_io_destructor);

    ret = create_send_buffer(kr, &buf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "create_send_buffer failed.\n");
        goto fail;
    }

    ret = fork_child(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "fork_child failed.\n");
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

errno_t
parse_krb5_child_response(TALLOC_CTX *mem_ctx, uint8_t *buf, ssize_t len,
                          struct pam_data *pd, int pwd_exp_warning,
                          struct krb5_child_response **_res)
{
    ssize_t pref_len;
    size_t p;
    errno_t ret;
    bool skip;
    char *ccname = NULL;
    size_t ccname_len = 0;
    int32_t msg_status;
    int32_t msg_type;
    int32_t msg_len;
    int64_t time_data;
    struct tgt_times tgtt;
    uint32_t expiration;
    uint32_t msg_subtype;
    struct krb5_child_response *res;
    const char *upn = NULL;
    size_t upn_len = 0;
    bool otp = false;

    if ((size_t) len < sizeof(int32_t)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "message too short.\n");
        return EINVAL;
    }

    memset(&tgtt, 0, sizeof(struct tgt_times));

    if (pwd_exp_warning < 0) {
        pwd_exp_warning = KERBEROS_PWEXPIRE_WARNING_TIME;
    }

    /* A buffer with the following structure is expected.
     * int32_t status of the request (required)
     * message (zero or more)
     *
     * A message consists of:
     * int32_t type of the message
     * int32_t length of the following data
     * uint8_t[len] data
     */

    p=0;
    SAFEALIGN_COPY_INT32(&msg_status, buf+p, &p);

    while (p < len) {
        skip = false;
        SAFEALIGN_COPY_INT32(&msg_type, buf+p, &p);
        SAFEALIGN_COPY_INT32(&msg_len, buf+p, &p);

        DEBUG(SSSDBG_TRACE_LIBS, "child response [%d][%d][%d].\n",
              msg_status, msg_type, msg_len);

        if (msg_len > len - p) {
            DEBUG(SSSDBG_CRIT_FAILURE, "message format error [%d] > [%zu].\n",
                  msg_len, len - p);
            return EINVAL;
        }

        /* We need to save the name of the credential cache file. To find it
         * we check if the data part of a message starts with
         * CCACHE_ENV_NAME"=". pref_len also counts the trailing '=' because
         * sizeof() counts the trailing '\0' of a string. */
        pref_len = sizeof(CCACHE_ENV_NAME);
        if ((msg_type == SSS_PAM_ENV_ITEM) &&
            (msg_len > pref_len) &&
            (strncmp((const char *) &buf[p], CCACHE_ENV_NAME"=", pref_len) == 0)) {
            ccname = (char *) &buf[p+pref_len];
            ccname_len = msg_len-pref_len;
        }

        if (msg_type == SSS_KRB5_INFO_TGT_LIFETIME &&
            msg_len == 4*sizeof(int64_t)) {
            SAFEALIGN_COPY_INT64(&time_data, buf+p, NULL);
            tgtt.authtime = int64_to_time_t(time_data);
            SAFEALIGN_COPY_INT64(&time_data, buf+p+sizeof(int64_t), NULL);
            tgtt.starttime = int64_to_time_t(time_data);
            SAFEALIGN_COPY_INT64(&time_data, buf+p+2*sizeof(int64_t), NULL);
            tgtt.endtime = int64_to_time_t(time_data);
            SAFEALIGN_COPY_INT64(&time_data, buf+p+3*sizeof(int64_t), NULL);
            tgtt.renew_till = int64_to_time_t(time_data);
            DEBUG(SSSDBG_TRACE_LIBS, "TGT times are [%ld][%ld][%ld][%ld].\n",
                  tgtt.authtime, tgtt.starttime, tgtt.endtime, tgtt.renew_till);
        }

        if (msg_type == SSS_KRB5_INFO_UPN) {
            upn = (char *) buf + p;
            upn_len = msg_len;
        }

        if (msg_type == SSS_PAM_USER_INFO) {
            SAFEALIGN_COPY_UINT32(&msg_subtype, buf + p, NULL);
            if (msg_subtype == SSS_PAM_USER_INFO_EXPIRE_WARN) {
                SAFEALIGN_COPY_UINT32(&expiration,
                                      buf + p + sizeof(uint32_t), NULL);
                if (pwd_exp_warning > 0 &&
                    difftime(pwd_exp_warning, expiration) < 0.0) {
                    skip = true;
                }
            }
        }

        if (msg_type == SSS_OTP) {
            otp = true;
            skip = true;
        }

        if (!skip) {
            ret = pam_add_response(pd, msg_type, msg_len, &buf[p]);
            if (ret != EOK) {
                /* This is not a fatal error */
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            }
        }

        p += msg_len;

        if ((p < len) && (p + 2*sizeof(int32_t) > len)) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "The remainder of the message is too short.\n");
            return EINVAL;
        }
    }

    res = talloc_zero(mem_ctx, struct krb5_child_response);
    if (!res) return ENOMEM;

    res->otp = otp;
    res->msg_status = msg_status;
    memcpy(&res->tgtt, &tgtt, sizeof(tgtt));

    if (ccname) {
        res->ccname = talloc_strndup(res, ccname, ccname_len);
        if (res->ccname == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            talloc_free(res);
            return ENOMEM;
        }
    }

    if (upn != NULL) {
        res->correct_upn = talloc_strndup(res, upn, upn_len);
        if (res->correct_upn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            talloc_free(res);
            return ENOMEM;
        }
    }

    *_res = res;
    return EOK;
}
