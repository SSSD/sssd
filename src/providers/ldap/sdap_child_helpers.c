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
#include <signal.h>

#include "util/util.h"
#include "util/sss_krb5.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_private.h"
#include "util/child_common.h"

#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#else
#define LDAP_CHILD SSSD_LIBEXEC_PATH"/ldap_child"
#endif

#define SIGTERM_TO_SIGKILL_TIME 2

static void get_tgt_timeout_handler(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt);

static void child_callback(int child_status,
                           struct tevent_signal *sige,
                           void *pvt)
{
    if (WEXITSTATUS(child_status) == CHILD_TIMEOUT_EXIT_CODE) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "LDAP child was terminated due to timeout\n");

        struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
        tevent_req_error(req, ETIMEDOUT);
    }
}

static errno_t create_child_req_send_buffer(TALLOC_CTX *mem_ctx,
                                            enum ldap_child_command cmd,
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
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    buf->size = 7 * sizeof(uint32_t);
    if (realm_str) {
        buf->size += strlen(realm_str);
    }
    if (princ_str) {
        buf->size += strlen(princ_str);
    }
    if (keytab_name) {
        buf->size += strlen(keytab_name);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "buffer size: %zu\n", buf->size);

    buf->data = talloc_size(buf, buf->size);
    if (buf->data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        talloc_free(buf);
        return ENOMEM;
    }

    rp = 0;

    /* command */
    SAFEALIGN_SET_UINT32(&buf->data[rp], (uint32_t)cmd, &rp);

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
                                int  *result, krb5_error_code *kerr,
                                char **ccache, time_t *expire_time_out)
{
    size_t p = 0;
    uint32_t len;
    uint32_t res;
    char *ccn;
    time_t expire_time;
    krb5_error_code krberr;

    /* operation result code */
    SAFEALIGN_COPY_UINT32_CHECK(&res, buf + p, size, &p);

    /* krb5 error code */
    safealign_memcpy(&krberr, buf+p, sizeof(krberr), &p);

    /* ccache name size */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    if (len > size - p) return EINVAL;

    ccn = talloc_size(mem_ctx, sizeof(char) * (len + 1));
    if (ccn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }
    safealign_memcpy(ccn, buf+p, sizeof(char) * len, &p);
    ccn[len] = '\0';

    if (p + sizeof(time_t) > size) {
        talloc_free(ccn);
        return EINVAL;
    }
    safealign_memcpy(&expire_time, buf+p, sizeof(time_t), &p);

    *result = res;
    *ccache = ccn;
    *expire_time_out = expire_time;
    *kerr = krberr;
    return EOK;
}

static errno_t parse_select_principal_response(TALLOC_CTX *mem_ctx,
                                               uint8_t *buf, ssize_t size,
                                               char **sasl_primary,
                                               char **sasl_realm)
{
    uint32_t len = 0;
    size_t p = 0;

    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    if (len > size - p) {
        return EINVAL;
    }
    *sasl_primary = talloc_size(mem_ctx, sizeof(char) * (len + 1));
    if (*sasl_primary == NULL) {
        return ENOMEM;
    }
    safealign_memcpy(*sasl_primary, buf + p, sizeof(char) * len, &p);
    (*sasl_primary)[len] = '\0';

    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    if (len > size - p) {
        return EINVAL;
    }
    *sasl_realm = talloc_size(mem_ctx, sizeof(char) * (len + 1));
    if (*sasl_realm == NULL) {
        return ENOMEM;
    }
    safealign_memcpy(*sasl_realm, buf + p, sizeof(char) * len, &p);
    (*sasl_realm)[len] = '\0';

    DEBUG(SSSDBG_TRACE_LIBS, "result: '%s', '%s'\n", *sasl_primary, *sasl_realm);

    return EOK;
}

errno_t sdap_select_principal_from_keytab_sync(TALLOC_CTX *mem_ctx,
                                               const char *princ_str,
                                               const char *realm_str,
                                               const char *keytab_name,
                                               char **sasl_primary,
                                               char **sasl_realm)
{
    static uint8_t response[2048];
    struct io_buffer *buf = NULL;
    int ret;
    struct child_io_fds *io = NULL;
    ssize_t len;

    ret = create_child_req_send_buffer(mem_ctx, LDAP_CHILD_SELECT_PRINCIPAL,
                                       realm_str, princ_str, keytab_name, 0,
                                       &buf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "create_child_req_send_buffer() failed.\n");
        ret = EFAULT;
        goto done;
    }

    ret = sss_child_start(mem_ctx, NULL, LDAP_CHILD, NULL, false,
                          LDAP_CHILD_LOG_FILE, STDOUT_FILENO,
                          NULL, NULL,
                          0, NULL, NULL, false, &io);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_child_start() failed.\n");
        goto done;
    }

    len = sss_atomic_write_s(io->write_to_child_fd, buf->data, buf->size);
    if (len != buf->size) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_atomic_write_s() failed\n");
        ret = EIO;
        goto done;
    }

    FD_CLOSE(io->write_to_child_fd);

    len = sss_atomic_read_s(io->read_from_child_fd,
                            response, sizeof(response));
    if (len <= 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get principal from keytab (sss_atomic_read_s() failed), "
              "see ldap_child.log (pid = %ld) for details.\n", (long)(io->pid));
        ret = EIO;
        goto done;
    }

    FD_CLOSE(io->read_from_child_fd);

    if (waitpid(io->pid, NULL, WNOHANG) != io->pid) {
        DEBUG(SSSDBG_MINOR_FAILURE, "waitpid(ldap_child) failed, "
              "process might be leaking\n");
    }

    ret = parse_select_principal_response(mem_ctx, response, len,
                                          sasl_primary, sasl_realm);

done:
    talloc_free(io);
    talloc_free(buf);

    return ret;
}

/* ==The-public-async-interface============================================*/

struct sdap_get_tgt_state {
    struct tevent_context *ev;
    struct child_io_fds *io;
    ssize_t len;
    uint8_t *buf;

    struct tevent_timer *kill_te;
};

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

    /* prepare the data to pass to child */
    ret = create_child_req_send_buffer(state, LDAP_CHILD_GET_TGT,
                                       realm_str, princ_str, keytab_name, lifetime,
                                       &buf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "create_child_req_send_buffer() failed.\n");
        goto fail;
    }

    ret = sss_child_start(state, state->ev, LDAP_CHILD, NULL, false,
                          LDAP_CHILD_LOG_FILE, STDOUT_FILENO,
                          child_callback, req,
                          timeout, get_tgt_timeout_handler, req, false,
                          &(state->io));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_child_start() failed.\n");
        goto fail;
    }

    subreq = write_pipe_send(state, ev, buf->data, buf->size,
                             state->io->write_to_child_fd);
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

    FD_CLOSE(state->io->write_to_child_fd);

    subreq = read_pipe_send(state, state->ev,
                            state->io->read_from_child_fd);
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

    FD_CLOSE(state->io->read_from_child_fd);

    if (state->kill_te == NULL) {
        tevent_req_done(req);
        return;
    }

    /* wait for child callback to terminate the request */
}

int sdap_get_tgt_recv(struct tevent_req *req,
                      TALLOC_CTX *mem_ctx,
                      int  *result,
                      krb5_error_code *kerr,
                      char **ccname,
                      time_t *expire_time_out)
{
    struct sdap_get_tgt_state *state = tevent_req_data(req,
                                             struct sdap_get_tgt_state);
    char *ccn;
    time_t expire_time;
    int  res;
    int ret;
    krb5_error_code krberr;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ret = parse_child_response(mem_ctx, state->buf, state->len,
                               &res, &krberr, &ccn, &expire_time);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot parse child response: [%d][%s]\n", ret, strerror(ret));
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Child responded: %d [%s], expired on [%"SPRItime"]\n",
          res, ccn, expire_time);
    *result = res;
    *kerr = krberr;
    *ccname = ccn;
    *expire_time_out = expire_time;
    return EOK;
}

static void get_tgt_sigkill_handler(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_tgt_state *state = tevent_req_data(req,
                                            struct sdap_get_tgt_state);
    int ret;

    DEBUG(SSSDBG_TRACE_ALL,
          "timeout for sending SIGKILL to TGT child [%d] reached.\n",
          state->io->pid);

    ret = kill(state->io->pid, SIGKILL);
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "kill failed [%d][%s].\n", errno, strerror(errno));
    }

    tevent_req_error(req, ETIMEDOUT);
}

static void get_tgt_timeout_handler(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_tgt_state *state = tevent_req_data(req,
                                            struct sdap_get_tgt_state);
    int ret;

    DEBUG(SSSDBG_TRACE_ALL,
          "timeout for sending SIGTERM to TGT child [%d] reached.\n",
          state->io->pid);

    ret = kill(state->io->pid, SIGTERM);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Sending SIGTERM failed [%d][%s].\n", ret, strerror(ret));
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Setting %d seconds timeout for sending SIGKILL to TGT child\n",
          SIGTERM_TO_SIGKILL_TIME);

    tv = tevent_timeval_current_ofs(SIGTERM_TO_SIGKILL_TIME, 0);

    state->kill_te = tevent_add_timer(ev, req, tv, get_tgt_sigkill_handler, req);
    if (state->kill_te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
        tevent_req_error(req, ECANCELED);
    }
}
