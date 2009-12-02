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

struct io_buffer {
    uint8_t *data;
    size_t size;
};

struct sdap_child_req {
    /* child info */
    pid_t child_pid;
    int read_from_child_fd;
    int write_to_child_fd;

    /* for handling timeout */
    struct tevent_context *ev;
    int timeout;
    struct tevent_timer *timeout_handler;
    struct tevent_req *req;

    /* parameters */
    const char *realm_str;
    const char *princ_str;
    const char *keytab_name;
};

static int sdap_child_req_destructor(void *ptr)
{
    int ret;
    struct sdap_child_req *cr = talloc_get_type(ptr, struct sdap_child_req);

    if (cr == NULL) return EOK;

    if (cr->read_from_child_fd != -1) {
        ret = close(cr->read_from_child_fd);
        if (ret != EOK) {
            ret = errno;
            DEBUG(1, ("close failed [%d][%s].\n", ret, strerror(ret)));
        }
    }
    if (cr->write_to_child_fd != -1) {
        ret = close(cr->write_to_child_fd);
        if (ret != EOK) {
            ret = errno;
            DEBUG(1, ("close failed [%d][%s].\n", ret, strerror(ret)));
        }
    }

    memset(cr, 0, sizeof(struct sdap_child_req));

    return EOK;
}

static void sdap_child_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv, void *pvt)
{
    struct sdap_child_req *lr = talloc_get_type(pvt, struct sdap_child_req);
    int ret;

    if (lr->timeout_handler == NULL) {
        return;
    }

    DEBUG(9, ("timeout for ldap child [%d] reached.\n", lr->child_pid));

    ret = kill(lr->child_pid, SIGKILL);
    if (ret == -1) {
        DEBUG(1, ("kill failed [%d][%s].\n", errno, strerror(errno)));
    }

    tevent_req_error(lr->req, EIO);
}

static errno_t activate_child_timeout_handler(struct sdap_child_req *child_req)
{
    struct timeval tv;

    tv = tevent_timeval_current();
    tv = tevent_timeval_add(&tv,
                            child_req->timeout,
                            0);
    child_req->timeout_handler = tevent_add_timer(child_req->ev, child_req, tv,
                                                  sdap_child_timeout, child_req);
    if (child_req->timeout_handler == NULL) {
        DEBUG(1, ("tevent_add_timer failed.\n"));
        return ENOMEM;
    }

    return EOK;
}

static errno_t prepare_child_argv(TALLOC_CTX *mem_ctx,
                                  struct sdap_child_req *child_req,
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
                                       ldap_child_debug_fd);
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

    argv[--argc] = talloc_strdup(argv, LDAP_CHILD);
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

static errno_t fork_ldap_child(struct sdap_child_req *child_req)
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
        close(pipefd_to_child[1]);
        ret = dup2(pipefd_to_child[0], STDIN_FILENO);
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("dup2 failed [%d][%s].\n", err, strerror(err)));
            return err;
        }

        close(pipefd_from_child[0]);
        ret = dup2(pipefd_from_child[1], STDOUT_FILENO);
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("dup2 failed [%d][%s].\n", err, strerror(err)));
            return err;
        }

        ret = prepare_child_argv(child_req, child_req, &argv);
        if (ret != EOK) {
            DEBUG(1, ("prepare_child_argv.\n"));
            return ret;
        }

        ret = execv(LDAP_CHILD, argv);
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("execv failed [%d][%s].\n", err, strerror(err)));
            return err;
        }
    } else if (pid > 0) { /* parent */
        child_req->child_pid = pid;
        child_req->read_from_child_fd = pipefd_from_child[0];
        close(pipefd_from_child[1]);
        child_req->write_to_child_fd = pipefd_to_child[1];
        close(pipefd_to_child[0]);
        fd_nonblocking(child_req->read_from_child_fd);
        fd_nonblocking(child_req->write_to_child_fd);

    } else { /* error */
        err = errno;
        DEBUG(1, ("fork failed [%d][%s].\n", err, strerror(err)));
        return err;
    }

    return EOK;
}

static errno_t create_ldap_send_buffer(struct sdap_child_req *child_req, struct io_buffer **io_buf)
{
    struct io_buffer *buf;
    size_t rp;

    buf = talloc(child_req, struct io_buffer);
    if (buf == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }

    buf->size = 3*sizeof(int);
    if (child_req->realm_str)
        buf->size += strlen(child_req->realm_str);
    if (child_req->princ_str)
        buf->size += strlen(child_req->princ_str);
    if (child_req->keytab_name)
        buf->size += strlen(child_req->keytab_name);
    DEBUG(7, ("buffer size: %d\n", buf->size));

    buf->data = talloc_size(child_req, buf->size);
    if (buf->data == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        talloc_free(buf);
        return ENOMEM;
    }

    rp = 0;
    /* realm */
    ((uint32_t *)(&buf->data[rp]))[0] =
                        (uint32_t) (child_req->realm_str ?
                                   strlen(child_req->realm_str) : 0);
    rp += sizeof(uint32_t);
    if (child_req->realm_str) {
        memcpy(&buf->data[rp], child_req->realm_str, strlen(child_req->realm_str));
        rp += strlen(child_req->realm_str);
    }

    /* principal */
    ((uint32_t *)(&buf->data[rp]))[0] =
                        (uint32_t) (child_req->princ_str ?
                                   strlen(child_req->princ_str) : 0);
    rp += sizeof(uint32_t);
    if (child_req->princ_str) {
        memcpy(&buf->data[rp], child_req->princ_str, strlen(child_req->princ_str));
        rp += strlen(child_req->princ_str);
    }

    /* keytab */
    ((uint32_t *)(&buf->data[rp]))[0] =
                        (uint32_t) (child_req->keytab_name ?
                                   strlen(child_req->keytab_name) : 0);
    rp += sizeof(uint32_t);
    if (child_req->keytab_name) {
        memcpy(&buf->data[rp], child_req->keytab_name, strlen(child_req->keytab_name));
        rp += strlen(child_req->keytab_name);
    }

    *io_buf = buf;
    return EOK;
}

static int parse_child_response(TALLOC_CTX *mem_ctx,
                                uint8_t *buf, ssize_t size,
                                int  *result,
                                char **ccache)
{
    size_t p = 0;
    uint32_t *len;
    uint32_t *res;
    char *ccn;

    /* ccache size the ccache itself*/
    if ((p + sizeof(uint32_t)) > size) return EINVAL;
    res = ((uint32_t *)(buf+p));
    p += sizeof(uint32_t);

    /* ccache size the ccache itself*/
    if ((p + sizeof(uint32_t)) > size) return EINVAL;
    len = ((uint32_t *)(buf+p));
    p += sizeof(uint32_t);

    if ((p + *len ) > size) return EINVAL;

    ccn = talloc_size(mem_ctx, sizeof(char) * (*len + 1));
    if (ccn == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        return ENOMEM;
    }
    memcpy(ccn, buf+p, sizeof(char) * (*len + 1));
    ccn[*len] = '\0';

    *result = *res;
    *ccache = ccn;
    return EOK;
}

/* ==The-public-async-interface============================================*/

struct sdap_krb5_get_tgt_state {
    struct sdap_child_req *lr;
    ssize_t len;
    uint8_t *buf;
};

static void sdap_krb5_get_tgt_done(struct tevent_req *subreq);

struct tevent_req *sdap_krb5_get_tgt_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          int timeout,
                                          const char *realm_str,
                                          const char *princ_str,
                                          const char *keytab_name)
{
    struct sdap_child_req *child_req = NULL;
    struct sdap_krb5_get_tgt_state *state = NULL;
    int ret;
    struct io_buffer *buf = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;

    /* prepare the data to pass to child */
    child_req = talloc_zero(mem_ctx, struct sdap_child_req);
    if (!child_req) goto fail;

    child_req->ev = ev;
    child_req->read_from_child_fd = -1;
    child_req->write_to_child_fd = -1;
    child_req->realm_str = realm_str;
    child_req->princ_str = princ_str;
    child_req->keytab_name = keytab_name;
    child_req->timeout = timeout;
    talloc_set_destructor((TALLOC_CTX *) child_req, sdap_child_req_destructor);

    ret = create_ldap_send_buffer(child_req, &buf);
    if (ret != EOK) {
        DEBUG(1, ("create_ldap_send_buffer failed.\n"));
        return NULL;
    }

    ret = fork_ldap_child(child_req);
    if (ret != EOK) {
        DEBUG(1, ("fork_ldap_child failed.\n"));
        goto fail;
    }

    ret = write(child_req->write_to_child_fd, buf->data, buf->size);
    close(child_req->write_to_child_fd);
    child_req->write_to_child_fd = -1;
    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("write failed [%d][%s].\n", ret, strerror(ret)));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct sdap_krb5_get_tgt_state);
    if (req == NULL) {
        return NULL;
    }

    state->lr = child_req;

    child_req->req = req;
    ret = activate_child_timeout_handler(child_req);
    if (ret != EOK) {
        DEBUG(1, ("activate_child_timeout_handler failed.\n"));
        return NULL;
    }

    subreq = read_pipe_send(state, ev, child_req->read_from_child_fd);
    if (tevent_req_nomem(subreq, req)) {
        return tevent_req_post(req, ev);
    }
    tevent_req_set_callback(subreq, sdap_krb5_get_tgt_done, req);

    return req;
fail:
    return NULL;
}

static void sdap_krb5_get_tgt_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_krb5_get_tgt_state *state = tevent_req_data(req,
                                                       struct sdap_krb5_get_tgt_state);
    int ret;

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    talloc_zfree(subreq);
    talloc_zfree(state->lr->timeout_handler);
    close(state->lr->read_from_child_fd);
    state->lr->read_from_child_fd = -1;
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

int sdap_krb5_get_tgt_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           int  *result,
                           char **ccname)
{
    struct sdap_krb5_get_tgt_state *state = tevent_req_data(req,
                                                            struct sdap_krb5_get_tgt_state);
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

/* Setup child logging */
int setup_child(struct sdap_id_ctx *ctx)
{
    int ret;
    const char *mech;
    struct tevent_signal *sige;
    unsigned v;
    FILE *debug_filep;

    mech = dp_opt_get_string(ctx->opts->basic,
                             SDAP_SASL_MECH);
    if (!mech) {
        return EOK;
    }

    sige = tevent_add_signal(ctx->be->ev, ctx, SIGCHLD, SA_SIGINFO,
                             child_sig_handler, NULL);
    if (sige == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        return ENOMEM;
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
