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
#include <pwd.h>
#include <sys/stat.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "util/find_uid.h"
#include "db/sysdb.h"
#include "providers/child_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"

#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#else
#define KRB5_CHILD SSSD_LIBEXEC_PATH"/krb5_child"
#endif

static errno_t add_krb5_env(struct dp_option *opts, const char *ccname,
                            struct pam_data *pd)
{
    int ret;
    const char *dummy;
    char *env;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    if (ccname != NULL) {
        env = talloc_asprintf(tmp_ctx, "%s=%s",CCACHE_ENV_NAME, ccname);
        if (env == NULL) {
            DEBUG(1, ("talloc_asprintf failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        ret = pam_add_response(pd, PAM_ENV_ITEM, strlen(env)+1,
                               (uint8_t *) env);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
            goto done;
        }
    }

    dummy = dp_opt_get_cstring(opts, KRB5_REALM);
    if (dummy != NULL) {
        env = talloc_asprintf(tmp_ctx, "%s=%s", SSSD_KRB5_REALM, dummy);
        if (env == NULL) {
            DEBUG(1, ("talloc_asprintf failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        ret = pam_add_response(pd, PAM_ENV_ITEM, strlen(env)+1,
                               (uint8_t *) env);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
            goto done;
        }
    }

    dummy = dp_opt_get_cstring(opts, KRB5_KDC);
    if (dummy != NULL) {
        env = talloc_asprintf(tmp_ctx, "%s=%s", SSSD_KRB5_KDC, dummy);
        if (env == NULL) {
            DEBUG(1, ("talloc_asprintf failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        ret = pam_add_response(pd, PAM_ENV_ITEM, strlen(env)+1,
                               (uint8_t *) env);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t check_if_ccache_file_is_used(uid_t uid, const char *ccname,
                                            bool *result)
{
    int ret;
    size_t offset = 0;
    struct stat stat_buf;
    const char *filename;
    bool active;

    *result = false;

    if (ccname == NULL || *ccname == '\0') {
        return EINVAL;
    }

    if (strncmp(ccname, "FILE:", 5) == 0) {
        offset = 5;
    }

    filename = ccname + offset;

    if (filename[0] != '/') {
        DEBUG(1, ("Only absolute path names are allowed"));
        return EINVAL;
    }

    ret = lstat(filename, &stat_buf);

    if (ret == -1 && errno != ENOENT) {
        DEBUG(1, ("stat failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    } else if (ret == EOK) {
        if (stat_buf.st_uid != uid) {
            DEBUG(1, ("Cache file [%s] exists, but is owned by [%d] instead of "
                      "[%d].\n", filename, stat_buf.st_uid, uid));
            return EINVAL;
        }

        if (!S_ISREG(stat_buf.st_mode)) {
            DEBUG(1, ("Cache file [%s] exists, but is not a regular file.\n",
                      filename));
            return EINVAL;
        }
    }

    ret = check_if_uid_is_active(uid, &active);
    if (ret != EOK) {
        DEBUG(1, ("check_if_uid_is_active failed.\n"));
        return ret;
    }

    if (!active) {
        DEBUG(5, ("User [%d] is not active\n", uid));
    } else {
        DEBUG(9, ("User [%d] is still active, reusing ccache file [%s].\n",
                  uid, filename));
        *result = true;
    }
    return EOK;
}

struct krb5_save_ccname_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;
    const char *name;
    struct sysdb_attrs *attrs;
};

static void krb5_save_ccname_trans(struct tevent_req *subreq);
static void krb5_set_user_attr_done(struct tevent_req *subreq);

static struct tevent_req *krb5_save_ccname_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct sysdb_ctx *sysdb,
                                                struct sss_domain_info *domain,
                                                const char *name,
                                                const char *ccname)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct krb5_save_ccname_state *state;
    int ret;

    if (name == NULL || ccname == NULL) {
        DEBUG(1, ("Missing user or ccache name.\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct krb5_save_ccname_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = NULL;
    state->domain = domain;
    state->name = name;

    state->attrs = sysdb_new_attrs(state);
    ret = sysdb_attrs_add_string(state->attrs, SYSDB_CCACHE_FILE, ccname);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
        goto failed;
    }

    subreq = sysdb_transaction_send(state, ev, sysdb);
    if (subreq == NULL) {
        goto failed;
    }
    tevent_req_set_callback(subreq, krb5_save_ccname_trans, req);

    return req;

failed:
    talloc_free(req);
    return NULL;
}

static void krb5_save_ccname_trans(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct krb5_save_ccname_state *state = tevent_req_data(req,
                                                 struct krb5_save_ccname_state);
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                      state->domain, state->name,
                                      state->attrs, SYSDB_MOD_REP);
    if (subreq == NULL) {
        DEBUG(6, ("Error: Out of memory\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, krb5_set_user_attr_done, req);
}

static void krb5_set_user_attr_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct krb5_save_ccname_state *state = tevent_req_data(req,
                                                 struct krb5_save_ccname_state);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(6, ("Error: %d (%s)\n", ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (subreq == NULL) {
        DEBUG(6, ("Error: Out of memory\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
    return;
}

int krb5_save_ccname_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t create_send_buffer(struct krb5child_req *kr, struct io_buffer **io_buf)
{
    struct io_buffer *buf;
    size_t rp;
    const char *keytab;
    uint32_t validate;

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

    buf->size = 9*sizeof(uint32_t) + strlen(kr->pd->upn) + strlen(kr->ccname) +
                strlen(keytab) +
                kr->pd->authtok_size;
    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK) {
        buf->size += sizeof(uint32_t) + kr->pd->newauthtok_size;
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

    ((uint32_t *)(&buf->data[rp]))[0] = kr->pd->pw_uid;
    rp += sizeof(uint32_t);

    ((uint32_t *)(&buf->data[rp]))[0] = kr->pd->gr_gid;
    rp += sizeof(uint32_t);

    ((uint32_t *)(&buf->data[rp]))[0] = validate;
    rp += sizeof(uint32_t);

    ((uint32_t *)(&buf->data[rp]))[0] = kr->is_offline;
    rp += sizeof(uint32_t);

    ((uint32_t *)(&buf->data[rp]))[0] = (uint32_t) strlen(kr->pd->upn);
    rp += sizeof(uint32_t);

    memcpy(&buf->data[rp], kr->pd->upn, strlen(kr->pd->upn));
    rp += strlen(kr->pd->upn);

    ((uint32_t *)(&buf->data[rp]))[0] = (uint32_t) strlen(kr->ccname);
    rp += sizeof(uint32_t);

    memcpy(&buf->data[rp], kr->ccname, strlen(kr->ccname));
    rp += strlen(kr->ccname);

    ((uint32_t *)(&buf->data[rp]))[0] = (uint32_t) strlen(keytab);
    rp += sizeof(uint32_t);

    memcpy(&buf->data[rp], keytab, strlen(keytab));
    rp += strlen(keytab);

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
        case SSS_PAM_CHAUTHTOK_PRELIM:
            return talloc_get_type(be_req->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                                       struct krb5_ctx);
            break;
        default:
            DEBUG(1, ("Unsupported PAM task.\n"));
            return NULL;
    }
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
    struct krb5child_req *kr = talloc_get_type(ptr, struct krb5child_req);

    if (kr == NULL) return EOK;

    child_cleanup(kr->read_from_child_fd, kr->write_to_child_fd);
    memset(kr, 0, sizeof(struct krb5child_req));

    return EOK;
}

static errno_t krb5_setup(struct be_req *req, struct krb5child_req **krb5_req)
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
    kr->is_offline = false;
    kr->active_ccache_present = true;
    talloc_set_destructor((TALLOC_CTX *) kr, krb5_cleanup);

    kr->pd = pd;
    kr->req = req;
    kr->krb5_ctx = krb5_ctx;

    *krb5_req = kr;

    return EOK;

failed:
    talloc_zfree(kr);

    return err;
}

static errno_t fork_child(struct krb5child_req *kr)
{
    int pipefd_to_child[2];
    int pipefd_from_child[2];
    pid_t pid;
    int ret;
    errno_t err;

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
        /* We need to keep the root privileges to read the keytab file if
         * validation is enabled, otherwise we can drop them here and run
         * krb5_child with user privileges.
         * If authtok_size is zero we are offline and want to create an empty
         * ccache file. In this case we can drop the privileges, too. */
        if (!dp_opt_get_bool(kr->krb5_ctx->opts, KRB5_VALIDATE) ||
            kr->pd->authtok_size == 0) {
            ret = become_user(kr->pd->pw_uid, kr->pd->gr_gid);
            if (ret != EOK) {
                DEBUG(1, ("become_user failed.\n"));
                return ret;
            }
        }

        err = exec_child(kr,
                         pipefd_to_child, pipefd_from_child,
                         KRB5_CHILD, kr->krb5_ctx->child_debug_fd);
        if (err != EOK) {
            DEBUG(1, ("Could not exec LDAP child: [%d][%s].\n",
                      err, strerror(err)));
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

struct handle_child_state {
    struct tevent_context *ev;
    struct krb5child_req *kr;
    uint8_t *buf;
    ssize_t len;
};

static void handle_child_step(struct tevent_req *subreq);
static void handle_child_done(struct tevent_req *subreq);

static struct tevent_req *handle_child_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct krb5child_req *kr)
{
    struct tevent_req *req, *subreq;
    struct handle_child_state *state;
    struct io_buffer *buf;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct handle_child_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->kr = kr;
    state->buf = NULL;
    state->len = 0;

    ret = create_send_buffer(kr, &buf);
    if (ret != EOK) {
        DEBUG(1, ("create_send_buffer failed.\n"));
        goto fail;
    }

    ret = fork_child(kr);
    if (ret != EOK) {
        DEBUG(1, ("fork_child failed.\n"));
        goto fail;
    }

    subreq = write_pipe_send(state, ev, buf->data, buf->size,
                             kr->write_to_child_fd);
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

    close(state->kr->write_to_child_fd);
    state->kr->write_to_child_fd = -1;

    subreq = read_pipe_send(state, state->ev, state->kr->read_from_child_fd);
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

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    close(state->kr->read_from_child_fd);
    state->kr->read_from_child_fd = -1;

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

static void get_user_attr_done(void *pvt, int err, struct ldb_result *res);
static void krb5_resolve_done(struct tevent_req *req);
static void krb5_save_ccname_done(struct tevent_req *req);
static void krb5_child_done(struct tevent_req *req);
static void krb5_pam_handler_cache_done(struct tevent_req *treq);

void krb5_pam_handler(struct be_req *be_req)
{
    struct pam_data *pd;
    const char **attrs;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err = DP_ERR_FATAL;
    int ret;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    if (pd->cmd != SSS_PAM_AUTHENTICATE && pd->cmd != SSS_PAM_CHAUTHTOK &&
        pd->cmd != SSS_PAM_CHAUTHTOK_PRELIM) {
        DEBUG(4, ("krb5 does not handles pam task %d.\n", pd->cmd));
        pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        goto done;
    }

    if (be_is_offline(be_req->be_ctx) &&
        (pd->cmd == SSS_PAM_CHAUTHTOK || pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM)) {
        DEBUG(9, ("Password changes are not possible while offline.\n"));
        pam_status = PAM_AUTHINFO_UNAVAIL;
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    attrs = talloc_array(be_req, const char *, 4);
    if (attrs == NULL) {
        goto done;
    }

    attrs[0] = SYSDB_UPN;
    attrs[1] = SYSDB_HOMEDIR;
    attrs[2] = SYSDB_CCACHE_FILE;
    attrs[3] = NULL;

    ret = sysdb_get_user_attr(be_req, be_req->be_ctx->sysdb,
                              be_req->be_ctx->domain, pd->user, attrs,
                              get_user_attr_done, be_req);

    if (ret) {
        goto done;
    }

    return;

done:
    pd->pam_status = pam_status;

    krb_reply(be_req, dp_err, pd->pam_status);
}

static void get_user_attr_done(void *pvt, int err, struct ldb_result *res)
{
    struct be_req *be_req = talloc_get_type(pvt, struct be_req);
    struct krb5_ctx *krb5_ctx;
    struct krb5child_req *kr = NULL;
    struct tevent_req *req;
    krb5_error_code kerr;
    int ret;
    struct pam_data *pd;
    int pam_status=PAM_SYSTEM_ERR;
    int dp_err = DP_ERR_FATAL;
    const char *ccache_file = NULL;
    const char *realm;

    ret = krb5_setup(be_req, &kr);
    if (ret != EOK) {
        DEBUG(1, ("krb5_setup failed.\n"));
        goto failed;
    }

    pd = kr->pd;
    krb5_ctx = kr->krb5_ctx;

    if (err != LDB_SUCCESS) {
        DEBUG(5, ("sysdb search for upn of user [%s] failed.\n", pd->user));
        goto failed;
    }

    realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
    if (realm == NULL) {
        DEBUG(1, ("Missing Kerberos realm.\n"));
        goto failed;
    }

    switch (res->count) {
    case 0:
        DEBUG(5, ("No attributes for user [%s] found.\n", pd->user));
        goto failed;
        break;

    case 1:
        pd->upn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_UPN, NULL);
        if (pd->upn == NULL) {
            /* NOTE: this is a hack, works only in some environments */
            pd->upn = talloc_asprintf(be_req, "%s@%s", pd->user, realm);
            if (pd->upn == NULL) {
                DEBUG(1, ("failed to build simple upn.\n"));
                goto failed;
            }
            DEBUG(9, ("Using simple UPN [%s].\n", pd->upn));
        }

        kr->homedir = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_HOMEDIR,
                                                  NULL);
        if (kr->homedir == NULL) {
            DEBUG(4, ("Home directory for user [%s] not known.\n", pd->user));
        }

        ccache_file = ldb_msg_find_attr_as_string(res->msgs[0],
                                                  SYSDB_CCACHE_FILE,
                                                  NULL);
        if (ccache_file != NULL) {
            ret = check_if_ccache_file_is_used(pd->pw_uid, ccache_file,
                                               &kr->active_ccache_present);
            if (ret != EOK) {
                DEBUG(1, ("check_if_ccache_file_is_used failed.\n"));
                goto failed;
            }

            kerr = check_for_valid_tgt(ccache_file, realm, pd->upn,
                                       &kr->valid_tgt_present);
            if (kerr != 0) {
                DEBUG(1, ("check_for_valid_tgt failed.\n"));
                goto failed;
            }
        } else {
            kr->active_ccache_present = false;
            kr->valid_tgt_present = false;
            DEBUG(4, ("No ccache file for user [%s] found.\n", pd->user));
        }
        DEBUG(9, ("Ccache_file is [%s] and is %s active and TGT is %s valid.\n",
                  ccache_file ? ccache_file : "not set",
                  kr->active_ccache_present ? "" : "not",
                  kr->valid_tgt_present ? "" : "not"));
        kr->ccname = ccache_file;
        break;

    default:
        DEBUG(1, ("A user search by name (%s) returned > 1 results!\n",
                  pd->user));
        goto failed;
        break;
    }

    req = be_resolve_server_send(kr, be_req->be_ctx->ev, be_req->be_ctx,
                                 krb5_ctx->service->name);
    if (req == NULL) {
        DEBUG(1, ("handle_child_send failed.\n"));
        goto failed;
    }

    tevent_req_set_callback(req, krb5_resolve_done, kr);

    return;

failed:
    talloc_free(kr);

    pd->pam_status = pam_status;
    krb_reply(be_req, dp_err, pd->pam_status);
}

static void krb5_resolve_done(struct tevent_req *req)
{
    struct krb5child_req *kr = tevent_req_callback_data(req,
                                                        struct krb5child_req);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err = DP_ERR_FATAL;
    struct pam_data *pd = kr->pd;
    struct be_req *be_req = kr->req;
    char *msg;
    size_t offset = 0;

    ret = be_resolve_server_recv(req, &kr->srv);
    talloc_zfree(req);
    if (ret) {
        /* all servers have been tried and none
         * was found good, setting offline,
         * but we still have to call the child to setup
         * the ccache file. */
        be_mark_offline(be_req->be_ctx);
        kr->is_offline = true;
    }

    if (kr->ccname == NULL ||
        (be_is_offline(be_req->be_ctx) && !kr->active_ccache_present &&
            !kr->valid_tgt_present) ||
        (!be_is_offline(be_req->be_ctx) && !kr->active_ccache_present)) {
            DEBUG(9, ("Recreating  ccache file.\n"));
            if (kr->ccname != NULL) {
                if (strncmp(kr->ccname, "FILE:", 5) == 0) {
                    offset = 5;
                }
                if (kr->ccname[offset] != '/') {
                    DEBUG(1, ("Ccache file name [%s] is not an absolute path.\n",
                              kr->ccname + offset));
                    goto done;
                }
                ret = unlink(kr->ccname + offset);
                if (ret == -1 && errno != ENOENT) {
                    DEBUG(1, ("unlink [%s] failed [%d][%s].\n", kr->ccname,
                             errno, strerror(errno)));
                    goto done;
                }
            }
            kr->ccname = expand_ccname_template(kr, kr,
                                          dp_opt_get_cstring(kr->krb5_ctx->opts,
                                                             KRB5_CCNAME_TMPL)
                                    );
            if (kr->ccname == NULL) {
                DEBUG(1, ("expand_ccname_template failed.\n"));
                goto done;
            }
    }

    if (be_is_offline(be_req->be_ctx)) {
        DEBUG(9, ("Preparing for offline operation.\n"));
        kr->is_offline = true;

        if (kr->valid_tgt_present) {
            DEBUG(9, ("Valid TGT available, nothing to do.\n"));
            msg = talloc_asprintf(pd, "%s=%s", CCACHE_ENV_NAME, kr->ccname);
            if (msg == NULL) {
                DEBUG(1, ("talloc_asprintf failed.\n"));
                goto done;
            }

            ret = pam_add_response(pd, PAM_ENV_ITEM, strlen(msg) + 1,
                                   (uint8_t *) msg);
            if (ret != EOK) {
                DEBUG(1, ("pam_add_response failed.\n"));
            }

            pam_status = PAM_AUTHINFO_UNAVAIL;
            dp_err = DP_ERR_OFFLINE;
            goto done;
        }
        memset(pd->authtok, 0, pd->authtok_size);
        pd->authtok_size = 0;

        if (kr->active_ccache_present) {
            req = krb5_save_ccname_send(kr, be_req->be_ctx->ev,
                                        be_req->be_ctx->sysdb,
                                        be_req->be_ctx->domain, pd->user,
                                        kr->ccname);
            if (req == NULL) {
                DEBUG(1, ("krb5_save_ccname_send failed.\n"));
                goto done;
            }

            tevent_req_set_callback(req, krb5_save_ccname_done, kr);
            return;
        }
    }

    req = handle_child_send(kr, be_req->be_ctx->ev, kr);
    if (req == NULL) {
        DEBUG(1, ("handle_child_send failed.\n"));
        goto done;
    }

    tevent_req_set_callback(req, krb5_child_done, kr);
    return;

done:
    talloc_free(kr);
    pd->pam_status = pam_status;
    krb_reply(be_req, dp_err, pd->pam_status);
}

static void krb5_child_done(struct tevent_req *req)
{
    struct krb5child_req *kr = tevent_req_callback_data(req,
                                                        struct krb5child_req);
    struct pam_data *pd = kr->pd;
    struct be_req *be_req = kr->req;
    int ret;
    uint8_t *buf;
    ssize_t len;
    ssize_t pref_len;
    int p;
    int32_t *msg_status;
    int32_t *msg_type;
    int32_t *msg_len;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err = DP_ERR_FATAL;

    ret = handle_child_recv(req, pd, &buf, &len);
    talloc_zfree(kr->timeout_handler);
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

    if (*msg_status != PAM_SUCCESS && *msg_status != PAM_AUTHINFO_UNAVAIL) {
        pam_status = *msg_status;
        dp_err = DP_ERR_OK;

        ret = pam_add_response(pd, *msg_type, *msg_len, &buf[p]);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }

        goto done;
    } else {
        pd->pam_status = *msg_status;
    }

    if (*msg_status == PAM_SUCCESS && pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
        pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        goto done;
    }

    pref_len = strlen(CCACHE_ENV_NAME)+1;
    if (*msg_len > pref_len &&
        strncmp((const char *) &buf[p], CCACHE_ENV_NAME"=", pref_len) == 0) {
        kr->ccname = talloc_strndup(kr, (char *) &buf[p+pref_len],
                                   *msg_len-pref_len);
        if (kr->ccname == NULL) {
            DEBUG(1, ("talloc_strndup failed.\n"));
            goto done;
        }
    } else {
        DEBUG(1, ("Missing ccache name in child response [%.*s].\n", *msg_len,
                                                                     &buf[p]));
        goto done;
    }

    if (*msg_status == PAM_AUTHINFO_UNAVAIL) {
        if (kr->srv != NULL) {
            fo_set_port_status(kr->srv, PORT_NOT_WORKING);
        }
        be_mark_offline(be_req->be_ctx);
        kr->is_offline = true;
    } else if (kr->srv != NULL) {
        fo_set_port_status(kr->srv, PORT_WORKING);
    }

    struct sysdb_attrs *attrs;
    attrs = sysdb_new_attrs(kr);
    ret = sysdb_attrs_add_string(attrs, SYSDB_CCACHE_FILE, kr->ccname);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
        goto done;
    }

    req = krb5_save_ccname_send(kr, be_req->be_ctx->ev, be_req->be_ctx->sysdb,
                                be_req->be_ctx->domain, pd->user, kr->ccname);
    if (req == NULL) {
        DEBUG(1, ("krb5_save_ccname_send failed.\n"));
        goto done;
    }

    tevent_req_set_callback(req, krb5_save_ccname_done, kr);
    return;
done:
    talloc_free(kr);
    pd->pam_status = pam_status;
    krb_reply(be_req, dp_err, pd->pam_status);
}

static void krb5_save_ccname_done(struct tevent_req *req)
{
    struct krb5child_req *kr = tevent_req_callback_data(req,
                                                        struct krb5child_req);
    struct pam_data *pd = kr->pd;
    struct be_req *be_req = kr->req;
    struct krb5_ctx *krb5_ctx = kr->krb5_ctx;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err = DP_ERR_FATAL;
    int ret;
    char *password = NULL;

    if (pd->cmd == SSS_PAM_AUTHENTICATE) {
        ret = add_krb5_env(krb5_ctx->opts, kr->ccname, pd);
        if (ret != EOK) {
            DEBUG(1, ("add_krb5_env failed.\n"));
            goto failed;
        }
    }

    ret = sysdb_set_user_attr_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("Saving ccache name failed.\n"));
        goto failed;
    }

    if (kr->is_offline) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        pam_status = PAM_AUTHINFO_UNAVAIL;
        dp_err = DP_ERR_OFFLINE;
        goto failed;
    }

    if (be_req->be_ctx->domain->cache_credentials == TRUE) {

        /* password caching failures are not fatal errors */
        pd->pam_status = PAM_SUCCESS;

        switch(pd->cmd) {
            case SSS_PAM_AUTHENTICATE:
            case SSS_PAM_CHAUTHTOK_PRELIM:
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
            goto failed;
        }

        talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

        req = sysdb_cache_password_send(be_req, be_req->be_ctx->ev,
                                        be_req->be_ctx->sysdb, NULL,
                                        be_req->be_ctx->domain, pd->user,
                                        password);
        if (req == NULL) {
            DEBUG(2, ("cache_password_send failed, offline auth may not work.\n"));
            goto failed;
        }
        tevent_req_set_callback(req, krb5_pam_handler_cache_done, be_req);
        return;
    }

    pam_status = PAM_SUCCESS;
    dp_err = DP_ERR_OK;

failed:
    talloc_free(kr);

    pd->pam_status = pam_status;
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

