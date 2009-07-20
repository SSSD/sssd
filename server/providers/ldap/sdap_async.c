/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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

#include "db/sysdb.h"
#include "providers/ldap/sdap_async.h"
#include "util/util.h"

/* ==LDAP-Memory-Handling================================================= */

static int lmsg_destructor(void *mem)
{
    ldap_msgfree((LDAPMessage *)mem);
    return 0;
}

static int sdap_msg_attach(TALLOC_CTX *memctx, LDAPMessage *msg)
{
    void *h;

    if (!msg) return EINVAL;

    h = sss_mem_attach(memctx, msg, lmsg_destructor);
    if (!h) return ENOMEM;

    return EOK;
}

/* ==sdap-hanlde-utility-functions======================================== */

static inline void sdap_handle_release(struct sdap_handle *sh);
static int sdap_handle_destructor(void *mem);

static struct sdap_handle *sdap_handle_create(TALLOC_CTX *memctx)
{
    struct sdap_handle *sh;

    sh = talloc_zero(memctx, struct sdap_handle);
    if (!sh) return NULL;

    talloc_set_destructor((TALLOC_CTX *)sh, sdap_handle_destructor);

    return sh;
}

static int sdap_handle_destructor(void *mem)
{
    struct sdap_handle *sh = talloc_get_type(mem, struct sdap_handle);

    sdap_handle_release(sh);

    return 0;
}

static inline void sdap_handle_release(struct sdap_handle *sh)
{
    if (sh->connected) {
        struct sdap_op *op;

        while (sh->ops) {
            op = sh->ops;
            op->callback(op->data, EIO, NULL);
            talloc_free(op);
        }

        talloc_zfree(sh->fde);
        ldap_unbind_ext(sh->ldap, NULL, NULL);
        sh->connected = false;
        sh->ldap = NULL;
    }
}

static int get_fd_from_ldap(LDAP *ldap, int *fd)
{
    int ret;

    ret = ldap_get_option(ldap, LDAP_OPT_DESC, fd);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to get fd from ldap!!\n"));
        *fd = -1;
        return EIO;
    }

    return EOK;
}

/* ==Parse-Results-And-Handle-Disconnections============================== */

static void sdap_process_message(struct sdap_handle *sh, LDAPMessage *msg)
{
    struct sdap_msg *reply = NULL;
    struct sdap_op *op;
    int msgid;
    int msgtype;
    int ret;

    msgid = ldap_msgid(msg);
    if (msgid == -1) {
        DEBUG(2, ("can't fire callback, message id invalid!\n"));
        ldap_msgfree(msg);
        return;
    }

    for (op = sh->ops; op; op = op->next) {
        if (op->msgid == msgid && !op->done) {
            msgtype = ldap_msgtype(msg);

            switch (msgtype) {
            case LDAP_RES_SEARCH_ENTRY:
            case LDAP_RES_SEARCH_REFERENCE:
                /* more ops to come with this msgid */
                ret = EOK;
                break;

            case LDAP_RES_BIND:
            case LDAP_RES_SEARCH_RESULT:
            case LDAP_RES_MODIFY:
            case LDAP_RES_ADD:
            case LDAP_RES_DELETE:
            case LDAP_RES_MODDN:
            case LDAP_RES_COMPARE:
            case LDAP_RES_EXTENDED:
            case LDAP_RES_INTERMEDIATE:
                /* no more results expected with this msgid */
                op->done = true;
                ret = EOK;
                break;

            default:
                /* unkwon msg type ?? */
                DEBUG(1, ("Couldn't figure out the msg type! [%0x]\n",
                          msgtype));
                ret = EIO;
            }

            if (ret == EOK) {
                reply = talloc(op, struct sdap_msg);
                if (!reply) {
                    ldap_msgfree(msg);
                    ret = ENOMEM;
                } else {
                    reply->msg = msg;
                    ret = sdap_msg_attach(reply, msg);
                    if (ret != EOK) {
                        ldap_msgfree(msg);
                        talloc_zfree(reply);
                    }
                }
            }

            op->callback(op->data, ret, reply);

            break;
        }
    }

    if (op == NULL) {
        DEBUG(2, ("Unmatched msgid, discarding message (type: %0x)\n",
                  ldap_msgtype(msg)));
        return;
    }
}

static void sdap_ldap_results(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *pvt)
{
    struct sdap_handle *sh = talloc_get_type(pvt, struct sdap_handle);
    struct timeval no_timeout = {0, 0};
    LDAPMessage *msg;
    int ret;

    while (1) {
        if (!sh->connected) {
            DEBUG(2, ("FDE fired but LDAP connection is not connected!\n"));
            sdap_handle_release(sh);
            return;
        }

        ret = ldap_result(sh->ldap, LDAP_RES_ANY, 0, &no_timeout, &msg);
        if (ret == 0) {
            DEBUG(6, ("FDE fired but ldap_result found nothing!\n"));
            return;
        }

        if (ret == -1) {
            DEBUG(4, ("ldap_result gave -1, something bad happend!\n"));

            sdap_handle_release(sh);
            return;
        }

        sdap_process_message(sh, msg);
    }
}

static int sdap_install_ldap_callbacks(struct sdap_handle *sh,
                                       struct tevent_context *ev)
{
    int fd;
    int ret;

    ret = get_fd_from_ldap(sh->ldap, &fd);
    if (ret) return ret;

    sh->fde = tevent_add_fd(ev, sh, fd, TEVENT_FD_READ, sdap_ldap_results, sh);
    if (!sh->fde) return ENOMEM;

    return EOK;
}


/* ==LDAP-Operations-Helpers============================================== */

static int sdap_op_destructor(void *mem)
{
    struct sdap_op *op = (struct sdap_op *)mem;

    DLIST_REMOVE(op->sh->ops, op);

    if (op->done) return 0;

    /* we don't check the result here, if a message was really abandoned,
     * hopefully the server will get an abandon.
     * If the operation was already fully completed, this is going to be
     * just a noop */
    ldap_abandon_ext(op->sh->ldap, op->msgid, NULL, NULL);

    return 0;
}

static void sdap_op_timeout(struct tevent_req *req)
{
    struct sdap_op *op = tevent_req_callback_data(req, struct sdap_op);

    /* should never happen, but just in case */
    if (op->done) {
        DEBUG(2, ("Timeout happened after op was finished !?\n"));
        return;
    }

    /* signal the caller that we have a timeout */
    op->callback(op->data, ETIME, NULL);

    /* send back to the server an abandon (see destructor) and free the op */
    talloc_free(op);
}

static int sdap_op_add(TALLOC_CTX *memctx, struct tevent_context *ev,
                       struct sdap_handle *sh, int msgid,
                       sdap_op_callback_t *callback, void *data,
                       int timeout)
{
    struct sdap_op *op;

    op = talloc_zero(memctx, struct sdap_op);
    if (!op) return ENOMEM;

    op->sh = sh;
    op->msgid = msgid;
    op->callback = callback;
    op->data = data;

    /* check if we need to set a timeout */
    if (timeout) {
        struct tevent_req *req;
        struct timeval tv;

        tv = tevent_timeval_current();
        tv = tevent_timeval_add(&tv, timeout, 0);

        /* allocate on op, so when it get freed the timeout is removed */
        req = tevent_wakeup_send(op, ev, tv);
        if (!req) {
            talloc_zfree(op);
            return ENOMEM;
        }
        tevent_req_set_callback(req, sdap_op_timeout, op);
    }

    DLIST_ADD(sh->ops, op);

    talloc_set_destructor((TALLOC_CTX *)op, sdap_op_destructor);

    return EOK;
}

/* ==Connect-to-LDAP-Server=============================================== */

struct sdap_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    int msgid;

    struct sdap_msg *reply;
    int result;
};

static void sdap_connect_done(void *pvt, int error, struct sdap_msg *reply);

struct tevent_req *sdap_connect_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sdap_options *opts,
                                     bool use_start_tls)
{
    struct tevent_req *req;
    struct sdap_connect_state *state;
    struct timeval tv;
    int ver;
    int lret;
    int ret = EOK;

    req = tevent_req_create(memctx, &state, struct sdap_connect_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sdap_handle_create(state);
    if (!state->sh) {
        talloc_zfree(req);
        return NULL;
    }
    /* Initialize LDAP handler */
    lret = ldap_initialize(&state->sh->ldap, opts->basic[SDAP_URI].value);
    if (lret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_initialize failed: %s\n", ldap_err2string(ret)));
        goto fail;
    }

    /* Force ldap version to 3 */
    ver = LDAP_VERSION3;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set ldap version to 3\n"));
        goto fail;
    }

    /* Set Network Timeout */
    tv.tv_sec = opts->network_timeout;
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set network timeout to %d\n",
                  opts->network_timeout));
        goto fail;
    }

    /* Set Default Timeout */
    tv.tv_sec = opts->opt_timeout;
    tv.tv_usec = 0;
    lret = ldap_set_option(state->sh->ldap, LDAP_OPT_TIMEOUT, &tv);
    if (lret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set default timeout to %d\n",
                  opts->opt_timeout));
        goto fail;
    }

    /* if we do not use start_tls the connection is not really connected yet
     * just fake an async procedure and leave connection to the bind call */
    if (!use_start_tls) {
        tevent_req_post(req, ev);
        return req;
    }

    DEBUG(4, ("Executing START TLS\n"));

    lret = ldap_start_tls(state->sh->ldap, NULL, NULL, &state->msgid);
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_start_tls failed: [%s]", ldap_err2string(ret)));
        goto fail;
    }

    state->sh->connected = true;
    ret = sdap_install_ldap_callbacks(state->sh, state->ev);
    if (ret) goto fail;

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, state->sh, state->msgid,
                      sdap_connect_done, req, 5);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    if (ret) {
        tevent_req_error(req, ret);
    } else {
        if (lret == LDAP_SERVER_DOWN) {
            tevent_req_error(req, EAGAIN);
        } else {
            tevent_req_error(req, EIO);
        }
    }
    tevent_req_post(req, ev);
    return req;
}

static void sdap_connect_done(void *pvt, int error, struct sdap_msg *reply)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_connect_state *state = tevent_req_data(req,
                                          struct sdap_connect_state);
    char *errmsg;
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    ret = ldap_parse_result(state->sh->ldap, state->reply->msg,
                            &state->result, NULL, &errmsg, NULL, NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d)\n", state->msgid));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(3, ("START TLS result: %s(%d), %s\n",
              ldap_err2string(state->result), state->result, errmsg));

/* FIXME: take care that ldap_install_tls might block */
    ret = ldap_install_tls(state->sh->ldap);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_install_tls failed.\n"));
        state->result = ret;
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

int sdap_connect_recv(struct tevent_req *req,
                      TALLOC_CTX *memctx,
                      struct sdap_handle **sh)
{
    struct sdap_connect_state *state = tevent_req_data(req,
                                                  struct sdap_connect_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        /* if tstate shows in progress, it is because
         * we did not ask to perform tls, just pretend all is fine */
        if (tstate != TEVENT_REQ_IN_PROGRESS) {
            return err;
        }
    }

    *sh = talloc_steal(memctx, state->sh);
    if (!*sh) {
        return ENOMEM;
    }
    return EOK;
}

/* ==Simple-Bind========================================================== */

struct simple_bind_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    const char *user_dn;
    struct berval *pw;
    int msgid;

    struct sdap_msg *reply;
    int result;
};

static void simple_bind_done(void *pvt, int error, struct sdap_msg *reply);

static struct tevent_req *simple_bind_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           const char *user_dn,
                                           struct berval *pw)
{
    struct tevent_req *req;
    struct simple_bind_state *state;
    int ret = EOK;

    req = tevent_req_create(memctx, &state, struct simple_bind_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

    state->ev = ev;
    state->sh = sh;
    state->user_dn = user_dn;
    state->pw = pw;

    DEBUG(4, ("Executing simple bind as: %s\n", state->user_dn));

    ret = ldap_sasl_bind(state->sh->ldap, state->user_dn, LDAP_SASL_SIMPLE,
                         state->pw, NULL, NULL, &state->msgid);
    if (ret == -1 || state->msgid == -1) {
        DEBUG(1, ("ldap_bind failed\n"));
        goto fail;
    }
    DEBUG(8, ("ldap simple bind sent, msgid = %d\n", state->msgid));

    if (!sh->connected) {
        sh->connected = true;
        ret = sdap_install_ldap_callbacks(sh, ev);
        if (ret) goto fail;
    }

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, sh, state->msgid,
                      simple_bind_done, req, 5);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    if (ret == LDAP_SERVER_DOWN) {
        tevent_req_error(req, EAGAIN);
    } else {
        tevent_req_error(req, EIO);
    }
    tevent_req_post(req, ev);
    return req;
}

static void simple_bind_done(void *pvt, int error, struct sdap_msg *reply)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct simple_bind_state *state = tevent_req_data(req,
                                            struct simple_bind_state);
    char *errmsg;
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    ret = ldap_parse_result(state->sh->ldap, state->reply->msg,
                            &state->result, NULL, &errmsg, NULL, NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d)\n", state->msgid));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(3, ("Bind result: %s(%d), %s\n",
              ldap_err2string(state->result), state->result, errmsg));

    tevent_req_done(req);
}

static int simple_bind_recv(struct tevent_req *req, int *ldaperr)
{
    struct simple_bind_state *state = tevent_req_data(req,
                                            struct simple_bind_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        *ldaperr = LDAP_OTHER;
        return -1;
    }

    *ldaperr = state->result;
    return 0;
}

/* ==Authenticaticate-User-by-DN========================================== */

struct sdap_auth_state {
    const char *user_dn;
    struct berval pw;
    int msgid;
    int result;
};

static void sdap_auth_done(struct tevent_req *subreq);

struct tevent_req *sdap_auth_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_handle *sh,
                                  const char *user_dn,
                                  const char *password)
{
    struct tevent_req *req, *subreq;
    struct sdap_auth_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_auth_state);
    if (!req) return NULL;

    state->user_dn = user_dn;
    if (password) {
        state->pw.bv_val = discard_const(password);
        state->pw.bv_len = strlen(password);
    } else {
        state->pw.bv_val = NULL;
        state->pw.bv_len = 0;
    }

    subreq = simple_bind_send(state, ev, sh, user_dn, &state->pw);
    if (!subreq) {
        tevent_req_error(req, EFAULT);
        return tevent_req_post(req, ev);
    }

    tevent_req_set_callback(subreq, sdap_auth_done, req);
    return req;
}

static void sdap_auth_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_auth_state *state = tevent_req_data(req,
                                                 struct sdap_auth_state);
    int ret;

    ret = simple_bind_recv(subreq, &state->result);
    if (ret == -1) {
        tevent_req_error(req, EFAULT);
        return;
    }
    tevent_req_done(req);
}

int sdap_auth_recv(struct tevent_req *req, enum sdap_result *result)
{
    struct sdap_auth_state *state = tevent_req_data(req,
                                                 struct sdap_auth_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        *result = SDAP_ERROR;
        return err;
    }
    switch (state->result) {
        case LDAP_SUCCESS:
            *result = SDAP_AUTH_SUCCESS;
            break;
        case LDAP_INVALID_CREDENTIALS:
            *result = SDAP_AUTH_FAILED;
            break;
        default:
            *result = SDAP_ERROR;
    }
    return EOK;
}


/* ==Save-User-Entry====================================================== */

struct sdap_save_user_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sss_domain_info *dom;

    struct sysdb_attrs *attrs;
};

static void sdap_save_user_done(struct tevent_req *subreq);

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static struct tevent_req *sdap_save_user_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sysdb_handle *handle,
                                              struct sdap_options *opts,
                                              struct sss_domain_info *dom,
                                              struct sdap_handle *sh,
                                              struct sdap_msg *entry)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_user_state *state;
    struct ldb_message_element *el;
    int ret;
    const char *name;
    const char *pwd;
    const char *gecos;
    const char *homedir;
    const char *shell;
    long int l;
    uid_t uid;
    gid_t gid;

    req = tevent_req_create(memctx, &state, struct sdap_save_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->sh = sh;
    state->dom = dom;
    state->opts = opts;

    ret = sdap_parse_user(state, state->opts, state->sh,
                          entry, &state->attrs, NULL);
    if (ret) goto fail;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_NAME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        ret = EINVAL;
        goto fail;
    }
    name = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_PWD].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) pwd = NULL;
    else pwd = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_GECOS].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) gecos = NULL;
    else gecos = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_HOME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) homedir = NULL;
    else homedir = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_SHELL].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) shell = NULL;
    else shell = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_UID].sys_name, &el);
    if (ret) goto fail;
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    uid = l;

    ret = sysdb_attrs_get_el(state->attrs,
                             opts->user_map[SDAP_AT_USER_GID].sys_name, &el);
    if (ret) goto fail;
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    gid = l;

    DEBUG(6, ("Storing info for user %s\n", name));

    subreq = sysdb_store_user_send(state, state->ev, state->handle,
                                   state->dom, name, pwd, uid, gid,
                                   gecos, homedir, shell);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_save_user_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_save_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_store_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_save_user_recv(struct tevent_req *req)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (!err) return EIO;
        return err;
    }

    return EOK;
}


/* ==Save-Group-Entry===================================================== */

struct sdap_save_group_state {
    struct tevent_context *ev;
    struct sysdb_handle *handle;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sss_domain_info *dom;

    struct sysdb_attrs *attrs;
};

static void sdap_save_group_done(struct tevent_req *subreq);

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static struct tevent_req *sdap_save_group_send(TALLOC_CTX *memctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct sdap_options *opts,
                                               struct sss_domain_info *dom,
                                               struct sdap_handle *sh,
                                               struct sdap_msg *entry)
{
    struct tevent_req *req, *subreq;
    struct sdap_save_group_state *state;
    struct ldb_message_element *el;
    int i, ret;
    char *name;
    const char **members;
    long int l;
    gid_t gid;

    req = tevent_req_create(memctx, &state, struct sdap_save_group_state);
    if (!req) return NULL;

    state->ev = ev;
    state->handle = handle;
    state->sh = sh;
    state->dom = dom;
    state->opts = opts;

    ret = sdap_parse_group(state, state->opts, state->sh,
                           entry, &state->attrs, NULL);
    if (ret) goto fail;

    ret = sysdb_attrs_get_el(state->attrs,
                          opts->group_map[SDAP_AT_GROUP_NAME].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) {
        ret = EINVAL;
        goto fail;
    }
    name = (char *)el->values[0].data;

    ret = sysdb_attrs_get_el(state->attrs,
                          opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
    if (ret) goto fail;
    if (el->num_values == 0) members = NULL;
    else {
        members = talloc_array(state, const char *, el->num_values +1);
        if (!members) {
            ret = ENOMEM;
            goto fail;
        }
        for (i = 0; i < el->num_values; i++) {
            members[i] = (char *)el->values[i].data;
        }
        members[i] =  NULL;
    }

    ret = sysdb_attrs_get_el(state->attrs,
                          opts->group_map[SDAP_AT_GROUP_GID].sys_name, &el);
    if (ret) goto fail;
    errno = 0;
    l = strtol((const char *)el->values[0].data, NULL, 0);
    if (errno) {
        ret = EINVAL;
        goto fail;
    }
    gid = l;

    DEBUG(6, ("Storing info for group %s\n", name));

    subreq = sysdb_store_group_send(state, state->ev, state->handle,
                                    state->dom, name, gid, members);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_save_group_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_save_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_store_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_save_group_recv(struct tevent_req *req)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (!err) return EIO;
        return err;
    }

    return EOK;
}


/* ==Search-Users-with-filter============================================= */

struct sdap_get_users_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    const char **attrs;
    const char *filter;

    struct sysdb_handle *handle;
    int msgid;
};

static void sdap_get_users_transaction(struct tevent_req *subreq);
static void sdap_get_users_done(void *pvt, int error,
                                struct sdap_msg *reply);
static void sdap_get_users_save_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_users_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_users_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->filter = filter;
    state->attrs = attrs;

    subreq = sysdb_transaction_send(state, state->ev, sysdb);
    if (!subreq) return NULL;
    tevent_req_set_callback(subreq, sdap_get_users_transaction, req);

    return req;
}

static void sdap_get_users_transaction(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    int lret, ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(5, ("calling ldap_search_ext with [%s].\n", state->filter));

    lret = ldap_search_ext(state->sh->ldap,
                           state->opts->basic[SDAP_USER_SEARCH_BASE].value,
                           LDAP_SCOPE_SUBTREE, state->filter,
                           discard_const(state->attrs),
                           false, NULL, NULL, NULL, 0, &state->msgid);
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", ldap_err2string(lret)));
        tevent_req_error(req, EIO);
        return;
    }
    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", state->msgid));

    /* FIXME: get timeouts from configuration, for now 10 minutes */
    ret = sdap_op_add(state, state->ev, state->sh, state->msgid,
                      sdap_get_users_done, req, 600);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        tevent_req_error(req, ret);
    }
}

static void sdap_get_users_done(void *pvt, int error, struct sdap_msg *reply)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    struct tevent_req *subreq;
    char *errmsg;
    int result;
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    switch (ldap_msgtype(reply->msg)) {
    case LDAP_RES_SEARCH_REFERENCE:
        /* ignore references for now */
        talloc_free(reply);
        break;

    case LDAP_RES_SEARCH_ENTRY:
        /* FIXME: should we set a timeout tevent timed function ?  */

        /* FIXME: use a queue of requests so they are performed one at
         * a time (tevent_queue_*) */
        subreq = sdap_save_user_send(state, state->ev, state->handle,
                                     state->opts, state->dom,
                                     state->sh, reply);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_users_save_done, req);
        /* attach reply to subreq,
         * will not be needed anymore once subreq is done */
        talloc_steal(subreq, reply);

        break;

    case LDAP_RES_SEARCH_RESULT:
        /* End of the story */

        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, NULL, NULL, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(2, ("ldap_parse_result failed (%d)\n", state->msgid));
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(3, ("Search result: %s(%d), %s\n",
                  ldap_err2string(result), result, errmsg));

        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
        break;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static void sdap_get_users_save_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_save_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
}

int sdap_get_users_recv(struct tevent_req *req)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    return EOK;
}

/* ==Search-Groups-with-filter============================================ */

struct sdap_get_groups_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    const char **attrs;
    const char *filter;

    struct sysdb_handle *handle;
    int msgid;
};

static void sdap_get_groups_transaction(struct tevent_req *subreq);
static void sdap_get_groups_done(void *pvt, int error,
                                 struct sdap_msg *reply);
static void sdap_get_groups_save_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_groups_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_groups_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->filter = filter;
    state->attrs = attrs;

    subreq = sysdb_transaction_send(state, state->ev, sysdb);
    if (!subreq) return NULL;
    tevent_req_set_callback(subreq, sdap_get_groups_transaction, req);

    return req;
}

static void sdap_get_groups_transaction(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                               struct sdap_get_groups_state);
    int ret, lret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(5, ("calling ldap_search_ext with [%s].\n", state->filter));

    lret = ldap_search_ext(state->sh->ldap,
                           state->opts->basic[SDAP_GROUP_SEARCH_BASE].value,
                           LDAP_SCOPE_SUBTREE, state->filter,
                           discard_const(state->attrs),
                           false, NULL, NULL, NULL, 0, &state->msgid);
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", ldap_err2string(lret)));
        tevent_req_error(req, EIO);
        return;
    }
    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", state->msgid));

    /* FIXME: get timeouts from configuration, for now 10 minutes */
    ret = sdap_op_add(state, state->ev, state->sh, state->msgid,
                      sdap_get_groups_done, req, 600);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        tevent_req_error(req, ret);
    }
}

static void sdap_get_groups_done(void *pvt, int error,
                                 struct sdap_msg *reply)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    struct tevent_req *subreq;
    char *errmsg;
    int result;
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    switch (ldap_msgtype(reply->msg)) {
    case LDAP_RES_SEARCH_REFERENCE:
        /* ignore references for now */
        talloc_free(reply);
        break;

    case LDAP_RES_SEARCH_ENTRY:
        /* FIXME: should we set a timeout tevent timed function ?  */

        /* FIXME: use a queue of requests so they are performed one at
         * a time (tevent_queue_*) */
        subreq = sdap_save_group_send(state, state->ev, state->handle,
                                     state->opts, state->dom,
                                     state->sh, reply);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_groups_save_done, req);
        /* attach reply to subreq,
         * will not be needed anymore once subreq is done */
        talloc_steal(subreq, reply);

        break;

    case LDAP_RES_SEARCH_RESULT:
        /* End of the story */

        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, NULL, NULL, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(2, ("ldap_parse_result failed (%d)\n", state->msgid));
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(3, ("Search result: %s(%d), %s\n",
                  ldap_err2string(result), result, errmsg));

        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
        break;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static void sdap_get_groups_save_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_save_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
}

int sdap_get_groups_recv(struct tevent_req *req)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    return EOK;
}

/* ==Initgr-call-(groups-a-user-is-member-of)============================= */

struct sdap_get_initgr_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    const char *name;
    const char **grp_attrs;

    const char *filter;

    struct sysdb_handle *handle;
    int msgid;
};

static void sdap_get_initgr_process(struct tevent_req *subreq);
static void sdap_get_initgr_transaction(struct tevent_req *subreq);
static void sdap_get_initgr_done(void *pvt, int error, struct sdap_msg *reply);
static void sdap_get_initgr_save_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_initgr_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sss_domain_info *dom,
                                        struct sysdb_ctx *sysdb,
                                        struct sdap_options *opts,
                                        struct sdap_handle *sh,
                                        const char *name,
                                        const char **grp_attrs)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_initgr_state *state;
    struct timeval tv = {0, 0};
    const char **attrs;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_get_initgr_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->sh = sh;
    state->name = name;
    state->grp_attrs = grp_attrs;

    switch (opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:

        subreq = tevent_wakeup_send(state, ev, tv);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_process, req);
        break;

    case SDAP_SCHEMA_RFC2307BIS:

        attrs = talloc_array(state, const char *, 2);
        if (!attrs) {
            ret = ENOMEM;
            goto fail;
        }
        attrs[0] = SYSDB_ORIG_DN;
        attrs[1] = NULL;

        subreq = sysdb_search_user_by_name_send(state, ev, sysdb, NULL,
                                                dom, name, attrs);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_process, req);
        break;

    default:
        ret = EINVAL;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, EIO);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_get_initgr_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    struct ldb_message *msg;
    const char *user_dn;
    int ret;

    switch (state->opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:

        if (!tevent_wakeup_recv(subreq)) {
            tevent_req_error(req, EFAULT);
            return;
        }
        talloc_zfree(subreq);

        state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                           state->opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                           state->name,
                           state->opts->group_map[SDAP_OC_GROUP].name);
        break;

    case SDAP_SCHEMA_RFC2307BIS:

        ret = sysdb_search_user_recv(subreq, state, &msg);
        talloc_zfree(subreq);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }

        user_dn = ldb_msg_find_attr_as_string(msg, SYSDB_ORIG_DN, NULL);
        if (!user_dn) {
            tevent_req_error(req, ENOENT);
            return;
        }

        state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                            state->opts->user_map[SDAP_AT_GROUP_MEMBER].name,
                            user_dn,
                            state->opts->user_map[SDAP_OC_GROUP].name);

        talloc_free(msg);
        break;

    default:
        tevent_req_error(req, EINVAL);
        return;
    }

    if (!state->filter) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = sysdb_transaction_send(state, state->ev, state->sysdb);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sdap_get_initgr_transaction, req);
}

static void sdap_get_initgr_transaction(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    int ret, lret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(5, ("calling ldap_search_ext with filter:[%s].\n", state->filter));

    lret = ldap_search_ext(state->sh->ldap,
                           state->opts->basic[SDAP_GROUP_SEARCH_BASE].value,
                           LDAP_SCOPE_SUBTREE, state->filter,
                           discard_const(state->grp_attrs),
                           false, NULL, NULL, NULL, 0, &state->msgid);
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", ldap_err2string(lret)));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", state->msgid));

    /* FIXME: get timeouts from configuration, for now 10 minutes */
    ret = sdap_op_add(state, state->ev, state->sh, state->msgid,
                      sdap_get_initgr_done, req, 600);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        tevent_req_error(req, ret);
    }
}

static void sdap_get_initgr_done(void *pvt, int error, struct sdap_msg *reply)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_initgr_state *state = tevent_req_data(req,
                                               struct sdap_get_initgr_state);
    struct tevent_req *subreq;
    char *errmsg;
    int result;
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    switch (ldap_msgtype(reply->msg)) {
    case LDAP_RES_SEARCH_REFERENCE:
        /* ignore references for now */
        talloc_free(reply);
        break;

    case LDAP_RES_SEARCH_ENTRY:
        /* FIXME: should we set a timeout tevent timed function ?  */

        /* FIXME: use a queue of requests so they are performed one at
         * a time (tevent_queue_*) */
        subreq = sdap_save_group_send(state, state->ev, state->handle,
                                     state->opts, state->dom,
                                     state->sh, reply);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_initgr_save_done, req);
        /* attach reply to subreq,
         * will not be needed anymore once subreq is done */
        talloc_steal(subreq, reply);

        break;

    case LDAP_RES_SEARCH_RESULT:
        /* End of the story */

        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, NULL, NULL, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(2, ("ldap_parse_result failed (%d)\n", state->msgid));
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(3, ("Search result: %s(%d), %s\n",
                  ldap_err2string(result), result, errmsg));

        subreq = sysdb_transaction_commit_send(state, state->ev,
                                               state->handle);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* sysdb_transaction_complete will call tevent_req_done(req) */
        tevent_req_set_callback(subreq, sysdb_transaction_complete, req);
        break;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static void sdap_get_initgr_save_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_save_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
}

int sdap_get_initgr_recv(struct tevent_req *req)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    return EOK;
}

struct sdap_exop_modify_passwd_state {
    struct sdap_handle *sh;
    int msgid;
    char *user_dn;
    char *password;
    char *new_password;
    int result;
    struct sdap_msg *reply;
};

static void sdap_exop_modify_passwd_done(void *pvt, int error, struct sdap_msg *reply);

struct tevent_req *sdap_exop_modify_passwd_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           char *user_dn,
                                           char *password,
                                           char *new_password)
{
    struct tevent_req *req = NULL;
    struct sdap_exop_modify_passwd_state *state;
    int ret;
    BerElement *ber = NULL;
    struct berval *bv = NULL;

    req = tevent_req_create(memctx, &state,
                            struct sdap_exop_modify_passwd_state);
    if (!req) return NULL;

    state->sh = sh;
    state->reply = NULL;

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        DEBUG(7, ("ber_alloc_t failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    ret = ber_printf( ber, "{tststs}", LDAP_TAG_EXOP_MODIFY_PASSWD_ID,
                     user_dn,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_OLD, password,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, new_password);
    if (ret == -1) {
        DEBUG(1, ("ber_printf failed.\n"));
        ber_free(ber, 1);
        talloc_zfree(req);
        return NULL;
    }

    ret = ber_flatten(ber, &bv);
    ber_free(ber, 1);
    if (ret == -1) {
        DEBUG(1, ("ber_flatten failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    DEBUG(4, ("Executing extended operation\n"));

    ret = ldap_extended_operation(state->sh->ldap, LDAP_EXOP_MODIFY_PASSWD,
                                  bv, NULL, NULL, &state->msgid);
    ber_bvfree(bv);
    if (ret == -1 || state->msgid == -1) {
        DEBUG(1, ("ldap_extended_operation failed\n"));
        goto fail;
    }
    DEBUG(8, ("ldap_extended_operation sent, msgid = %d\n", state->msgid));

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, state->sh, state->msgid,
                      sdap_exop_modify_passwd_done, req, 5);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, EIO);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_exop_modify_passwd_done(void *pvt, int error, struct sdap_msg *reply)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);
    char *errmsg;
    int ret;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    state->reply = talloc_steal(state, reply);

    ret = ldap_parse_result(state->sh->ldap, state->reply->msg,
                            &state->result, NULL, &errmsg, NULL, NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d)\n", state->msgid));
        tevent_req_error(req, EIO);
        return;
    }

    DEBUG(3, ("ldap_extended_operation result: %s(%d), %s\n",
              ldap_err2string(state->result), state->result, errmsg));

    tevent_req_done(req);
}

int sdap_exop_modify_passwd_recv(struct tevent_req *req,
                                 enum sdap_result *result)
{
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);
    enum tevent_req_state tstate;
    uint64_t err;

    *result = SDAP_ERROR;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    if (state->result == LDAP_SUCCESS) {
        *result = SDAP_SUCCESS;
    }

    return EOK;
}
