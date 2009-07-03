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

static int sdap_handle_destructor(void *mem)
{
    struct sdap_handle *h = talloc_get_type(mem, struct sdap_handle);
    if (h->connected) {
        ldap_unbind_ext(h->ldap, NULL, NULL);
        h->connected = false;
        h->ldap = NULL;
        h->fd = -1;
    }
    return 0;
}

static struct sdap_handle *sdap_handle_create(TALLOC_CTX *memctx)
{
    struct sdap_handle *sh;

    sh = talloc_zero(memctx, struct sdap_handle);
    if (!sh) return NULL;

    sh->fd = -1;

    talloc_set_destructor((TALLOC_CTX *)sh, sdap_handle_destructor);

    return sh;
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

static enum sdap_result sdap_check_result(struct sdap_handle *sh,
                                          int msgid, bool wait_all,
                                          LDAPMessage **msg, int *restype)
{
    struct timeval no_timeout = {0, 0};
    int ret;

    ret = ldap_result(sh->ldap, msgid, wait_all, &no_timeout, msg);
    if (ret == 0) {
        DEBUG(8, ("ldap result not ready yet (%d)\n", msgid));
        /* retry */
        return SDAP_RETRY;
    }
    if (ret == -1) {
        DEBUG(2, ("ldap result not available (%d)\n", msgid));

        /* Fatal error returned, kill the connection, and reset the handle */
        ldap_unbind_ext(sh->ldap, NULL, NULL);
        sh->connected = false;
        sh->ldap = NULL;
        sh->fd = -1;

        return SDAP_ERROR;
    }
    DEBUG(8, ("ldap result returned %d\n", ret));

    *restype = ret;
    return SDAP_SUCCESS;
}


/* ==Connect-to-LDAP-Server=============================================== */

struct sdap_connect_state {
    struct sdap_options *opts;
    struct sdap_handle *sh;

    int msgid;

    struct sdap_msg *reply;
    int result;
};

static void sdap_connect_done(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *pvt);

struct tevent_req *sdap_connect_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sdap_options *opts,
                                     bool use_start_tls)
{
    struct tevent_req *req;
    struct sdap_connect_state *state;
    struct tevent_fd *fde;
    struct timeval tv;
    int ver;
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_connect_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

    state->opts = opts;
    state->sh = sdap_handle_create(state);
    if (!state->sh) {
        talloc_zfree(req);
        return NULL;
    }
    /* Initialize LDAP handler */
    ret = ldap_initialize(&state->sh->ldap, opts->basic[SDAP_URI].value);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_initialize failed: %s\n", ldap_err2string(ret)));
        goto fail;
    }

    /* Force ldap version to 3 */
    ver = LDAP_VERSION3;
    ret = ldap_set_option(state->sh->ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set ldap version to 3\n"));
        goto fail;
    }

    /* Set Network Timeout */
    tv.tv_sec = opts->network_timeout;
    tv.tv_usec = 0;
    ret = ldap_set_option(state->sh->ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("Failed to set network timeout to %d\n",
                  opts->network_timeout));
        goto fail;
    }

    /* Set Default Timeout */
    tv.tv_sec = opts->opt_timeout;
    tv.tv_usec = 0;
    ret = ldap_set_option(state->sh->ldap, LDAP_OPT_TIMEOUT, &tv);
    if (ret != LDAP_OPT_SUCCESS) {
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

    ret = ldap_start_tls(state->sh->ldap, NULL, NULL, &state->msgid);
    if (ret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_start_tls failed: [%s]", ldap_err2string(ret)));
        goto fail;
    }

    state->sh->connected = true;
    ret = get_fd_from_ldap(state->sh->ldap, &state->sh->fd);
    if (ret) goto fail;

    fde = tevent_add_fd(ev, state,
                        state->sh->fd, TEVENT_FD_READ,
                        sdap_connect_done, req);
    if (!fde) {
        DEBUG(1, ("Failed to set up fd event!\n"));
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

static void sdap_connect_done(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_connect_state *state = tevent_req_data(req,
                                          struct sdap_connect_state);
    enum sdap_result res;
    char *errmsg;
    int restype;
    int ret;

    res = sdap_check_result(state->sh, state->msgid, true,
                            &state->reply->msg, &restype);
    if (res != SDAP_SUCCESS) {
        if (res != SDAP_RETRY) {
            tevent_req_error(req, EIO);
        }
        return;
    }

    ret = sdap_msg_attach(state->reply, state->reply->msg);
    if (ret) {
        DEBUG(1, ("Error appending memory: %s(%d)\n", strerror(ret), ret));
    }

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
         * we did not asq to perform tls, just pretend all is fine */
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
    struct sdap_handle *sh;
    const char *user_dn;
    struct berval *pw;
    int msgid;

    struct sdap_msg *reply;
    int result;
};

static void simple_bind_done(struct tevent_context *ev,
                             struct tevent_fd *fde,
                             uint16_t flags, void *pvt);

static struct tevent_req *simple_bind_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           const char *user_dn,
                                           struct berval *pw)
{
    struct tevent_req *req;
    struct simple_bind_state *state;
    struct tevent_fd *fde;
    int ret;

    req = tevent_req_create(memctx, &state, struct simple_bind_state);
    if (!req) return NULL;

    state->reply = talloc(state, struct sdap_msg);
    if (!state->reply) {
        talloc_zfree(req);
        return NULL;
    }

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
        ret = get_fd_from_ldap(sh->ldap, &sh->fd);
        if (ret) goto fail;
    }

    fde = tevent_add_fd(ev, state,
                        sh->fd, TEVENT_FD_READ,
                        simple_bind_done, req);
    if (!fde) {
        talloc_zfree(req);
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

static void simple_bind_done(struct tevent_context *ev,
                             struct tevent_fd *fde,
                             uint16_t flags, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct simple_bind_state *state = tevent_req_data(req,
                                            struct simple_bind_state);
    enum sdap_result res;
    char *errmsg;
    int restype;
    int ret;

    res = sdap_check_result(state->sh, state->msgid, true,
                            &state->reply->msg, &restype);
    if (res != SDAP_SUCCESS) {
        if (res != SDAP_RETRY) {
            tevent_req_error(req, EIO);
        }
        return;
    }

    ret = sdap_msg_attach(state->reply, state->reply->msg);
    if (ret) {
        DEBUG(1, ("Error appending memory: %s(%d)\n", strerror(ret), ret));
    }

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
    struct sysdb_handle *handle;

    struct tevent_fd *fde;
    int msgid;
};

static void sdap_get_users_transaction(struct tevent_req *subreq);
static void sdap_get_users_done(struct tevent_context *ev,
                                struct tevent_fd *fde,
                                uint16_t flags, void *pvt);
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
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_get_users_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;

    DEBUG(5, ("calling ldap_search_ext with [%s].\n", filter));

    ret = ldap_search_ext(state->sh->ldap,
                          opts->basic[SDAP_USER_SEARCH_BASE].value,
                          LDAP_SCOPE_SUBTREE, filter, discard_const(attrs),
                          false, NULL, NULL, NULL, 0, &state->msgid);
    if (ret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", ldap_err2string(ret)));
        goto fail;
    }
    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", state->msgid));

    subreq = sysdb_transaction_send(state, state->ev, sysdb);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_get_users_transaction, req);

    return req;

fail:
    tevent_req_error(req, EIO);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_get_users_transaction(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    state->fde = tevent_add_fd(state->ev, state,
                               state->sh->fd, TEVENT_FD_READ,
                               sdap_get_users_done, req);
    if (!state->fde) {
        DEBUG(1, ("Failed to set up fd event!\n"));
        tevent_req_error(req, ENOMEM);
    }
}

static void sdap_get_users_done(struct tevent_context *ev,
                                struct tevent_fd *fde,
                                uint16_t flags, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    struct tevent_req *subreq;
    LDAPMessage *msg = NULL;
    struct sdap_msg *reply;
    enum sdap_result res;
    char *errmsg;
    int restype;
    int result;
    int ret;

    res = sdap_check_result(state->sh, state->msgid, false,
                            &msg, &restype);
    if (res != SDAP_SUCCESS) {
        if (res != SDAP_RETRY) {
            tevent_req_error(req, EIO);
            return;
        }

        /* make sure fd is readable so we can fetch the next result */
        TEVENT_FD_READABLE(state->fde);
        return;
    }

    if (!msg) {
        tevent_req_error(req, EIO);
        return;
    }

    reply = talloc_zero(state, struct sdap_msg);
    if (!reply) {
        ldap_msgfree(msg);
        tevent_req_error(req, ENOMEM);
        return;
    }

    reply->msg = msg;
    ret = sdap_msg_attach(reply, msg);
    if (ret) {
        DEBUG(1, ("Error appending memory: %s(%d)\n", strerror(ret), ret));
        tevent_req_error(req, EFAULT);
        return;
    }

    switch (restype) {
    case LDAP_RES_SEARCH_REFERENCE:
        /* ignore references for now */
        ldap_msgfree(msg);
        break;

    case LDAP_RES_SEARCH_ENTRY:
        /* FIXME: should we set a timeout tevent timed function ?  */

        /* stop reading until operation is done */
        TEVENT_FD_NOT_READABLE(state->fde);

        subreq = sdap_save_user_send(state, state->ev, state->handle,
                                     state->opts, state->dom,
                                     state->sh, reply);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* attach reply to subreq,
         * will not be needed anymore once subreq is done */
        talloc_steal(subreq, reply);

        tevent_req_set_callback(subreq, sdap_get_users_save_done, req);
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

static void sdap_fake_users_done(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv, void *pvt);

static void sdap_get_users_save_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    struct timeval tv = { 0, 0 };
    struct tevent_timer *te;
    int ret;

    ret = sdap_save_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* unfortunately LDAP libraries consume everything sitting on the wire but
     * do not give us a way to know if there is anything waiting to be read or
     * or not. So schedule a fake fde event and wake up ourselves again. If we
     * get a SDAP_RETRY it is fine.  */

    te = tevent_add_timer(state->ev, state, tv,
                          sdap_fake_users_done, req);
    if (!te) {
        tevent_req_error(req, ENOMEM);
        return;
    }
}

static void sdap_fake_users_done(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);

    sdap_get_users_done(state->ev, state->fde, 0, pvt);
}


int sdap_get_users_recv(struct tevent_req *req)
{
    struct sdap_get_users_state *state = tevent_req_data(req,
                                             struct sdap_get_users_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {

        /* FIXME: send abandon ?
         * read all to flush the read queue ?
         * close the connection ? */

        /* closing for now */
        ldap_unbind_ext(state->sh->ldap, NULL, NULL);
        state->sh->connected = false;
        state->sh->ldap = NULL;
        state->sh->fd = -1;

        return err;
    }

    return EOK;
}

/* ==Search-Groups-with-filter============================================ */

struct sdap_get_groups_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sss_domain_info *dom;
    struct sysdb_handle *handle;

    struct tevent_fd *fde;
    int msgid;
};

static void sdap_get_groups_transaction(struct tevent_req *subreq);
static void sdap_get_groups_done(struct tevent_context *ev,
                                struct tevent_fd *fde,
                                uint16_t flags, void *pvt);
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
    int ret;

    req = tevent_req_create(memctx, &state, struct sdap_get_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;

    DEBUG(5, ("calling ldap_search_ext with [%s].\n", filter));

    ret = ldap_search_ext(state->sh->ldap,
                          opts->basic[SDAP_GROUP_SEARCH_BASE].value,
                          LDAP_SCOPE_SUBTREE, filter, discard_const(attrs),
                          false, NULL, NULL, NULL, 0, &state->msgid);
    if (ret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", ldap_err2string(ret)));
        goto fail;
    }
    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", state->msgid));

    subreq = sysdb_transaction_send(state, state->ev, sysdb);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_get_groups_transaction, req);

    return req;

fail:
    tevent_req_error(req, EIO);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_get_groups_transaction(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                               struct sdap_get_groups_state);
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    state->fde = tevent_add_fd(state->ev, state,
                               state->sh->fd, TEVENT_FD_READ,
                               sdap_get_groups_done, req);
    if (!state->fde) {
        DEBUG(1, ("Failed to set up fd event!\n"));
        tevent_req_error(req, ENOMEM);
    }
}

static void sdap_get_groups_done(struct tevent_context *ev,
                                struct tevent_fd *fde,
                                uint16_t flags, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    struct tevent_req *subreq;
    LDAPMessage *msg = NULL;
    struct sdap_msg *reply;
    enum sdap_result res;
    char *errmsg;
    int restype;
    int result;
    int ret;

    res = sdap_check_result(state->sh, state->msgid, false,
                            &msg, &restype);
    if (res != SDAP_SUCCESS) {
        if (res != SDAP_RETRY) {
            tevent_req_error(req, EIO);
            return;
        }

        /* make sure fd is readable so we can fetch the next result */
        TEVENT_FD_READABLE(state->fde);
        return;
    }

    if (!msg) {
        tevent_req_error(req, EIO);
        return;
    }

    reply = talloc_zero(state, struct sdap_msg);
    if (!reply) {
        ldap_msgfree(msg);
        tevent_req_error(req, ENOMEM);
        return;
    }

    reply->msg = msg;
    ret = sdap_msg_attach(reply, msg);
    if (ret) {
        DEBUG(1, ("Error appending memory: %s(%d)\n", strerror(ret), ret));
        tevent_req_error(req, EFAULT);
        return;
    }

    switch (restype) {
    case LDAP_RES_SEARCH_REFERENCE:
        /* ignore references for now */
        ldap_msgfree(msg);
        break;

    case LDAP_RES_SEARCH_ENTRY:
        /* FIXME: should we set a timeout tevent timed function ?  */

        /* stop reading until operation is done */
        TEVENT_FD_NOT_READABLE(state->fde);

        subreq = sdap_save_group_send(state, state->ev, state->handle,
                                     state->opts, state->dom,
                                     state->sh, reply);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        /* attach reply to subreq,
         * will not be needed anymore once subreq is done */
        talloc_steal(subreq, reply);

        tevent_req_set_callback(subreq, sdap_get_groups_save_done, req);
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

static void sdap_fake_groups_done(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv, void *pvt);

static void sdap_get_groups_save_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    struct timeval tv = { 0, 0 };
    struct tevent_timer *te;
    int ret;

    ret = sdap_save_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* unfortunately LDAP libraries consume everything sitting on the wire but
     * do not give us a way to know if there is anything waiting to be read or
     * or not. So schedule a fake fde event and wake up ourselves again. If we
     * get a SDAP_RETRY it is fine.  */

    te = tevent_add_timer(state->ev, state, tv,
                          sdap_fake_groups_done, req);
    if (!te) {
        tevent_req_error(req, ENOMEM);
        return;
    }
}

static void sdap_fake_groups_done(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    sdap_get_groups_done(state->ev, state->fde, 0, pvt);
}


int sdap_get_groups_recv(struct tevent_req *req)
{
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                             struct sdap_get_groups_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {

        /* FIXME: send abandon ?
         * read all to flush the read queue ?
         * close the connection ? */

        /* closing for now */
        ldap_unbind_ext(state->sh->ldap, NULL, NULL);
        state->sh->connected = false;
        state->sh->ldap = NULL;
        state->sh->fd = -1;

        return err;
    }

    return EOK;
}

