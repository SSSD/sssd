/*
    SSSD

    proxy_auth.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include "providers/proxy/proxy.h"

struct proxy_client_ctx {
    struct be_req *be_req;
    struct proxy_auth_ctx *auth_ctx;
};

static struct tevent_req *proxy_child_send(TALLOC_CTX *mem_ctx,
                                           struct proxy_auth_ctx *ctx,
                                           struct be_req *be_req);
static void proxy_child_done(struct tevent_req *child_req);
void proxy_pam_handler(struct be_req *req)
{
    struct pam_data *pd;
    struct proxy_auth_ctx *ctx;
    struct tevent_req *child_req = NULL;
    struct proxy_client_ctx *client_ctx;

    pd = talloc_get_type(req->req_data, struct pam_data);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        case SSS_PAM_ACCT_MGMT:
            ctx = talloc_get_type(req->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                  struct proxy_auth_ctx);
            break;
        case SSS_PAM_SETCRED:
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_CLOSE_SESSION:
            pd->pam_status = PAM_SUCCESS;
            proxy_reply(req, DP_ERR_OK, EOK, NULL);
            return;
        default:
            DEBUG(1, ("Unsupported PAM task.\n"));
            pd->pam_status = PAM_MODULE_UNKNOWN;
            proxy_reply(req, DP_ERR_OK, EINVAL, "Unsupported PAM task");
            return;
    }

    client_ctx = talloc(req, struct proxy_client_ctx);
    if (client_ctx == NULL) {
        proxy_reply(req, DP_ERR_FATAL, ENOMEM, NULL);
        return;
    }
    client_ctx->auth_ctx = ctx;
    client_ctx->be_req = req;

    /* Queue the request and spawn a child if there
     * is an available slot.
     */
    child_req = proxy_child_send(req, ctx, req);
    if (child_req == NULL) {
        /* Could not queue request
         * Return an error
         */
        proxy_reply(req, DP_ERR_FATAL, EINVAL, "Could not queue request\n");
        return;
    }
    tevent_req_set_callback(child_req, proxy_child_done, client_ctx);
    return;
}

struct pc_init_ctx;

static int proxy_child_destructor(TALLOC_CTX *ctx)
{
    struct proxy_child_ctx *child_ctx =
            talloc_get_type(ctx, struct proxy_child_ctx);
    hash_key_t key;
    int hret;

    DEBUG(8, ("Removing proxy child id [%d]\n", child_ctx->id));
    key.type = HASH_KEY_ULONG;
    key.ul = child_ctx->id;
    hret = hash_delete(child_ctx->auth_ctx->request_table, &key);
    if (!(hret == HASH_SUCCESS ||
          hret == HASH_ERROR_KEY_NOT_FOUND)) {
        DEBUG(1, ("Hash error [%d][%s]\n", hret, hash_error_string(hret)));
        /* Nothing we can do about this, so just continue */
    }
    return 0;
}

static struct tevent_req *proxy_child_init_send(TALLOC_CTX *mem_ctx,
                                              struct proxy_child_ctx *child_ctx,
                                              struct proxy_auth_ctx *auth_ctx);
static void proxy_child_init_done(struct tevent_req *subreq);
static struct tevent_req *proxy_child_send(TALLOC_CTX *mem_ctx,
                                           struct proxy_auth_ctx *auth_ctx,
                                           struct be_req *be_req)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct proxy_child_ctx *state;
    int hret;
    hash_key_t key;
    hash_value_t value;
    uint32_t first;

    req = tevent_req_create(mem_ctx, &state, struct proxy_child_ctx);
    if (req == NULL) {
        DEBUG(1, ("Could not send PAM request to child\n"));
        return NULL;
    }

    state->be_req = be_req;
    state->auth_ctx = auth_ctx;
    state->pd = talloc_get_type(be_req->req_data, struct pam_data);

    /* Find an available key */
    key.type = HASH_KEY_ULONG;
    key.ul = auth_ctx->next_id;

    first = auth_ctx->next_id;
    while (auth_ctx->next_id == 0 ||
            hash_has_key(auth_ctx->request_table, &key)) {
        /* Handle overflow, zero is a reserved value
         * Also handle the unlikely case where the next ID
         * is still awaiting being run
         */
        auth_ctx->next_id++;
        key.ul = auth_ctx->next_id;

        if (auth_ctx->next_id == first) {
            /* We've looped through all possible integers! */
            DEBUG(0, ("Serious error: queue is too long!\n"));
            talloc_zfree(req);
            return NULL;
        }
    }

    state->id = auth_ctx->next_id;
    auth_ctx->next_id++;

    value.type = HASH_VALUE_PTR;
    value.ptr = req;
    DEBUG(8, ("Queueing request [%d]\n", key.ul));
    hret = hash_enter(auth_ctx->request_table,
                      &key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(1, ("Could not add request to the queue\n"));
        talloc_zfree(req);
        return NULL;
    }

    talloc_set_destructor((TALLOC_CTX *) state,
                          proxy_child_destructor);

    if (auth_ctx->running < auth_ctx->max_children) {
        /* There's an available slot; start a child
         * to handle the request
         */

        auth_ctx->running++;
        subreq = proxy_child_init_send(auth_ctx, state, auth_ctx);
        if (!subreq) {
            DEBUG(1, ("Could not fork child process\n"));
            auth_ctx->running--;
            talloc_zfree(req);
            return NULL;
        }
        tevent_req_set_callback(subreq, proxy_child_init_done, req);

        state->running = true;
    }
    else {
        /* If there was no available slot, it will be queued
         * until a slot is available
         */
        DEBUG(8, ("All available child slots are full, queuing request\n"));
    }
    return req;
}

static int pc_init_destructor (TALLOC_CTX *ctx)
{
    struct pc_init_ctx *init_ctx =
            talloc_get_type(ctx, struct pc_init_ctx);

    /* If the init request has died, forcibly kill the child */
    kill(init_ctx->pid, SIGKILL);
    return 0;
}

static void pc_init_sig_handler(struct tevent_context *ev,
                           struct tevent_signal *sige, int signum,
                           int count, void *__siginfo, void *pvt);
static void pc_init_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t, void *ptr);
static struct tevent_req *proxy_child_init_send(TALLOC_CTX *mem_ctx,
                                              struct proxy_child_ctx *child_ctx,
                                              struct proxy_auth_ctx *auth_ctx)
{
    struct tevent_req *req;
    struct pc_init_ctx *state;
    char **proxy_child_args;
    struct timeval tv;
    errno_t ret;
    pid_t pid;

    req = tevent_req_create(mem_ctx, &state, struct pc_init_ctx);
    if (req == NULL) {
        DEBUG(1, ("Could not create tevent_req\n"));
        return NULL;
    }

    state->child_ctx = child_ctx;

    state->command = talloc_asprintf(req,
            "%s/proxy_child -d %d%s%s --domain %s --id %d",
            SSSD_LIBEXEC_PATH, debug_level,
            (debug_timestamps ? "" : " --debug-timestamps=0"),
            (debug_to_file ? " --debug-to-files" : ""),
            auth_ctx->be->domain->name,
            child_ctx->id);
    if (state->command == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        return NULL;
    }

    DEBUG(7, ("Starting proxy child with args [%s]\n", state->command));

    pid = fork();
    if (pid < 0) {
        ret = errno;
        DEBUG(1, ("fork failed [%d][%s].\n", ret, strerror(ret)));
        talloc_zfree(req);
        return NULL;
    }

    if (pid == 0) { /* child */
        proxy_child_args = parse_args(state->command);
        execvp(proxy_child_args[0], proxy_child_args);

        ret = errno;
        DEBUG(0, ("Could not start proxy child [%s]: [%d][%s].\n",
                  state->command, ret, strerror(ret)));

        _exit(1);
    }

    else { /* parent */
        state->pid = pid;
        /* Make sure to kill the child process if we abort */
        talloc_set_destructor((TALLOC_CTX *)state, pc_init_destructor);

        state->sige = tevent_add_signal(auth_ctx->be->ev, req,
                                        SIGCHLD, SA_SIGINFO,
                                        pc_init_sig_handler, req);
        if (state->sige == NULL) {
            DEBUG(1, ("tevent_add_signal failed.\n"));
            talloc_zfree(req);
            return NULL;
        }

        /* Save the init request to the child context.
         * This is technically a layering violation,
         * but it's the only sane way to be able to
         * identify which client is which when it
         * connects to the backend in
         * client_registration()
         */
        child_ctx->init_req = req;

        /* Wait six seconds for the child to connect
         * This is because the connection handler will add
         * its own five-second timeout, and we don't want to
         * be faster here.
         */
        tv = tevent_timeval_current_ofs(6, 0);
        state->timeout = tevent_add_timer(auth_ctx->be->ev, req,
                                          tv, pc_init_timeout, req);

        /* processing will continue once the connection is received
         * in proxy_client_init()
         */
        return req;
    }
}

static void pc_init_sig_handler(struct tevent_context *ev,
                                struct tevent_signal *sige, int signum,
                                int count, void *__siginfo, void *pvt)
{
    int ret;
    int child_status;
    struct tevent_req *req;
    struct pc_init_ctx *init_ctx;

    if (count <= 0) {
        DEBUG(0, ("SIGCHLD handler called with invalid child count\n"));
        return;
    }

    req = talloc_get_type(pvt, struct tevent_req);
    init_ctx = tevent_req_data(req, struct pc_init_ctx);

    DEBUG(7, ("Waiting for child [%d].\n", init_ctx->pid));

    errno = 0;
    ret = waitpid(init_ctx->pid, &child_status, WNOHANG);

    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("waitpid failed [%d][%s].\n", ret, strerror(ret)));
    } else if (ret == 0) {
        DEBUG(1, ("waitpid did not find a child with changed status.\n"));
    } else {
        if (WIFEXITED(child_status)) {
            DEBUG(4, ("child [%d] exited with status [%d].\n", ret,
                      WEXITSTATUS(child_status)));
            tevent_req_error(req, EIO);
        } else if (WIFSIGNALED(child_status)) {
            DEBUG(4, ("child [%d] was terminate by signal [%d].\n", ret,
                      WTERMSIG(child_status)));
            tevent_req_error(req, EIO);
        } else {
            if (WIFSTOPPED(child_status)) {
                DEBUG(1, ("child [%d] was stopped by signal [%d].\n", ret,
                          WSTOPSIG(child_status)));
            }
            if (WIFCONTINUED(child_status)) {
                DEBUG(1, ("child [%d] was resumed by delivery of SIGCONT.\n",
                          ret));
            }
            DEBUG(1, ("Child is still running, no new child is started.\n"));
            return;
        }
    }
}

static void pc_init_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t, void *ptr)
{
    struct tevent_req *req;

    DEBUG(2, ("Client timed out before Identification!\n"));
    req = talloc_get_type(ptr, struct tevent_req);
    tevent_req_error(req, ETIMEDOUT);
}

static errno_t proxy_child_init_recv(struct tevent_req *req,
                                   pid_t *pid,
                                   struct sbus_connection **conn)
{
    struct pc_init_ctx *state;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    state = tevent_req_data(req, struct pc_init_ctx);

    /* Unset the destructor since we initialized successfully.
     * We don't want to kill the child now that it's properly
     * set up.
     */
    talloc_set_destructor((TALLOC_CTX *)state, NULL);

    *pid = state->pid;
    *conn = state->conn;

    return EOK;
}

struct proxy_child_sig_ctx {
    struct proxy_auth_ctx *auth_ctx;
    pid_t pid;
};
static void proxy_child_sig_handler(struct tevent_context *ev,
                                    struct tevent_signal *sige, int signum,
                                    int count, void *__siginfo, void *pvt);
static struct tevent_req *proxy_pam_conv_send(TALLOC_CTX *mem_ctx,
                                              struct proxy_auth_ctx *auth_ctx,
                                              struct sbus_connection *conn,
                                              struct pam_data *pd,
                                              pid_t pid);
static void proxy_pam_conv_done(struct tevent_req *subreq);
static void proxy_child_init_done(struct tevent_req *subreq) {
    int ret;
    struct tevent_signal *sige;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct proxy_child_ctx *child_ctx =
            tevent_req_data(req, struct proxy_child_ctx);
    struct proxy_child_sig_ctx *sig_ctx;

    ret = proxy_child_init_recv(subreq, &child_ctx->pid, &child_ctx->conn);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(6, ("Proxy child init failed [%d]\n", ret));
        tevent_req_error(req, ret);
        return;
    }

    /* An initialized child is available, awaiting the PAM command */
    subreq = proxy_pam_conv_send(req, child_ctx->auth_ctx,
                                 child_ctx->conn, child_ctx->pd,
                                 child_ctx->pid);
    if (!subreq) {
        DEBUG(1,("Could not start PAM conversation\n"));
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, proxy_pam_conv_done, req);

    /* Add a signal handler for the child under the auth_ctx,
     * that way if the child exits after completion of the
     * request, it will still be handled.
     */
    sig_ctx = talloc_zero(child_ctx->auth_ctx, struct proxy_child_sig_ctx);
    if(sig_ctx == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    sig_ctx->auth_ctx = child_ctx->auth_ctx;
    sig_ctx->pid = child_ctx->pid;

    sige = tevent_add_signal(child_ctx->auth_ctx->be->ev,
                             child_ctx->auth_ctx,
                             SIGCHLD, SA_SIGINFO,
                             proxy_child_sig_handler,
                             sig_ctx);
    if (sige == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* Steal the signal context onto the signal event
     * so that when the signal is freed, the context
     * will go with it.
     */
    talloc_steal(sige, sig_ctx);
}

static void remove_sige(struct tevent_context *ev,
                        struct tevent_immediate *imm,
                        void *pvt);
static void run_proxy_child_queue(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt);
static void proxy_child_sig_handler(struct tevent_context *ev,
                                    struct tevent_signal *sige, int signum,
                                    int count, void *__siginfo, void *pvt)
{
    int ret;
    int child_status;
    struct proxy_child_sig_ctx *sig_ctx;
    struct tevent_immediate *imm;
    struct tevent_immediate *imm2;

    if (count <= 0) {
        DEBUG(0, ("SIGCHLD handler called with invalid child count\n"));
        return;
    }

    sig_ctx = talloc_get_type(pvt, struct proxy_child_sig_ctx);
    DEBUG(7, ("Waiting for child [%d].\n", sig_ctx->pid));

    errno = 0;
    ret = waitpid(sig_ctx->pid, &child_status, WNOHANG);

    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("waitpid failed [%d][%s].\n", ret, strerror(ret)));
    } else if (ret == 0) {
        DEBUG(1, ("waitpid did not found a child with changed status.\n"));
    } else {
        if (WIFEXITED(child_status)) {
            DEBUG(4, ("child [%d] exited with status [%d].\n", ret,
                      WEXITSTATUS(child_status)));
        } else if (WIFSIGNALED(child_status)) {
            DEBUG(4, ("child [%d] was terminated by signal [%d].\n", ret,
                      WTERMSIG(child_status)));
        } else {
            if (WIFSTOPPED(child_status)) {
                DEBUG(1, ("child [%d] was stopped by signal [%d].\n", ret,
                          WSTOPSIG(child_status)));
            }
            if (WIFCONTINUED(child_status)) {
                DEBUG(1, ("child [%d] was resumed by delivery of SIGCONT.\n",
                          ret));
            }
            DEBUG(1, ("Child is still running, no new child is started.\n"));
            return;
        }

        imm = tevent_create_immediate(ev);
        if (imm == NULL) {
            DEBUG(1, ("tevent_create_immediate failed.\n"));
            return;
        }

        tevent_schedule_immediate(imm, ev, run_proxy_child_queue,
                                  sig_ctx->auth_ctx);

        /* schedule another immediate timer to delete the sigchld handler */
        imm2 = tevent_create_immediate(ev);
        if (imm == NULL) {
            DEBUG(1, ("tevent_create_immediate failed.\n"));
            return;
        }

        tevent_schedule_immediate(imm2, ev, remove_sige, sige);
    }

    return;
}

static void remove_sige(struct tevent_context *ev,
                        struct tevent_immediate *imm,
                        void *pvt)
{
    talloc_free(pvt);
}

struct proxy_conv_ctx {
    struct proxy_auth_ctx *auth_ctx;
    struct sbus_connection *conn;
    struct pam_data *pd;
    pid_t pid;
};
static void proxy_pam_conv_reply(DBusPendingCall *pending, void *ptr);
static struct tevent_req *proxy_pam_conv_send(TALLOC_CTX *mem_ctx,
                                              struct proxy_auth_ctx *auth_ctx,
                                              struct sbus_connection *conn,
                                              struct pam_data *pd,
                                              pid_t pid)
{
    errno_t ret;
    bool dp_ret;
    DBusMessage *msg;
    struct tevent_req *req;
    struct proxy_conv_ctx *state;

    req = tevent_req_create(mem_ctx, &state, struct proxy_conv_ctx);
    if (req == NULL) {
        return NULL;
    }

    state->auth_ctx = auth_ctx;
    state->conn = conn;
    state->pd = pd;
    state->pid = pid;

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_PAMHANDLER);
    if (msg == NULL) {
        DEBUG(1, ("dbus_message_new_method_call failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    DEBUG(4, ("Sending request with the following data:\n"));
    DEBUG_PAM_DATA(4, pd);

    dp_ret = dp_pack_pam_request(msg, pd);
    if (!dp_ret) {
        DEBUG(1, ("Failed to build message\n"));
        dbus_message_unref(msg);
        talloc_zfree(req);
        return NULL;
    }

    ret = sbus_conn_send(state->conn, msg, state->auth_ctx->timeout_ms,
                         proxy_pam_conv_reply, req, NULL);
    if (ret != EOK) {
        dbus_message_unref(msg);
        talloc_zfree(req);
        return NULL;
    }

    dbus_message_unref(msg);
    return req;
}

static void proxy_pam_conv_reply(DBusPendingCall *pending, void *ptr)
{
    struct tevent_req *req;
    struct proxy_conv_ctx *state;
    DBusError dbus_error;
    DBusMessage *reply;
    int type;
    int ret;

    DEBUG(8, ("Handling pam conversation reply\n"));

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct proxy_conv_ctx);

    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    dbus_pending_call_unref(pending);
    if (reply == NULL) {
        DEBUG(0, ("Severe error. A reply callback was called but no reply was"
                  "received and no timeout occurred\n"));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, EIO);
    }

    type = dbus_message_get_type(reply);
    switch (type) {
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
            ret = dp_unpack_pam_response(reply, state->pd, &dbus_error);
            if (!ret) {
                DEBUG(0, ("Failed to parse reply.\n"));
                state->pd->pam_status = PAM_SYSTEM_ERR;
                dbus_message_unref(reply);
                tevent_req_error(req, EIO);
                return;
            }
            DEBUG(4, ("received: [%d][%s]\n",
                      state->pd->pam_status,
                      state->pd->domain));
            break;
        case DBUS_MESSAGE_TYPE_ERROR:
            DEBUG(0, ("Reply error [%s].\n",
                    dbus_message_get_error_name(reply)));
            state->pd->pam_status = PAM_SYSTEM_ERR;
            break;
        default:
            DEBUG(0, ("Default... what now?.\n"));
            state->pd->pam_status = PAM_SYSTEM_ERR;
    }
    dbus_message_unref(reply);

    /* Kill the child */
    kill(state->pid, SIGKILL);

    /* Conversation is finished */
    tevent_req_done(req);
}

static errno_t proxy_pam_conv_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void proxy_pam_conv_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = proxy_pam_conv_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(6, ("Proxy PAM conversation failed [%d]\n", ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int proxy_child_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          struct pam_data **pd)
{
    struct proxy_child_ctx *ctx;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ctx = tevent_req_data(req, struct proxy_child_ctx);
    *pd = talloc_steal(mem_ctx, ctx->pd);

    return EOK;
}

static void proxy_child_done(struct tevent_req *req)
{
    struct proxy_client_ctx *client_ctx =
            tevent_req_callback_data(req, struct proxy_client_ctx);
    struct pam_data *pd;
    char *password;
    int ret;
    struct tevent_immediate *imm;

    ret = proxy_child_recv(req, client_ctx, &pd);
    talloc_zfree(req);
    if (ret != EOK) {
        /* Pam child failed */
        client_ctx->auth_ctx->running--;
        proxy_reply(client_ctx->be_req, DP_ERR_FATAL, ret,
                    "PAM child failed");

        /* Start the next auth in the queue, if any */
        imm = tevent_create_immediate(client_ctx->be_req->be_ctx->ev);
        if (imm == NULL) {
            DEBUG(1, ("tevent_create_immediate failed.\n"));
            return;
        }

        tevent_schedule_immediate(imm,
                                  client_ctx->be_req->be_ctx->ev,
                                  run_proxy_child_queue,
                                  client_ctx->auth_ctx);
        return;
    }

    /* Check if we need to save the cached credentials */
    if ((pd->cmd == SSS_PAM_AUTHENTICATE || pd->cmd == SSS_PAM_CHAUTHTOK) &&
            pd->pam_status == PAM_SUCCESS &&
            client_ctx->be_req->be_ctx->domain->cache_credentials) {
        password = talloc_strndup(client_ctx->be_req,
                                  (char *) pd->authtok,
                                  pd->authtok_size);
        if (!password) {
            /* password caching failures are not fatal errors */
            DEBUG(2, ("Failed to cache password\n"));
            goto done;
        }
        talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

        ret = sysdb_cache_password(client_ctx,
                                   client_ctx->be_req->be_ctx->sysdb,
                                   client_ctx->be_req->be_ctx->domain,
                                   pd->user, password);

        /* password caching failures are not fatal errors */
        /* so we just log it any return */
        if (ret != EOK) {
            DEBUG(2, ("Failed to cache password (%d)[%s]!?\n",
                      ret, strerror(ret)));
        }
    }

done:
    proxy_reply(client_ctx->be_req, DP_ERR_OK, EOK, NULL);
}

static void run_proxy_child_queue(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt)
{
    struct proxy_auth_ctx *auth_ctx;
    struct hash_iter_context_t *iter;
    struct hash_entry_t *entry;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct proxy_child_ctx *state;

    auth_ctx = talloc_get_type(pvt, struct proxy_auth_ctx);

    /* Launch next queued request */
    iter = new_hash_iter_context(auth_ctx->request_table);
    while ((entry = iter->next(iter)) != NULL) {
        req = talloc_get_type(entry->value.ptr, struct tevent_req);
        state = tevent_req_data(req, struct proxy_child_ctx);
        if (!state->running) {
            break;
        }
    }

    if (!entry) {
        /* Nothing pending on the queue */
        return;
    }

    if (auth_ctx->running < auth_ctx->max_children) {
        /* There's an available slot; start a child
         * to handle the request
         */
        auth_ctx->running++;
        subreq = proxy_child_init_send(auth_ctx, state, auth_ctx);
        if (!subreq) {
            DEBUG(1, ("Could not fork child process\n"));
            auth_ctx->running--;
            talloc_zfree(req);
            return;
        }
        tevent_req_set_callback(subreq, proxy_child_init_done, req);

        state->running = true;
    }
}
