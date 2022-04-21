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

#include <signal.h>

#include "providers/proxy/proxy.h"
#include "sss_iface/sss_iface_async.h"
#include "util/sss_chain_id.h"

struct pc_init_ctx;

static int proxy_child_destructor(TALLOC_CTX *ctx)
{
    struct proxy_child_ctx *child_ctx =
            talloc_get_type(ctx, struct proxy_child_ctx);
    hash_key_t key;
    int hret;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Removing proxy child id [%d]\n", child_ctx->id);
    key.type = HASH_KEY_ULONG;
    key.ul = child_ctx->id;
    hret = hash_delete(child_ctx->auth_ctx->request_table, &key);
    if (!(hret == HASH_SUCCESS ||
          hret == HASH_ERROR_KEY_NOT_FOUND)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Hash error [%d][%s]\n", hret, hash_error_string(hret));
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
                                           struct pam_data *pd)
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
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->auth_ctx = auth_ctx;
    state->pd = pd;

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
            DEBUG(SSSDBG_FATAL_FAILURE, "Serious error: queue is too long!\n");
            talloc_zfree(req);
            return NULL;
        }
    }

    state->id = auth_ctx->next_id;
    auth_ctx->next_id++;

    value.type = HASH_VALUE_PTR;
    value.ptr = req;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Queueing request [%lu]\n", key.ul);
    hret = hash_enter(auth_ctx->request_table,
                      &key, &value);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not add request to the queue\n");
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
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not fork child process\n");
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
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "All available child slots are full, queuing request\n");
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not create tevent_req\n");
        return NULL;
    }

    state->child_ctx = child_ctx;

    state->command = talloc_asprintf(req,
            "%s/proxy_child -d %#.4x --debug-timestamps=%d "
            "--debug-microseconds=%d --logger=%s --domain %s --id %d "
            "--chain-id=%lu",
            SSSD_LIBEXEC_PATH, debug_level, debug_timestamps,
            debug_microseconds, sss_logger_str[sss_logger],
            auth_ctx->be->domain->name,
            child_ctx->id, sss_chain_id_get());
    if (state->command == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "Starting proxy child with args [%s]\n", state->command);

    pid = fork();
    if (pid < 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fork failed [%d][%s].\n", ret, strerror(ret));
        talloc_zfree(req);
        return NULL;
    }

    if (pid == 0) { /* child */
        proxy_child_args = parse_args(state->command);
        execvp(proxy_child_args[0], proxy_child_args);

        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not start proxy child [%s]: [%d][%s].\n",
                  state->command, ret, strerror(ret));

        _exit(1);
    }

    else { /* parent */
        state->pid = pid;
        /* Make sure to kill the child process if we abort */
        talloc_set_destructor((TALLOC_CTX *)state, pc_init_destructor);

        state->sige = tevent_add_signal(auth_ctx->be->ev, req,
                                        SIGCHLD, 0,
                                        pc_init_sig_handler, req);
        if (state->sige == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_signal failed.\n");
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "SIGCHLD handler called with invalid child count\n");
        return;
    }

    req = talloc_get_type(pvt, struct tevent_req);
    init_ctx = tevent_req_data(req, struct pc_init_ctx);

    DEBUG(SSSDBG_TRACE_LIBS, "Waiting for child [%d].\n", init_ctx->pid);

    errno = 0;
    ret = waitpid(init_ctx->pid, &child_status, WNOHANG);

    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "waitpid failed [%d][%s].\n", ret, strerror(ret));
    } else if (ret == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "waitpid did not find a child with changed status.\n");
    } else {
        if (WIFEXITED(child_status)) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "child [%d] exited with status [%d].\n", ret,
                      WEXITSTATUS(child_status));
            tevent_req_error(req, EIO);
        } else if (WIFSIGNALED(child_status)) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "child [%d] was terminate by signal [%d].\n", ret,
                      WTERMSIG(child_status));
            tevent_req_error(req, EIO);
        } else {
            if (WIFSTOPPED(child_status)) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "child [%d] was stopped by signal [%d].\n", ret,
                          WSTOPSIG(child_status));
            }
            if (WIFCONTINUED(child_status) == true) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "child [%d] was resumed by delivery of SIGCONT.\n",
                          ret);
            }
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Child is still running, no new child is started.\n");
            return;
        }
    }
}

static void pc_init_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t, void *ptr)
{
    struct tevent_req *req;

    DEBUG(SSSDBG_OP_FAILURE, "Client timed out before Identification!\n");
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
    struct tevent_req *req;
};
static void proxy_child_sig_handler(struct tevent_context *ev,
                                    struct tevent_signal *sige, int signum,
                                    int count, void *__siginfo, void *pvt);
static struct tevent_req *
proxy_pam_conv_send(TALLOC_CTX *mem_ctx, struct proxy_auth_ctx *auth_ctx,
                    struct sbus_connection *conn,
                    struct proxy_child_sig_ctx *sig_ctx, struct pam_data *pd,
                    pid_t pid, uint32_t id);
static void proxy_child_init_conv_done(struct tevent_req *subreq);
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
        DEBUG(SSSDBG_TRACE_FUNC, "Proxy child init failed [%d]\n", ret);
        tevent_req_error(req, ret);
        return;
    }

    sig_ctx = talloc_zero(child_ctx->auth_ctx, struct proxy_child_sig_ctx);
    if (sig_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* An initialized child is available, awaiting the PAM command */
    subreq = proxy_pam_conv_send(req, child_ctx->auth_ctx,
                                 child_ctx->conn, sig_ctx, child_ctx->pd,
                                 child_ctx->pid, child_ctx->id);
    if (!subreq) {
        talloc_free(sig_ctx);
        DEBUG(SSSDBG_CRIT_FAILURE,"Could not start PAM conversation\n");
        tevent_req_error(req, EIO);
        return;
    }
    tevent_req_set_callback(subreq, proxy_child_init_conv_done, req);

    /* Add a signal handler for the child under the auth_ctx,
     * that way if the child exits after completion of the
     * request, it will still be handled.
     */
    sig_ctx->auth_ctx = child_ctx->auth_ctx;
    sig_ctx->pid = child_ctx->pid;

    sige = tevent_add_signal(child_ctx->auth_ctx->be->ev,
                             child_ctx->auth_ctx,
                             SIGCHLD, 0,
                             proxy_child_sig_handler,
                             sig_ctx);
    if (sige == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_signal failed.\n");
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "SIGCHLD handler called with invalid child count\n");
        return;
    }

    sig_ctx = talloc_get_type(pvt, struct proxy_child_sig_ctx);
    DEBUG(SSSDBG_TRACE_LIBS, "Waiting for child [%d].\n", sig_ctx->pid);

    errno = 0;
    ret = waitpid(sig_ctx->pid, &child_status, WNOHANG);

    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "waitpid failed [%d][%s].\n", ret, strerror(ret));
    } else if (ret == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "waitpid did not found a child with changed status.\n");
    } else {
        if (WIFEXITED(child_status)) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "child [%d] exited with status [%d].\n", ret,
                      WEXITSTATUS(child_status));
        } else if (WIFSIGNALED(child_status) == true) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "child [%d] was terminated by signal [%d].\n", ret,
                      WTERMSIG(child_status));
        } else {
            if (WIFSTOPPED(child_status)) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "child [%d] was stopped by signal [%d].\n", ret,
                          WSTOPSIG(child_status));
            }
            if (WIFCONTINUED(child_status) == true) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "child [%d] was resumed by delivery of SIGCONT.\n",
                          ret);
            }
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Child is still running, no new child is started.\n");
            return;
        }

        /* Free request if it is still running */
        if (sig_ctx->req != NULL) {
            tevent_req_error(sig_ctx->req, ERR_PROXY_CHILD_SIGNAL);
        }

        imm = tevent_create_immediate(ev);
        if (imm == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "tevent_create_immediate failed.\n");
            return;
        }

        tevent_schedule_immediate(imm, ev, run_proxy_child_queue,
                                  sig_ctx->auth_ctx);

        /* schedule another immediate timer to delete the sigchld handler */
        imm2 = tevent_create_immediate(ev);
        if (imm2 == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "tevent_create_immediate failed.\n");
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
    struct proxy_child_sig_ctx *sig_ctx;
    struct pam_data *pd;
    pid_t pid;
};

static void proxy_pam_conv_done(struct tevent_req *subreq);

static struct tevent_req *
proxy_pam_conv_send(TALLOC_CTX *mem_ctx, struct proxy_auth_ctx *auth_ctx,
                    struct sbus_connection *conn,
                    struct proxy_child_sig_ctx *sig_ctx, struct pam_data *pd,
                    pid_t pid, uint32_t id)
{
    struct proxy_conv_ctx *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    char *sbus_cliname;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct proxy_conv_ctx);
    if (req == NULL) {
        return NULL;
    }

    state->auth_ctx = auth_ctx;
    state->conn = conn;
    state->sig_ctx = sig_ctx;
    state->pd = pd;
    state->pid = pid;

    sbus_cliname = sss_iface_proxy_bus(state, id);
    if (sbus_cliname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Sending request with the following data:\n");
    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    subreq = sbus_call_proxy_auth_PAM_send(state, state->conn, sbus_cliname,
                                           SSS_BUS_PATH, pd);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    state->sig_ctx->req = subreq;

    tevent_req_set_callback(subreq, proxy_pam_conv_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_post(req, auth_ctx->be->ev);
        tevent_req_error(req, ret);
    }

    return req;
}

static void proxy_pam_conv_done(struct tevent_req *subreq)
{
    struct pam_data *response;
    struct response_data *resp;
    struct proxy_conv_ctx *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct proxy_conv_ctx);

    state->sig_ctx->req = NULL;

    ret = sbus_call_proxy_auth_PAM_recv(state, subreq, &response);
    talloc_zfree(subreq);

    /* Kill the child */
    kill(state->pid, SIGKILL);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get reply from child [%d]: %s\n",
              ret, sss_strerror(ret));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, ret);
        return;
    }

    state->pd->pam_status = response->pam_status;
    state->pd->account_locked = response->account_locked;

    for (resp = response->resp_list; resp != NULL; resp = resp->next) {
        talloc_steal(state->pd, resp);

        if (resp->next == NULL) {
            resp->next = state->pd->resp_list;
            state->pd->resp_list = response->resp_list;
            break;
        }
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "received: [%d][%s]\n",
          state->pd->pam_status,
          state->pd->domain);

    tevent_req_done(req);
}

static errno_t proxy_pam_conv_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void proxy_child_init_conv_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = proxy_pam_conv_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Proxy PAM conversation failed [%d]\n", ret);
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

static void run_proxy_child_queue(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt)
{
    struct proxy_auth_ctx *auth_ctx;
    struct hash_iter_context_t *iter;
    struct hash_entry_t *entry;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq;
    struct proxy_child_ctx *state = NULL;

    auth_ctx = talloc_get_type(pvt, struct proxy_auth_ctx);

    /* Launch next queued request */
    iter = new_hash_iter_context(auth_ctx->request_table);
    if (iter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "new_hash_iter_context failed.\n");
        return;
    }

    while ((entry = iter->next(iter)) != NULL) {
        req = talloc_get_type(entry->value.ptr, struct tevent_req);
        state = tevent_req_data(req, struct proxy_child_ctx);
        if (!state->running) {
            break;
        }
    }
    free(iter);

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
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not fork child process\n");
            auth_ctx->running--;
            talloc_zfree(req);
            return;
        }
        tevent_req_set_callback(subreq, proxy_child_init_done, req);

        state->running = true;
    }
}

struct proxy_pam_handler_state {
    struct pam_data *pd;
    struct proxy_auth_ctx *auth_ctx;
    struct be_ctx *be_ctx;
};

static void proxy_pam_handler_done(struct tevent_req *subreq);

struct tevent_req *
proxy_pam_handler_send(TALLOC_CTX *mem_ctx,
                      struct proxy_auth_ctx *proxy_auth_ctx,
                      struct pam_data *pd,
                      struct dp_req_params *params)
{
    struct proxy_pam_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct proxy_pam_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->auth_ctx = proxy_auth_ctx;
    state->be_ctx = params->be_ctx;

    /* Tell frontend that we do not support Smartcard authentication */
    if (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_SC_PIN
            || sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_SC_KEYPAD) {
        pd->pam_status = PAM_BAD_ITEM;
        goto immediately;
    }


    switch (pd->cmd) {
    case SSS_PAM_AUTHENTICATE:
    case SSS_PAM_CHAUTHTOK:
    case SSS_PAM_CHAUTHTOK_PRELIM:
    case SSS_PAM_ACCT_MGMT:
        /* Queue the request and spawn a child if there is an available slot. */
        subreq = proxy_child_send(state, proxy_auth_ctx, state->pd);
        if (subreq == NULL) {
            pd->pam_status = PAM_SYSTEM_ERR;
            goto immediately;
        }
        tevent_req_set_callback(subreq, proxy_pam_handler_done, req);
        break;
    case SSS_PAM_SETCRED:
    case SSS_PAM_OPEN_SESSION:
    case SSS_PAM_CLOSE_SESSION:
        pd->pam_status = PAM_SUCCESS;
        goto immediately;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported PAM task %d\n", pd->cmd);
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto immediately;
    }

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void proxy_pam_handler_done(struct tevent_req *subreq)
{
    struct proxy_pam_handler_state *state;
    struct tevent_immediate *imm;
    struct tevent_req *req;
    const char *password;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct proxy_pam_handler_state);

    ret = proxy_child_recv(subreq, state, &state->pd);

    /* During the proxy_child_send request SIGKILL will be sent to the child
     * process unconditionally, so we can assume here that the child process
     * is gone even if the request returns an error. */
    state->auth_ctx->running--;

    talloc_zfree(subreq);
    if (ret != EOK) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    /* Start the next auth in the queue, if any */
    imm = tevent_create_immediate(state->be_ctx->ev);
    if (imm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_create_immediate failed.\n");
        /* We'll still finish the current request, but we're
         * likely to have problems if there are queued events
         * if we've gotten into this state.
         * Hopefully this is impossible, since freeing req
         * above should guarantee that we have enough memory
         * to create this immediate event.
         */
    } else {
        tevent_schedule_immediate(imm, state->be_ctx->ev,
                                  run_proxy_child_queue,
                                  state->auth_ctx);
    }

    /* Check if we need to save the cached credentials */
    if ((state->pd->cmd == SSS_PAM_AUTHENTICATE || state->pd->cmd == SSS_PAM_CHAUTHTOK)
            && (state->pd->pam_status == PAM_SUCCESS) && state->be_ctx->domain->cache_credentials) {

        ret = sss_authtok_get_password(state->pd->authtok, &password, NULL);
        if (ret) {
            /* password caching failures are not fatal errors */
            DEBUG(SSSDBG_OP_FAILURE, "Failed to cache password\n");
            goto done;
        }

        ret = sysdb_cache_password(state->be_ctx->domain, state->pd->user, password);

        /* password caching failures are not fatal errors */
        /* so we just log it any return */
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to cache password (%d)[%s]!?\n",
                  ret, sss_strerror(ret));
        }
    }

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
proxy_pam_handler_recv(TALLOC_CTX *mem_ctx,
                      struct tevent_req *req,
                      struct pam_data **_data)
{
    struct proxy_pam_handler_state *state = NULL;

    state = tevent_req_data(req, struct proxy_pam_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
