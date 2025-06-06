/*
   SSSD

   Helper functions to be used by 'monitor' process to handle services.

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
#include <string.h>
#include <sys/wait.h>
#include <dhash.h>

#include "util/debug.h"
#include "util/util_errors.h"
#include "util/util.h"
#include "monitor/monitor_services.h"


struct sss_sigchild_ctx {
    struct tevent_context *ev;
    hash_table_t *children;
    int options;
};

struct sss_child_ctx {
    pid_t pid;
    sss_child_fn_t cb;
    void *pvt;
    struct sss_sigchild_ctx *sigchld_ctx;
};

struct sss_child_cb_pvt {
    struct sss_child_ctx *child_ctx;
    int wait_status;
};


static void sss_child_invoke_cb(struct tevent_context *ev,
                                struct tevent_immediate *imm,
                                void *pvt)
{
    struct sss_child_cb_pvt *cb_pvt;
    struct sss_child_ctx *child_ctx;
    hash_key_t key;
    int error;

    cb_pvt = talloc_get_type(pvt, struct sss_child_cb_pvt);
    child_ctx = cb_pvt->child_ctx;

    key.type = HASH_KEY_ULONG;
    key.ul = child_ctx->pid;

    error = hash_delete(child_ctx->sigchld_ctx->children, &key);
    if (error != HASH_SUCCESS && error != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_OP_FAILURE,
              "failed to delete child_ctx from hash table [%d]: %s\n",
               error, hash_error_string(error));
    }

    if (child_ctx->cb) {
        child_ctx->cb(child_ctx->pid, cb_pvt->wait_status, child_ctx->pvt);
    }

    talloc_free(imm);
}

static void sss_child_handler(struct tevent_context *ev,
                              struct tevent_signal *se,
                              int signum,
                              int count,
                              void *siginfo,
                              void *private_data)
{
    struct sss_sigchild_ctx *sigchld_ctx;
    struct tevent_immediate *imm;
    struct sss_child_cb_pvt *invoke_pvt;
    struct sss_child_ctx *child_ctx;
    hash_key_t key;
    hash_value_t value;
    int error;
    int wait_status;
    pid_t pid;

    sigchld_ctx = talloc_get_type(private_data, struct sss_sigchild_ctx);
    key.type = HASH_KEY_ULONG;

    do {
        do {
            errno = 0;
            pid = waitpid(-1, &wait_status, WNOHANG | sigchld_ctx->options);
        } while (pid == -1 && errno == EINTR);

        if (pid == -1) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "waitpid failed [%d]: %s\n", errno, strerror(errno));
            return;
        } else if (pid == 0) continue;

        key.ul = pid;
        error = hash_lookup(sigchld_ctx->children, &key, &value);
        if (error == HASH_SUCCESS) {
            child_ctx = talloc_get_type(value.ptr, struct sss_child_ctx);

            imm = tevent_create_immediate(child_ctx);
            if (imm == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Out of memory invoking SIGCHLD callback\n");
                return;
            }

            invoke_pvt = talloc_zero(child_ctx, struct sss_child_cb_pvt);
            if (invoke_pvt == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "out of memory invoking SIGCHLD callback\n");
                return;
            }
            invoke_pvt->child_ctx = child_ctx;
            invoke_pvt->wait_status = wait_status;

            tevent_schedule_immediate(imm, sigchld_ctx->ev,
                                      sss_child_invoke_cb, invoke_pvt);
        } else if (error == HASH_ERROR_KEY_NOT_FOUND) {
            DEBUG(SSSDBG_TRACE_LIBS,
                 "BUG: waitpid() returned [%d] but it was not in the table. "
                  "This could be due to a linked library creating processes "
                  "without registering them with the sigchld handler\n",
                  pid);
            /* We will simply ignore this and return to the loop
             * This will prevent a zombie, but may cause unexpected
             * behavior in the code that was trying to handle this
             * pid.
             */
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "SIGCHLD hash table error [%d]: %s\n",
                   error, hash_error_string(error));
            /* This is bad, but we should try to check for other
             * children anyway, to avoid potential zombies.
             */
        }
    } while (pid != 0);
}

errno_t sss_sigchld_init(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sss_sigchild_ctx **child_ctx)
{
    errno_t ret;
    struct sss_sigchild_ctx *sigchld_ctx;
    struct tevent_signal *tes;

    sigchld_ctx = talloc_zero(mem_ctx, struct sss_sigchild_ctx);
    if (!sigchld_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing sss_sigchild_ctx\n");
        return ENOMEM;
    }
    sigchld_ctx->ev = ev;

    ret = sss_hash_create(sigchld_ctx, 0, &sigchld_ctx->children);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing children hash table: [%s]\n",
               strerror(ret));
        talloc_free(sigchld_ctx);
        return ret;
    }

    BlockSignals(false, SIGCHLD);
    tes = tevent_add_signal(ev, sigchld_ctx, SIGCHLD, SA_SIGINFO,
                            sss_child_handler, sigchld_ctx);
    if (tes == NULL) {
        talloc_free(sigchld_ctx);
        return EIO;
    }

    *child_ctx = sigchld_ctx;
    return EOK;
}

static int sss_child_destructor(void *ptr)
{
    struct sss_child_ctx *child_ctx;
    hash_key_t key;
    int error;

    child_ctx = talloc_get_type(ptr, struct sss_child_ctx);
    key.type = HASH_KEY_ULONG;
    key.ul = child_ctx->pid;

    error = hash_delete(child_ctx->sigchld_ctx->children, &key);
    if (error != HASH_SUCCESS && error != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "failed to delete child_ctx from hash table [%d]: %s\n",
               error, hash_error_string(error));
    }

    return 0;
}

errno_t sss_child_register(TALLOC_CTX *mem_ctx,
                           struct sss_sigchild_ctx *sigchld_ctx,
                           pid_t pid,
                           sss_child_fn_t cb,
                           void *pvt,
                           struct sss_child_ctx **child_ctx)
{
    struct sss_child_ctx *child;
    hash_key_t key;
    hash_value_t value;
    int error;

    child = talloc_zero(mem_ctx, struct sss_child_ctx);
    if (child == NULL) {
        return ENOMEM;
    }

    child->pid = pid;
    child->cb = cb;
    child->pvt = pvt;
    child->sigchld_ctx = sigchld_ctx;

    key.type = HASH_KEY_ULONG;
    key.ul = pid;

    value.type = HASH_VALUE_PTR;
    value.ptr = child;

    error = hash_enter(sigchld_ctx->children, &key, &value);
    if (error != HASH_SUCCESS) {
        talloc_free(child);
        return ENOMEM;
    }

    talloc_set_destructor((TALLOC_CTX *) child, sss_child_destructor);

    *child_ctx = child;
    return EOK;
}
