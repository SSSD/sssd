/*
    SSSD

    Child process handling helpers.

    Authors:
        Sumit Bose   <sbose@redhat.com>

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

#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <talloc.h>
#include <tevent.h>

#include "util/debug.h"
#include "util/sss_prctl.h"
#include "util/sss_chain_id.h"
#include "util/child_common.h"

#define PIPE_INIT { -1, -1 }

#define PIPE_CLOSE(p) do {          \
    FD_CLOSE(p[0]);            \
    FD_CLOSE(p[1]);            \
} while(0);



struct sss_child_ctx {
    struct tevent_signal *sige;
    pid_t pid;
    int child_status;
    sss_child_sigchld_callback_t cb;
    void *pvt;
    struct sss_child_ctx **pvt_watch;
};

static void cancel_pvt_watch(struct sss_child_ctx *ctx)
{
    if (ctx->pvt_watch != NULL) {
        talloc_set_destructor(ctx->pvt_watch, NULL);
        talloc_free(ctx->pvt_watch);
        ctx->pvt_watch = NULL;
    }
}

static int pvt_watch_destructor(struct sss_child_ctx **watch)
{
    if ((watch != NULL) && (*watch != NULL)) {
        (*watch)->cb = NULL;
        (*watch)->pvt = NULL;
        (*watch)->pvt_watch = NULL;
    }
    return 0;
}

static errno_t child_debug_init(const char *logfile, int *debug_fd)
{
    int ret;
    FILE *debug_filep;

    if (debug_fd == NULL) {
        return EOK;
    }

    if (sss_logger == FILES_LOGGER && *debug_fd == -1) {
        ret = open_debug_file_ex(logfile, &debug_filep, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Error setting up logging (%d) [%s]\n",
                        ret, sss_strerror(ret));
            return ret;
        }

        *debug_fd = fileno(debug_filep);
        if (*debug_fd == -1) {
            ret = errno;
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fileno failed [%d][%s]\n", ret, strerror(ret));
            return ret;
        }
    }

    return EOK;
}


static void child_sig_handler(struct tevent_context *ev,
                              struct tevent_signal *sige, int signum,
                              int count, void *__siginfo, void *pvt);

/* `sss_child_handler_setup()` and `sss_child_handler_destroy()`
 * aren't static because they are used in unit test and
 * also in 'ipa_subdomains_server.c'. Those are exceptions.
 * In general direct usage of those internal helpers isn't
 * welcome.
 */
int sss_child_handler_setup(struct tevent_context *ev, int pid,
                            sss_child_sigchld_callback_t cb, void *pvt,
                            struct sss_child_ctx **_child_ctx)
{
    struct sss_child_ctx *child_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Setting up signal handler up for pid [%d]\n", pid);

    child_ctx = talloc_zero(ev, struct sss_child_ctx);
    if (child_ctx == NULL) {
        return ENOMEM;
    }

    if (pvt != NULL) {
        child_ctx->pvt_watch = talloc_zero(pvt, struct sss_child_ctx *);
        if (child_ctx->pvt_watch == NULL) {
            talloc_free(child_ctx);
            return ENOMEM;
        }
        *(child_ctx->pvt_watch) = child_ctx;
        talloc_set_destructor(child_ctx->pvt_watch, pvt_watch_destructor);
    }

    child_ctx->sige = tevent_add_signal(ev, child_ctx, SIGCHLD, SA_SIGINFO,
                                        child_sig_handler, child_ctx);
    if(!child_ctx->sige) {
        cancel_pvt_watch(child_ctx);
        talloc_free(child_ctx);
        return ENOMEM;
    }

    child_ctx->pid = pid;
    child_ctx->cb = cb;
    child_ctx->pvt = pvt;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Signal handler set up for pid [%d]\n", pid);

    if (_child_ctx != NULL) {
        *_child_ctx = child_ctx;
    }

    return EOK;
}

void sss_child_handler_destroy(struct sss_child_ctx *ctx)
{
    /* We still want to wait for the child to finish, but the caller is not
     * interested in the result anymore (e.g. timeout was reached). */
    ctx->cb = NULL;
    ctx->pvt = NULL;
    cancel_pvt_watch(ctx);

    sss_child_terminate(ctx->pid);
}

static void child_invoke_callback(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt);

static void child_sig_handler(struct tevent_context *ev,
                              struct tevent_signal *sige, int signum,
                              int count, void *__siginfo, void *pvt)
{
    int ret, err;
    struct sss_child_ctx *child_ctx;
    struct tevent_immediate *imm;

    if (count <= 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "SIGCHLD handler called with invalid child count\n");
        return;
    }

    child_ctx = talloc_get_type(pvt, struct sss_child_ctx);
    DEBUG(SSSDBG_TRACE_LIBS, "Waiting for child [%d].\n", child_ctx->pid);

    errno = 0;
    ret = waitpid(child_ctx->pid, &child_ctx->child_status, WNOHANG);

    if (ret == -1) {
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "waitpid failed [%d][%s].\n", err, strerror(err));
    } else if (ret == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "waitpid did not find a child with changed status.\n");
    } else {
        if (WIFEXITED(child_ctx->child_status)) {
            if (WEXITSTATUS(child_ctx->child_status) != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "child [%d] failed with status [%d].\n", ret,
                          WEXITSTATUS(child_ctx->child_status));
            } else {
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "child [%d] finished successfully.\n", ret);
            }
        } else if (WIFSIGNALED(child_ctx->child_status)) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "child [%d] was terminated by signal [%d].\n", ret,
                      WTERMSIG(child_ctx->child_status));
        } else {
            if (WIFSTOPPED(child_ctx->child_status)) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "child [%d] was stopped by signal [%d].\n", ret,
                          WSTOPSIG(child_ctx->child_status));
            }
            if (WIFCONTINUED(child_ctx->child_status) == true) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "child [%d] was resumed by delivery of SIGCONT.\n",
                          ret);
            }

            return;
        }

        /* Invoke the callback in a tevent_immediate handler
         * so that it is safe to free the tevent_signal *
         */
        imm = tevent_create_immediate(child_ctx);
        if (imm == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Out of memory invoking sig handler callback\n");
            return;
        }

        tevent_schedule_immediate(imm, ev, child_invoke_callback,
                                  child_ctx);
    }

    return;
}

static void child_invoke_callback(struct tevent_context *ev,
                                  struct tevent_immediate *imm,
                                  void *pvt)
{
    struct sss_child_ctx *child_ctx =
            talloc_get_type(pvt, struct sss_child_ctx);

    cancel_pvt_watch(child_ctx);

    if (child_ctx->cb) {
        child_ctx->cb(child_ctx->child_status, child_ctx->sige, child_ctx->pvt);
    }

    /* Stop monitoring for this child */
    talloc_free(child_ctx);
}

static errno_t prepare_child_argv(TALLOC_CTX *mem_ctx,
                                  int child_debug_fd,
                                  const char *binary,
                                  const char *extra_argv[],
                                  bool extra_args_only,
                                  char ***_argv)
{
    uint_t argc;
    char ** argv = NULL;
    errno_t ret = EINVAL;
    size_t i;

    /* basic args */
    if (extra_args_only) {
        /* program name and NULL */
        argc = 2;
    } else {
        /* program name, dumpable,
         * debug-microseconds, debug-timestamps,
         * logger or debug-fd,
         * debug-level, backtrace,
         * chain-id and NULL
         */
        argc = 9;
    }

    if (extra_argv) {
        for (i = 0; extra_argv[i]; i++) argc++;
    }

    argv  = talloc_array(mem_ctx, char *, argc);
    if (argv == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    argv[--argc] = NULL;

    /* Add extra_attrs first */
    if (extra_argv) {
        for (i = 0; extra_argv[i]; i++) {
            argv[--argc] = talloc_strdup(argv, extra_argv[i]);
            if (argv[argc] == NULL) {
                ret = ENOMEM;
                goto fail;
            }
        }
    }

    if (!extra_args_only) {
        argv[--argc] = talloc_asprintf(argv, "--debug-level=%#.4x",
                                  debug_level);
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        argv[--argc] = talloc_asprintf(argv, "--backtrace=%d",
                                       sss_get_debug_backtrace_enable() ? 1 : 0);
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        argv[--argc] = talloc_asprintf(argv, "--chain-id=%lu", sss_chain_id_get());
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        if (sss_logger == FILES_LOGGER) {
            argv[--argc] = talloc_asprintf(argv, "--debug-fd=%d",
                                           child_debug_fd);
            if (argv[argc] == NULL) {
                ret = ENOMEM;
                goto fail;
            }
        } else {
            argv[--argc] = talloc_asprintf(argv, "--logger=%s",
                                           sss_logger_str[sss_logger]);
            if (argv[argc] == NULL) {
                ret = ENOMEM;
                goto fail;
            }
        }

        argv[--argc] = talloc_asprintf(argv, "--debug-timestamps=%d",
                                       debug_timestamps);
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        argv[--argc] = talloc_asprintf(argv, "--debug-microseconds=%d",
                                       debug_microseconds);
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        /* Some helpers, namely 'krb5_child' and 'ldap_child',
         * will ignore '--dumpable' argument to avoid leaking
         * host keytab accidentially.
         */
        argv[--argc] = talloc_asprintf(argv, "--dumpable=%d",
                                           sss_prctl_get_dumpable());
        if (argv[argc] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    argv[--argc] = talloc_strdup(argv, binary);
    if (argv[argc] == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    if (argc != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: unprocessed args\n");
        ret = EINVAL;
        goto fail;
    }

    *_argv = argv;

    return EOK;

fail:
    talloc_free(argv);
    return ret;
}

static void log_child_command(TALLOC_CTX *mem_ctx, const char *binary,
                              char *argv[]) {
    int n;
    char *command;

    if(DEBUG_IS_SET(SSSDBG_TRACE_INTERNAL)){
        command = talloc_strdup(mem_ctx, "");
        if (command == NULL) {
            return;
        }
        if (argv != NULL) {
            for (n = 0; argv[n] != NULL; ++n) {
                command = talloc_asprintf_append(command, " %s", argv[n]);
                if (command == NULL) {
                    return;
                }
            }
        }
        /* child proccess might have no log file open */
        fprintf(stderr, "exec_child_ex command: [%s] %s\n", binary, command);
        talloc_free(command);
    }
}

/* Isn't static because it is used in unit test */
void exec_child_ex(TALLOC_CTX *mem_ctx,
                   int *pipefd_to_child, int *pipefd_from_child,
                   const char *binary, const char *logfile,
                   const char *extra_argv[], bool extra_args_only,
                   int child_in_fd, int child_out_fd)
{
    int ret;
    errno_t err;
    char **argv;
    int debug_fd = -1;

    if (logfile) {
        ret = child_debug_init(logfile, &debug_fd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "child_debug_init() failed.\n");
            exit(EXIT_FAILURE);
        }
    } else {
        debug_fd = STDERR_FILENO;
    }

    if ((pipefd_to_child != NULL) && (pipefd_to_child[0] != -1)
        && (child_in_fd != -1)) {
        close(pipefd_to_child[1]);
        ret = dup2(pipefd_to_child[0], child_in_fd);
        if (ret == -1) {
            err = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "dup2 failed [%d][%s].\n", err, strerror(err));
            exit(EXIT_FAILURE);
        }
    }

    /* some helpers, like 'selinux_child', do not write a response */
    if ((pipefd_from_child != NULL) && (pipefd_from_child[1] != -1)
        && (child_out_fd != -1)) {
        close(pipefd_from_child[0]);
        ret = dup2(pipefd_from_child[1], child_out_fd);
        if (ret == -1) {
            err = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "dup2 failed [%d][%s].\n", err, strerror(err));
            exit(EXIT_FAILURE);
        }
    }

    ret = prepare_child_argv(mem_ctx, debug_fd,
                             binary, extra_argv, extra_args_only,
                             &argv);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "prepare_child_argv() failed.\n");
        exit(EXIT_FAILURE);
    }

    log_child_command(mem_ctx, binary, argv);
    execv(binary, argv);
    err = errno;
    DEBUG(SSSDBG_OP_FAILURE, "execv failed [%d][%s].\n", err, strerror(err));
    exit(EXIT_FAILURE);
}

static int child_io_destructor(void *ptr)
{
    int ret;
    struct child_io_fds *io = talloc_get_type(ptr, struct child_io_fds);
    if (io == NULL) return EOK;

    if (io->write_to_child_fd != -1) {
        ret = close(io->write_to_child_fd);
        io->write_to_child_fd = -1;
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "close failed [%d][%s].\n", ret, strerror(ret));
        }
    }

    if (io->read_from_child_fd != -1) {
        ret = close(io->read_from_child_fd);
        io->read_from_child_fd = -1;
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "close failed [%d][%s].\n", ret, strerror(ret));
        }
    }

    return EOK;
}

void sss_child_handle_exited(int child_status, struct tevent_signal *sige, void *pvt)
{
    struct child_io_fds *io = talloc_get_type(pvt, struct child_io_fds);

    /* Do not free it if we still need to read some data. Just mark that the
     * child has exited so we know we need to free it later. */
    if (io->in_use) {
        io->child_exited = true;
        return;
    }

    /* The child has finished and we don't need to use the file descriptors
     * any more. This will close them and remove them from io hash table. */
    talloc_free(io);
}

void sss_child_terminate(pid_t pid)
{
    int ret;

    if (pid == 0) {
        return;
    }

    ret = kill(pid, SIGKILL);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "kill failed [%d]: %s\n",
              ret, sss_strerror(ret));
    }
}

struct child_timeout_ctx {
    tevent_timer_handler_t timeout_cb;
    void *timeout_pvt;
    bool auto_terminate;
    pid_t pid;
};

static void child_handle_timeout(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv,
                                 void *pvt)
{
    struct child_timeout_ctx *ctx =
            talloc_get_type(pvt, struct child_timeout_ctx);
    bool auto_terminate = ctx->auto_terminate;
    pid_t pid = ctx->pid;

    if (ctx->timeout_cb) {
        ctx->timeout_cb(ev, te, tv, ctx->timeout_pvt);
        /* At this point 'ctx' might be already gone */
    }

    if (auto_terminate) {
        sss_child_terminate(pid);
    }
}

static struct tevent_timer *activate_child_timeout_handler(TALLOC_CTX *mem_ctx,
                                                           struct tevent_context *ev,
                                                           pid_t pid,
                                                           uint32_t timeout_seconds,
                                                           tevent_timer_handler_t handler,
                                                           void *handler_pvt_ctx,
                                                           bool auto_terminate)
{
    struct timeval tv;
    struct tevent_timer *timeout_handler;
    struct child_timeout_ctx *ctx;

    if (timeout_seconds == 0) {
        if (auto_terminate) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Ignoring 'auto_terminate = true' due to zero timeout\n");
        }
        return NULL;
    }

    ctx = talloc_zero(mem_ctx, struct child_timeout_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        return NULL;
    }

    ctx->auto_terminate = auto_terminate;
    ctx->timeout_cb = handler;
    ctx->timeout_pvt = handler_pvt_ctx;
    ctx->pid = pid;

    tv = tevent_timeval_current();
    tv = tevent_timeval_add(&tv, timeout_seconds, 0);
    timeout_handler = tevent_add_timer(ev, mem_ctx, tv, child_handle_timeout, ctx);
    if (timeout_handler == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
        talloc_free(ctx);
    }

    return timeout_handler;
}

errno_t sss_child_start(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        const char *binary,
                        const char *extra_args[], bool extra_args_only,
                        const char *logfile,
                        int child_out_fd,
                        sss_child_sigchld_callback_t cb, void *pvt,
                        unsigned timeout,
                        tevent_timer_handler_t timeout_cb,
                        void *timeout_pvt,
                        bool auto_terminate,
                        struct child_io_fds **_io)
{
    TALLOC_CTX *tmp_ctx;
    int pipefd_to_child[2] = PIPE_INIT;
    int pipefd_from_child[2] = PIPE_INIT;
    struct child_io_fds *io = NULL;
    pid_t pid = 0;
    struct tevent_timer *timeout_handler = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (_io != NULL) {
        ret = pipe(pipefd_from_child);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "pipe (from) failed [%d][%s].\n", errno, strerror(errno));
            goto done;
        }

        ret = pipe(pipefd_to_child);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "pipe (to) failed [%d][%s].\n", errno, strerror(errno));
            goto done;
        }
    } else { /* (_io == NULL) => 'child_out_fd' won't be used */
        if (child_out_fd != -1) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Ignoring 'child_out_fd' due to NULL io\n");
        }
        child_out_fd = -1;
    }

    pid = fork();

    if (pid == 0) { /* child */
        exec_child_ex(tmp_ctx,
                      pipefd_to_child, pipefd_from_child,
                      binary, logfile,
                      extra_args, extra_args_only,
                      STDIN_FILENO, child_out_fd);

        /* We should never get here */
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Could not exec '%s'\n", binary);
        ret = ERR_INTERNAL;
        goto done;
    } else if (pid < 0) { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "fork failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    /* parent */
    if (_io != NULL) {
        io = talloc_zero(tmp_ctx, struct child_io_fds);
        if (io == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
            ret = ENOMEM;
            goto done;
        }
        talloc_set_destructor((void*)io, child_io_destructor);

        io->pid = pid;

        io->read_from_child_fd = pipefd_from_child[0];
        io->write_to_child_fd = pipefd_to_child[1];
        FD_CLOSE(pipefd_from_child[1]);
        FD_CLOSE(pipefd_to_child[0]);
        ret = sss_fd_nonblocking(io->read_from_child_fd);
        if (ret == EOK) {
            ret = sss_fd_nonblocking(io->write_to_child_fd);
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "sss_fd_nonblocking() failed\n");
            goto done;
        }
    }

    if (ev != NULL) { /* sdap-select-principal use NULL in sync mode */
        if ((cb != NULL) && (pvt == NULL) && (_io == NULL)) {
            DEBUG(SSSDBG_FATAL_FAILURE, "SIGCHLD cb without context\n");
            ret = EINVAL;
            goto done;
        }
        ret = sss_child_handler_setup(ev, pid, cb, (pvt ? pvt : io), NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up child signal handler "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        timeout_handler = activate_child_timeout_handler(mem_ctx,
                                  ev, pid,
                                  (uint32_t) timeout, timeout_cb, timeout_pvt,
                                  auto_terminate);
        if ((timeout > 0) && (timeout_handler == NULL)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup child timeout\n");
            ret = EFAULT;
            goto done;
        }
        if (_io != NULL) {
            io->timeout_handler = timeout_handler;
        }
    }

    if (_io != NULL) {
        talloc_steal(mem_ctx, io);
        *_io = io;
    }
    ret = EOK;

done:
    if (ret != EOK) {
        PIPE_CLOSE(pipefd_from_child);
        PIPE_CLOSE(pipefd_to_child);
        sss_child_terminate(pid);
    }

    talloc_free(tmp_ctx);
    return ret;
}
