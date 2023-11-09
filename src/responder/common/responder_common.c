/*
   SSSD

   Common Responder methods

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <popt.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "util/util_creds.h"
#include "sss_iface/sss_iface_async.h"
#include "util/sss_chain_id_tevent.h"
#include "util/sss_chain_id.h"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define SHELL_REALLOC_INCREMENT 5
#define SHELL_REALLOC_MAX       50

static errno_t set_close_on_exec(int fd)
{
    int v;
    int ferr;
    errno_t error;

    /* Get the current flags for this file descriptor */
    v = fcntl(fd, F_GETFD, 0);

    errno = 0;
    /* Set the close-on-exec flags on this fd */
    ferr = fcntl(fd, F_SETFD, v | FD_CLOEXEC);
    if (ferr < 0) {
        error = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to set fd close-on-exec: [%d][%s]\n",
                  error, strerror(error));
        return error;
    }
    return EOK;
}

static void client_close_fn(struct tevent_context *ev,
                            struct tevent_fd *fde, int fd,
                            void *ptr)
{
    errno_t ret;
    struct cli_ctx *ctx = talloc_get_type(ptr, struct cli_ctx);

    if ((ctx->cfd > 0) && close(ctx->cfd) < 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to close fd [%d]: [%s]\n",
               ctx->cfd, strerror(ret));
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Terminated client [%p][%d]\n",
           ctx, ctx->cfd);

    ctx->cfd = -1;
}

static errno_t get_client_cred(struct cli_ctx *cctx)
{
    SEC_CTX secctx;
    int ret;

    cctx->creds = talloc_zero(cctx, struct cli_creds);
    if (!cctx->creds) return ENOMEM;

    socklen_t client_cred_len = sizeof(struct ucred);
    char proc_path[32];
    char cmd_line[255] = { 0 };
    int proc_fd;

    cctx->creds->ucred.uid = -1;
    cctx->creds->ucred.gid = -1;
    cctx->creds->ucred.pid = -1;

    ret = getsockopt(cctx->cfd, SOL_SOCKET, SO_PEERCRED, &cctx->creds->ucred,
                     &client_cred_len);
    if (ret != EOK) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "getsockopt failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }
    if (client_cred_len != sizeof(struct ucred)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "getsockopt returned unexpected message size.\n");
        return ENOMSG;
    }

    if (cctx->creds->ucred.pid > -1) {
        ret = snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline",
                       (int)cctx->creds->ucred.pid);
        if ((ret > 0) && (ret < sizeof(proc_path))) {
            proc_fd = open(proc_path, O_RDONLY);
            if (proc_fd != -1) {
                if (sss_fd_nonblocking(proc_fd) == EOK) {
                    ret = read(proc_fd, cmd_line, sizeof(cmd_line)-1);
                    if (ret > 0) {
                        cmd_line[ret] = 0;
                        cctx->cmd_line = talloc_strdup(cctx, cmd_line);
                    }
                }
                close(proc_fd);
            }
        }
    }

    if (cctx->cmd_line == NULL) {
        cctx->cmd_line = "-unknown-";
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Client [%p][%d] creds: euid[%d] egid[%d] pid[%d] cmd_line['%s'].\n",
          cctx, cctx->cfd,
          cctx->creds->ucred.uid, cctx->creds->ucred.gid,
          cctx->creds->ucred.pid, cmd_line);

    ret = SELINUX_getpeercon(cctx->cfd, &secctx);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "The following failure is expected to happen in case SELinux is disabled:\n"
              "SELINUX_getpeercon failed [%d][%s].\n"
              "Please, consider enabling SELinux in your system.\n", ret, strerror(ret));
        /* This is not fatal, as SELinux may simply be disabled */
        ret = EOK;
    } else {
        cctx->creds->selinux_ctx = SELINUX_context_new(secctx);
        SELINUX_freecon(secctx);
    }

    return ret;
}

uid_t client_euid(struct cli_creds *creds)
{
    if (!creds) return -1;
    return cli_creds_get_uid(creds);
}

errno_t check_allowed_uids(uid_t uid, size_t allowed_uids_count,
                           const uid_t *allowed_uids)
{
    size_t c;

    if (allowed_uids == NULL) {
        return EINVAL;
    }

    for (c = 0; c < allowed_uids_count; c++) {
        if (uid == allowed_uids[c]) {
            return EOK;
        }
    }

    return EACCES;
}

errno_t csv_string_to_uid_array(TALLOC_CTX *mem_ctx, const char *csv_string,
                                size_t *_uid_count, uid_t **_uids)
{
    int ret;
    size_t c;
    char **list = NULL;
    int list_size;
    uid_t *uids = NULL;
    char *endptr;
    const char *envvar;
    bool loops_were_allowed;

    envvar = getenv("_SSS_LOOPS");
    loops_were_allowed = (envvar == NULL || strcmp(envvar, "NO") != 0);

    if (!loops_were_allowed) {
        ret = unsetenv("_SSS_LOOPS");
        if (ret != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to unset _SSS_LOOPS.\n");
            goto done;
        }
    }

    ret = split_on_separator(mem_ctx, csv_string, ',', true, false,
                             &list, &list_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed [%d][%s].\n",
                                  ret, strerror(ret));
        goto done;
    }

    uids = talloc_array(mem_ctx, uint32_t, list_size);
    if (uids == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; c < list_size; c++) {
        if (*list[c] == '\0') {
            DEBUG(SSSDBG_OP_FAILURE, "Empty list item.\n");
            ret = EINVAL;
            goto done;
        }

        uids[c] = strtouint32(list[c], &endptr, 10);
        if ((errno != 0) || (*endptr != '\0') || (list[c] == endptr)) {
            ret = errno;
            if (ret == ERANGE) {
                DEBUG(SSSDBG_OP_FAILURE, "List item [%s] is out of range.\n",
                                          list[c]);
                goto done;
            }

            ret = sss_user_by_name_or_uid(list[c], &uids[c], NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "List item [%s] is neither a valid "
                                         "UID nor a user name which could be "
                                         "resolved by getpwnam().\n", list[c]);
                sss_log(SSS_LOG_WARNING, "List item [%s] is neither a valid "
                                         "UID nor a user name which could be "
                                         "resolved by getpwnam().\n", list[c]);
                goto done;
            }
        }
    }

    *_uid_count = list_size;
    *_uids = uids;

    ret = EOK;

done:
    if (!loops_were_allowed) {
        if (setenv("_SSS_LOOPS", "NO" , 0) != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to restore _SSS_LOOPS.\n");
        }
    }
    talloc_free(list);
    if (ret != EOK) {
        talloc_free(uids);
    }

    return ret;
}

static void client_send(struct cli_ctx *cctx)
{
    struct cli_protocol *pctx;
    int ret;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_send(pctx->creq->out, cctx->cfd);
    if (ret == EAGAIN) {
        /* not all data was sent, loop again */
        return;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to send data, aborting client!\n");
        talloc_free(cctx);
        return;
    }

    /* ok all sent */
    TEVENT_FD_NOT_WRITEABLE(cctx->cfde);
    TEVENT_FD_READABLE(cctx->cfde);
    talloc_zfree(pctx->creq);
    return;
}

static int client_cmd_execute(struct cli_ctx *cctx, struct sss_cmd_table *sss_cmds)
{
    struct cli_protocol *pctx;
    enum sss_cli_command cmd;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    cmd = sss_packet_get_cmd(pctx->creq->in);
    return sss_cmd_execute(cctx, cmd, sss_cmds);
}

static void client_recv(struct cli_ctx *cctx)
{
    struct cli_protocol *pctx;
    int ret;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    if (!pctx->creq) {
        pctx->creq = talloc_zero(cctx, struct cli_request);
        if (!pctx->creq) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to alloc request, aborting client!\n");
            talloc_free(cctx);
            return;
        }
    }

    if (!pctx->creq->in) {
        ret = sss_packet_new(pctx->creq, SSS_PACKET_MAX_RECV_SIZE,
                             0, &pctx->creq->in);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to alloc request, aborting client!\n");
            talloc_free(cctx);
            return;
        }
    }

    ret = sss_packet_recv(pctx->creq->in, cctx->cfd);
    switch (ret) {
    case EOK:
        /* do not read anymore */
        TEVENT_FD_NOT_READABLE(cctx->cfde);
        /* execute command */
        ret = client_cmd_execute(cctx, cctx->rctx->sss_cmds);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to execute request, aborting client!\n");
            talloc_free(cctx);
        }
        /* past this point cctx can be freed at any time by callbacks
         * in case of error, do not use it */
        return;

    case EAGAIN:
        /* need to read still some data, loop again */
        break;

    case EINVAL:
        DEBUG(SSSDBG_TRACE_FUNC,
              "Invalid data from client, closing connection!\n");
        talloc_free(cctx);
        break;

    case ENODATA:
        DEBUG(SSSDBG_FUNC_DATA, "Client disconnected!\n");
        talloc_free(cctx);
        break;

    default:
        DEBUG(SSSDBG_TRACE_FUNC, "Failed to read request, aborting client!\n");
        talloc_free(cctx);
    }

    return;
}

static errno_t schedule_responder_idle_timer(struct resp_ctx *rctx);

static void responder_idle_handler(struct tevent_context *ev,
                                   struct tevent_timer *te,
                                   struct timeval current_time,
                                   void *data)
{
    struct resp_ctx *rctx;
    time_t now;

    rctx = talloc_get_type(data, struct resp_ctx);

    now = time(NULL);
    if (rctx->last_request_time > now) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Time shift detected, re-scheduling the responder timeout\n");
        goto end;
    }

    if ((now - rctx->last_request_time) >= rctx->idle_timeout) {
        /* This responder is idle. Terminate it */
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Terminating idle responder [%p]\n", rctx);

        talloc_free(rctx);

        orderly_shutdown(0);
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Re-scheduling the idle timeout [%s] for the responder [%p]\n",
          CONFDB_RESPONDER_IDLE_TIMEOUT, rctx);

end:
    schedule_responder_idle_timer(rctx);
}

static errno_t schedule_responder_idle_timer(struct resp_ctx *rctx)
{
    struct timeval tv;

    tv = tevent_timeval_current_ofs(rctx->idle_timeout / 2, 0);

    talloc_zfree(rctx->idle);
    rctx->idle = tevent_add_timer(rctx->ev,
                                  rctx,
                                  tv,
                                  responder_idle_handler,
                                  rctx);
    if (rctx->idle == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate time event: responder [%p] shutdown timeout\n",
              rctx);
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Re-scheduling the idle timeout [%s] for the responder [%p]\n",
          CONFDB_RESPONDER_IDLE_TIMEOUT, rctx);

    return EOK;
}

static errno_t setup_responder_idle_timer(struct resp_ctx *rctx)
{
    errno_t ret;

    rctx->last_request_time = time(NULL);

    ret = schedule_responder_idle_timer(rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Error scheduling the idle timeout [%s] for the responder [%p]: "
              "%d [%s]\n",
              CONFDB_RESPONDER_IDLE_TIMEOUT, rctx, ret, sss_strerror(ret));
        return ret;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Setting up the idle timeout [%s] for the responder [%p]\n",
          CONFDB_RESPONDER_IDLE_TIMEOUT, rctx);

    return EOK;
}

static void client_fd_handler(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *ptr)
{
    sss_client_fd_handler(ptr, client_recv, client_send, flags);
}

static errno_t setup_client_idle_timer(struct cli_ctx *cctx);

static int cli_ctx_destructor(struct cli_ctx *cctx)
{
    if (cctx->creds == NULL) {
        return 0;
    }

    if (cctx->creds->selinux_ctx == NULL) {
        return 0;
    }

    SELINUX_context_free(cctx->creds->selinux_ctx);
    cctx->creds->selinux_ctx = NULL;

    return 0;
}

struct accept_fd_ctx {
    struct resp_ctx *rctx;
    connection_setup_t connection_setup;
};

/*
 * Use this function only before the client context is established
 */
static void accept_and_terminate_cli(int fd)
{
    struct sockaddr_un addr;
    int client_fd;
    socklen_t len;

    /* accept and close to signal the client we have a problem */
    memset(&addr, 0, sizeof(addr));
    len = sizeof(addr);
    client_fd = accept(fd, (struct sockaddr *)&addr, &len);
    if (client_fd == -1) {
        return;
    }
    close(client_fd);
    return;
}

static void accept_fd_handler(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *ptr)
{
    static uid_t last_violator_uid = (uid_t)-1;
    /* accept and attach new event handler */
    struct accept_fd_ctx *accept_ctx =
            talloc_get_type(ptr, struct accept_fd_ctx);
    struct resp_ctx *rctx = accept_ctx->rctx;
    struct cli_ctx *cctx;
    socklen_t len;
    int ret;

    rctx->client_id_num++;

    cctx = talloc_zero(rctx, struct cli_ctx);
    if (!cctx) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Out of memory trying to setup client context!\n");
        accept_and_terminate_cli(rctx->lfd);
        return;
    }

    talloc_set_destructor(cctx, cli_ctx_destructor);

    cctx->client_id_num = rctx->client_id_num;

    len = sizeof(cctx->addr);
    cctx->cfd = accept(rctx->lfd, (struct sockaddr *)&cctx->addr, &len);
    if (cctx->cfd == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Accept failed [%s]\n", strerror(errno));
        talloc_free(cctx);
        return;
    }

    ret = get_client_cred(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "get_client_cred() failed\n");
        close(cctx->cfd);
        talloc_free(cctx);
        return;
    }

    cctx->priv = (client_euid(cctx->creds) == 0);

    if (rctx->allowed_uids_count != 0) {
        if (client_euid(cctx->creds) == -1) {
            DEBUG(SSSDBG_CRIT_FAILURE, "allowed_uids configured, " \
                                        "but platform does not support " \
                                        "reading peer credential from the " \
                                        "socket. Access denied.\n");
            close(cctx->cfd);
            talloc_free(cctx);
            return;
        }

        ret = check_allowed_uids(client_euid(cctx->creds), rctx->allowed_uids_count,
                                 rctx->allowed_uids);
        if (ret != EOK) {
            if (ret == EACCES) {
                if (client_euid(cctx->creds) != last_violator_uid) {
                    last_violator_uid = client_euid(cctx->creds);
                    DEBUG(SSSDBG_IMPORTANT_INFO,
                          "Access denied for uid [%"SPRIuid"].\n",
                          last_violator_uid);
                }
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "check_allowed_uids failed.\n");
            }
            close(cctx->cfd);
            talloc_free(cctx);
            return;
        }
    }

    ret = accept_ctx->connection_setup(cctx);
    if (ret != EOK) {
        close(cctx->cfd);
        talloc_free(cctx);
        DEBUG(SSSDBG_OP_FAILURE, "Failed to setup client handler\n");
        return;
    }

    cctx->cfde = tevent_add_fd(ev, cctx, cctx->cfd,
                               TEVENT_FD_READ, cctx->cfd_handler,
                               cctx);
    if (!cctx->cfde) {
        close(cctx->cfd);
        talloc_free(cctx);
        DEBUG(SSSDBG_OP_FAILURE, "Failed to queue client handler\n");
        return;
    }
    tevent_fd_set_close_fn(cctx->cfde, client_close_fn);

    cctx->ev = ev;
    cctx->rctx = rctx;

    /* Record the new time and set up the idle timer */
    ret = reset_client_idle_timer(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not create idle timer for client. "
              "This connection may not auto-terminate\n");
        /* Non-fatal, continue */
    }

    ret = setup_client_idle_timer(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not create idle timer for client. "
               "This connection may not auto-terminate\n");
        /* Non-fatal, continue */
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "[CID#%u] Client [cmd %s][uid %u][%p][%d] connected!\n",
          cctx->client_id_num, cctx->cmd_line, client_euid(cctx->creds),
          cctx, cctx->cfd);

    return;
}

static void client_idle_handler(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval current_time,
                                void *data)
{
    time_t now = time(NULL);
    struct cli_ctx *cctx = talloc_get_type(data, struct cli_ctx);

    if (cctx->last_request_time > now) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Time shift detected, re-scheduling the client timeout [%s].\n",
              CONFDB_RESPONDER_CLI_IDLE_TIMEOUT);
        goto done;
    }

    if ((now - cctx->last_request_time) > cctx->rctx->client_idle_timeout) {
        /* This connection is idle. Terminate it */
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Terminating idle client [%p][%d]\n",
              cctx, cctx->cfd);

        /* The cli_ctx destructor will handle the rest */
        talloc_free(cctx);
        return;
    }

done:
    setup_client_idle_timer(cctx);
}

errno_t reset_client_idle_timer(struct cli_ctx *cctx)
{
    cctx->last_request_time = time(NULL);

    return EOK;
}

static errno_t setup_client_idle_timer(struct cli_ctx *cctx)
{
    struct timeval tv =
            tevent_timeval_current_ofs(cctx->rctx->client_idle_timeout/2, 0);

    talloc_zfree(cctx->idle);

    cctx->idle = tevent_add_timer(cctx->ev, cctx, tv, client_idle_handler, cctx);
    if (!cctx->idle) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL,
          "Idle timer re-set for client [%p][%d]\n",
           cctx, cctx->cfd);

    return EOK;
}

int create_pipe_fd(const char *sock_name, int *_fd, mode_t umaskval)
{
    struct sockaddr_un addr;
    mode_t orig_umaskval;
    errno_t ret;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        return EIO;
    }

    orig_umaskval = umask(umaskval);

    ret = sss_fd_nonblocking(fd);
    if (ret != EOK) {
        goto done;
    }

    ret = set_close_on_exec(fd);
    if (ret != EOK) {
        goto done;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_name, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    /* make sure we have no old sockets around */
    ret = unlink(sock_name);
    if (ret != 0 && errno != ENOENT) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot remove old socket (errno=%d [%s]), bind might fail!\n",
              ret, sss_strerror(ret));
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to bind on socket '%s' [%d]: %s\n",
              sock_name, ret, sss_strerror(ret));
        goto done;
    }

    if (listen(fd, 128) == -1) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to listen on socket '%s' [%d]: %s\n",
              sock_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    /* restore previous umask value */
    umask(orig_umaskval);
    if (ret == EOK) {
        *_fd = fd;
    } else {
        close(fd);
    }
    return ret;
}

/* create a unix socket and listen to it */
static int set_unix_socket(struct resp_ctx *rctx,
                           connection_setup_t conn_setup)
{
    errno_t ret;
    struct accept_fd_ctx *accept_ctx = NULL;

    if (rctx->sock_name != NULL ) {
        /* Set the umask so that permissions are set right on the socket.
         * It must be readable and writable by anybody on the system. */
        if (rctx->lfd == -1) {
            ret = create_pipe_fd(rctx->sock_name, &rctx->lfd, SCKT_RSP_UMASK);
            if (ret != EOK) {
                return ret;
            }
        }

        accept_ctx = talloc_zero(rctx, struct accept_fd_ctx);
        if(!accept_ctx) goto failed;
        accept_ctx->rctx = rctx;
        accept_ctx->connection_setup = conn_setup;

        rctx->lfde = tevent_add_fd(rctx->ev, rctx, rctx->lfd,
                                   TEVENT_FD_READ, accept_fd_handler,
                                   accept_ctx);
        if (!rctx->lfde) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to queue handler on pipe\n");
            goto failed;
        }
    }

    return EOK;

failed:
    if (rctx->lfd >= 0) close(rctx->lfd);
    return EIO;
}

int activate_unix_sockets(struct resp_ctx *rctx,
                          connection_setup_t conn_setup)
{
    int ret;

#ifdef HAVE_SYSTEMD
    struct sockaddr_un sockaddr;
    socklen_t sockaddr_len = sizeof(sockaddr);

    if ((rctx->lfd == -1) && (rctx->sock_name != NULL)) {
        /* if systemd support is available, check if the sockets
         * have been opened for us, via socket activation */
        ret = sd_listen_fds(1);
        if (ret < 0) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unexpected error probing for active sockets. "
                  "Will proceed with no sockets. [Error %d (%s)]\n",
                  -ret, sss_strerror(-ret));
        } else if (ret > 1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "More than one activated sockets have been found\n");
            ret = E2BIG;
            goto done;
        }

        if (ret == 1) {
            rctx->lfd = SD_LISTEN_FDS_START;
            ret = sd_is_socket_unix(rctx->lfd, SOCK_STREAM, 1, NULL, 0);
            if (ret < 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Activated socket is not a UNIX listening socket\n");
                ret = EIO;
                goto done;
            }

            ret = getsockname(rctx->lfd, (struct sockaddr *) &sockaddr, &sockaddr_len);
            if (ret == EOK) {
                if (rctx->sock_name &&
                    memcmp(rctx->sock_name, sockaddr.sun_path, strlen(rctx->sock_name)) != 0) {
                    DEBUG(SSSDBG_IMPORTANT_INFO,
                          "Warning: socket path defined in systemd unit (%s) and sssd.conf (%s) don't match\n",
                          sockaddr.sun_path, rctx->sock_name);
                }
            }

            ret = sss_fd_nonblocking(rctx->lfd);
            if (ret != EOK) goto done;
        }
    }
#endif

    ret = set_unix_socket(rctx, conn_setup);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Fatal error initializing sockets\n");
        goto done;
    }

done:
    return ret;
}

void sss_client_fd_handler(void *ptr,
                           void (*recv_fn) (struct cli_ctx *cctx),
                           void (*send_fn) (struct cli_ctx *cctx),
                           uint16_t flags)
{
    errno_t ret;
    uint64_t old_chain_id;
    struct cli_ctx *cctx = talloc_get_type(ptr, struct cli_ctx);

    /* Always reset the responder idle timer on any activity */
    cctx->rctx->last_request_time = time(NULL);

    /* Always reset the client idle timer on any activity */
    ret = reset_client_idle_timer(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not create idle timer for the client. "
              "This connection may not auto-terminate.\n");
        /* Non-fatal, continue */
    }

    /* Set the chain id */
    old_chain_id = sss_chain_id_set(cctx->client_id_num);

    if (flags & TEVENT_FD_READ) {
        recv_fn(cctx);
        return;
    }

    if (flags & TEVENT_FD_WRITE) {
        send_fn(cctx);
        return;
    }
    /* Restore the original chain id  */
    sss_chain_id_set(old_chain_id);
}

int sss_connection_setup(struct cli_ctx *cctx)
{
    cctx->protocol_ctx = talloc_zero(cctx, struct cli_protocol);
    if (!cctx->protocol_ctx) {
        return ENOMEM;
    }

    cctx->cfd_handler = client_fd_handler;

    return EOK;
}

static int sss_responder_ctx_destructor(void *ptr)
{
    struct resp_ctx *rctx = talloc_get_type(ptr, struct resp_ctx);

    /* mark that we are shutting down the responder, so it is propagated
     * into underlying contexts that are freed right before rctx */
    DEBUG(SSSDBG_TRACE_FUNC, "Responder is being shut down\n");
    rctx->shutting_down = true;

    return 0;
}

static errno_t responder_init_ncache(TALLOC_CTX *mem_ctx,
                                     struct confdb_ctx *cdb,
                                     struct sss_nc_ctx **ncache)
{
    uint32_t neg_timeout;
    uint32_t locals_timeout;
    int tmp_value;
    int ret;

    /* neg_timeout */
    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENTRY_NEG_TIMEOUT,
                         15, &tmp_value);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Fatal failure of setup negative cache timeout [%s].\n",
              CONFDB_NSS_ENTRY_NEG_TIMEOUT);
        ret = ENOENT;
        goto done;
    }

    if (tmp_value < 0) {
        ret = EINVAL;
        goto done;
    }

    neg_timeout = tmp_value;

    /* local_timeout */
    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_RESPONDER_LOCAL_NEG_TIMEOUT,
                         CONFDB_RESPONDER_LOCAL_NEG_TIMEOUT_DEFAULT,
                         &tmp_value);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Fatal failure of setup negative cache timeout [%s].\n",
              CONFDB_RESPONDER_LOCAL_NEG_TIMEOUT);
        ret = ENOENT;
        goto done;
    }

    if (tmp_value < 0) {
        ret = EINVAL;
        goto done;
    }

    locals_timeout = tmp_value;

    /* negative cache init */
    ret = sss_ncache_init(mem_ctx, neg_timeout, locals_timeout, ncache);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Fatal failure of initializing negative cache.\n");
        goto done;
    }

    ret = EOK;

done:
    return ret;
}

static errno_t sss_get_etc_shells(TALLOC_CTX *mem_ctx, char ***_shells)
{
    int i = 0;
    char *sh;
    char **shells = NULL;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    int size;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    shells = talloc_array(tmp_ctx, char *, SHELL_REALLOC_INCREMENT);
    if (!shells) {
        ret = ENOMEM;
        goto done;
    }
    size = SHELL_REALLOC_INCREMENT;

    setusershell();
    while ((sh = getusershell())) {
        shells[i] = talloc_strdup(shells, sh);
        if (!shells[i]) {
            endusershell();
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Found shell %s in /etc/shells\n", shells[i]);
        i++;

        if (i == size) {
            size += SHELL_REALLOC_INCREMENT;
            if (size > SHELL_REALLOC_MAX) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Reached maximum number of shells [%d]. "
                          "Users may be denied access. "
                          "Please check /etc/shells for sanity\n",
                          SHELL_REALLOC_MAX);
                break;
            }
            shells = talloc_realloc(NULL, shells, char *,
                                    size);
            if (!shells) {
                ret = ENOMEM;
                goto done;
            }
        }
    }
    endusershell();

    if (i + 1 < size) {
        shells = talloc_realloc(NULL, shells, char *, i + 1);
        if (!shells) {
            ret = ENOMEM;
            goto done;
        }
    }
    shells[i] = NULL;

    *_shells = talloc_move(mem_ctx, &shells);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb,
                     struct sss_cmd_table sss_cmds[],
                     const char *sss_pipe_name,
                     int pipe_fd,
                     const char *confdb_service_path,
                     const char *conn_name,
                     const char *svc_name,
                     connection_setup_t conn_setup,
                     struct resp_ctx **responder_ctx)
{
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    int ret;
    char *tmp = NULL;

    rctx = talloc_zero(mem_ctx, struct resp_ctx);
    if (!rctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing resp_ctx\n");
        return ENOMEM;
    }
    rctx->ev = ev;
    rctx->cdb = cdb;
    rctx->sss_cmds = sss_cmds;
    rctx->sock_name = sss_pipe_name;
    rctx->lfd = pipe_fd;
    rctx->confdb_service_path = confdb_service_path;
    rctx->shutting_down = false;
    rctx->socket_activated = is_socket_activated();

    talloc_set_destructor((TALLOC_CTX*)rctx, sss_responder_ctx_destructor);

    ret = confdb_get_int(rctx->cdb, rctx->confdb_service_path,
                         CONFDB_RESPONDER_CLI_IDLE_TIMEOUT,
                         CONFDB_RESPONDER_CLI_IDLE_DEFAULT_TIMEOUT,
                         &rctx->client_idle_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the client idle timeout [%s] [%d]: %s\n",
              CONFDB_RESPONDER_CLI_IDLE_TIMEOUT, ret, strerror(ret));
        goto fail;
    }

    /* Ensure that the client timeout is at least ten seconds */
    if (rctx->client_idle_timeout < 10) {
        rctx->client_idle_timeout = 10;
    }

    if (rctx->socket_activated) {
        ret = responder_setup_idle_timeout_config(rctx);
        if (ret != EOK) {
            goto fail;
        }
    }

    ret = confdb_get_bool(rctx->cdb, rctx->confdb_service_path,
                          CONFDB_RESPONDER_CACHE_FIRST,
                          CONFDB_RESPONDER_CACHE_FIRST_DEFAILT,
                          &rctx->cache_first);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get \"cache_first_option\".\n"
              "Querying the caches first before querying the "
              "Data Providers will not be enforced [%d]: %s.\n",
              ret, sss_strerror(ret));
    }

    ret = confdb_get_int(rctx->cdb, rctx->confdb_service_path,
                         CONFDB_RESPONDER_GET_DOMAINS_TIMEOUT,
                         GET_DOMAINS_DEFAULT_TIMEOUT, &rctx->domains_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the default domain timeout [%s] [%d]: %s\n",
              CONFDB_RESPONDER_GET_DOMAINS_TIMEOUT, ret, strerror(ret));
        goto fail;
    }

    if (rctx->domains_timeout < 0) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "timeout [%s] can't be set to negative value, "
              "setting default [%d] seconds.\n",
              CONFDB_RESPONDER_GET_DOMAINS_TIMEOUT,
              GET_DOMAINS_DEFAULT_TIMEOUT);
        rctx->domains_timeout = GET_DOMAINS_DEFAULT_TIMEOUT;
    }

    ret = confdb_get_domains(rctx->cdb, &rctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error setting up domain map\n");
        goto fail;
    }

    ret = confdb_get_string(rctx->cdb, rctx, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_DEFAULT_DOMAIN, NULL,
                            &rctx->default_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the default domain [%d]: %s\n",
               ret, strerror(ret));
        goto fail;
    }

    ret = confdb_get_string(rctx->cdb, rctx, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_OVERRIDE_SPACE, NULL,
                            &tmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the space substitution character [%d]: %s\n",
               ret, strerror(ret));
        goto fail;
    }

    if (tmp != NULL) {
        if (strlen(tmp) > 1) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Option %s is longer than 1 character "
                  "only the first character %c will be used\n",
                  CONFDB_MONITOR_OVERRIDE_SPACE, tmp[0]);
        }

        rctx->override_space = tmp[0];
    }

    ret = confdb_get_string(rctx->cdb, rctx,
                            CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_DOMAIN_RESOLUTION_ORDER, NULL,
                            &tmp);
    if (ret == EOK) {
        rctx->domain_resolution_order = sss_replace_char(rctx, tmp, ',', ':');
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot get the \"domain_resolution_order\" option.\n"
              "The set up lookup_order won't be followed [%d]: %s.\n",
              ret, sss_strerror(ret));
    }

    /* Read shell settings */
    ret = confdb_get_string(cdb, rctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_OVERRIDE_SHELL, NULL,
                            &rctx->override_shell);
    if (ret != EOK && ret != ENOENT) goto fail;

    ret = confdb_get_string_as_list(cdb, rctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_ALLOWED_SHELL,
                                    &rctx->allowed_shells);
    if (ret != EOK && ret != ENOENT) goto fail;

    ret = confdb_get_string_as_list(cdb, rctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_VETOED_SHELL,
                                    &rctx->vetoed_shells);
    if (ret != EOK && ret != ENOENT) goto fail;

    ret = sss_get_etc_shells(rctx, &rctx->etc_shells);
    if (ret != EOK) goto fail;

    ret = confdb_get_string(cdb, rctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_SHELL_FALLBACK,
                            CONFDB_DEFAULT_SHELL_FALLBACK,
                            &rctx->shell_fallback);
    if (ret != EOK) goto fail;

    ret = confdb_get_string(cdb, rctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_DEFAULT_SHELL,
                            NULL,
                            &rctx->default_shell);
    if (ret != EOK) goto fail;

    /* Read session_recording section */
    ret = session_recording_conf_load(rctx, rctx->cdb, &rctx->sr_conf);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed loading session recording configuration: %s\n",
              strerror(ret));
        goto fail;
    }

    for (dom = rctx->domains; dom; dom = get_next_domain(dom, 0)) {
        ret = sss_names_init(rctx->cdb, rctx->cdb, dom->name, &dom->names);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fatal error initializing regex data for domain: %s\n",
                   dom->name);
            goto fail;
        }
    }

    ret = sysdb_init(rctx, rctx->domains);
    if (ret != EOK) {
        SYSDB_VERSION_ERROR_DAEMON(ret);
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing sysdb connection\n");
        goto fail;
    }

    /* after all initializations we are ready to listen on our socket */
    ret = activate_unix_sockets(rctx, conn_setup);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing socket\n");
        goto fail;
    }

    ret = responder_init_ncache(rctx, rctx->cdb, &rctx->ncache);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "fatal error initializing negcache\n");
        goto fail;
    }

    ret = sss_ad_default_names_ctx(rctx, &rctx->global_names);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_ad_default_names_ctx failed.\n");
        goto fail;
    }

    ret = sss_sbus_connect(rctx, rctx->ev, conn_name,
                           &rctx->last_request_time, &rctx->sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to SSSD D-Bus server "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    ret = sss_resp_register_sbus_iface(rctx->sbus_conn, rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register D-Bus interface "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Responder initialization complete (%s)\n",
          rctx->socket_activated  ? "socket-activated" : "explicitly configured");

    *responder_ctx = rctx;
    return EOK;

fail:
    talloc_free(rctx);
    return ret;
}

struct sss_domain_info *
responder_get_domain(struct resp_ctx *rctx, const char *name)
{
    struct sss_domain_info *dom;
    struct sss_domain_info *ret_dom = NULL;

    for (dom = rctx->domains; dom;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        if (sss_domain_get_state(dom) == DOM_DISABLED) {
            continue;
        }

        if (strcasecmp(dom->name, name) == 0 ||
            (dom->flat_name != NULL &&
             strcasecmp(dom->flat_name, name) == 0)) {
            ret_dom = dom;
            break;
        }
    }

    if (!ret_dom) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown domain [%s]\n", name);
    }

    return ret_dom;
}

errno_t responder_get_domain_by_id(struct resp_ctx *rctx, const char *id,
                                   struct sss_domain_info **_ret_dom)
{
    struct sss_domain_info *dom;
    struct sss_domain_info *ret_dom = NULL;
    size_t id_len;
    size_t dom_id_len;
    int ret;

    if (id == NULL || _ret_dom == NULL) {
        return EINVAL;
    }

    id_len = strlen(id);

    for (dom = rctx->domains; dom;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        if (sss_domain_get_state(dom) == DOM_DISABLED ||
                dom->domain_id == NULL) {
            continue;
        }

        dom_id_len = strlen(dom->domain_id);
        if ((id_len >= dom_id_len) &&
            strncasecmp(dom->domain_id, id, dom_id_len) == 0) {
            if (IS_SUBDOMAIN(dom) &&
                ((time(NULL) - dom->parent->subdomains_last_checked.tv_sec) >
                                                      rctx->domains_timeout)) {
                DEBUG(SSSDBG_TRACE_FUNC, "Domain entry with id [%s] " \
                                          "is expired.\n", id);
                ret = EAGAIN;
                goto done;
            }
            ret_dom = dom;
            break;
        }
    }

    if (ret_dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown domain id [%s], checking for "
                                  "possible subdomains!\n", id);
        ret = ENOENT;
    } else {
        *_ret_dom = ret_dom;
        ret = EOK;
    }

done:
    return ret;
}

errno_t
responder_logrotate(TALLOC_CTX *mem_ctx,
                    struct sbus_request *sbus_req,
                    struct resp_ctx *rctx)
{
    return server_common_rotate_logs(rctx->cdb, rctx->confdb_service_path);

    return EOK;
}

void responder_set_fd_limit(rlim_t fd_limit)
{
    struct rlimit current_limit, new_limit;
    int limret;

    /* First, let's see if we have permission to just set
     * the value as-is.
     */
    new_limit.rlim_cur = fd_limit;
    new_limit.rlim_max = fd_limit;
    limret = setrlimit(RLIMIT_NOFILE, &new_limit);
    if (limret == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Maximum file descriptors set to [%"SPRIrlim"]\n",
               new_limit.rlim_cur);
        return;
    }

    /* We couldn't set the soft and hard limits to this
     * value. Let's see how high we CAN set it.
     */

    /* Determine the maximum hard limit */
    limret = getrlimit(RLIMIT_NOFILE, &current_limit);
    if (limret == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Current fd limit: [%"SPRIrlim"]\n",
               current_limit.rlim_cur);
        /* Choose the lesser of the requested and the hard limit */
        if (current_limit.rlim_max < fd_limit) {
            new_limit.rlim_cur = current_limit.rlim_max;
        } else {
            new_limit.rlim_cur = fd_limit;
        }
        new_limit.rlim_max = current_limit.rlim_max;

        limret = setrlimit(RLIMIT_NOFILE, &new_limit);
        if (limret == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Maximum file descriptors set to [%"SPRIrlim"]\n",
                   new_limit.rlim_cur);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not set new fd limits. Proceeding with "
                   "[%"SPRIrlim"]\n", current_limit.rlim_cur);
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not determine fd limits. "
               "Proceeding with system values\n");
    }
}

errno_t responder_setup_idle_timeout_config(struct resp_ctx *rctx)
{
    errno_t ret;

    ret = confdb_get_int(rctx->cdb, rctx->confdb_service_path,
                         CONFDB_RESPONDER_IDLE_TIMEOUT,
                         CONFDB_RESPONDER_IDLE_DEFAULT_TIMEOUT,
                         &rctx->idle_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the responder idle timeout [%s] [%d]: %s\n",
              CONFDB_RESPONDER_IDLE_TIMEOUT, ret, sss_strerror(ret));
        goto fail;
    }

    /* Idle timeout set to 0 means that no timeout will be set up to
     * the responder */
    if (rctx->idle_timeout == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Responder idle timeout won't be set up as the "
              "responder_idle_timeout is set to 0\n");
    } else {
        /* Ensure that the responder timeout is at least sixty seconds */
        if (rctx->idle_timeout < 60) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "responder_idle_timeout is set to a value lower than "
                  "the minimum allowed (60s). "
                  "The minimum allowed value will be used.\n");

            rctx->idle_timeout = 60;
        }

        ret = setup_responder_idle_timer(rctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "An error occurred when setting up the responder's idle "
                  "timeout [%s] for the responder [%p]: %s [%d].\n"
                  "The responder won't be automatically shutdown after %d "
                  "seconds inactive.\n",
                  CONFDB_RESPONDER_IDLE_TIMEOUT,
                  rctx, sss_strerror(ret), ret,
                  rctx->idle_timeout);
        }
    }

    ret = EOK;

fail:
    return ret;

}

/* ====== Helper functions for the domain resolution order ======= */
static errno_t
sss_resp_new_cr_domains_from_ipa_id_view(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *domains,
                                         struct sysdb_ctx *sysdb,
                                         struct cache_req_domain **_cr_domains)
{
    TALLOC_CTX *tmp_ctx;
    struct cache_req_domain *cr_domains = NULL;
    const char *domain_resolution_order = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_get_view_domain_resolution_order(tmp_ctx, sysdb,
                                                 &domain_resolution_order);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sysdb_get_view_cache_req_domain() failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (ret == ENOENT) {
        goto done;
    }

    ret = cache_req_domain_new_list_from_domain_resolution_order(
                        mem_ctx, domains, domain_resolution_order, &cr_domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_DEFAULT,
              "cache_req_domain_new_list_from_domain_resolution_order() "
              "failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    *_cr_domains = cr_domains;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sss_resp_new_cr_domains_from_ipa_config(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domains,
                                        struct sysdb_ctx *sysdb,
                                        const char *domain,
                                        struct cache_req_domain **_cr_domains)
{
    TALLOC_CTX *tmp_ctx;
    const char *domain_resolution_order = NULL;
    errno_t ret;

    *_cr_domains = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_domain_get_domain_resolution_order(tmp_ctx, sysdb, domain,
                                                   &domain_resolution_order);

    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sysdb_domain_get_cache_req_domain() failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (ret == ENOENT) {
        goto done;
    }

    ret = cache_req_domain_new_list_from_domain_resolution_order(
                        mem_ctx, domains, domain_resolution_order, _cr_domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_DEFAULT,
              "cache_req_domain_new_list_from_domain_resolution_order() "
              "failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_resp_populate_cr_domains(struct resp_ctx *rctx)
{
    struct cache_req_domain *cr_domains = NULL;
    struct sss_domain_info *dom;
    errno_t ret;

    if (rctx->domain_resolution_order != NULL) {
        ret = cache_req_domain_new_list_from_domain_resolution_order(
                rctx, rctx->domains,
                rctx->domain_resolution_order, &cr_domains);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Using domain_resolution_order from sssd.conf\n");
            goto done;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to use domain_resolution_order set in the config file.\n"
                  "Trying to fallback to use ipaDomainOrderResolution setup by "
                  "IPA.\n");
        }
    }

    for (dom = rctx->domains; dom != NULL; dom = dom->next) {
        if (dom->provider != NULL && strcmp(dom->provider, "ipa") == 0) {
            break;
        }
    }

    if (dom == NULL) {
        ret = cache_req_domain_new_list_from_domain_resolution_order(
                                        rctx, rctx->domains, NULL, &cr_domains);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to flatten the list of domains.\n");
        }
        goto done;
    }

    if (dom->has_views) {
        ret = sss_resp_new_cr_domains_from_ipa_id_view(rctx, rctx->domains,
                                                       dom->sysdb,
                                                       &cr_domains);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Using domain_resolution_order from IPA ID View\n");
            goto done;
        }

        if (ret != ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to use ipaDomainResolutionOrder set for the "
                  "view \"%s\".\n"
                  "Trying to fallback to use ipaDomainOrderResolution "
                  "set in ipaConfig for the domain: %s.\n",
                  dom->view_name, dom->name);
        }
    }

    ret = sss_resp_new_cr_domains_from_ipa_config(rctx, rctx->domains,
                                                  dom->sysdb, dom->name,
                                                  &cr_domains);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Using domain_resolution_order from IPA Config\n");
        goto done;
    }

    if (ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to use ipaDomainResolutionOrder set in ipaConfig "
              "for the domain: \"%s\".\n"
              "No ipaDomainResolutionOrder will be followed.\n",
              dom->name);
    }

    ret = cache_req_domain_new_list_from_domain_resolution_order(
                                        rctx, rctx->domains, NULL, &cr_domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to flatten the list of domains.\n");
        goto done;
    }

    ret = EOK;

done:
    cache_req_domain_list_zfree(&rctx->cr_domains);
    rctx->cr_domains = cr_domains;

    return ret;
}

/**
 * Helper functions to format output names
 */
int sized_output_name(TALLOC_CTX *mem_ctx,
                      struct resp_ctx *rctx,
                      const char *orig_name,
                      struct sss_domain_info *name_dom,
                      struct sized_string **_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *name_str;
    struct sized_string *name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    name = talloc_zero(tmp_ctx, struct sized_string);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_output_fqname(name, name_dom, orig_name,
                            rctx->override_space, &name_str);
    if (ret != EOK) {
        goto done;
    }

    to_sized_string(name, name_str);
    *_name = talloc_steal(mem_ctx, name);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sized_domain_name(TALLOC_CTX *mem_ctx,
                      struct resp_ctx *rctx,
                      const char *member_name,
                      struct sized_string **_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *domname;
    struct sss_domain_info *member_dom;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, member_name, NULL, &domname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_parse_internal_fqname failed\n");
        goto done;
    }

    if (domname == NULL) {
        ret = ERR_WRONG_NAME_FORMAT;
        goto done;
    }

    member_dom = find_domain_by_name(get_domains_head(rctx->domains),
                                     domname, true);
    if (member_dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    ret = sized_output_name(mem_ctx, rctx, member_name,
                            member_dom, _name);
done:
    talloc_free(tmp_ctx);
    return ret;
}
