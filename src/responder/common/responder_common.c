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
#include <popt.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"

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

static int client_destructor(struct cli_ctx *ctx)
{
    errno_t ret;

    if ((ctx->cfd > 0) && close(ctx->cfd) < 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to close fd [%d]: [%s]\n",
               ctx->cfd, strerror(ret));
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Terminated client [%p][%d]\n",
           ctx, ctx->cfd);
    return 0;
}

static errno_t get_client_cred(struct cli_ctx *cctx)
{
    cctx->client_euid = -1;
    cctx->client_egid = -1;
    cctx->client_pid = -1;

#ifdef HAVE_UCRED
    int ret;
    struct ucred client_cred;
    socklen_t client_cred_len = sizeof(client_cred);

    ret = getsockopt(cctx->cfd, SOL_SOCKET, SO_PEERCRED, &client_cred,
                     &client_cred_len);
    if (ret != EOK) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "getsock failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }
    if (client_cred_len != sizeof(struct ucred)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "getsockopt returned unexpected message size.\n");
        return ENOMSG;
    }

    cctx->client_euid = client_cred.uid;
    cctx->client_egid = client_cred.gid;
    cctx->client_pid = client_cred.pid;

    DEBUG(SSSDBG_TRACE_ALL, "Client creds: euid[%d] egid[%d] pid[%d].\n",
              cctx->client_euid, cctx->client_egid, cctx->client_pid);
#endif

    return EOK;
}

errno_t check_allowed_uids(uid_t uid, size_t allowed_uids_count,
                           uid_t *allowed_uids)
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
                                bool allow_sss_loop,
                                size_t *_uid_count, uid_t **_uids)
{
    int ret;
    size_t c;
    char **list = NULL;
    int list_size;
    uid_t *uids = NULL;
    char *endptr;

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

    if (allow_sss_loop) {
        ret = unsetenv("_SSS_LOOPS");
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to unset _SSS_LOOPS, getpwnam "
                                      "might not find sssd users.\n");
        }
    }

    for (c = 0; c < list_size; c++) {
        errno = 0;
        if (*list[c] == '\0') {
            DEBUG(SSSDBG_OP_FAILURE, "Empty list item.\n");
            ret = EINVAL;
            goto done;
        }

        uids[c] = strtouint32(list[c], &endptr, 10);
        if (errno != 0 || *endptr != '\0') {
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
    if(setenv("_SSS_LOOPS", "NO", 0) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set _SSS_LOOPS.\n");
    }
    talloc_free(list);
    if (ret != EOK) {
        talloc_free(uids);
    }

    return ret;
}


static void client_send(struct cli_ctx *cctx)
{
    int ret;

    ret = sss_packet_send(cctx->creq->out, cctx->cfd);
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
    talloc_free(cctx->creq);
    cctx->creq = NULL;
    return;
}

static int client_cmd_execute(struct cli_ctx *cctx, struct sss_cmd_table *sss_cmds)
{
    enum sss_cli_command cmd;

    cmd = sss_packet_get_cmd(cctx->creq->in);
    return sss_cmd_execute(cctx, cmd, sss_cmds);
}

static void client_recv(struct cli_ctx *cctx)
{
    int ret;

    if (!cctx->creq) {
        cctx->creq = talloc_zero(cctx, struct cli_request);
        if (!cctx->creq) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to alloc request, aborting client!\n");
            talloc_free(cctx);
            return;
        }
    }

    if (!cctx->creq->in) {
        ret = sss_packet_new(cctx->creq, SSS_PACKET_MAX_RECV_SIZE,
                             0, &cctx->creq->in);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to alloc request, aborting client!\n");
            talloc_free(cctx);
            return;
        }
    }

    ret = sss_packet_recv(cctx->creq->in, cctx->cfd);
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

static errno_t reset_idle_timer(struct cli_ctx *cctx);

static void client_fd_handler(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *ptr)
{
    errno_t ret;
    struct cli_ctx *cctx = talloc_get_type(ptr, struct cli_ctx);

    /* Always reset the idle timer on any activity */
    ret = reset_idle_timer(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not create idle timer for client. "
               "This connection may not auto-terminate\n");
        /* Non-fatal, continue */
    }

    if (flags & TEVENT_FD_READ) {
        client_recv(cctx);
        return;
    }
    if (flags & TEVENT_FD_WRITE) {
        client_send(cctx);
        return;
    }
}

struct accept_fd_ctx {
    struct resp_ctx *rctx;
    bool is_private;
};

static void idle_handler(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval current_time,
                         void *data);

static void accept_fd_handler(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *ptr)
{
    /* accept and attach new event handler */
    struct accept_fd_ctx *accept_ctx =
            talloc_get_type(ptr, struct accept_fd_ctx);
    struct resp_ctx *rctx = accept_ctx->rctx;
    struct cli_ctx *cctx;
    socklen_t len;
    struct stat stat_buf;
    int ret;
    int fd = accept_ctx->is_private ? rctx->priv_lfd : rctx->lfd;
    int client_fd;

    if (accept_ctx->is_private) {
        ret = stat(rctx->priv_sock_name, &stat_buf);
        if (ret == -1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "stat on privileged pipe failed: [%d][%s].\n", errno,
                      strerror(errno));
            return;
        }

        if ( ! (stat_buf.st_uid == 0 && stat_buf.st_gid == 0 &&
               (stat_buf.st_mode&(S_IFSOCK|S_IRUSR|S_IWUSR)) == stat_buf.st_mode)) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "privileged pipe has an illegal status.\n");
    /* TODO: what is the best response to this condition? Terminate? */
            return;
        }
    }

    cctx = talloc_zero(rctx, struct cli_ctx);
    if (!cctx) {
        struct sockaddr_un addr;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Out of memory trying to setup client context%s!\n",
                  accept_ctx->is_private ? " on privileged pipe": "");
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

    len = sizeof(cctx->addr);
    cctx->cfd = accept(fd, (struct sockaddr *)&cctx->addr, &len);
    if (cctx->cfd == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Accept failed [%s]\n", strerror(errno));
        talloc_free(cctx);
        return;
    }

    cctx->priv = accept_ctx->is_private;

    ret = get_client_cred(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_client_cred failed, "
                  "client cred may not be available.\n");
    }

    if (rctx->allowed_uids_count != 0) {
        if (cctx->client_euid == -1) {
            DEBUG(SSSDBG_CRIT_FAILURE, "allowed_uids configured, " \
                                        "but platform does not support " \
                                        "reading peer credential from the " \
                                        "socket. Access denied.\n");
            close(cctx->cfd);
            talloc_free(cctx);
            return;
        }

        ret = check_allowed_uids(cctx->client_euid, rctx->allowed_uids_count,
                                 rctx->allowed_uids);
        if (ret != EOK) {
            if (ret == EACCES) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Access denied for uid [%d].\n",
                                            cctx->client_euid);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "check_allowed_uids failed.\n");
            }
            close(cctx->cfd);
            talloc_free(cctx);
            return;
        }
    }

    cctx->cfde = tevent_add_fd(ev, cctx, cctx->cfd,
                               TEVENT_FD_READ, client_fd_handler, cctx);
    if (!cctx->cfde) {
        close(cctx->cfd);
        talloc_free(cctx);
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to queue client handler%s\n",
               accept_ctx->is_private ? " on privileged pipe" : "");
        return;
    }

    cctx->ev = ev;
    cctx->rctx = rctx;

    talloc_set_destructor(cctx, client_destructor);

    /* Set up the idle timer */
    ret = reset_idle_timer(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not create idle timer for client. "
               "This connection may not auto-terminate\n");
        /* Non-fatal, continue */
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Client connected%s!\n",
           accept_ctx->is_private ? " to privileged pipe" : "");

    return;
}

static errno_t reset_idle_timer(struct cli_ctx *cctx)
{
    struct timeval tv =
            tevent_timeval_current_ofs(cctx->rctx->client_idle_timeout, 0);

    talloc_zfree(cctx->idle);

    cctx->idle = tevent_add_timer(cctx->ev, cctx, tv, idle_handler, cctx);
    if (!cctx->idle) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL,
          "Idle timer re-set for client [%p][%d]\n",
           cctx, cctx->cfd);

    return EOK;
}

static void idle_handler(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval current_time,
                         void *data)
{
    /* This connection is idle. Terminate it */
    struct cli_ctx *cctx =
            talloc_get_type(data, struct cli_ctx);

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Terminating idle client [%p][%d]\n",
           cctx, cctx->cfd);

    /* The cli_ctx destructor will handle the rest */
    talloc_free(cctx);
}

static int sss_dp_init(struct resp_ctx *rctx,
                       struct sbus_vtable *dp_intf,
                       const char *cli_name,
                       struct sss_domain_info *domain)
{
    struct be_conn *be_conn;
    int ret;

    be_conn = talloc_zero(rctx, struct be_conn);
    if (!be_conn) return ENOMEM;

    be_conn->cli_name = cli_name;
    be_conn->domain = domain;
    be_conn->rctx = rctx;

    /* Set up SBUS connection to the monitor */
    ret = dp_get_sbus_address(be_conn, &be_conn->sbus_address, domain->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not locate DP address.\n");
        return ret;
    }
    ret = sbus_client_init(rctx, rctx->ev,
                           be_conn->sbus_address,
                           &be_conn->conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to connect to monitor services.\n");
        return ret;
    }

    ret = sbus_conn_register_iface(be_conn->conn, dp_intf, DP_PATH, rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to export data provider.\n");
        return ret;
    }

    DLIST_ADD_END(rctx->be_conns, be_conn, struct be_conn *);

    /* Identify ourselves to the DP */
    ret = dp_common_send_id(be_conn->conn,
                            DATA_PROVIDER_VERSION,
                            cli_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to identify to the DP!\n");
        return ret;
    }

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
              "Cannot remove old socket (errno=%d), bind might fail!\n", ret);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to bind on socket '%s'\n", sock_name);
        ret = EIO;
        goto done;
    }
    if (listen(fd, 10) == -1) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to listen on socket '%s'\n", sock_name);
        ret = EIO;
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
static int set_unix_socket(struct resp_ctx *rctx)
{
    errno_t ret;
    struct accept_fd_ctx *accept_ctx;

/* for future use */
#if 0
    char *default_pipe;
    int ret;

    default_pipe = talloc_asprintf(rctx, "%s/%s", PIPE_PATH,
                                   rctx->sss_pipe_name);
    if (!default_pipe) {
        return ENOMEM;
    }

    ret = confdb_get_string(rctx->cdb, rctx,
                            rctx->confdb_socket_path, "unixSocket",
                            default_pipe, &rctx->sock_name);
    if (ret != EOK) {
        talloc_free(default_pipe);
        return ret;
    }
    talloc_free(default_pipe);

    default_pipe = talloc_asprintf(rctx, "%s/private/%s", PIPE_PATH,
                                   rctx->sss_pipe_name);
    if (!default_pipe) {
        return ENOMEM;
    }

    ret = confdb_get_string(rctx->cdb, rctx,
                            rctx->confdb_socket_path, "privUnixSocket",
                            default_pipe, &rctx->priv_sock_name);
    if (ret != EOK) {
        talloc_free(default_pipe);
        return ret;
    }
    talloc_free(default_pipe);
#endif

    if (rctx->sock_name != NULL ) {
        /* Set the umask so that permissions are set right on the socket.
         * It must be readable and writable by anybody on the system. */
        if (rctx->lfd == -1) {
            ret = create_pipe_fd(rctx->sock_name, &rctx->lfd, 0111);
            if (ret != EOK) {
                return ret;
            }
        }

        accept_ctx = talloc_zero(rctx, struct accept_fd_ctx);
        if(!accept_ctx) goto failed;
        accept_ctx->rctx = rctx;
        accept_ctx->is_private = false;

        rctx->lfde = tevent_add_fd(rctx->ev, rctx, rctx->lfd,
                                   TEVENT_FD_READ, accept_fd_handler,
                                   accept_ctx);
        if (!rctx->lfde) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to queue handler on pipe\n");
            goto failed;
        }
    }

    if (rctx->priv_sock_name != NULL ) {
        /* create privileged pipe */
        if (rctx->priv_lfd == -1) {
            ret = create_pipe_fd(rctx->priv_sock_name, &rctx->priv_lfd, 0177);
            if (ret != EOK) {
                goto failed;
            }
        }

        accept_ctx = talloc_zero(rctx, struct accept_fd_ctx);
        if(!accept_ctx) goto failed;
        accept_ctx->rctx = rctx;
        accept_ctx->is_private = true;

        rctx->priv_lfde = tevent_add_fd(rctx->ev, rctx, rctx->priv_lfd,
                                   TEVENT_FD_READ, accept_fd_handler,
                                   accept_ctx);
        if (!rctx->priv_lfde) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to queue handler on privileged pipe\n");
            goto failed;
        }
    }

    return EOK;

failed:
    close(rctx->lfd);
    close(rctx->priv_lfd);
    return EIO;
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

int sss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb,
                     struct sss_cmd_table sss_cmds[],
                     const char *sss_pipe_name,
                     int pipe_fd,
                     const char *sss_priv_pipe_name,
                     int priv_pipe_fd,
                     const char *confdb_service_path,
                     const char *svc_name,
                     uint16_t svc_version,
                     struct mon_cli_iface *monitor_intf,
                     const char *cli_name,
                     struct sbus_vtable *dp_intf,
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
    rctx->priv_sock_name = sss_priv_pipe_name;
    rctx->lfd = pipe_fd;
    rctx->priv_lfd = priv_pipe_fd;
    rctx->confdb_service_path = confdb_service_path;
    rctx->shutting_down = false;

    talloc_set_destructor((TALLOC_CTX*)rctx, sss_responder_ctx_destructor);

    ret = confdb_get_int(rctx->cdb, rctx->confdb_service_path,
                         CONFDB_RESPONDER_CLI_IDLE_TIMEOUT,
                         CONFDB_RESPONDER_CLI_IDLE_DEFAULT_TIMEOUT,
                         &rctx->client_idle_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the client idle timeout [%d]: %s\n",
               ret, strerror(ret));
        goto fail;
    }

    /* Ensure that the client timeout is at least ten seconds */
    if (rctx->client_idle_timeout < 10) {
        rctx->client_idle_timeout = 10;
    }

    ret = confdb_get_int(rctx->cdb, rctx->confdb_service_path,
                         CONFDB_RESPONDER_GET_DOMAINS_TIMEOUT,
                         GET_DOMAINS_DEFAULT_TIMEOUT, &rctx->domains_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannnot get the default domain timeout [%d]: %s\n",
               ret, strerror(ret));
        goto fail;
    }

    if (rctx->domains_timeout < 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "timeout can't be set to negative value, setting default\n");
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
              "Cannnot get the default domain [%d]: %s\n",
               ret, strerror(ret));
        goto fail;
    }

    ret = confdb_get_string(rctx->cdb, rctx, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_OVERRIDE_SPACE, NULL,
                            &tmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannnot get the space substitution character [%d]: %s\n",
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

    ret = sss_monitor_init(rctx, rctx->ev, monitor_intf,
                           svc_name, svc_version, rctx,
                           &rctx->mon_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error setting up message bus\n");
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

        /* skip local domain, it doesn't have a backend */
        if (strcasecmp(dom->provider, "local") == 0) {
            continue;
        }

        ret = sss_dp_init(rctx, dp_intf, cli_name, dom);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fatal error setting up backend connector\n");
            goto fail;
        }
    }

    ret = sysdb_init(rctx, rctx->domains, false);
    if (ret != EOK) {
        SYSDB_VERSION_ERROR_DAEMON(ret);
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing resp_ctx\n");
        goto fail;
    }

    /* after all initializations we are ready to listen on our socket */
    ret = set_unix_socket(rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing socket\n");
        goto fail;
    }

    /* Create DP request table */
    ret = sss_hash_create(rctx, 30, &rctx->dp_request_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not create hash table for the request queue\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Responder Initialization complete\n");

    *responder_ctx = rctx;
    return EOK;

fail:
    talloc_free(rctx);
    return ret;
}

int sss_dp_get_domain_conn(struct resp_ctx *rctx, const char *domain,
                           struct be_conn **_conn)
{
    struct be_conn *iter;

    if (!rctx->be_conns) return ENOENT;

    for (iter = rctx->be_conns; iter; iter = iter->next) {
        if (strcasecmp(domain, iter->domain->name) == 0) break;
    }

    if (!iter) return ENOENT;

    *_conn = iter;

    return EOK;
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

int responder_logrotate(struct sbus_request *dbus_req, void *data)
{
    errno_t ret;
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);

    ret = server_common_rotate_logs(rctx->cdb, rctx->confdb_service_path);
    if (ret != EOK) return ret;

    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
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
