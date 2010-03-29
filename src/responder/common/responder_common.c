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

/* for struct ucred */
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <popt.h>
#include "config.h"
#include "util/util.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"

static void set_nonblocking(int fd)
{
    unsigned v;
    v = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, v | O_NONBLOCK);
}

static void set_close_on_exec(int fd)
{
    unsigned v;
    v = fcntl(fd, F_GETFD, 0);
    fcntl(fd, F_SETFD, v | FD_CLOEXEC);
}

static int client_destructor(struct cli_ctx *ctx)
{
    if (ctx->cfd > 0) close(ctx->cfd);
    return 0;
}

static errno_t get_client_cred(struct cli_ctx *cctx)
{
#ifdef HAVE_UCRED
    int ret;
    struct ucred client_cred;
    socklen_t client_cred_len = sizeof(client_cred);

    cctx->client_euid = -1;
    cctx->client_egid = -1;
    cctx->client_pid = -1;

    ret = getsockopt(cctx->cfd, SOL_SOCKET, SO_PEERCRED, &client_cred,
                     &client_cred_len);
    if (ret != EOK) {
        ret = errno;
        DEBUG(1, ("getsock failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }
    if (client_cred_len != sizeof(struct ucred)) {
        DEBUG(1, ("getsockopt returned unexpected message size.\n"));
        return ENOMSG;
    }

    cctx->client_euid = client_cred.uid;
    cctx->client_egid = client_cred.gid;
    cctx->client_pid = client_cred.pid;

    DEBUG(9, ("Client creds: euid[%d] egid[%d] pid[%d].\n",
              cctx->client_euid, cctx->client_egid, cctx->client_pid));
#endif

    return EOK;
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
        DEBUG(0, ("Failed to send data, aborting client!\n"));
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

static void client_recv(struct cli_ctx *cctx)
{
    int ret;

    if (!cctx->creq) {
        cctx->creq = talloc_zero(cctx, struct cli_request);
        if (!cctx->creq) {
            DEBUG(0, ("Failed to alloc request, aborting client!\n"));
            talloc_free(cctx);
            return;
        }
    }

    if (!cctx->creq->in) {
        ret = sss_packet_new(cctx->creq, SSS_PACKET_MAX_RECV_SIZE,
                             0, &cctx->creq->in);
        if (ret != EOK) {
            DEBUG(0, ("Failed to alloc request, aborting client!\n"));
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
        ret = sss_cmd_execute(cctx, cctx->rctx->sss_cmds);
        if (ret != EOK) {
            DEBUG(0, ("Failed to execute request, aborting client!\n"));
            talloc_free(cctx);
        }
        /* past this point cctx can be freed at any time by callbacks
         * in case of error, do not use it */
        return;

    case EAGAIN:
        /* need to read still some data, loop again */
        break;

    case EINVAL:
        DEBUG(6, ("Invalid data from client, closing connection!\n"));
        talloc_free(cctx);
        break;

    case ENODATA:
        DEBUG(5, ("Client disconnected!\n"));
        talloc_free(cctx);
        break;

    default:
        DEBUG(6, ("Failed to read request, aborting client!\n"));
        talloc_free(cctx);
    }

    return;
}

static void client_fd_handler(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *ptr)
{
    struct cli_ctx *cctx = talloc_get_type(ptr, struct cli_ctx);

    if (flags & TEVENT_FD_READ) {
        client_recv(cctx);
        return;
    }
    if (flags & TEVENT_FD_WRITE) {
        client_send(cctx);
        return;
    }
}

/* TODO: this is a copy of accept_fd_handler, maybe both can be put into on
 * handler.  */
static void accept_priv_fd_handler(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *ptr)
{
    /* accept and attach new event handler */
    struct resp_ctx *rctx = talloc_get_type(ptr, struct resp_ctx);
    struct cli_ctx *cctx;
    socklen_t len;
    struct stat stat_buf;
    int ret;

    ret = stat(rctx->priv_sock_name, &stat_buf);
    if (ret == -1) {
        DEBUG(1, ("stat on privileged pipe failed: [%d][%s].\n", errno,
                  strerror(errno)));
        return;
    }

    if ( ! (stat_buf.st_uid == 0 && stat_buf.st_gid == 0 &&
           (stat_buf.st_mode&(S_IFSOCK|S_IRUSR|S_IWUSR)) == stat_buf.st_mode)) {
        DEBUG(1, ("privileged pipe has an illegal status.\n"));
/* TODO: what is the best response to this condition? Terminate? */
        return;
    }


    cctx = talloc_zero(rctx, struct cli_ctx);
    if (!cctx) {
        struct sockaddr_un addr;
        int fd;
        DEBUG(0, ("Out of memory trying to setup client context on privileged pipe!\n"));
        /* accept and close to signal the client we have a problem */
        memset(&addr, 0, sizeof(addr));
        len = sizeof(addr);
        fd = accept(rctx->priv_lfd, (struct sockaddr *)&addr, &len);
        if (fd == -1) {
            return;
        }
        close(fd);
        return;
    }

    len = sizeof(cctx->addr);
    cctx->cfd = accept(rctx->priv_lfd, (struct sockaddr *)&cctx->addr, &len);
    if (cctx->cfd == -1) {
        DEBUG(1, ("Accept failed [%s]\n", strerror(errno)));
        talloc_free(cctx);
        return;
    }

    cctx->priv = 1;

    ret = get_client_cred(cctx);
    if (ret != EOK) {
        DEBUG(2, ("get_client_cred failed, "
                  "client cred may not be available.\n"));
    }

    cctx->cfde = tevent_add_fd(ev, cctx, cctx->cfd,
                               TEVENT_FD_READ, client_fd_handler, cctx);
    if (!cctx->cfde) {
        close(cctx->cfd);
        talloc_free(cctx);
        DEBUG(2, ("Failed to queue client handler on privileged pipe\n"));
    }

    cctx->ev = ev;
    cctx->rctx = rctx;

    talloc_set_destructor(cctx, client_destructor);

    DEBUG(4, ("Client connected to privileged pipe!\n"));

    return;
}

static void accept_fd_handler(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              uint16_t flags, void *ptr)
{
    /* accept and attach new event handler */
    struct resp_ctx *rctx = talloc_get_type(ptr, struct resp_ctx);
    struct cli_ctx *cctx;
    socklen_t len;
    int ret;

    cctx = talloc_zero(rctx, struct cli_ctx);
    if (!cctx) {
        struct sockaddr_un addr;
        int fd;
        DEBUG(0, ("Out of memory trying to setup client context!\n"));
        /* accept and close to signal the client we have a problem */
        memset(&addr, 0, sizeof(addr));
        len = sizeof(addr);
        fd = accept(rctx->lfd, (struct sockaddr *)&addr, &len);
        if (fd == -1) {
            return;
        }
        close(fd);
        return;
    }

    len = sizeof(cctx->addr);
    cctx->cfd = accept(rctx->lfd, (struct sockaddr *)&cctx->addr, &len);
    if (cctx->cfd == -1) {
        DEBUG(1, ("Accept failed [%s]\n", strerror(errno)));
        talloc_free(cctx);
        return;
    }

    ret = get_client_cred(cctx);
    if (ret != EOK) {
        DEBUG(2, ("get_client_cred failed, "
                  "client cred may not be available.\n"));
    }

    cctx->cfde = tevent_add_fd(ev, cctx, cctx->cfd,
                               TEVENT_FD_READ, client_fd_handler, cctx);
    if (!cctx->cfde) {
        close(cctx->cfd);
        talloc_free(cctx);
        DEBUG(2, ("Failed to queue client handler\n"));
    }

    cctx->ev = ev;
    cctx->rctx = rctx;

    talloc_set_destructor(cctx, client_destructor);

    DEBUG(4, ("Client connected!\n"));

    return;
}

static int sss_monitor_init(struct resp_ctx *rctx,
                            struct sbus_interface *intf,
                            const char *svc_name,
                            uint16_t svc_version)
{
    char *sbus_address;
    int ret;

    /* Set up SBUS connection to the monitor */
    ret = monitor_get_sbus_address(rctx, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate monitor address.\n"));
        return ret;
    }

    ret = sbus_client_init(rctx, rctx->ev, sbus_address,
                           intf, &rctx->mon_conn,
                           NULL, NULL);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

    /* Identify ourselves to the monitor */
    ret = monitor_common_send_id(rctx->mon_conn, svc_name, svc_version);
    if (ret != EOK) {
        DEBUG(0, ("Failed to identify to the monitor!\n"));
        return ret;
    }

    return EOK;
}

static int sss_dp_init(struct resp_ctx *rctx,
                       struct sbus_interface *intf,
                       const char *cli_name,
                       struct sss_domain_info *domain)
{
    struct be_conn *be_conn;
    int ret;

    be_conn = talloc_zero(rctx, struct be_conn);
    if (!be_conn) return ENOMEM;

    be_conn->cli_name = cli_name;
    be_conn->domain = domain;
    be_conn->intf = intf;

    /* Set up SBUS connection to the monitor */
    ret = dp_get_sbus_address(be_conn, &be_conn->sbus_address, domain->name);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate DP address.\n"));
        return ret;
    }
    ret = sbus_client_init(rctx, rctx->ev,
                           be_conn->sbus_address,
                           intf, &be_conn->conn,
                           NULL, NULL);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

    DLIST_ADD_END(rctx->be_conns, be_conn, struct be_conn *);

    /* Identify ourselves to the DP */
    ret = dp_common_send_id(be_conn->conn,
                            DATA_PROVIDER_VERSION,
                            cli_name);
    if (ret != EOK) {
        DEBUG(0, ("Failed to identify to the DP!\n"));
        return ret;
    }

    return EOK;
}

/* create a unix socket and listen to it */
static int set_unix_socket(struct resp_ctx *rctx)
{
    struct sockaddr_un addr;

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
        rctx->lfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (rctx->lfd == -1) {
            return EIO;
        }

        /* Set the umask so that permissions are set right on the socket.
         * It must be readable and writable by anybody on the system. */
        umask(0111);

        set_nonblocking(rctx->lfd);
        set_close_on_exec(rctx->lfd);

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, rctx->sock_name, sizeof(addr.sun_path));

        /* make sure we have no old sockets around */
        unlink(rctx->sock_name);

        if (bind(rctx->lfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            DEBUG(0,("Unable to bind on socket '%s'\n", rctx->sock_name));
            goto failed;
        }
        if (listen(rctx->lfd, 10) != 0) {
            DEBUG(0,("Unable to listen on socket '%s'\n", rctx->sock_name));
            goto failed;
        }

        rctx->lfde = tevent_add_fd(rctx->ev, rctx, rctx->lfd,
                                   TEVENT_FD_READ, accept_fd_handler, rctx);
        if (!rctx->lfde) {
            DEBUG(0, ("Failed to queue handler on pipe\n"));
            goto failed;
        }
    }

    if (rctx->priv_sock_name != NULL ) {
        /* create privileged pipe */
        rctx->priv_lfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (rctx->priv_lfd == -1) {
            close(rctx->lfd);
            return EIO;
        }

        umask(0177);

        set_nonblocking(rctx->priv_lfd);
        set_close_on_exec(rctx->priv_lfd);

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, rctx->priv_sock_name, sizeof(addr.sun_path));

        unlink(rctx->priv_sock_name);

        if (bind(rctx->priv_lfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            DEBUG(0,("Unable to bind on socket '%s'\n", rctx->priv_sock_name));
            goto failed;
        }
        if (listen(rctx->priv_lfd, 10) != 0) {
            DEBUG(0,("Unable to listen on socket '%s'\n", rctx->priv_sock_name));
            goto failed;
        }

        rctx->priv_lfde = tevent_add_fd(rctx->ev, rctx, rctx->priv_lfd,
                                   TEVENT_FD_READ, accept_priv_fd_handler, rctx);
        if (!rctx->priv_lfde) {
            DEBUG(0, ("Failed to queue handler on privileged pipe\n"));
            goto failed;
        }
    }

    /* we want default permissions on created files to be very strict,
       so set our umask to 0177 */
    umask(0177);
    return EOK;

failed:
    /* we want default permissions on created files to be very strict,
       so set our umask to 0177 */
    umask(0177);
    close(rctx->lfd);
    close(rctx->priv_lfd);
    return EIO;
}

int sss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb,
                     struct sss_cmd_table sss_cmds[],
                     const char *sss_pipe_name,
                     const char *sss_priv_pipe_name,
                     const char *confdb_service_path,
                     const char *svc_name,
                     uint16_t svc_version,
                     struct sbus_interface *monitor_intf,
                     const char *cli_name,
                     struct sbus_interface *dp_intf,
                     struct resp_ctx **responder_ctx)
{
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    int ret;

    rctx = talloc_zero(mem_ctx, struct resp_ctx);
    if (!rctx) {
        DEBUG(0, ("fatal error initializing resp_ctx\n"));
        return ENOMEM;
    }
    rctx->ev = ev;
    rctx->cdb = cdb;
    rctx->sss_cmds = sss_cmds;
    rctx->sock_name = sss_pipe_name;
    rctx->priv_sock_name = sss_priv_pipe_name;
    rctx->confdb_service_path = confdb_service_path;

    ret = confdb_get_domains(rctx->cdb, &rctx->domains);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up domain map\n"));
        return ret;
    }

    ret = sss_monitor_init(rctx, monitor_intf, svc_name, svc_version);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up message bus\n"));
        return ret;
    }

    for (dom = rctx->domains; dom; dom = dom->next) {

        /* skip local domain, it doesn't have a backend */
        if (strcasecmp(dom->provider, "local") == 0) {
            continue;
        }

        ret = sss_dp_init(rctx, dp_intf, cli_name, dom);
        if (ret != EOK) {
            DEBUG(0, ("fatal error setting up backend connector\n"));
            return ret;
        }
    }

    ret = sysdb_init(rctx, ev, cdb, NULL, false, &rctx->db_list);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing resp_ctx\n"));
        return ret;
    }

    ret = sss_names_init(rctx, rctx->cdb, &rctx->names);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing regex data\n"));
        return ret;
    }

    /* after all initializations we are ready to listen on our socket */
    ret = set_unix_socket(rctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing socket\n"));
        return ret;
    }

    DEBUG(1, ("Responder Initialization complete\n"));

    *responder_ctx = rctx;
    return EOK;
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

