/*
   SSSD

   PAM Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2009
   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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
#include <dbus/dbus.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"
#include "responder/pam/pamsrv.h"
#include "responder/common/negcache.h"
#include "responder/common/responder_sbus.h"

#define DEFAULT_PAM_FD_LIMIT 8192
#define ALL_UIDS_ALLOWED "all"
#define ALL_DOMAIMS_ARE_PUBLIC "all"
#define NO_DOMAIMS_ARE_PUBLIC "none"
#define DEFAULT_ALLOWED_UIDS ALL_UIDS_ALLOWED
#define DEFAULT_PAM_CERT_AUTH false
#define DEFAULT_PAM_CERT_DB_PATH SYSCONFDIR"/pki/nssdb"

struct mon_cli_iface monitor_pam_methods = {
    { &mon_cli_iface_meta, 0 },
    .ping = monitor_common_pong,
    .resInit = monitor_common_res_init,
    .shutDown = NULL,
    .goOffline = NULL,
    .resetOffline = NULL,
    .rotateLogs = responder_logrotate,
    .clearMemcache = NULL,
    .clearEnumCache = NULL,
    .sysbusReconnect = NULL,
};

static struct data_provider_iface pam_dp_methods = {
    { &data_provider_iface_meta, 0 },
    .RegisterService = NULL,
    .pamHandler = NULL,
    .sudoHandler = NULL,
    .autofsHandler = NULL,
    .hostHandler = NULL,
    .getDomains = NULL,
    .getAccountInfo = NULL,
};

static void pam_dp_reconnect_init(struct sbus_connection *conn, int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Reconnected to the Data Provider.\n");

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "PAM");
        /* all fine */
        if (ret == EOK) {
            handle_requests_after_reconnect(be_conn->rctx);
            return;
        }
    }

    /* Handle failure */
    DEBUG(SSSDBG_FATAL_FAILURE, "Could not reconnect to %s provider.\n",
              be_conn->domain->name);

    /* FIXME: kill the frontend and let the monitor restart it ? */
    /* pam_shutdown(rctx); */
}

static errno_t get_trusted_uids(struct pam_ctx *pctx)
{
    char *uid_str;
    errno_t ret;

    ret = confdb_get_string(pctx->rctx->cdb, pctx->rctx,
                            CONFDB_PAM_CONF_ENTRY, CONFDB_PAM_TRUSTED_USERS,
                            DEFAULT_ALLOWED_UIDS, &uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get allowed UIDs.\n");
        goto done;
    }

    if (strcmp(uid_str, ALL_UIDS_ALLOWED) == 0) {
         DEBUG(SSSDBG_TRACE_FUNC, "All UIDs are allowed.\n");
         pctx->trusted_uids_count = 0;
    } else {
        ret = csv_string_to_uid_array(pctx->rctx, uid_str, true,
                                      &pctx->trusted_uids_count,
                                      &pctx->trusted_uids);
    }

    talloc_free(uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to set allowed UIDs.\n");
        goto done;
    }

done:
    return ret;
}

static errno_t get_public_domains(TALLOC_CTX *mem_ctx, struct pam_ctx *pctx)
{
    char *domains_str = NULL;
    errno_t ret;

    ret = confdb_get_string(pctx->rctx->cdb, pctx->rctx,
                            CONFDB_PAM_CONF_ENTRY, CONFDB_PAM_PUBLIC_DOMAINS,
                            NO_DOMAIMS_ARE_PUBLIC, &domains_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get allowed UIDs.\n");
        goto done;
    }

    if (strcmp(domains_str, ALL_DOMAIMS_ARE_PUBLIC) == 0) { /* all */
        /* copy all domains */
        ret = get_dom_names(mem_ctx,
                            pctx->rctx->domains,
                            &pctx->public_domains,
                            &pctx->public_domains_count);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "get_dom_names failed.\n");
            goto done;
        }
    } else if (strcmp(domains_str, NO_DOMAIMS_ARE_PUBLIC) == 0) { /* none */
        pctx->public_domains = NULL;
        pctx->public_domains_count = 0;
    } else {
        ret = split_on_separator(mem_ctx, domains_str, ',', true, false,
                                 &pctx->public_domains,
                                 &pctx->public_domains_count);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed [%d][%s].\n",
                  ret, strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(domains_str);
    return ret;
}

static int pam_process_init(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct confdb_ctx *cdb,
                            int pipe_fd, int priv_pipe_fd)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *pam_cmds;
    struct be_conn *iter;
    struct pam_ctx *pctx;
    int ret, max_retries;
    int id_timeout;
    int fd_limit;

    pam_cmds = get_pam_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           pam_cmds,
                           SSS_PAM_SOCKET_NAME, pipe_fd,
                           SSS_PAM_PRIV_SOCKET_NAME, priv_pipe_fd,
                           CONFDB_PAM_CONF_ENTRY,
                           SSS_PAM_SBUS_SERVICE_NAME,
                           SSS_PAM_SBUS_SERVICE_VERSION,
                           &monitor_pam_methods,
                           "PAM", &pam_dp_methods.vtable,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_process_init() failed\n");
        return ret;
    }

    pctx = talloc_zero(rctx, struct pam_ctx);
    if (!pctx) {
        ret = ENOMEM;
        goto done;
    }

    pctx->rctx = rctx;
    pctx->rctx->pvt_ctx = pctx;

    ret = get_trusted_uids(pctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "get_trusted_uids failed: %d:[%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = get_public_domains(pctx, pctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "get_public_domains failed: %d:[%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Enable automatic reconnection to the Data Provider */

    /* FIXME: "retries" is too generic, either get it from a global config
     * or specify these retries are about the sbus connections to DP */
    ret = confdb_get_int(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES, 3, &max_retries);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to set up automatic reconnection\n");
        goto done;
    }

    for (iter = pctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            pam_dp_reconnect_init, iter);
    }

    /* Set up the negative cache */
    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENTRY_NEG_TIMEOUT, 15,
                         &pctx->neg_timeout);
    if (ret != EOK) goto done;

    /* Set up the PAM identity timeout */
    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_ID_TIMEOUT, 5,
                         &id_timeout);
    if (ret != EOK) goto done;

    pctx->id_timeout = (size_t)id_timeout;

    ret = sss_ncache_init(pctx, &pctx->ncache);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing negative cache\n");
        goto done;
    }

    ret = sss_ncache_prepopulate(pctx->ncache, cdb, pctx->rctx);
    if (ret != EOK) {
        goto done;
    }

    /* Create table for initgroup lookups */
    ret = sss_hash_create(pctx, 10, &pctx->id_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not create initgroups hash table: [%s]\n",
              strerror(ret));
        goto done;
    }

    /* Set up file descriptor limits */
    ret = confdb_get_int(pctx->rctx->cdb,
                         CONFDB_PAM_CONF_ENTRY,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_PAM_FD_LIMIT,
                         &fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to set up file descriptor limit\n");
        goto done;
    }
    responder_set_fd_limit(fd_limit);

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx, pctx->ncache);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "schedule_get_domains_tasks failed.\n");
        goto done;
    }

    /* Check if certificate based authentication is enabled */
    ret = confdb_get_bool(pctx->rctx->cdb,
                          CONFDB_PAM_CONF_ENTRY,
                          CONFDB_PAM_CERT_AUTH,
                          DEFAULT_PAM_CERT_AUTH,
                          &pctx->cert_auth);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to determine get cert db path.\n");
        goto done;
    }

    pctx->p11_child_debug_fd = -1;
    if (pctx->cert_auth) {
        ret = p11_child_init(pctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "p11_child_init failed.\n");
            goto done;
        }

        ret = confdb_get_string(pctx->rctx->cdb, pctx,
                                CONFDB_PAM_CONF_ENTRY,
                                CONFDB_PAM_CERT_DB_PATH,
                                DEFAULT_PAM_CERT_DB_PATH,
                                &pctx->nss_db);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to determine if certificate based authentication is " \
                  "enabled or not.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(rctx);
    }
    return ret;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;
    uid_t uid;
    gid_t gid;
    int pipe_fd;
    int priv_pipe_fd;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_SERVER_OPTS(uid, gid)
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    umask(DFL_RSP_UMASK);

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                             poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_pam";

    /* Crate pipe file descriptors here before privileges are dropped
     * in server_setup() */
    ret = create_pipe_fd(SSS_PAM_SOCKET_NAME, &pipe_fd, 0111);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "create_pipe_fd failed [%d]: %s.\n",
              ret, sss_strerror(ret));
        return 2;
    }

    ret = create_pipe_fd(SSS_PAM_PRIV_SOCKET_NAME, &priv_pipe_fd, 0177);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "create_pipe_fd failed (priviledged pipe) [%d]: %s.\n",
              ret, sss_strerror(ret));
        return 2;
    }

    ret = server_setup("sssd[pam]", 0, uid, gid, CONFDB_PAM_CONF_ENTRY, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = pam_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx,
                           pipe_fd, priv_pipe_fd);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

