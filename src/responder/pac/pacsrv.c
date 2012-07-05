/*
   SSSD

   PAC Responder

   Copyright (C) Sumit Bose <sbose@redhat.com> 2011

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

#include "popt.h"
#include "util/util.h"
#include "responder/pac/pacsrv.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"

#define SSS_PAC_PIPE_NAME "pac"
#define DEFAULT_PAC_FD_LIMIT 8192
#define DEFAULT_ALLOWED_UIDS "0"

struct sbus_method monitor_pac_methods[] = {
    { MON_CLI_METHOD_PING, monitor_common_pong },
    { MON_CLI_METHOD_RES_INIT, monitor_common_res_init },
    { MON_CLI_METHOD_ROTATE, responder_logrotate },
    { NULL, NULL }
};

struct sbus_interface monitor_pac_interface = {
    MONITOR_INTERFACE,
    MONITOR_PATH,
    SBUS_DEFAULT_VTABLE,
    monitor_pac_methods,
    NULL
};

static struct sbus_method pac_dp_methods[] = {
    { NULL, NULL }
};

struct sbus_interface pac_dp_interface = {
    DP_INTERFACE,
    DP_PATH,
    SBUS_DEFAULT_VTABLE,
    pac_dp_methods,
    NULL
};


/* TODO: check if this can be made generic for all responders */
static void pac_dp_reconnect_init(struct sbus_connection *conn,
                                  int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, ("Reconnected to the Data Provider.\n"));

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "PAC");
        /* all fine */
        if (ret == EOK) {
            handle_requests_after_reconnect(be_conn->rctx);
            return;
        }
    }

    /* Failed to reconnect */
    DEBUG(SSSDBG_FATAL_FAILURE, ("Could not reconnect to %s provider.\n",
              be_conn->domain->name));

    /* FIXME: kill the frontend and let the monitor restart it ? */
    /* nss_shutdown(rctx); */
}

static void *idmap_talloc(size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void idmap_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

int pac_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
    struct sss_cmd_table *pac_cmds;
    struct be_conn *iter;
    struct pac_ctx *pac_ctx;
    int ret, max_retries;
    enum idmap_error_code err;
    int fd_limit;
    char *uid_str;

    pac_ctx = talloc_zero(mem_ctx, struct pac_ctx);
    if (!pac_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("fatal error initializing pac_ctx\n"));
        return ENOMEM;
    }

    pac_cmds = get_pac_cmds();

    ret = sss_process_init(pac_ctx, ev, cdb,
                           pac_cmds,
                           SSS_PAC_SOCKET_NAME, NULL,
                           CONFDB_PAC_CONF_ENTRY,
                           PAC_SBUS_SERVICE_NAME,
                           PAC_SBUS_SERVICE_VERSION,
                           &monitor_pac_interface,
                           "PAC", &pac_dp_interface,
                           &pac_ctx->rctx);
    if (ret != EOK) {
        return ret;
    }
    pac_ctx->rctx->pvt_ctx = pac_ctx;


    ret = confdb_get_string(pac_ctx->rctx->cdb, pac_ctx->rctx,
                            CONFDB_PAC_CONF_ENTRY, CONFDB_SERVICE_ALLOWED_UIDS,
                            DEFAULT_ALLOWED_UIDS, &uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to get allowed UIDs.\n"));
        return ret;
    }

    ret = csv_string_to_uid_array(pac_ctx->rctx, uid_str, true,
                                  &pac_ctx->rctx->allowed_uids_count,
                                  &pac_ctx->rctx->allowed_uids);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to set allowed UIDs.\n"));
        return ret;
    }

    /* Enable automatic reconnection to the Data Provider */
    ret = confdb_get_int(pac_ctx->rctx->cdb,
                         CONFDB_PAC_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES,
                         3, &max_retries);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to set up automatic reconnection\n"));
        return ret;
    }

    for (iter = pac_ctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            pac_dp_reconnect_init, iter);
    }

    err = sss_idmap_init(idmap_talloc, pac_ctx, idmap_free,
                         &pac_ctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("sss_idmap_init failed.\n"));
        return EFAULT;
    }

    /* Set up file descriptor limits */
    ret = confdb_get_int(pac_ctx->rctx->cdb,
                         CONFDB_PAC_CONF_ENTRY,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_PAC_FD_LIMIT,
                         &fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Failed to set up file descriptor limit\n"));
        return ret;
    }
    responder_set_fd_limit(fd_limit);

    DEBUG(SSSDBG_TRACE_FUNC, ("PAC Initialization complete\n"));

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

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

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_pac";

    ret = server_setup("sssd[pac]", 0, CONFDB_PAC_CONF_ENTRY, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set up to exit when parent process does\n"));
    }

    ret = pac_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
