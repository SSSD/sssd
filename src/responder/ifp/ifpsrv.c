/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: the responder server

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
#include "util/strtonum.h"
#include "confdb/confdb.h"
#include "responder/ifp/ifp_private.h"
#include "responder/ifp/ifp_domains.h"
#include "responder/ifp/ifp_components.h"
#include "responder/ifp/ifp_iface/ifp_iface_async.h"
#include "sss_iface/sss_iface_async.h"

#define DEFAULT_ALLOWED_UIDS "0"

struct sss_cmd_table *get_ifp_cmds(void)
{
    static struct sss_cmd_table ifp_cmds[] = {
        { SSS_GET_VERSION, sss_cmd_get_version },
        { SSS_CLI_NULL, NULL}
    };

    return ifp_cmds;
}

static errno_t
sysbus_init(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            const char *dbus_name,
            struct ifp_ctx  *ifp_ctx,
            struct sbus_connection **_sysbus)
{
    struct sbus_connection *sysbus;
    errno_t ret;

    sysbus = sbus_connect_system(mem_ctx, ev, dbus_name,
                                 &ifp_ctx->rctx->last_request_time);
    if (sysbus == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to connect to system bus!\n");
        return ERR_NO_SYSBUS;
    }

    sbus_connection_set_access_check(sysbus, ifp_access_check, ifp_ctx);

    ret = ifp_register_sbus_interface(sysbus, ifp_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not register interfaces\n");
        goto done;
    }

    ret = ifp_register_nodes(ifp_ctx, sysbus);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not register nodes factories\n");
        goto done;
    }

    *_sysbus = sysbus;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sysbus);
    }

    return ret;
}

static errno_t
ifp_sysbus_reconnect(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct ifp_ctx *ifp_ctx)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Attempting to reconnect to the system bus\n");

    if (ifp_ctx->sysbus != NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "Already connected to sysbus\n");
        return EOK;
    }

    /* Connect to the D-BUS system bus and set up methods */
    ret = sysbus_init(ifp_ctx, ifp_ctx->rctx->ev, IFP_BUS,
                      ifp_ctx, &ifp_ctx->sysbus);
    if (ret == ERR_NO_SYSBUS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "The system bus is not available..\n");
        return ret;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to connect to the system message bus\n");
        return ret;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Reconnected to the system bus!\n");

    return EOK;
}

static errno_t
ifp_register_service_iface(struct ifp_ctx *ifp_ctx,
                           struct resp_ctx *rctx)
{
    errno_t ret;

    SBUS_INTERFACE(iface_svc,
        sssd_service,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_service, rotateLogs, responder_logrotate, rctx),
            SBUS_SYNC(METHOD, sssd_service, sysbusReconnect, ifp_sysbus_reconnect, ifp_ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, sssd_service, debug_level, generic_get_debug_level, NULL),
            SBUS_SYNC(SETTER, sssd_service, debug_level, generic_set_debug_level, NULL)
        )
    );

    ret = sbus_connection_add_path(rctx->sbus_conn, SSS_BUS_PATH, &iface_svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register service interface"
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    return ret;
}

int ifp_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *ifp_cmds;
    struct ifp_ctx *ifp_ctx;
    int ret;
    char *uid_str;
    char *attr_list_str;
    char *wildcard_limit_str;
    char *endptr;

    ifp_cmds = get_ifp_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           ifp_cmds,
                           NULL, 0,
                           CONFDB_IFP_CONF_ENTRY,
                           SSS_BUS_IFP, SSS_IFP_SBUS_SERVICE_NAME,
                           sss_connection_setup,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_process_init() failed\n");
        return ret;
    }

    ifp_ctx = talloc_zero(rctx, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing ifp_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    ifp_ctx->rctx = rctx;
    ifp_ctx->rctx->pvt_ctx = ifp_ctx;

    ret = sss_names_init_from_args(ifp_ctx,
                                   SSS_DEFAULT_RE,
                                   "%1$s@%2$s", &ifp_ctx->snctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing regex data\n");
        goto fail;
    }

    ret = confdb_get_string(ifp_ctx->rctx->cdb, ifp_ctx->rctx,
                            CONFDB_IFP_CONF_ENTRY, CONFDB_SERVICE_ALLOWED_UIDS,
                            DEFAULT_ALLOWED_UIDS, &uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get allowed UIDs.\n");
        goto fail;
    }

    ret = csv_string_to_uid_array(ifp_ctx->rctx, uid_str,
                                  &ifp_ctx->rctx->allowed_uids_count,
                                  &ifp_ctx->rctx->allowed_uids);
    talloc_free(uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to set allowed UIDs.\n");
        goto fail;
    }

    ret = confdb_get_string(ifp_ctx->rctx->cdb, ifp_ctx->rctx,
                            CONFDB_IFP_CONF_ENTRY, CONFDB_IFP_USER_ATTR_LIST,
                            NULL, &attr_list_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get user attribute list.\n");
        goto fail;
    }

    ifp_ctx->user_whitelist = ifp_parse_user_attr_list(ifp_ctx, attr_list_str);
    talloc_free(attr_list_str);
    if (ifp_ctx->user_whitelist == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to parse the allowed attribute list\n");
        goto fail;
    }

    /* A bit convoluted way until we have a confdb_get_uint32 */
    ret = confdb_get_string(ifp_ctx->rctx->cdb,
                            ifp_ctx->rctx,
                            CONFDB_IFP_CONF_ENTRY,
                            CONFDB_IFP_WILDCARD_LIMIT,
                            NULL, /* no limit by default */
                            &wildcard_limit_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to retrieve limit for a wildcard search\n");
        goto fail;
    }

    if (wildcard_limit_str) {
        ifp_ctx->wildcard_limit = strtouint32(wildcard_limit_str, &endptr, 10);
        if ((errno != 0) || *endptr || (wildcard_limit_str == endptr)) {
            ret = errno ? errno : EINVAL;
            goto fail;
        }
    }

    /* Connect to the D-BUS system bus and set up methods */
    ret = sysbus_init(ifp_ctx, ifp_ctx->rctx->ev, IFP_BUS,
                      ifp_ctx, &ifp_ctx->sysbus);
    if (ret == ERR_NO_SYSBUS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "The system bus is not available..\n");
        /* Explicitly ignore, the D-Bus daemon will start us */
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to connect to the system message bus\n");
        talloc_free(ifp_ctx);
        return EIO;
    }

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx, NULL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "schedule_get_domains_tasks failed.\n");
        goto fail;
    }

    /* The responder is initialized. Now tell it to the monitor. */
    ret = sss_monitor_register_service(rctx, rctx->sbus_conn,
                                       SSS_IFP_SBUS_SERVICE_NAME,
                                       SSS_IFP_SBUS_SERVICE_VERSION,
                                       MT_SVC_SERVICE);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register to the monitor "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    ret = ifp_register_service_iface(ifp_ctx, rctx);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "InfoPipe Initialization complete\n");
    return EOK;

fail:
    talloc_free(rctx);
    return ret;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *opt_logger = NULL;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
        SSSD_RESPONDER_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
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

    /* set up things like debug, signals, daemonization, etc. */
    debug_log_file = "sssd_ifp";
    DEBUG_INIT(debug_level, opt_logger);

    ret = server_setup("ifp", true, 0, CONFDB_FILE,
                       CONFDB_IFP_CONF_ENTRY, &main_ctx, true);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = ifp_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);
    return 0;
}
