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
#include "sbus/sssd_dbus.h"
#include "monitor/monitor_interfaces.h"
#include "confdb/confdb.h"
#include "responder/ifp/ifp_private.h"
#include "responder/ifp/ifp_domains.h"
#include "responder/ifp/ifp_components.h"
#include "responder/common/responder_sbus.h"

#define DEFAULT_ALLOWED_UIDS "0"

static int ifp_sysbus_reconnect(struct sbus_request *dbus_req, void *data);

struct mon_cli_iface monitor_ifp_methods = {
    { &mon_cli_iface_meta, 0 },
    .ping = monitor_common_pong,
    .resInit = monitor_common_res_init,
    .shutDown = NULL,
    .goOffline = NULL,
    .resetOffline = NULL,
    .rotateLogs = responder_logrotate,
    .sysbusReconnect = ifp_sysbus_reconnect,
};

static struct data_provider_iface ifp_dp_methods = {
    { &data_provider_iface_meta, 0 },
    .RegisterService = NULL,
    .pamHandler = NULL,
    .sudoHandler = NULL,
    .autofsHandler = NULL,
    .hostHandler = NULL,
    .getDomains = NULL,
    .getAccountInfo = NULL,
};

struct infopipe_iface ifp_iface = {
    { &infopipe_iface_meta, 0 },
    .Ping = ifp_ping,

    /* components */
    .ListComponents = ifp_list_components,
    .ListResponders = ifp_list_responders,
    .ListBackends = ifp_list_backends,
    .FindMonitor = ifp_find_monitor,
    .FindResponderByName = ifp_find_responder_by_name,
    .FindBackendByName = ifp_find_backend_by_name,

    .GetUserAttr = ifp_user_get_attr,
    .GetUserGroups = ifp_user_get_groups,
    .ListDomains = ifp_list_domains,
    .FindDomainByName = ifp_find_domain_by_name,
};

struct infopipe_component ifp_component = {
    { &infopipe_component_meta, 0 },
    .Enable = ifp_component_enable,
    .Disable = ifp_component_disable,
    .ChangeDebugLevel = ifp_component_change_debug_level,
    .ChangeDebugLevelTemporarily = ifp_component_change_debug_level_tmp,
    .infopipe_component_get_name = ifp_component_get_name,
    .infopipe_component_get_debug_level = ifp_component_get_debug_level,
    .infopipe_component_get_enabled = ifp_component_get_enabled,
    .infopipe_component_get_type = ifp_component_get_type,
    /* FIXME: This should be part of Components.Backends interface, onece
     * SSSD supports multiple interfaces per object path. */
    .infopipe_component_get_providers = ifp_backend_get_providers
};

struct infopipe_domain ifp_domain = {
    { &infopipe_domain_meta, 0 },
    .infopipe_domain_get_name = ifp_dom_get_name,
    .infopipe_domain_get_provider = ifp_dom_get_provider,
    .infopipe_domain_get_primary_servers = ifp_dom_get_primary_servers,
    .infopipe_domain_get_backup_servers = ifp_dom_get_backup_servers,
    .infopipe_domain_get_min_id = ifp_dom_get_min_id,
    .infopipe_domain_get_max_id = ifp_dom_get_max_id,
    .infopipe_domain_get_realm = ifp_dom_get_realm,
    .infopipe_domain_get_forest = ifp_dom_get_forest,
    .infopipe_domain_get_login_format = ifp_dom_get_login_format,
    .infopipe_domain_get_fully_qualified_name_format = ifp_dom_get_fqdn_format,
    .infopipe_domain_get_enumerable = ifp_dom_get_enumerable,
    .infopipe_domain_get_use_fully_qualified_names = ifp_dom_get_use_fqdn,
    .infopipe_domain_get_subdomain = ifp_dom_get_subdomain,
    .infopipe_domain_get_parent_domain = ifp_dom_get_parent_domain
};

struct sysbus_iface {
    const char *path;
    struct sbus_vtable *iface_vtable;
};

static struct sysbus_iface ifp_ifaces[] = {
    { INFOPIPE_PATH, &ifp_iface.vtable },
    { INFOPIPE_DOMAIN_PATH, &ifp_domain.vtable },
    { INFOPIPE_COMPONENT_PATH, &ifp_component.vtable },
    { NULL, NULL },
};

struct sss_cmd_table *get_ifp_cmds(void)
{
    static struct sss_cmd_table ifp_cmds[] = {
        { SSS_GET_VERSION, sss_cmd_get_version },
        { SSS_CLI_NULL, NULL}
    };

    return ifp_cmds;
}

static void ifp_dp_reconnect_init(struct sbus_connection *conn,
                                  int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(SSSDBG_TRACE_FUNC, "Reconnected to the Data Provider.\n");

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "InfoPipe");
        /* all fine */
        if (ret == EOK) {
            handle_requests_after_reconnect(be_conn->rctx);
            return;
        }
    }

    /* Failed to reconnect */
    DEBUG(SSSDBG_FATAL_FAILURE, "Could not reconnect to %s provider.\n",
                                 be_conn->domain->name);
}

static errno_t
sysbus_init(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            const char *dbus_name,
            struct sysbus_iface *sysbus_ifaces,
            void *pvt,
            struct sysbus_ctx **sysbus)
{
    DBusError dbus_error;
    DBusConnection *conn = NULL;
    struct sysbus_ctx *system_bus = NULL;
    struct sbus_interface *sif;
    int i;
    errno_t ret;

    system_bus = talloc_zero(mem_ctx, struct sysbus_ctx);
    if (system_bus == NULL) {
        return ENOMEM;
    }

    dbus_error_init(&dbus_error);

    /* Connect to the well-known system bus */
    conn = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to connect to D-BUS system bus: [%s]\n",
              dbus_error.message);
        ret = ERR_NO_SYSBUS;
        goto fail;
    }
    dbus_connection_set_exit_on_disconnect(conn, FALSE);

    ret = dbus_bus_request_name(conn, dbus_name,
                                /* We want exclusive access */
                                DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                &dbus_error);
    if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        /* We were unable to register on the system bus */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to request name on the system bus: [%s]\n",
              dbus_error.message);
        ret = EIO;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Listening on %s\n", dbus_name);

    /* Integrate with tevent loop */
    ret = sbus_init_connection(system_bus, ev, conn,
                               SBUS_CONN_TYPE_SYSBUS,
                               &system_bus->conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not integrate D-BUS into mainloop.\n");
        goto fail;
    }

    for (i = 0; sysbus_ifaces[i].path != NULL; i++) {
        sif = sbus_new_interface(system_bus->conn,
                                 sysbus_ifaces[i].path,
                                 sysbus_ifaces[i].iface_vtable,
                                 pvt);
        if (sif == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not add the sbus interface\n");
            goto fail;
        }

        ret = sbus_conn_add_interface(system_bus->conn, sif);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not add the interface\n");
            goto fail;
        }
    }

    *sysbus = system_bus;
    return EOK;

fail:
    if (dbus_error_is_set(&dbus_error)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "DBus error message: %s\n", dbus_error.message);
        dbus_error_free(&dbus_error);
    }

    if (conn) dbus_connection_unref(conn);

    talloc_free(system_bus);
    return ret;
}

static int ifp_sysbus_reconnect(struct sbus_request *dbus_req, void *data)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);
    struct ifp_ctx *ifp_ctx = (struct ifp_ctx*) rctx->pvt_ctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Attempting to reconnect to the system bus\n");

    if (ifp_ctx->sysbus) {
        DEBUG(SSSDBG_TRACE_LIBS, "Already connected to sysbus\n");
        goto done;
    }

    /* Connect to the D-BUS system bus and set up methods */
    ret = sysbus_init(ifp_ctx, ifp_ctx->rctx->ev,
                      INFOPIPE_IFACE,
                      ifp_ifaces,
                      ifp_ctx, &ifp_ctx->sysbus);
    if (ret == ERR_NO_SYSBUS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "The system bus is not available..\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to connect to the system message bus\n");
        return ret;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Reconnected to the system bus!\n");

done:
    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}

int ifp_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *ifp_cmds;
    struct ifp_ctx *ifp_ctx;
    struct be_conn *iter;
    int ret;
    int max_retries;
    char *uid_str;
    char *attr_list_str;

    ifp_cmds = get_ifp_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           ifp_cmds,
                           NULL, NULL,
                           CONFDB_IFP_CONF_ENTRY,
                           SSS_IFP_SBUS_SERVICE_NAME,
                           SSS_IFP_SBUS_SERVICE_VERSION,
                           &monitor_ifp_methods,
                           "InfoPipe",
                           &ifp_dp_methods.vtable,
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
                                   "(?P<name>[^@]+)@?(?P<domain>[^@]*$)",
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

    ret = csv_string_to_uid_array(ifp_ctx->rctx, uid_str, true,
                                  &ifp_ctx->rctx->allowed_uids_count,
                                  &ifp_ctx->rctx->allowed_uids);
    talloc_free(uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to set allowed UIDs.\n");
        goto fail;
    }

    /* Set up the negative cache */
    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENTRY_NEG_TIMEOUT, 15,
                         &ifp_ctx->neg_timeout);
    if (ret != EOK) {
        goto fail;
    }

    ret = sss_ncache_init(rctx, &ifp_ctx->ncache);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "fatal error initializing negcache\n");
        goto fail;
    }

    ret = confdb_get_string(ifp_ctx->rctx->cdb, ifp_ctx->rctx,
                            CONFDB_IFP_CONF_ENTRY, CONFDB_IFP_USER_ATTR_LIST,
                            NULL, &attr_list_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get allowed UIDs.\n");
        goto fail;
    }

    ifp_ctx->user_whitelist = ifp_parse_attr_list(ifp_ctx, attr_list_str);
    talloc_free(attr_list_str);
    if (ifp_ctx->user_whitelist == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to parse the allowed attribute list\n");
        goto fail;
    }

    /* Enable automatic reconnection to the Data Provider */
    ret = confdb_get_int(ifp_ctx->rctx->cdb,
                         CONFDB_IFP_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES,
                         3, &max_retries);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to set up automatic reconnection\n");
        goto fail;
    }

    for (iter = ifp_ctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            ifp_dp_reconnect_init, iter);
    }

    /* Connect to the D-BUS system bus and set up methods */
    ret = sysbus_init(ifp_ctx, ifp_ctx->rctx->ev,
                      INFOPIPE_IFACE,
                      ifp_ifaces,
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

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "schedule_get_domains_tasks failed.\n");
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
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    DEBUG_INIT(debug_level);

    /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_ifp";

    ret = server_setup("sssd[ifp]", 0, CONFDB_IFP_CONF_ENTRY, &main_ctx);
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
