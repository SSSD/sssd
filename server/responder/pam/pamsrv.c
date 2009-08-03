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

/* Needed for res_init() */
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "popt.h"
#include "util/util.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "util/btreemap.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_sbus.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"
#include "responder/pam/pamsrv.h"

#define PAM_SBUS_SERVICE_VERSION 0x0001
#define PAM_SBUS_SERVICE_NAME "pam"
#define PAM_SRV_CONFIG "config/services/pam"

static int service_identity(DBusMessage *message, struct sbus_connection *conn);
static int service_pong(DBusMessage *message, struct sbus_connection *conn);
static int service_reload(DBusMessage *message, struct sbus_connection *conn);
static int service_res_init(DBusMessage *message, struct sbus_connection *conn);

struct sbus_method monitor_pam_methods[] = {
    { MON_CLI_METHOD_IDENTITY, service_identity },
    { MON_CLI_METHOD_PING, service_pong },
    { MON_CLI_METHOD_RELOAD, service_reload },
    { MON_CLI_METHOD_RES_INIT, service_res_init },
    { NULL, NULL }
};

struct sbus_interface monitor_pam_interface = {
    MONITOR_INTERFACE,
    MONITOR_PATH,
    SBUS_DEFAULT_VTABLE,
    monitor_pam_methods,
    NULL
};

static int service_identity(DBusMessage *message, struct sbus_connection *conn)
{
    dbus_uint16_t version = PAM_SBUS_SERVICE_VERSION;
    const char *name = PAM_SBUS_SERVICE_NAME;
    DBusMessage *reply;
    dbus_bool_t ret;

    DEBUG(4,("Sending ID reply: (%s,%d)\n", name, version));

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static int service_pong(DBusMessage *message, struct sbus_connection *conn)
{
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply, DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static int service_res_init(DBusMessage *message, struct sbus_connection *conn)
{
    int ret;

    ret = res_init();
    if(ret != 0) {
        return EIO;
    }

    return service_pong(message, conn);
}

static void pam_shutdown(struct resp_ctx *ctx);

static int service_reload(DBusMessage *message, struct sbus_connection *conn) {
    /* Monitor calls this function when we need to reload
     * our configuration information. Perform whatever steps
     * are needed to update the configuration objects.
     */

    /* Send an empty reply to acknowledge receipt */
    return service_pong(message, conn);
}

static void pam_dp_reconnect_init(struct sbus_connection *conn, int status, void *pvt)
{
    struct resp_ctx *rctx = talloc_get_type(pvt, struct resp_ctx);

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(1, ("Reconnected to the Data Provider.\n"));
        return;
    }

    /* Handle failure */
    DEBUG(0, ("Could not reconnect to data provider.\n"));
    /* Kill the backend and let the monitor restart it */
    pam_shutdown(rctx);
}

static void pam_shutdown(struct resp_ctx *rctx)
{
    /* TODO: Do clean-up here */

    /* Nothing left to do but exit() */
    exit(0);
}


static int pam_process_init(struct main_context *main_ctx,
                            struct resp_ctx *rctx)
{
    int ret, max_retries;

    /* Enable automatic reconnection to the Data Provider */

    /* FIXME: "retries" is too generic, either get it from a global config
     * or specify these retries are about the sbus connections to DP */
    ret = confdb_get_int(rctx->cdb, rctx, SERVICE_CONF_ENTRY,
                         "reconnection_retries", 3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        return ret;
    }

    sbus_reconnect_init(rctx->dp_conn, max_retries,
                        pam_dp_reconnect_init, rctx);

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;
    struct sbus_interface *pam_dp_interface;
    struct sss_cmd_table *sss_cmds;
    struct resp_ctx *rctx;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
        SSSD_MAIN_OPTS
		{ NULL }
	};

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

    /* set up things like debug , signals, daemonization, etc... */
    ret = server_setup("sssd[pam]", 0, PAM_SRV_CONFIG, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    pam_dp_interface = get_pam_dp_interface();
    sss_cmds = register_sss_cmds();
    ret = sss_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx,
                           sss_cmds,
                           SSS_PAM_SOCKET_NAME,
                           SSS_PAM_PRIV_SOCKET_NAME,
                           PAM_SRV_CONFIG,
                           pam_dp_interface,
                           &monitor_pam_interface,
                           &rctx);
    if (ret != EOK) return 3;

    ret = pam_process_init(main_ctx, rctx);
    if (ret != EOK) return 4;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

