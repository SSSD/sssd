/*
   SSSD

   PAM Responder

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
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "util/btreemap.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder_cmd.h"
#include "responder/common/responder_common.h"
#include "providers/data_provider.h"
#include "monitor/monitor_sbus.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"
#include "responder/pam/pamsrv.h"
#include "../sss_client/sss_cli.h"

#define PAM_SBUS_SERVICE_VERSION 0x0001
#define PAM_SBUS_SERVICE_NAME "pam"
#define PAM_SRV_CONFIG "config/services/pam"

static int service_identity(DBusMessage *message, struct sbus_conn_ctx *sconn);
static int service_pong(DBusMessage *message, struct sbus_conn_ctx *sconn);
static int service_reload(DBusMessage *message, struct sbus_conn_ctx *sconn);

struct sbus_method sss_sbus_methods[] = {
    {SERVICE_METHOD_IDENTITY, service_identity},
    {SERVICE_METHOD_PING, service_pong},
    {SERVICE_METHOD_RELOAD, service_reload},
    {NULL, NULL}
};

static int service_identity(DBusMessage *message, struct sbus_conn_ctx *sconn)
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
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static int service_pong(DBusMessage *message, struct sbus_conn_ctx *sconn)
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
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static void pam_shutdown(struct resp_ctx *ctx);

static int service_reload(DBusMessage *message, struct sbus_conn_ctx *sconn) {
    /* Monitor calls this function when we need to reload
     * our configuration information. Perform whatever steps
     * are needed to update the configuration objects.
     */

    /* Send an empty reply to acknowledge receipt */
    return service_pong(message, sconn);
}

static void pam_dp_reconnect_init(struct sbus_conn_ctx *sconn, int status, void *pvt)
{
    int ret;
    struct resp_ctx *rctx = talloc_get_type(pvt, struct resp_ctx);

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        /* Add the methods back to the new connection */
        ret = sbus_conn_add_method_ctx(rctx->dp_ctx->scon_ctx,
                                       rctx->dp_ctx->sm_ctx);
        if (ret != EOK) {
            DEBUG(0, ("Could not re-add methods on reconnection.\n"));
            pam_shutdown(rctx);
        }

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
    ret = confdb_get_int(rctx->cdb, rctx, rctx->confdb_service_path,
                         "retries", 3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        return ret;
    }

    sbus_reconnect_init(rctx->dp_ctx->scon_ctx, max_retries,
                        pam_dp_reconnect_init, rctx);

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;
    struct sbus_method *pam_dp_methods;
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

    pam_dp_methods = register_pam_dp_methods();
    sss_cmds = register_sss_cmds();
    ret = sss_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx,
                           sss_sbus_methods,
                           sss_cmds,
                           SSS_PAM_SOCKET_NAME,
                           SSS_PAM_PRIV_SOCKET_NAME,
                           PAM_SRV_CONFIG,
                           pam_dp_methods,
                           &rctx);
    if (ret != EOK) return 3;

    ret = pam_process_init(main_ctx, rctx);
    if (ret != EOK) return 4;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

