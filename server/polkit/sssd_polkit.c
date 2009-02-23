/*
   SSSD

   PolicyKit

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include "popt.h"
#include "sssd_polkit.h"
#include "util/util.h"
#include "sbus/sbus_client.h"
#include "monitor/monitor_sbus.h"
#include "monitor/monitor_interfaces.h"

struct spk_ctx {
    struct event_context *ev;
    struct confdb_ctx *cdb;
    struct service_sbus_ctx *ss_ctx;
    struct sbus_srv_ctx *sbus_srv;
};

static int service_identity(DBusMessage *message, struct sbus_message_ctx *reply)
{
    dbus_uint16_t version = POLKIT_VERSION;
    const char *name = POLKIT_SERVICE_NAME;
    dbus_bool_t ret;

    DEBUG(4, ("Sending identity data [%s,%d]\n", name, version));

    reply->reply_message = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply->reply_message,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    return EOK;
}

static int service_pong(DBusMessage *message, struct sbus_message_ctx *reply)
{
    dbus_bool_t ret;

    reply->reply_message = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply->reply_message, DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    return EOK;
}

static int service_reload(DBusMessage *message, struct sbus_message_ctx *reply) {
    /* Monitor calls this function when we need to reload
     * our configuration information. Perform whatever steps
     * are needed to update the configuration objects.
     */

    /* Send an empty reply to acknowledge receipt */
    return service_pong(message, reply);
}

struct sbus_method mon_sbus_methods[] = {
    { SERVICE_METHOD_IDENTITY, service_identity },
    { SERVICE_METHOD_PING, service_pong },
    { SERVICE_METHOD_RELOAD, service_reload },
    { NULL, NULL }
};

static int spk_monitor_init(struct spk_ctx *spk_ctx)
{
    int ret;
    char *sbus_address;
    struct service_sbus_ctx *ss_ctx;
    struct sbus_method_ctx *sm_ctx;

    /* Set up SBUS connection to the monitor */
    ret = monitor_get_sbus_address(spk_ctx, spk_ctx->cdb, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate monitor address.\n"));
        return ret;
    }

    ret = monitor_init_sbus_methods(spk_ctx, mon_sbus_methods, &sm_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize SBUS methods.\n"));
        return ret;
    }

    ret = sbus_client_init(spk_ctx, spk_ctx->ev,
                           sbus_address, sm_ctx,
                           NULL /* Private Data */,
                           NULL /* Destructor */,
                           &ss_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

    /* Set up PolicyKit-specific listeners */
    /* None currently used */

    spk_ctx->ss_ctx = ss_ctx;

    return EOK;
}

static int spk_process_init(TALLOC_CTX *mem_ctx,
                            struct event_context *ev,
                            struct confdb_ctx *cdb)
{
    struct spk_ctx *spk_ctx;
    int ret;

    spk_ctx = talloc_zero(mem_ctx, struct spk_ctx);
    if (spk_ctx == NULL) {
        DEBUG(0, ("Fatal error initializing spk_ctx\n"));
        return ENOMEM;
    }
    spk_ctx->ev = ev;
    spk_ctx->cdb = cdb;

    ret = spk_monitor_init(spk_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Fatal error setting up monitor bus\n"));
    }
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
    ret = server_setup("sssd[infp]", 0, &main_ctx);
    if (ret != EOK) return 2;

    ret = spk_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
