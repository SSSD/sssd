/*
   SSSD

   InfoPipe

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
#include "util/util.h"
#include "util/btreemap.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sbus_client.h"
#include "monitor/monitor_sbus.h"
#include "monitor/monitor_interfaces.h"
#include "infopipe/sysbus.h"
#include "infopipe.h"

struct infp_ctx {
    struct event_context *ev;
    struct confdb_ctx *cdb;
    struct service_sbus_ctx *ss_ctx;
    struct sysbus_ctx *sysbus;
};

static int service_identity(DBusMessage *message, struct sbus_message_ctx *reply)
{
    dbus_uint16_t version = INFOPIPE_VERSION;
    const char *name = INFOPIPE_SERVICE_NAME;
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

static int infp_monitor_init(struct infp_ctx *infp_ctx)
{
    int ret;
    char *sbus_address;
    struct service_sbus_ctx *ss_ctx;
    struct sbus_method_ctx *sm_ctx;

    /* Set up SBUS connection to the monitor */
    ret = monitor_get_sbus_address(infp_ctx, infp_ctx->cdb, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate monitor address.\n"));
        return ret;
    }

    ret = monitor_init_sbus_methods(infp_ctx, mon_sbus_methods, &sm_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize SBUS methods.\n"));
        return ret;
    }

    ret = sbus_client_init(infp_ctx, infp_ctx->ev,
                           sbus_address, sm_ctx,
                           NULL /* Private Data */,
                           NULL /* Destructor */,
                           &ss_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to monitor services.\n"));
        return ret;
    }

    /* Set up InfoPipe-specific listeners */
    /* None currently used */

    infp_ctx->ss_ctx = ss_ctx;

    return EOK;
}

struct sbus_method infp_methods[] = {
    INFP_USER_METHODS
    INFP_GROUP_METHODS
    { NULL, NULL }
};

#define INTROSPECT_CHUNK_SIZE 128

int infp_introspect(DBusMessage *message, struct sbus_message_ctx *reply)
{
    FILE *xml_stream;
    char *introspect_xml;
    char *chunk;
    TALLOC_CTX *tmp_ctx;
    unsigned long xml_size;
    size_t chunk_size;
    int ret;
    dbus_bool_t dbret;

    tmp_ctx = talloc_new(reply);
    if(tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (reply->mh_ctx->introspection_xml == NULL) {
        /* Read in the Introspection XML the first time */
        xml_stream = fopen(SSSD_INTROSPECT_PATH"/"INFP_INTROSPECT_XML, "r");
        if(xml_stream == NULL) {
            DEBUG(0, ("Could not open the introspection XML for reading: [%d] [%s].\n", errno, SSSD_INTROSPECT_PATH"/"INFP_INTROSPECT_XML));
            return errno;
        }

        chunk = talloc_size(tmp_ctx, INTROSPECT_CHUNK_SIZE);
        if (chunk == NULL) {
            ret = ENOMEM;
            goto done;
        }

        xml_size = 0;
        introspect_xml = NULL;
        do {
            chunk_size = fread(chunk, 1, INTROSPECT_CHUNK_SIZE, xml_stream);
            introspect_xml = talloc_realloc_size(tmp_ctx, introspect_xml, xml_size+chunk_size+1);
            if (introspect_xml == NULL) {
                ret = ENOMEM;
                goto done;
            }
            memcpy(introspect_xml+xml_size, chunk, chunk_size);
            xml_size += chunk_size;
        } while(chunk_size == INTROSPECT_CHUNK_SIZE);
        introspect_xml[xml_size] = '\0';
        talloc_free(chunk);

        /* Store the instrospection XML for future calls */
        reply->mh_ctx->introspection_xml = introspect_xml;
        talloc_steal(reply->mh_ctx, introspect_xml);
    }
    else {
        /* Subsequent calls should just reuse the saved value */
        introspect_xml = reply->mh_ctx->introspection_xml;
    }

    /* Return the Introspection XML */
    reply->reply_message = dbus_message_new_method_return(message);
    if (reply->reply_message == NULL) {
        ret = ENOMEM;
        goto done;
    }
    dbret = dbus_message_append_args(reply->reply_message,
                                     DBUS_TYPE_STRING, &introspect_xml,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(9, ("%s\n", introspect_xml));
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int infp_process_init(TALLOC_CTX *mem_ctx,
                             struct event_context *ev,
                             struct confdb_ctx *cdb)
{
    struct infp_ctx *infp_ctx;
    int ret;

    infp_ctx = talloc_zero(mem_ctx, struct infp_ctx);
    if (infp_ctx == NULL) {
        DEBUG(0, ("Fatal error initializing infp_ctx\n"));
        return ENOMEM;
    }
    infp_ctx->ev = ev;
    infp_ctx->cdb = cdb;

    /* Connect to the monitor */
    ret = infp_monitor_init(infp_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Fatal error setting up monitor bus\n"));
        return EIO;
    }

    /* Connect to the D-BUS system bus and set up methods */
    ret = sysbus_init(infp_ctx, &infp_ctx->sysbus,
                      infp_ctx->ev, INFOPIPE_DBUS_NAME,
                      INFOPIPE_INTERFACE, INFOPIPE_PATH,
                      infp_methods, infp_introspect);
    if (ret != EOK) {
        DEBUG(0, ("Failed to connect to the system message bus\n"));
        return EIO;
    }

    /* Add the infp_ctx to the sbus_conn_ctx private data
     * so we can pass it into message handler functions
     */
    sbus_conn_set_private_data(sysbus_get_sbus_conn(infp_ctx->sysbus), infp_ctx);

    return ret;
}

int infp_check_permissions(DBusMessage *message, struct sbus_message_ctx *reply)
{
    reply->reply_message = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");
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

    ret = infp_process_init(main_ctx,
                            main_ctx->event_ctx,
                            main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
