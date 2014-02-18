/*
   SSSD

   Data Provider Helpers

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

/* Needed for res_init() */
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sbus_client.h"
#include "monitor/monitor_interfaces.h"

int monitor_get_sbus_address(TALLOC_CTX *mem_ctx, char **address)
{
    char *default_address;

    *address = NULL;
    default_address = talloc_asprintf(mem_ctx, "unix:path=%s/%s",
                                      PIPE_PATH, SSSD_SERVICE_PIPE);
    if (default_address == NULL) {
        return ENOMEM;
    }

    *address = default_address;
    return EOK;
}

static void id_callback(DBusPendingCall *pending, void *ptr)
{
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_bool_t ret;
    dbus_uint16_t mon_ver;
    int type;

    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Severe error. A reply callback was called but no"
                  " reply was received and no timeout occurred\n");

        /* FIXME: Destroy this connection ? */
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dbus_message_get_args(reply, &dbus_error,
                                    DBUS_TYPE_UINT16, &mon_ver,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse message\n");
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            /* FIXME: Destroy this connection ? */
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS,
              "Got id ack and version (%d) from Monitor\n", mon_ver);

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(SSSDBG_FATAL_FAILURE,"The Monitor returned an error [%s]\n",
                 dbus_message_get_error_name(reply));
        /* Falling through to default intentionally*/
    default:
        /*
         * Timeout or other error occurred or something
         * unexpected happened.
         * It doesn't matter which, because either way we
         * know that this connection isn't trustworthy.
         * We'll destroy it now.
         */

        /* FIXME: Destroy this connection ? */
        break;
    }

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
}

int monitor_common_send_id(struct sbus_connection *conn,
                           const char *name, uint16_t version)
{
    DBusMessage *msg;
    dbus_bool_t ret;
    int retval;

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       MON_SRV_PATH,
                                       MON_SRV_IFACE,
                                       MON_SRV_IFACE_REGISTERSERVICE);
    if (msg == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?!\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Sending ID: (%s,%d)\n", name, version);

    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
        return EIO;
    }

    retval = sbus_conn_send(conn, msg, 3000,
                            id_callback,
                            NULL, NULL);
    dbus_message_unref(msg);
    return retval;
}

int monitor_common_pong(struct sbus_request *dbus_req, void *data)
{
    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}

int monitor_common_res_init(struct sbus_request *dbus_req, void *data)
{
    int ret;

    ret = res_init();
    if(ret != 0) {
        return EIO;
    }

    /* Send an empty reply to acknowledge receipt */
    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}

errno_t monitor_common_rotate_logs(struct confdb_ctx *confdb,
                                   const char *conf_path)
{
    errno_t ret;
    int old_debug_level = debug_level;

    ret = rotate_debug_files();
    if (ret) {
        sss_log(SSS_LOG_ALERT, "Could not rotate debug files! [%d][%s]\n",
                               ret, strerror(ret));
        return ret;
    }

    /* Get new debug level from the confdb */
    ret = confdb_get_int(confdb, conf_path,
                         CONFDB_SERVICE_DEBUG_LEVEL,
                         old_debug_level,
                         &debug_level);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading from confdb (%d) [%s]\n",
                  ret, strerror(ret));
        /* Try to proceed with the old value */
        debug_level = old_debug_level;
    }

    if (debug_level != old_debug_level) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Debug level changed to %#.4x\n", debug_level);
        debug_level = debug_convert_old_level(debug_level);
    }

    return EOK;
}

errno_t sss_monitor_init(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct mon_cli_iface *mon_iface,
                         const char *svc_name,
                         uint16_t svc_version,
                         void *pvt,
                         struct sbus_connection **mon_conn)
{
    errno_t ret;
    char *sbus_address;
    struct sbus_interface *intf;
    struct sbus_connection *conn;

    /* Set up SBUS connection to the monitor */
    ret = monitor_get_sbus_address(NULL, &sbus_address);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not locate monitor address.\n");
        return ret;
    }

    ret = sbus_client_init(mem_ctx, ev, sbus_address, &conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to connect to monitor services.\n");
        talloc_free(sbus_address);
        return ret;
    }
    talloc_free(sbus_address);

    intf = sbus_new_interface(mem_ctx, MONITOR_PATH, &mon_iface->vtable, pvt);
    if (!intf) {
        ret = ENOMEM;
    } else {
        ret = sbus_conn_add_interface(conn, intf);
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to export monitor client.\n");
        return ret;
    }

    /* Identify ourselves to the monitor */
    ret = monitor_common_send_id(conn, svc_name, svc_version);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to identify to the monitor!\n");
        return ret;
    }

    *mon_conn = conn;

    return EOK;
}
