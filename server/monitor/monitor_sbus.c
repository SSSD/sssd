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
        DEBUG(0, ("Severe error. A reply callback was called but no"
                  " reply was received and no timeout occurred\n"));

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
            DEBUG(1, ("Failed to parse message\n"));
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            /* FIXME: Destroy this connection ? */
            goto done;
        }

        DEBUG(4, ("Got id ack and version (%d) from Monitor\n", mon_ver));

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(0,("The Monitor returned an error [%s]\n",
                 dbus_message_get_error_name(reply)));
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
    DBusPendingCall *pending_reply;
    DBusConnection *dbus_conn;
    DBusMessage *msg;
    dbus_bool_t ret;

    dbus_conn = sbus_get_connection(conn);

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       MON_SRV_PATH,
                                       MON_SRV_INTERFACE,
                                       MON_SRV_METHOD_REGISTER);
    if (msg == NULL) {
        DEBUG(0, ("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending ID: (%s,%d)\n", name, version));

    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_STRING, &name,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1, ("Failed to build message\n"));
        return EIO;
    }

    ret = dbus_connection_send_with_reply(dbus_conn, msg, &pending_reply,
                                          30000 /* TODO: set timeout */);
    if (!ret || !pending_reply) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         * We'll drop it using the default destructor.
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        dbus_message_unref(msg);
        return EIO;
    }

    /* Set up the reply handler */
    dbus_pending_call_set_notify(pending_reply, id_callback, NULL, NULL);
    dbus_message_unref(msg);

    return EOK;
}

int monitor_common_pong(DBusMessage *message,
                        struct sbus_connection *conn)
{
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply, DBUS_TYPE_INVALID);
    if (!ret) {
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    return EOK;
}

int monitor_common_res_init(DBusMessage *message,
                            struct sbus_connection *conn)
{
    int ret;

    ret = res_init();
    if(ret != 0) {
        return EIO;
    }

    /* Send an empty reply to acknowledge receipt */
    return monitor_common_pong(message, conn);
}

