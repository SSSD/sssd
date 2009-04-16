/*
   SSSD

   NSS Responder - Data Provider Interfaces

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

#include <sys/time.h>
#include <time.h>
#include "util/util.h"
#include "responder/common/responder_packet.h"
#include "responder/nss/nsssrv.h"
#include "providers/data_provider.h"
#include "sbus/sbus_client.h"
#include "providers/dp_sbus.h"

static int nss_dp_identity(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    dbus_uint16_t clitype = DP_CLI_FRONTEND;
    const char *cliname = "NSS";
    const char *nullname = "";
    DBusMessage *reply;
    dbus_bool_t ret;

    DEBUG(4,("Sending ID reply: (%d,%d,%s)\n",
             clitype, version, cliname));

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_UINT16, &clitype,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_STRING, &cliname,
                                   DBUS_TYPE_STRING, &nullname,
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

static struct sbus_method nss_dp_methods[] = {
    { DP_CLI_METHOD_IDENTITY, nss_dp_identity },
    { NULL, NULL }
};

struct sbus_method *get_nss_dp_methods(void)
{
    return nss_dp_methods;
}
