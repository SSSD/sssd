/*
   SSSD

   Data Provider Responder client - DP calls responder interface

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

#include "config.h"
#include <talloc.h>
#include <tevent.h>

#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "providers/data_provider.h"
#include "providers/data_provider/dp_private.h"
#include "responder/common/iface/responder_iface.h"
#include "src/responder/nss/nss_iface.h"

static void send_msg_to_all_clients(struct data_provider *provider,
                                    struct DBusMessage *msg)
{
    struct dp_client *cli;
    int i;

    for (i = 0; provider->clients[i] != NULL; i++) {
        cli = provider->clients[i];
        if (cli != NULL) {
           sbus_conn_send_reply(dp_client_conn(cli), msg);
        }
    }
}

static void dp_sbus_set_domain_state(struct data_provider *provider,
                                     struct sss_domain_info *dom,
                                     enum sss_domain_state state)
{
    DBusMessage *msg;
    const char *method = NULL;

    switch (state) {
    case DOM_ACTIVE:
        DEBUG(SSSDBG_TRACE_FUNC, "Ordering responders to enable domain %s\n",
              dom->name);
        method = IFACE_RESPONDER_DOMAIN_SETACTIVE;
        break;
    case DOM_INCONSISTENT:
        DEBUG(SSSDBG_TRACE_FUNC, "Ordering responders to disable domain %s\n",
              dom->name);
        method = IFACE_RESPONDER_DOMAIN_SETINCONSISTENT;
        break;
    default:
        /* No other methods provided at the moment */
        return;
    }

    sss_domain_set_state(dom, state);

    msg = sbus_create_message(NULL, NULL, RESPONDER_PATH,
                              IFACE_RESPONDER_DOMAIN, method,
                              DBUS_TYPE_STRING, &dom->name);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return;
    }

    send_msg_to_all_clients(provider, msg);
    dbus_message_unref(msg);
    return;
}

void dp_sbus_domain_active(struct data_provider *provider,
                           struct sss_domain_info *dom)
{
    return dp_sbus_set_domain_state(provider, dom, DOM_ACTIVE);
}

void dp_sbus_domain_inconsistent(struct data_provider *provider,
                                 struct sss_domain_info *dom)
{
    return dp_sbus_set_domain_state(provider, dom, DOM_INCONSISTENT);
}
