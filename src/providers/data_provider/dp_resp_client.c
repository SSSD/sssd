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
#include "responder/nss/nss_iface.h"

/* List of DP clients that deal with users or groups */
/* FIXME - it would be much cleaner to implement sbus signals
 * and let the responder subscribe to these messages rather than
 * keep a list here..
 *  https://fedorahosted.org/sssd/ticket/2233
 */
static enum dp_clients user_clients[] = {
    DPC_NSS,
    DPC_PAM,
    DPC_IFP,
    DPC_PAC,
    DPC_SUDO,

    DP_CLIENT_SENTINEL
};

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

static void send_msg_to_selected_clients(struct data_provider *provider,
                                         struct DBusMessage *msg,
                                         enum dp_clients *clients)
{
    struct dp_client *cli;
    int i;

    for (i = 0; clients[i] != DP_CLIENT_SENTINEL; i++) {
        cli = provider->clients[clients[i]];
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

static void dp_sbus_reset_ncache(struct data_provider *provider,
                                 struct sss_domain_info *dom,
                                 const char *method)
{
    DBusMessage *msg;

    msg = sbus_create_message(NULL, NULL, RESPONDER_PATH,
                              IFACE_RESPONDER_NCACHE, method);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return;
    }

    send_msg_to_selected_clients(provider, msg, user_clients);
    dbus_message_unref(msg);
    return;
}

void dp_sbus_reset_users_ncache(struct data_provider *provider,
                                struct sss_domain_info *dom)
{
    return dp_sbus_reset_ncache(provider, dom,
                                IFACE_RESPONDER_NCACHE_RESETUSERS);
}

void dp_sbus_reset_groups_ncache(struct data_provider *provider,
                                 struct sss_domain_info *dom)
{
    return dp_sbus_reset_ncache(provider, dom,
                                IFACE_RESPONDER_NCACHE_RESETGROUPS);
}

static void dp_sbus_reset_memcache(struct data_provider *provider,
                                   const char *method)
{
    DBusMessage *msg;

    msg = sbus_create_message(NULL, NULL, NSS_MEMORYCACHE_PATH,
                              IFACE_NSS_MEMORYCACHE, method);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return;
    }

    send_msg_to_selected_clients(provider, msg, user_clients);
    dbus_message_unref(msg);
    return;
}

void dp_sbus_reset_users_memcache(struct data_provider *provider)
{
    return dp_sbus_reset_memcache(provider,
                                  IFACE_NSS_MEMORYCACHE_INVALIDATEALLUSERS);
}

void dp_sbus_reset_groups_memcache(struct data_provider *provider)
{
    return dp_sbus_reset_memcache(provider,
                                  IFACE_NSS_MEMORYCACHE_INVALIDATEALLGROUPS);
}

void dp_sbus_reset_initgr_memcache(struct data_provider *provider)
{
    return dp_sbus_reset_memcache(provider,
                          IFACE_NSS_MEMORYCACHE_INVALIDATEALLINITGROUPS);
}

void dp_sbus_invalidate_group_memcache(struct data_provider *provider,
                                       gid_t gid)
{
    struct dp_client *dp_cli;
    DBusMessage *msg;
    dbus_bool_t dbret;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    dp_cli = provider->clients[DPC_NSS];
    if (dp_cli == NULL) {
        return;
    }

    msg = dbus_message_new_method_call(NULL,
                                       NSS_MEMORYCACHE_PATH,
                                       IFACE_NSS_MEMORYCACHE,
                                       IFACE_NSS_MEMORYCACHE_INVALIDATEGROUPBYID);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return;
    }

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_UINT32, &gid,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        dbus_message_unref(msg);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the group %"PRIu32" \n",
          gid);

    sbus_conn_send_reply(dp_client_conn(dp_cli), msg);
    dbus_message_unref(msg);

    return;
}
