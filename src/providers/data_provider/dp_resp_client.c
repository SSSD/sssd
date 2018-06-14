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
#include "providers/data_provider.h"
#include "providers/data_provider/dp_private.h"
#include "sss_iface/sss_iface_async.h"


/* List of DP clients that deal with users or groups */
/* FIXME - it would be much cleaner to implement sbus signals
 * and let the responder subscribe to these messages rather than
 * keep a list here..
 *  https://fedorahosted.org/sssd/ticket/2233
 */
static const char *user_clients[] = {
    SSS_BUS_NSS,
    SSS_BUS_PAM,
    SSS_BUS_IFP,
    SSS_BUS_PAC,
    SSS_BUS_SUDO,
    NULL
};

static const char *all_clients[] = {
    SSS_BUS_NSS,
    SSS_BUS_PAM,
    SSS_BUS_IFP,
    SSS_BUS_PAC,
    SSS_BUS_SUDO,
    SSS_BUS_SSH,
    SSS_BUS_AUTOFS,
    NULL
};

void dp_sbus_domain_active(struct data_provider *provider,
                           struct sss_domain_info *dom)
{
    const char *bus;
    struct tevent_req *subreq;
    struct sbus_connection *conn;
    int i;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Ordering responders to enable domain %s\n",
          dom->name);

    conn = provider->sbus_conn;
    for (i = 0; all_clients[i] != NULL; i++) {
        bus = all_clients[i];

        subreq = sbus_call_resp_domain_SetActive_send(provider, conn,
                    bus, SSS_BUS_PATH, dom->name);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
            return;
        }

        tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);
    }
}

void dp_sbus_domain_inconsistent(struct data_provider *provider,
                                 struct sss_domain_info *dom)
{
    const char *bus;
    struct tevent_req *subreq;
    struct sbus_connection *conn;
    int i;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Ordering responders to disable domain %s\n",
          dom->name);

    conn = provider->sbus_conn;
    for (i = 0; all_clients[i] != NULL; i++) {
        bus = all_clients[i];
        subreq = sbus_call_resp_domain_SetInconsistent_send(provider, conn,
                    bus, SSS_BUS_PATH, dom->name);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
            return;
        }

        tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);
    }
}

void dp_sbus_reset_users_ncache(struct data_provider *provider,
                                struct sss_domain_info *dom)
{
    const char *bus;
    struct tevent_req *subreq;
    struct sbus_connection *conn;
    int i;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering responders to reset user negative cache\n");

    conn = provider->sbus_conn;
    for (i = 0; user_clients[i] != NULL; i++) {
        bus = user_clients[i];
        subreq = sbus_call_resp_negcache_ResetUsers_send(provider, conn, bus,
                                                         SSS_BUS_PATH);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
            return;
        }

        tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);
    }
}

void dp_sbus_reset_groups_ncache(struct data_provider *provider,
                                 struct sss_domain_info *dom)
{
    const char *bus;
    struct tevent_req *subreq;
    struct sbus_connection *conn;
    int i;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering responders to reset group negative cache\n");

    conn = provider->sbus_conn;
    for (i = 0; user_clients[i] != NULL; i++) {
        bus = user_clients[i];

        subreq = sbus_call_resp_negcache_ResetGroups_send(provider, conn, bus,
                                                          SSS_BUS_PATH);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
            return;
        }

        tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);
    }
}

void dp_sbus_reset_users_memcache(struct data_provider *provider)
{
    struct tevent_req *subreq;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the users\n");

    subreq = sbus_call_nss_memcache_InvalidateAllUsers_send(provider,
                 provider->sbus_conn, SSS_BUS_NSS, SSS_BUS_PATH);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return;
    }

    tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);

    return;
}

void dp_sbus_reset_groups_memcache(struct data_provider *provider)
{
    struct tevent_req *subreq;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the groups\n");

    subreq = sbus_call_nss_memcache_InvalidateAllGroups_send(provider,
                 provider->sbus_conn, SSS_BUS_NSS, SSS_BUS_PATH);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return;
    }

    tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);

    return;
}

void dp_sbus_reset_initgr_memcache(struct data_provider *provider)
{
    struct tevent_req *subreq;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the initgroups\n");

    subreq = sbus_call_nss_memcache_InvalidateAllInitgroups_send(provider,
                 provider->sbus_conn, SSS_BUS_NSS, SSS_BUS_PATH);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return;
    }

    tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);

    return;
}

void dp_sbus_invalidate_group_memcache(struct data_provider *provider,
                                       gid_t gid)
{
    struct tevent_req *subreq;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the group %"PRIu32" \n",
          gid);

    subreq = sbus_call_nss_memcache_InvalidateGroupById_send(provider,
                 provider->sbus_conn, SSS_BUS_NSS, SSS_BUS_PATH,
                 (uint32_t)gid);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return;
    }

    tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);

    return;
}
