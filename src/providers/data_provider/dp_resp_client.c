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

void dp_sbus_reset_users_ncache(struct data_provider *provider,
                                struct sss_domain_info *dom)
{
    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering responders to reset user negative cache\n");

    sbus_emit_resp_negcache_ResetUsers(provider->sbus_conn, SSS_BUS_PATH);
}

void dp_sbus_reset_groups_ncache(struct data_provider *provider,
                                 struct sss_domain_info *dom)
{
    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering responders to reset group negative cache\n");

    sbus_emit_resp_negcache_ResetGroups(provider->sbus_conn, SSS_BUS_PATH);
}

void dp_sbus_reset_users_memcache(struct data_provider *provider)
{
    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the users\n");

    sbus_emit_nss_memcache_InvalidateAllUsers(provider->sbus_conn, SSS_BUS_PATH);
    return;
}

void dp_sbus_reset_groups_memcache(struct data_provider *provider)
{
    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the groups\n");

    sbus_emit_nss_memcache_InvalidateAllGroups(provider->sbus_conn, SSS_BUS_PATH);
    return;
}

void dp_sbus_reset_initgr_memcache(struct data_provider *provider)
{
    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the initgroups\n");

    sbus_emit_nss_memcache_InvalidateAllInitgroups(provider->sbus_conn, SSS_BUS_PATH);
    return;
}

void dp_sbus_invalidate_group_memcache(struct data_provider *provider,
                                       gid_t gid)
{
    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the group %"PRIu32" \n",
          gid);

    sbus_emit_nss_memcache_InvalidateGroupById(provider->sbus_conn, SSS_BUS_PATH, (uint32_t)gid);
    return;
}
