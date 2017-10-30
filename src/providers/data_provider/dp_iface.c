/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <dbus/dbus.h>

#include "sbus/sssd_dbus.h"
#include "providers/data_provider/dp_iface_generated.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp.h"

struct iface_dp iface_dp = {
    {&iface_dp_meta, 0},
    .pamHandler = dp_pam_handler,
    .sudoHandler = dp_sudo_handler,
    .autofsHandler = dp_autofs_handler,
    .hostHandler = dp_host_handler,
    .getDomains = dp_subdomains_handler,
    .getAccountInfo = dp_get_account_info_handler,
    .getAccountDomain = dp_get_account_domain_handler,
};

struct iface_dp_backend iface_dp_backend = {
    {&iface_dp_backend_meta, 0},
    .IsOnline = dp_backend_is_online
};

struct iface_dp_failover iface_dp_failover = {
    { &iface_dp_failover_meta, 0 },
    .ListServices = dp_failover_list_services,
    .ActiveServer = dp_failover_active_server,
    .ListServers = dp_failover_list_servers
};

struct iface_dp_access_control iface_dp_access_control = {
    { &iface_dp_access_control_meta, 0 },
    .RefreshRules = dp_access_control_refresh_rules_handler
};

static struct sbus_iface_map dp_map[] = {
    { DP_PATH, &iface_dp.vtable },
    { DP_PATH, &iface_dp_backend.vtable },
    { DP_PATH, &iface_dp_failover.vtable },
    { DP_PATH, &iface_dp_access_control.vtable },
    { NULL, NULL }
};

errno_t
dp_register_sbus_interface(struct sbus_connection *conn,
                           struct dp_client *pvt)
{
    return sbus_conn_register_iface_map(conn, dp_map, pvt);
}
