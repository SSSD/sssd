/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include "responder/ifp/ifp_iface_generated.h"
#include "responder/ifp/ifp_domains.h"
#include "responder/ifp/ifp_components.h"

struct infopipe_iface ifp_iface = {
    { &infopipe_iface_meta, 0 },
    .Ping = ifp_ping,

    /* components */
    .ListComponents = ifp_list_components,
    .ListResponders = ifp_list_responders,
    .ListBackends = ifp_list_backends,
    .FindMonitor = ifp_find_monitor,
    .FindResponderByName = ifp_find_responder_by_name,
    .FindBackendByName = ifp_find_backend_by_name,

    .GetUserAttr = ifp_user_get_attr,
    .GetUserGroups = ifp_user_get_groups,
    .ListDomains = ifp_list_domains,
    .FindDomainByName = ifp_find_domain_by_name,
};

struct infopipe_component ifp_component = {
    { &infopipe_component_meta, 0 },
    .Enable = ifp_component_enable,
    .Disable = ifp_component_disable,
    .ChangeDebugLevel = ifp_component_change_debug_level,
    .ChangeDebugLevelTemporarily = ifp_component_change_debug_level_tmp,
    .infopipe_component_get_name = ifp_component_get_name,
    .infopipe_component_get_debug_level = ifp_component_get_debug_level,
    .infopipe_component_get_enabled = ifp_component_get_enabled,
    .infopipe_component_get_type = ifp_component_get_type,
    /* FIXME: This should be part of Components.Backends interface, onece
     * SSSD supports multiple interfaces per object path. */
    .infopipe_component_get_providers = ifp_backend_get_providers
};

struct infopipe_domain ifp_domain = {
    { &infopipe_domain_meta, 0 },
    .infopipe_domain_get_name = ifp_dom_get_name,
    .infopipe_domain_get_provider = ifp_dom_get_provider,
    .infopipe_domain_get_primary_servers = ifp_dom_get_primary_servers,
    .infopipe_domain_get_backup_servers = ifp_dom_get_backup_servers,
    .infopipe_domain_get_min_id = ifp_dom_get_min_id,
    .infopipe_domain_get_max_id = ifp_dom_get_max_id,
    .infopipe_domain_get_realm = ifp_dom_get_realm,
    .infopipe_domain_get_forest = ifp_dom_get_forest,
    .infopipe_domain_get_login_format = ifp_dom_get_login_format,
    .infopipe_domain_get_fully_qualified_name_format = ifp_dom_get_fqdn_format,
    .infopipe_domain_get_enumerable = ifp_dom_get_enumerable,
    .infopipe_domain_get_use_fully_qualified_names = ifp_dom_get_use_fqdn,
    .infopipe_domain_get_subdomain = ifp_dom_get_subdomain,
    .infopipe_domain_get_parent_domain = ifp_dom_get_parent_domain
};

struct iface_map {
    const char *path;
    struct sbus_vtable *vtable;
};

static struct iface_map iface_map[] = {
    { INFOPIPE_PATH, &ifp_iface.vtable },
    { INFOPIPE_DOMAIN_PATH, &ifp_domain.vtable },
    { INFOPIPE_COMPONENT_PATH, &ifp_component.vtable },
    { NULL, NULL },
};

errno_t ifp_register_sbus_interface(struct sbus_connection *conn, void *pvt)
{
    errno_t ret;
    int i;

    for (i = 0; iface_map[i].path != NULL; i++) {
        ret = sbus_conn_register_iface(conn, iface_map[i].vtable,
                                       iface_map[i].path, pvt);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}
