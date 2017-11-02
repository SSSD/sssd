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
#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_groups.h"

struct iface_ifp iface_ifp = {
    { &iface_ifp_meta, 0 },
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

struct iface_ifp_components iface_ifp_components = {
    { &iface_ifp_components_meta, 0 },
    .get_name = ifp_component_get_name,
    .get_debug_level = ifp_component_get_debug_level,
    .get_enabled = ifp_component_get_enabled,
    .get_type = ifp_component_get_type,
    /* FIXME: This should be part of Components.Backends interface, onece
     * SSSD supports multiple interfaces per object path. */
    .get_providers = ifp_backend_get_providers
};

struct iface_ifp_domains iface_ifp_domains = {
    { &iface_ifp_domains_meta, 0 },
    .get_name = ifp_dom_get_name,
    .get_provider = ifp_dom_get_provider,
    .get_primary_servers = ifp_dom_get_primary_servers,
    .get_backup_servers = ifp_dom_get_backup_servers,
    .get_min_id = ifp_dom_get_min_id,
    .get_max_id = ifp_dom_get_max_id,
    .get_realm = ifp_dom_get_realm,
    .get_forest = ifp_dom_get_forest,
    .get_login_format = ifp_dom_get_login_format,
    .get_fully_qualified_name_format = ifp_dom_get_fqdn_format,
    .get_enumerable = ifp_dom_get_enumerable,
    .get_use_fully_qualified_names = ifp_dom_get_use_fqdn,
    .get_subdomain = ifp_dom_get_subdomain,
    .get_parent_domain = ifp_dom_get_parent_domain
};

struct iface_ifp_domains_domain iface_ifp_domains_domain = {
    { &iface_ifp_domains_domain_meta, 0 },
    .IsOnline = ifp_domains_domain_is_online,
    .ListServices = ifp_domains_domain_list_services,
    .ActiveServer = ifp_domains_domain_active_server,
    .ListServers = ifp_domains_domain_list_servers,
    .RefreshAccessRules = ifp_domains_domain_refresh_access_rules
};

struct iface_ifp_users iface_ifp_users = {
    { &iface_ifp_users_meta, 0 },
    .FindByName = ifp_users_find_by_name,
    .FindByID = ifp_users_find_by_id,
    .FindByCertificate = ifp_users_find_by_cert,
    .ListByCertificate = ifp_users_list_by_cert,
    .FindByNameAndCertificate = ifp_users_find_by_name_and_cert,
    .ListByName = ifp_users_list_by_name,
    .ListByDomainAndName = ifp_users_list_by_domain_and_name
};

struct iface_ifp_users_user iface_ifp_users_user = {
    { &iface_ifp_users_user_meta, 0 },
    .UpdateGroupsList = ifp_users_user_update_groups_list,
    .get_name = ifp_users_user_get_name,
    .get_uidNumber = ifp_users_user_get_uid_number,
    .get_gidNumber = ifp_users_user_get_gid_number,
    .get_gecos = ifp_users_user_get_gecos,
    .get_homeDirectory = ifp_users_user_get_home_directory,
    .get_loginShell = ifp_users_user_get_login_shell,
    .get_uniqueID = ifp_users_user_get_unique_id,
    .get_groups = ifp_users_user_get_groups,
    .get_domain = ifp_users_user_get_domain,
    .get_domainname = ifp_users_user_get_domainname,
    .get_extraAttributes = ifp_users_user_get_extra_attributes
};

struct iface_ifp_groups iface_ifp_groups = {
    { &iface_ifp_groups_meta, 0 },
    .FindByName = ifp_groups_find_by_name,
    .FindByID = ifp_groups_find_by_id,
    .ListByName = ifp_groups_list_by_name,
    .ListByDomainAndName = ifp_groups_list_by_domain_and_name
};

struct iface_ifp_groups_group iface_ifp_groups_group = {
    { &iface_ifp_groups_group_meta, 0 },
    .UpdateMemberList = ifp_groups_group_update_member_list,
    .get_name = ifp_groups_group_get_name,
    .get_gidNumber = ifp_groups_group_get_gid_number,
    .get_uniqueID = ifp_groups_group_get_unique_id,
    .get_users = ifp_groups_group_get_users,
    .get_groups = ifp_groups_group_get_groups
};

struct iface_ifp_cache iface_ifp_cache_user = {
    { &iface_ifp_cache_meta, 0 },
    .List = ifp_cache_list_user,
    .ListByDomain = ifp_cache_list_by_domain_user
};

struct iface_ifp_cache_object iface_ifp_cache_object_user = {
    { &iface_ifp_cache_object_meta, 0 },
    .Store = ifp_cache_object_store_user,
    .Remove = ifp_cache_object_remove_user
};

struct iface_ifp_cache iface_ifp_cache_group = {
    { &iface_ifp_cache_meta, 0 },
    .List = ifp_cache_list_group,
    .ListByDomain = ifp_cache_list_by_domain_group
};

struct iface_ifp_cache_object iface_ifp_cache_object_group = {
    { &iface_ifp_cache_object_meta, 0 },
    .Store = ifp_cache_object_store_group,
    .Remove = ifp_cache_object_remove_group
};

static struct sbus_iface_map iface_map[] = {
    { IFP_PATH, &iface_ifp.vtable },
    { IFP_PATH_DOMAINS, &iface_ifp_domains.vtable },
    { IFP_PATH_DOMAINS_TREE, &iface_ifp_domains.vtable },
    { IFP_PATH_DOMAINS_TREE, &iface_ifp_domains_domain.vtable },
    { IFP_PATH_COMPONENTS_TREE, &iface_ifp_components.vtable },
    { IFP_PATH_USERS, &iface_ifp_users.vtable },
    { IFP_PATH_USERS, &iface_ifp_cache_user.vtable },
    { IFP_PATH_USERS_TREE, &iface_ifp_users_user.vtable },
    { IFP_PATH_USERS_TREE, &iface_ifp_cache_object_user.vtable },
    { IFP_PATH_GROUPS, &iface_ifp_groups.vtable },
    { IFP_PATH_GROUPS, &iface_ifp_cache_group.vtable },
    { IFP_PATH_GROUPS_TREE, &iface_ifp_groups_group.vtable },
    { IFP_PATH_GROUPS_TREE, &iface_ifp_cache_object_group.vtable },
    { NULL, NULL },
};

errno_t ifp_register_sbus_interface(struct sbus_connection *conn, void *pvt)
{
    return sbus_conn_register_iface_map(conn, iface_map, pvt);
}
