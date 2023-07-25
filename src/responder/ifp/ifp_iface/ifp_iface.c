/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2018 Red Hat

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

#include "responder/common/responder.h"
#include "responder/ifp/ifp_private.h"
#include "responder/ifp/ifp_iface/ifp_iface_async.h"
#include "responder/ifp/ifp_cache.h"
#include "responder/ifp/ifp_components.h"
#include "responder/ifp/ifp_domains.h"
#include "responder/ifp/ifp_groups.h"
#include "responder/ifp/ifp_users.h"

errno_t
ifp_access_check(struct sbus_request *sbus_req,
                 struct ifp_ctx *ifp_ctx)
{
    uid_t uid;
    errno_t ret;

    /* We allow those special cases to access infopipe. */
    if (sbus_req->sender->uid < 0) {
        return EOK;
    }

    uid = (uid_t)sbus_req->sender->uid;

    ret = check_allowed_uids(uid,
                             ifp_ctx->rctx->allowed_uids_count,
                             ifp_ctx->rctx->allowed_uids);
    if (ret == EACCES) {
        DEBUG(SSSDBG_MINOR_FAILURE, "User %"PRIi64" not in ACL\n",
              sbus_req->sender->uid);
        return ret;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot check if user %"PRIi64
              "is present in ACL\n", sbus_req->sender->uid);
        return ret;
    }

    switch (sbus_req->type) {
    case SBUS_REQUEST_PROPERTY_GET:
        if (strcmp(sbus_req->interface, "org.freedesktop.sssd.infopipe.Users.User") == 0) {
            if (!ifp_is_user_attr_allowed(ifp_ctx, sbus_req->property)) {
                DEBUG(SSSDBG_TRACE_ALL, "Attribute %s is not allowed\n",
                      sbus_req->property);
                return EACCES;
            }
        }
        break;
    default:
        return EOK;
    }

    return EOK;
}

errno_t
ifp_register_sbus_interface(struct sbus_connection *conn,
                            struct ifp_ctx *ctx)
{
    errno_t ret;

    SBUS_INTERFACE(iface_ifp,
        org_freedesktop_sssd_infopipe,
        SBUS_METHODS(
            SBUS_SYNC(METHOD,  org_freedesktop_sssd_infopipe, Ping, ifp_ping, ctx),
            SBUS_SYNC(METHOD,  org_freedesktop_sssd_infopipe, ListComponents, ifp_list_components, ctx),
            SBUS_SYNC(METHOD,  org_freedesktop_sssd_infopipe, ListResponders, ifp_list_responders, ctx),
            SBUS_SYNC(METHOD,  org_freedesktop_sssd_infopipe, ListBackends, ifp_list_backends, ctx),
            SBUS_SYNC(METHOD,  org_freedesktop_sssd_infopipe, FindMonitor, ifp_find_monitor, ctx),
            SBUS_SYNC(METHOD,  org_freedesktop_sssd_infopipe, FindResponderByName, ifp_find_responder_by_name, ctx),
            SBUS_SYNC(METHOD,  org_freedesktop_sssd_infopipe, FindBackendByName, ifp_find_backend_by_name, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe, GetUserAttr, ifp_get_user_attr_send, ifp_get_user_attr_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe, GetUserGroups, ifp_user_get_groups_send, ifp_user_get_groups_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe, FindDomainByName, ifp_find_domain_by_name_send, ifp_find_domain_by_name_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe, ListDomains, ifp_list_domains_send, ifp_list_domains_recv, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_ifp_components,
        org_freedesktop_sssd_infopipe_Components,
        SBUS_METHODS(SBUS_NO_METHODS),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Components, name, ifp_component_get_name, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Components, debug_level, ifp_component_get_debug_level, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Components, enabled, ifp_component_get_enabled, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Components, type, ifp_component_get_type, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Components, providers, ifp_backend_get_providers, ctx)
        )
    );

    SBUS_INTERFACE(iface_ifp_domains,
        org_freedesktop_sssd_infopipe_Domains,
        SBUS_METHODS(SBUS_NO_METHODS),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, name, ifp_dom_get_name, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, provider, ifp_dom_get_provider, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, primary_servers, ifp_dom_get_primary_servers, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, backup_servers, ifp_dom_get_backup_servers, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, min_id, ifp_dom_get_min_id, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, max_id, ifp_dom_get_max_id, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, realm, ifp_dom_get_realm, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, forest, ifp_dom_get_forest, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, login_format, ifp_dom_get_login_format, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, fully_qualified_name_format, ifp_dom_get_fqdn_format, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, enumerable, ifp_dom_get_enumerable, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, use_fully_qualified_names, ifp_dom_get_use_fqdn, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, subdomain, ifp_dom_get_subdomain, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Domains, parent_domain, ifp_dom_get_parent_domain, ctx)
        )
    );

    SBUS_INTERFACE(iface_ifp_domains_domain,
        org_freedesktop_sssd_infopipe_Domains_Domain,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Domains_Domain, IsOnline, ifp_domains_domain_is_online_send, ifp_domains_domain_is_online_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Domains_Domain, ListServices, ifp_domains_domain_list_services_send, ifp_domains_domain_list_services_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Domains_Domain, ActiveServer, ifp_domains_domain_active_server_send, ifp_domains_domain_active_server_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Domains_Domain, ListServers, ifp_domains_domain_list_servers_send, ifp_domains_domain_list_servers_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Domains_Domain, RefreshAccessRules, ifp_domains_domain_refresh_access_rules_send, ifp_domains_domain_refresh_access_rules_recv, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_ifp_users,
        org_freedesktop_sssd_infopipe_Users,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, FindByName, ifp_users_find_by_name_send, ifp_users_find_by_name_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, FindByID, ifp_users_find_by_id_send, ifp_users_find_by_id_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, FindByCertificate, ifp_users_find_by_cert_send, ifp_users_find_by_cert_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, ListByCertificate, ifp_users_list_by_cert_send, ifp_users_list_by_cert_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, FindByNameAndCertificate, ifp_users_find_by_name_and_cert_send, ifp_users_find_by_name_and_cert_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, ListByName, ifp_users_list_by_name_send, ifp_users_list_by_attr_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, ListByDomainAndName, ifp_users_list_by_domain_and_name_send, ifp_users_list_by_domain_and_name_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, FindByValidCertificate, ifp_users_find_by_valid_cert_send, ifp_users_find_by_valid_cert_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Users, ListByAttr, ifp_users_list_by_attr_send, ifp_users_list_by_attr_recv, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_ifp_users_user,
        org_freedesktop_sssd_infopipe_Users_User,
        SBUS_METHODS(SBUS_NO_METHODS),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, name, ifp_users_user_get_name, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, uidNumber, ifp_users_user_get_uid_number, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, gidNumber, ifp_users_user_get_gid_number, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, gecos, ifp_users_user_get_gecos, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, homeDirectory, ifp_users_user_get_home_directory, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, loginShell, ifp_users_user_get_login_shell, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, uniqueID, ifp_users_user_get_unique_id, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, groups, ifp_users_user_get_groups, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, domain, ifp_users_user_get_domain, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, domainname, ifp_users_user_get_domainname, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Users_User, extraAttributes, ifp_users_user_get_extra_attributes, ctx)
        )
    );

    SBUS_INTERFACE(iface_ifp_cache_user,
        org_freedesktop_sssd_infopipe_Cache,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, org_freedesktop_sssd_infopipe_Cache, List, ifp_cache_list_user, ctx),
            SBUS_SYNC(METHOD, org_freedesktop_sssd_infopipe_Cache, ListByDomain, ifp_cache_list_by_domain_user, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_ifp_cache_object_user,
        org_freedesktop_sssd_infopipe_Cache_Object,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, org_freedesktop_sssd_infopipe_Cache_Object, Store, ifp_cache_object_store_user, ctx),
            SBUS_SYNC(METHOD, org_freedesktop_sssd_infopipe_Cache_Object, Remove, ifp_cache_object_remove_user, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_ifp_groups,
        org_freedesktop_sssd_infopipe_Groups,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Groups, FindByName, ifp_groups_find_by_name_send, ifp_groups_find_by_name_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Groups, FindByID, ifp_groups_find_by_id_send, ifp_groups_find_by_id_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Groups, ListByName, ifp_groups_list_by_name_send, ifp_groups_list_by_name_recv, ctx),
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Groups, ListByDomainAndName, ifp_groups_list_by_domain_and_name_send, ifp_groups_list_by_domain_and_name_recv, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_ifp_groups_group,
        org_freedesktop_sssd_infopipe_Groups_Group,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, org_freedesktop_sssd_infopipe_Groups_Group, UpdateMemberList, ifp_groups_group_update_member_list_send, ifp_groups_group_update_member_list_recv, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Groups_Group, name, ifp_groups_group_get_name, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Groups_Group, gidNumber, ifp_groups_group_get_gid_number, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Groups_Group, uniqueID, ifp_groups_group_get_unique_id, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Groups_Group, users, ifp_groups_group_get_users, ctx),
            SBUS_SYNC(GETTER, org_freedesktop_sssd_infopipe_Groups_Group, groups, ifp_groups_group_get_groups, ctx)
        )
    );

    SBUS_INTERFACE(iface_ifp_cache_group,
        org_freedesktop_sssd_infopipe_Cache,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, org_freedesktop_sssd_infopipe_Cache, List, ifp_cache_list_group, ctx),
            SBUS_SYNC(METHOD, org_freedesktop_sssd_infopipe_Cache, ListByDomain, ifp_cache_list_by_domain_group, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    SBUS_INTERFACE(iface_ifp_cache_object_group,
        org_freedesktop_sssd_infopipe_Cache_Object,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, org_freedesktop_sssd_infopipe_Cache_Object, Store, ifp_cache_object_store_group, ctx),
            SBUS_SYNC(METHOD, org_freedesktop_sssd_infopipe_Cache_Object, Remove, ifp_cache_object_remove_group, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    struct sbus_path paths[] = {
        { IFP_PATH, &iface_ifp },
        { IFP_PATH_DOMAINS, &iface_ifp_domains },
        { IFP_PATH_DOMAINS_TREE, &iface_ifp_domains },
        { IFP_PATH_DOMAINS_TREE, &iface_ifp_domains_domain },
        { IFP_PATH_COMPONENTS_TREE, &iface_ifp_components },
        { IFP_PATH_USERS, &iface_ifp_users },
        { IFP_PATH_USERS, &iface_ifp_cache_user },
        { IFP_PATH_USERS_TREE, &iface_ifp_users_user },
        { IFP_PATH_USERS_TREE, &iface_ifp_cache_object_user },
        { IFP_PATH_GROUPS, &iface_ifp_groups },
        { IFP_PATH_GROUPS, &iface_ifp_cache_group },
        { IFP_PATH_GROUPS_TREE, &iface_ifp_groups_group },
        { IFP_PATH_GROUPS_TREE, &iface_ifp_cache_object_group },
        {NULL, NULL}
    };

    ret = sbus_connection_add_path_map(conn, paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to add paths [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}
