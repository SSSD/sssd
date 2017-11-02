/* The following declarations are auto-generated from ifp_iface.xml */

#ifndef __IFP_IFACE_XML__
#define __IFP_IFACE_XML__

#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for org.freedesktop.sssd.infopipe */
#define IFACE_IFP "org.freedesktop.sssd.infopipe"
#define IFACE_IFP_PING "Ping"
#define IFACE_IFP_LISTCOMPONENTS "ListComponents"
#define IFACE_IFP_LISTRESPONDERS "ListResponders"
#define IFACE_IFP_LISTBACKENDS "ListBackends"
#define IFACE_IFP_FINDMONITOR "FindMonitor"
#define IFACE_IFP_FINDRESPONDERBYNAME "FindResponderByName"
#define IFACE_IFP_FINDBACKENDBYNAME "FindBackendByName"
#define IFACE_IFP_GETUSERATTR "GetUserAttr"
#define IFACE_IFP_GETUSERGROUPS "GetUserGroups"
#define IFACE_IFP_FINDDOMAINBYNAME "FindDomainByName"
#define IFACE_IFP_LISTDOMAINS "ListDomains"

/* constants for org.freedesktop.sssd.infopipe.Components */
#define IFACE_IFP_COMPONENTS "org.freedesktop.sssd.infopipe.Components"
#define IFACE_IFP_COMPONENTS_NAME "name"
#define IFACE_IFP_COMPONENTS_DEBUG_LEVEL "debug_level"
#define IFACE_IFP_COMPONENTS_ENABLED "enabled"
#define IFACE_IFP_COMPONENTS_TYPE "type"
#define IFACE_IFP_COMPONENTS_PROVIDERS "providers"

/* constants for org.freedesktop.sssd.infopipe.Domains */
#define IFACE_IFP_DOMAINS "org.freedesktop.sssd.infopipe.Domains"
#define IFACE_IFP_DOMAINS_NAME "name"
#define IFACE_IFP_DOMAINS_PROVIDER "provider"
#define IFACE_IFP_DOMAINS_PRIMARY_SERVERS "primary_servers"
#define IFACE_IFP_DOMAINS_BACKUP_SERVERS "backup_servers"
#define IFACE_IFP_DOMAINS_MIN_ID "min_id"
#define IFACE_IFP_DOMAINS_MAX_ID "max_id"
#define IFACE_IFP_DOMAINS_REALM "realm"
#define IFACE_IFP_DOMAINS_FOREST "forest"
#define IFACE_IFP_DOMAINS_LOGIN_FORMAT "login_format"
#define IFACE_IFP_DOMAINS_FULLY_QUALIFIED_NAME_FORMAT "fully_qualified_name_format"
#define IFACE_IFP_DOMAINS_ENUMERABLE "enumerable"
#define IFACE_IFP_DOMAINS_USE_FULLY_QUALIFIED_NAMES "use_fully_qualified_names"
#define IFACE_IFP_DOMAINS_SUBDOMAIN "subdomain"
#define IFACE_IFP_DOMAINS_PARENT_DOMAIN "parent_domain"

/* constants for org.freedesktop.sssd.infopipe.Domains.Domain */
#define IFACE_IFP_DOMAINS_DOMAIN "org.freedesktop.sssd.infopipe.Domains.Domain"
#define IFACE_IFP_DOMAINS_DOMAIN_ISONLINE "IsOnline"
#define IFACE_IFP_DOMAINS_DOMAIN_LISTSERVICES "ListServices"
#define IFACE_IFP_DOMAINS_DOMAIN_ACTIVESERVER "ActiveServer"
#define IFACE_IFP_DOMAINS_DOMAIN_LISTSERVERS "ListServers"
#define IFACE_IFP_DOMAINS_DOMAIN_REFRESHACCESSRULES "RefreshAccessRules"

/* constants for org.freedesktop.sssd.infopipe.Cache */
#define IFACE_IFP_CACHE "org.freedesktop.sssd.infopipe.Cache"
#define IFACE_IFP_CACHE_LIST "List"
#define IFACE_IFP_CACHE_LISTBYDOMAIN "ListByDomain"

/* constants for org.freedesktop.sssd.infopipe.Cache.Object */
#define IFACE_IFP_CACHE_OBJECT "org.freedesktop.sssd.infopipe.Cache.Object"
#define IFACE_IFP_CACHE_OBJECT_STORE "Store"
#define IFACE_IFP_CACHE_OBJECT_REMOVE "Remove"

/* constants for org.freedesktop.sssd.infopipe.Users */
#define IFACE_IFP_USERS "org.freedesktop.sssd.infopipe.Users"
#define IFACE_IFP_USERS_FINDBYNAME "FindByName"
#define IFACE_IFP_USERS_FINDBYID "FindByID"
#define IFACE_IFP_USERS_FINDBYCERTIFICATE "FindByCertificate"
#define IFACE_IFP_USERS_LISTBYCERTIFICATE "ListByCertificate"
#define IFACE_IFP_USERS_FINDBYNAMEANDCERTIFICATE "FindByNameAndCertificate"
#define IFACE_IFP_USERS_LISTBYNAME "ListByName"
#define IFACE_IFP_USERS_LISTBYDOMAINANDNAME "ListByDomainAndName"

/* constants for org.freedesktop.sssd.infopipe.Users.User */
#define IFACE_IFP_USERS_USER "org.freedesktop.sssd.infopipe.Users.User"
#define IFACE_IFP_USERS_USER_UPDATEGROUPSLIST "UpdateGroupsList"
#define IFACE_IFP_USERS_USER_NAME "name"
#define IFACE_IFP_USERS_USER_UIDNUMBER "uidNumber"
#define IFACE_IFP_USERS_USER_GIDNUMBER "gidNumber"
#define IFACE_IFP_USERS_USER_GECOS "gecos"
#define IFACE_IFP_USERS_USER_HOMEDIRECTORY "homeDirectory"
#define IFACE_IFP_USERS_USER_LOGINSHELL "loginShell"
#define IFACE_IFP_USERS_USER_UNIQUEID "uniqueID"
#define IFACE_IFP_USERS_USER_GROUPS "groups"
#define IFACE_IFP_USERS_USER_DOMAIN "domain"
#define IFACE_IFP_USERS_USER_DOMAINNAME "domainname"
#define IFACE_IFP_USERS_USER_EXTRAATTRIBUTES "extraAttributes"

/* constants for org.freedesktop.sssd.infopipe.Groups */
#define IFACE_IFP_GROUPS "org.freedesktop.sssd.infopipe.Groups"
#define IFACE_IFP_GROUPS_FINDBYNAME "FindByName"
#define IFACE_IFP_GROUPS_FINDBYID "FindByID"
#define IFACE_IFP_GROUPS_LISTBYNAME "ListByName"
#define IFACE_IFP_GROUPS_LISTBYDOMAINANDNAME "ListByDomainAndName"

/* constants for org.freedesktop.sssd.infopipe.Groups.Group */
#define IFACE_IFP_GROUPS_GROUP "org.freedesktop.sssd.infopipe.Groups.Group"
#define IFACE_IFP_GROUPS_GROUP_UPDATEMEMBERLIST "UpdateMemberList"
#define IFACE_IFP_GROUPS_GROUP_NAME "name"
#define IFACE_IFP_GROUPS_GROUP_GIDNUMBER "gidNumber"
#define IFACE_IFP_GROUPS_GROUP_UNIQUEID "uniqueID"
#define IFACE_IFP_GROUPS_GROUP_USERS "users"
#define IFACE_IFP_GROUPS_GROUP_GROUPS "groups"

/* ------------------------------------------------------------------------
 * DBus handlers
 *
 * These structures are filled in by implementors of the different
 * dbus interfaces to handle method calls.
 *
 * Handler functions of type sbus_msg_handler_fn accept raw messages,
 * other handlers are typed appropriately. If a handler that is
 * set to NULL is invoked it will result in a
 * org.freedesktop.DBus.Error.NotSupported error for the caller.
 *
 * Handlers have a matching xxx_finish() function (unless the method has
 * accepts raw messages). These finish functions the
 * sbus_request_return_and_finish() with the appropriate arguments to
 * construct a valid reply. Once a finish function has been called, the
 * @dbus_req it was called with is freed and no longer valid.
 */

/* vtable for org.freedesktop.sssd.infopipe */
struct iface_ifp {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*Ping)(struct sbus_request *req, void *data, const char *arg_ping);
    int (*ListComponents)(struct sbus_request *req, void *data);
    int (*ListResponders)(struct sbus_request *req, void *data);
    int (*ListBackends)(struct sbus_request *req, void *data);
    int (*FindMonitor)(struct sbus_request *req, void *data);
    int (*FindResponderByName)(struct sbus_request *req, void *data, const char *arg_name);
    int (*FindBackendByName)(struct sbus_request *req, void *data, const char *arg_name);
    sbus_msg_handler_fn GetUserAttr;
    int (*GetUserGroups)(struct sbus_request *req, void *data, const char *arg_user);
    int (*FindDomainByName)(struct sbus_request *req, void *data, const char *arg_name);
    int (*ListDomains)(struct sbus_request *req, void *data);
};

/* finish function for Ping */
int iface_ifp_Ping_finish(struct sbus_request *req, const char *arg_pong);

/* finish function for ListComponents */
int iface_ifp_ListComponents_finish(struct sbus_request *req, const char *arg_components[], int len_components);

/* finish function for ListResponders */
int iface_ifp_ListResponders_finish(struct sbus_request *req, const char *arg_responders[], int len_responders);

/* finish function for ListBackends */
int iface_ifp_ListBackends_finish(struct sbus_request *req, const char *arg_backends[], int len_backends);

/* finish function for FindMonitor */
int iface_ifp_FindMonitor_finish(struct sbus_request *req, const char *arg_monitor);

/* finish function for FindResponderByName */
int iface_ifp_FindResponderByName_finish(struct sbus_request *req, const char *arg_responder);

/* finish function for FindBackendByName */
int iface_ifp_FindBackendByName_finish(struct sbus_request *req, const char *arg_backend);

/* finish function for GetUserGroups */
int iface_ifp_GetUserGroups_finish(struct sbus_request *req, const char *arg_values[], int len_values);

/* finish function for FindDomainByName */
int iface_ifp_FindDomainByName_finish(struct sbus_request *req, const char *arg_domain);

/* finish function for ListDomains */
int iface_ifp_ListDomains_finish(struct sbus_request *req, const char *arg_domain[], int len_domain);

/* vtable for org.freedesktop.sssd.infopipe.Components */
struct iface_ifp_components {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    void (*get_name)(struct sbus_request *, void *data, const char **);
    void (*get_debug_level)(struct sbus_request *, void *data, uint32_t*);
    void (*get_enabled)(struct sbus_request *, void *data, bool*);
    void (*get_type)(struct sbus_request *, void *data, const char **);
    void (*get_providers)(struct sbus_request *, void *data, const char ***, int *);
};

/* vtable for org.freedesktop.sssd.infopipe.Domains */
struct iface_ifp_domains {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    void (*get_name)(struct sbus_request *, void *data, const char **);
    void (*get_provider)(struct sbus_request *, void *data, const char **);
    void (*get_primary_servers)(struct sbus_request *, void *data, const char ***, int *);
    void (*get_backup_servers)(struct sbus_request *, void *data, const char ***, int *);
    void (*get_min_id)(struct sbus_request *, void *data, uint32_t*);
    void (*get_max_id)(struct sbus_request *, void *data, uint32_t*);
    void (*get_realm)(struct sbus_request *, void *data, const char **);
    void (*get_forest)(struct sbus_request *, void *data, const char **);
    void (*get_login_format)(struct sbus_request *, void *data, const char **);
    void (*get_fully_qualified_name_format)(struct sbus_request *, void *data, const char **);
    void (*get_enumerable)(struct sbus_request *, void *data, bool*);
    void (*get_use_fully_qualified_names)(struct sbus_request *, void *data, bool*);
    void (*get_subdomain)(struct sbus_request *, void *data, bool*);
    void (*get_parent_domain)(struct sbus_request *, void *data, const char **);
};

/* vtable for org.freedesktop.sssd.infopipe.Domains.Domain */
struct iface_ifp_domains_domain {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*IsOnline)(struct sbus_request *req, void *data);
    int (*ListServices)(struct sbus_request *req, void *data);
    int (*ActiveServer)(struct sbus_request *req, void *data, const char *arg_service);
    int (*ListServers)(struct sbus_request *req, void *data, const char *arg_service_name);
    int (*RefreshAccessRules)(struct sbus_request *req, void *data);
};

/* finish function for IsOnline */
int iface_ifp_domains_domain_IsOnline_finish(struct sbus_request *req, bool arg_status);

/* finish function for ListServices */
int iface_ifp_domains_domain_ListServices_finish(struct sbus_request *req, const char *arg_services[], int len_services);

/* finish function for ActiveServer */
int iface_ifp_domains_domain_ActiveServer_finish(struct sbus_request *req, const char *arg_server);

/* finish function for ListServers */
int iface_ifp_domains_domain_ListServers_finish(struct sbus_request *req, const char *arg_servers[], int len_servers);

/* finish function for RefreshAccessRules */
int iface_ifp_domains_domain_RefreshAccessRules_finish(struct sbus_request *req);

/* vtable for org.freedesktop.sssd.infopipe.Cache */
struct iface_ifp_cache {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*List)(struct sbus_request *req, void *data);
    int (*ListByDomain)(struct sbus_request *req, void *data, const char *arg_domain_name);
};

/* finish function for List */
int iface_ifp_cache_List_finish(struct sbus_request *req, const char *arg_result[], int len_result);

/* finish function for ListByDomain */
int iface_ifp_cache_ListByDomain_finish(struct sbus_request *req, const char *arg_result[], int len_result);

/* vtable for org.freedesktop.sssd.infopipe.Cache.Object */
struct iface_ifp_cache_object {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*Store)(struct sbus_request *req, void *data);
    int (*Remove)(struct sbus_request *req, void *data);
};

/* finish function for Store */
int iface_ifp_cache_object_Store_finish(struct sbus_request *req, bool arg_result);

/* finish function for Remove */
int iface_ifp_cache_object_Remove_finish(struct sbus_request *req, bool arg_result);

/* vtable for org.freedesktop.sssd.infopipe.Users */
struct iface_ifp_users {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*FindByName)(struct sbus_request *req, void *data, const char *arg_name);
    int (*FindByID)(struct sbus_request *req, void *data, uint32_t arg_id);
    int (*FindByCertificate)(struct sbus_request *req, void *data, const char *arg_pem_cert);
    int (*ListByCertificate)(struct sbus_request *req, void *data, const char *arg_pem_cert, uint32_t arg_limit);
    int (*FindByNameAndCertificate)(struct sbus_request *req, void *data, const char *arg_name, const char *arg_pem_cert);
    int (*ListByName)(struct sbus_request *req, void *data, const char *arg_name_filter, uint32_t arg_limit);
    int (*ListByDomainAndName)(struct sbus_request *req, void *data, const char *arg_domain_name, const char *arg_name_filter, uint32_t arg_limit);
};

/* finish function for FindByName */
int iface_ifp_users_FindByName_finish(struct sbus_request *req, const char *arg_result);

/* finish function for FindByID */
int iface_ifp_users_FindByID_finish(struct sbus_request *req, const char *arg_result);

/* finish function for FindByCertificate */
int iface_ifp_users_FindByCertificate_finish(struct sbus_request *req, const char *arg_result);

/* finish function for ListByCertificate */
int iface_ifp_users_ListByCertificate_finish(struct sbus_request *req, const char *arg_result[], int len_result);

/* finish function for FindByNameAndCertificate */
int iface_ifp_users_FindByNameAndCertificate_finish(struct sbus_request *req, const char *arg_result);

/* finish function for ListByName */
int iface_ifp_users_ListByName_finish(struct sbus_request *req, const char *arg_result[], int len_result);

/* finish function for ListByDomainAndName */
int iface_ifp_users_ListByDomainAndName_finish(struct sbus_request *req, const char *arg_result[], int len_result);

/* vtable for org.freedesktop.sssd.infopipe.Users.User */
struct iface_ifp_users_user {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*UpdateGroupsList)(struct sbus_request *req, void *data);
    void (*get_name)(struct sbus_request *, void *data, const char **);
    void (*get_uidNumber)(struct sbus_request *, void *data, uint32_t*);
    void (*get_gidNumber)(struct sbus_request *, void *data, uint32_t*);
    void (*get_gecos)(struct sbus_request *, void *data, const char **);
    void (*get_homeDirectory)(struct sbus_request *, void *data, const char **);
    void (*get_loginShell)(struct sbus_request *, void *data, const char **);
    void (*get_uniqueID)(struct sbus_request *, void *data, const char **);
    void (*get_groups)(struct sbus_request *, void *data, const char ***, int *);
    void (*get_domain)(struct sbus_request *, void *data, const char **);
    void (*get_domainname)(struct sbus_request *, void *data, const char **);
    void (*get_extraAttributes)(struct sbus_request *, void *data, hash_table_t **);
};

/* finish function for UpdateGroupsList */
int iface_ifp_users_user_UpdateGroupsList_finish(struct sbus_request *req);

/* vtable for org.freedesktop.sssd.infopipe.Groups */
struct iface_ifp_groups {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*FindByName)(struct sbus_request *req, void *data, const char *arg_name);
    int (*FindByID)(struct sbus_request *req, void *data, uint32_t arg_id);
    int (*ListByName)(struct sbus_request *req, void *data, const char *arg_name_filter, uint32_t arg_limit);
    int (*ListByDomainAndName)(struct sbus_request *req, void *data, const char *arg_domain_name, const char *arg_name_filter, uint32_t arg_limit);
};

/* finish function for FindByName */
int iface_ifp_groups_FindByName_finish(struct sbus_request *req, const char *arg_result);

/* finish function for FindByID */
int iface_ifp_groups_FindByID_finish(struct sbus_request *req, const char *arg_result);

/* finish function for ListByName */
int iface_ifp_groups_ListByName_finish(struct sbus_request *req, const char *arg_result[], int len_result);

/* finish function for ListByDomainAndName */
int iface_ifp_groups_ListByDomainAndName_finish(struct sbus_request *req, const char *arg_result[], int len_result);

/* vtable for org.freedesktop.sssd.infopipe.Groups.Group */
struct iface_ifp_groups_group {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*UpdateMemberList)(struct sbus_request *req, void *data);
    void (*get_name)(struct sbus_request *, void *data, const char **);
    void (*get_gidNumber)(struct sbus_request *, void *data, uint32_t*);
    void (*get_uniqueID)(struct sbus_request *, void *data, const char **);
    void (*get_users)(struct sbus_request *, void *data, const char ***, int *);
    void (*get_groups)(struct sbus_request *, void *data, const char ***, int *);
};

/* finish function for UpdateMemberList */
int iface_ifp_groups_group_UpdateMemberList_finish(struct sbus_request *req);

/* ------------------------------------------------------------------------
 * DBus Interface Metadata
 *
 * These structure definitions are filled in with the information about
 * the interfaces, methods, properties and so on.
 *
 * The actual definitions are found in the accompanying C file next
 * to this header.
 */

/* interface info for org.freedesktop.sssd.infopipe */
extern const struct sbus_interface_meta iface_ifp_meta;

/* interface info for org.freedesktop.sssd.infopipe.Components */
extern const struct sbus_interface_meta iface_ifp_components_meta;

/* interface info for org.freedesktop.sssd.infopipe.Domains */
extern const struct sbus_interface_meta iface_ifp_domains_meta;

/* interface info for org.freedesktop.sssd.infopipe.Domains.Domain */
extern const struct sbus_interface_meta iface_ifp_domains_domain_meta;

/* interface info for org.freedesktop.sssd.infopipe.Cache */
extern const struct sbus_interface_meta iface_ifp_cache_meta;

/* interface info for org.freedesktop.sssd.infopipe.Cache.Object */
extern const struct sbus_interface_meta iface_ifp_cache_object_meta;

/* interface info for org.freedesktop.sssd.infopipe.Users */
extern const struct sbus_interface_meta iface_ifp_users_meta;

/* interface info for org.freedesktop.sssd.infopipe.Users.User */
extern const struct sbus_interface_meta iface_ifp_users_user_meta;

/* interface info for org.freedesktop.sssd.infopipe.Groups */
extern const struct sbus_interface_meta iface_ifp_groups_meta;

/* interface info for org.freedesktop.sssd.infopipe.Groups.Group */
extern const struct sbus_interface_meta iface_ifp_groups_group_meta;

#endif /* __IFP_IFACE_XML__ */
