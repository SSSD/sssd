/* The following declarations are auto-generated from ifp_iface.xml */

#ifndef __IFP_IFACE_XML__
#define __IFP_IFACE_XML__

#include "sbus/sssd_dbus.h"

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
#define IFACE_IFP_COMPONENTS_ENABLE "Enable"
#define IFACE_IFP_COMPONENTS_DISABLE "Disable"
#define IFACE_IFP_COMPONENTS_CHANGEDEBUGLEVEL "ChangeDebugLevel"
#define IFACE_IFP_COMPONENTS_CHANGEDEBUGLEVELTEMPORARILY "ChangeDebugLevelTemporarily"
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
    sbus_msg_handler_fn Ping;
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
    int (*Enable)(struct sbus_request *req, void *data);
    int (*Disable)(struct sbus_request *req, void *data);
    int (*ChangeDebugLevel)(struct sbus_request *req, void *data, uint32_t arg_new_level);
    int (*ChangeDebugLevelTemporarily)(struct sbus_request *req, void *data, uint32_t arg_new_level);
    void (*get_name)(struct sbus_request *, void *data, const char * *);
    void (*get_debug_level)(struct sbus_request *, void *data, uint32_t *);
    void (*get_enabled)(struct sbus_request *, void *data, bool *);
    void (*get_type)(struct sbus_request *, void *data, const char * *);
    void (*get_providers)(struct sbus_request *, void *data, const char * * *, int *);
};

/* finish function for Enable */
int iface_ifp_components_Enable_finish(struct sbus_request *req);

/* finish function for Disable */
int iface_ifp_components_Disable_finish(struct sbus_request *req);

/* finish function for ChangeDebugLevel */
int iface_ifp_components_ChangeDebugLevel_finish(struct sbus_request *req);

/* finish function for ChangeDebugLevelTemporarily */
int iface_ifp_components_ChangeDebugLevelTemporarily_finish(struct sbus_request *req);

/* vtable for org.freedesktop.sssd.infopipe.Domains */
struct iface_ifp_domains {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    void (*get_name)(struct sbus_request *, void *data, const char * *);
    void (*get_provider)(struct sbus_request *, void *data, const char * *);
    void (*get_primary_servers)(struct sbus_request *, void *data, const char * * *, int *);
    void (*get_backup_servers)(struct sbus_request *, void *data, const char * * *, int *);
    void (*get_min_id)(struct sbus_request *, void *data, uint32_t *);
    void (*get_max_id)(struct sbus_request *, void *data, uint32_t *);
    void (*get_realm)(struct sbus_request *, void *data, const char * *);
    void (*get_forest)(struct sbus_request *, void *data, const char * *);
    void (*get_login_format)(struct sbus_request *, void *data, const char * *);
    void (*get_fully_qualified_name_format)(struct sbus_request *, void *data, const char * *);
    void (*get_enumerable)(struct sbus_request *, void *data, bool *);
    void (*get_use_fully_qualified_names)(struct sbus_request *, void *data, bool *);
    void (*get_subdomain)(struct sbus_request *, void *data, bool *);
    void (*get_parent_domain)(struct sbus_request *, void *data, const char * *);
};

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

#endif /* __IFP_IFACE_XML__ */
