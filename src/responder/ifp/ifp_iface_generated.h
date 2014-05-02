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
#define INFOPIPE_IFACE "org.freedesktop.sssd.infopipe"
#define INFOPIPE_IFACE_PING "Ping"
#define INFOPIPE_IFACE_LISTCOMPONENTS "ListComponents"
#define INFOPIPE_IFACE_LISTRESPONDERS "ListResponders"
#define INFOPIPE_IFACE_LISTBACKENDS "ListBackends"
#define INFOPIPE_IFACE_FINDMONITOR "FindMonitor"
#define INFOPIPE_IFACE_FINDRESPONDERBYNAME "FindResponderByName"
#define INFOPIPE_IFACE_FINDBACKENDBYNAME "FindBackendByName"
#define INFOPIPE_IFACE_GETUSERATTR "GetUserAttr"
#define INFOPIPE_IFACE_GETUSERGROUPS "GetUserGroups"
#define INFOPIPE_IFACE_FINDDOMAINBYNAME "FindDomainByName"
#define INFOPIPE_IFACE_LISTDOMAINS "ListDomains"

/* constants for org.freedesktop.sssd.infopipe.Components */
#define INFOPIPE_COMPONENT "org.freedesktop.sssd.infopipe.Components"
#define INFOPIPE_COMPONENT_ENABLE "Enable"
#define INFOPIPE_COMPONENT_DISABLE "Disable"
#define INFOPIPE_COMPONENT_CHANGEDEBUGLEVEL "ChangeDebugLevel"
#define INFOPIPE_COMPONENT_CHANGEDEBUGLEVELTEMPORARILY "ChangeDebugLevelTemporarily"
#define INFOPIPE_COMPONENT_NAME "name"
#define INFOPIPE_COMPONENT_DEBUG_LEVEL "debug_level"
#define INFOPIPE_COMPONENT_ENABLED "enabled"
#define INFOPIPE_COMPONENT_TYPE "type"
#define INFOPIPE_COMPONENT_PROVIDERS "providers"

/* constants for org.freedesktop.sssd.infopipe.Domains */
#define INFOPIPE_DOMAIN "org.freedesktop.sssd.infopipe.Domains"
#define INFOPIPE_DOMAIN_NAME "name"
#define INFOPIPE_DOMAIN_PROVIDER "provider"
#define INFOPIPE_DOMAIN_PRIMARY_SERVERS "primary_servers"
#define INFOPIPE_DOMAIN_BACKUP_SERVERS "backup_servers"
#define INFOPIPE_DOMAIN_MIN_ID "min_id"
#define INFOPIPE_DOMAIN_MAX_ID "max_id"
#define INFOPIPE_DOMAIN_REALM "realm"
#define INFOPIPE_DOMAIN_FOREST "forest"
#define INFOPIPE_DOMAIN_LOGIN_FORMAT "login_format"
#define INFOPIPE_DOMAIN_FULLY_QUALIFIED_NAME_FORMAT "fully_qualified_name_format"
#define INFOPIPE_DOMAIN_ENUMERABLE "enumerable"
#define INFOPIPE_DOMAIN_USE_FULLY_QUALIFIED_NAMES "use_fully_qualified_names"
#define INFOPIPE_DOMAIN_SUBDOMAIN "subdomain"
#define INFOPIPE_DOMAIN_PARENT_DOMAIN "parent_domain"

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
struct infopipe_iface {
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
int infopipe_iface_ListComponents_finish(struct sbus_request *req, const char *arg_components[], int len_components);

/* finish function for ListResponders */
int infopipe_iface_ListResponders_finish(struct sbus_request *req, const char *arg_responders[], int len_responders);

/* finish function for ListBackends */
int infopipe_iface_ListBackends_finish(struct sbus_request *req, const char *arg_backends[], int len_backends);

/* finish function for FindMonitor */
int infopipe_iface_FindMonitor_finish(struct sbus_request *req, const char *arg_monitor);

/* finish function for FindResponderByName */
int infopipe_iface_FindResponderByName_finish(struct sbus_request *req, const char *arg_responder);

/* finish function for FindBackendByName */
int infopipe_iface_FindBackendByName_finish(struct sbus_request *req, const char *arg_backend);

/* finish function for GetUserGroups */
int infopipe_iface_GetUserGroups_finish(struct sbus_request *req, const char *arg_values[], int len_values);

/* finish function for FindDomainByName */
int infopipe_iface_FindDomainByName_finish(struct sbus_request *req, const char *arg_domain);

/* finish function for ListDomains */
int infopipe_iface_ListDomains_finish(struct sbus_request *req, const char *arg_domain[], int len_domain);

/* vtable for org.freedesktop.sssd.infopipe.Components */
struct infopipe_component {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*Enable)(struct sbus_request *req, void *data);
    int (*Disable)(struct sbus_request *req, void *data);
    int (*ChangeDebugLevel)(struct sbus_request *req, void *data, uint32_t arg_new_level);
    int (*ChangeDebugLevelTemporarily)(struct sbus_request *req, void *data, uint32_t arg_new_level);
    void (*infopipe_component_get_name)(struct sbus_request *, void *data, const char * *);
    void (*infopipe_component_get_debug_level)(struct sbus_request *, void *data, uint32_t *);
    void (*infopipe_component_get_enabled)(struct sbus_request *, void *data, bool *);
    void (*infopipe_component_get_type)(struct sbus_request *, void *data, const char * *);
    void (*infopipe_component_get_providers)(struct sbus_request *, void *data, const char * * *, int *);
};

/* finish function for Enable */
int infopipe_component_Enable_finish(struct sbus_request *req);

/* finish function for Disable */
int infopipe_component_Disable_finish(struct sbus_request *req);

/* finish function for ChangeDebugLevel */
int infopipe_component_ChangeDebugLevel_finish(struct sbus_request *req);

/* finish function for ChangeDebugLevelTemporarily */
int infopipe_component_ChangeDebugLevelTemporarily_finish(struct sbus_request *req);

/* vtable for org.freedesktop.sssd.infopipe.Domains */
struct infopipe_domain {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    void (*infopipe_domain_get_name)(struct sbus_request *, void *data, const char * *);
    void (*infopipe_domain_get_provider)(struct sbus_request *, void *data, const char * *);
    void (*infopipe_domain_get_primary_servers)(struct sbus_request *, void *data, const char * * *, int *);
    void (*infopipe_domain_get_backup_servers)(struct sbus_request *, void *data, const char * * *, int *);
    void (*infopipe_domain_get_min_id)(struct sbus_request *, void *data, uint32_t *);
    void (*infopipe_domain_get_max_id)(struct sbus_request *, void *data, uint32_t *);
    void (*infopipe_domain_get_realm)(struct sbus_request *, void *data, const char * *);
    void (*infopipe_domain_get_forest)(struct sbus_request *, void *data, const char * *);
    void (*infopipe_domain_get_login_format)(struct sbus_request *, void *data, const char * *);
    void (*infopipe_domain_get_fully_qualified_name_format)(struct sbus_request *, void *data, const char * *);
    void (*infopipe_domain_get_enumerable)(struct sbus_request *, void *data, bool *);
    void (*infopipe_domain_get_use_fully_qualified_names)(struct sbus_request *, void *data, bool *);
    void (*infopipe_domain_get_subdomain)(struct sbus_request *, void *data, bool *);
    void (*infopipe_domain_get_parent_domain)(struct sbus_request *, void *data, const char * *);
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
extern const struct sbus_interface_meta infopipe_iface_meta;

/* interface info for org.freedesktop.sssd.infopipe.Components */
extern const struct sbus_interface_meta infopipe_component_meta;

/* interface info for org.freedesktop.sssd.infopipe.Domains */
extern const struct sbus_interface_meta infopipe_domain_meta;

#endif /* __IFP_IFACE_XML__ */
