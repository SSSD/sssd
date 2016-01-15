/* The following declarations are auto-generated from dp_iface.xml */

#ifndef __DP_IFACE_XML__
#define __DP_IFACE_XML__

#include "sbus/sssd_dbus.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for org.freedesktop.sssd.DataProvider.Client */
#define IFACE_DP_CLIENT "org.freedesktop.sssd.DataProvider.Client"
#define IFACE_DP_CLIENT_REGISTER "Register"

/* constants for org.freedesktop.sssd.dataprovider */
#define IFACE_DP "org.freedesktop.sssd.dataprovider"
#define IFACE_DP_PAMHANDLER "pamHandler"
#define IFACE_DP_SUDOHANDLER "sudoHandler"
#define IFACE_DP_AUTOFSHANDLER "autofsHandler"
#define IFACE_DP_HOSTHANDLER "hostHandler"
#define IFACE_DP_GETDOMAINS "getDomains"
#define IFACE_DP_GETACCOUNTINFO "getAccountInfo"

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

/* vtable for org.freedesktop.sssd.DataProvider.Client */
struct iface_dp_client {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*Register)(struct sbus_request *req, void *data, const char *arg_Name);
};

/* finish function for Register */
int iface_dp_client_Register_finish(struct sbus_request *req);

/* vtable for org.freedesktop.sssd.dataprovider */
struct iface_dp {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn pamHandler;
    sbus_msg_handler_fn sudoHandler;
    int (*autofsHandler)(struct sbus_request *req, void *data, uint32_t arg_dp_flags, const char *arg_mapname);
    int (*hostHandler)(struct sbus_request *req, void *data, uint32_t arg_dp_flags, const char *arg_name, const char *arg_alias);
    int (*getDomains)(struct sbus_request *req, void *data, const char *arg_domain_hint);
    int (*getAccountInfo)(struct sbus_request *req, void *data, uint32_t arg_dp_flags, uint32_t arg_entry_type, uint32_t arg_attr_type, const char *arg_filter, const char *arg_domain, const char *arg_extra);
};

/* finish function for autofsHandler */
int iface_dp_autofsHandler_finish(struct sbus_request *req, uint16_t arg_dp_error, uint32_t arg_error, const char *arg_error_message);

/* finish function for hostHandler */
int iface_dp_hostHandler_finish(struct sbus_request *req, uint16_t arg_dp_error, uint32_t arg_error, const char *arg_error_message);

/* finish function for getDomains */
int iface_dp_getDomains_finish(struct sbus_request *req, uint16_t arg_dp_error, uint32_t arg_error, const char *arg_error_message);

/* finish function for getAccountInfo */
int iface_dp_getAccountInfo_finish(struct sbus_request *req, uint16_t arg_dp_error, uint32_t arg_error, const char *arg_error_message);

/* ------------------------------------------------------------------------
 * DBus Interface Metadata
 *
 * These structure definitions are filled in with the information about
 * the interfaces, methods, properties and so on.
 *
 * The actual definitions are found in the accompanying C file next
 * to this header.
 */

/* interface info for org.freedesktop.sssd.DataProvider.Client */
extern const struct sbus_interface_meta iface_dp_client_meta;

/* interface info for org.freedesktop.sssd.dataprovider */
extern const struct sbus_interface_meta iface_dp_meta;

#endif /* __DP_IFACE_XML__ */
