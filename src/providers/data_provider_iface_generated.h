/* The following declarations are auto-generated from data_provider_iface.xml */

#ifndef __DATA_PROVIDER_IFACE_XML__
#define __DATA_PROVIDER_IFACE_XML__

#include "sbus/sssd_dbus.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for org.freedesktop.sssd.dataprovider */
#define DATA_PROVIDER_IFACE "org.freedesktop.sssd.dataprovider"
#define DATA_PROVIDER_IFACE_REGISTERSERVICE "RegisterService"
#define DATA_PROVIDER_IFACE_PAMHANDLER "pamHandler"
#define DATA_PROVIDER_IFACE_SUDOHANDLER "sudoHandler"
#define DATA_PROVIDER_IFACE_AUTOFSHANDLER "autofsHandler"
#define DATA_PROVIDER_IFACE_HOSTHANDLER "hostHandler"
#define DATA_PROVIDER_IFACE_GETDOMAINS "getDomains"
#define DATA_PROVIDER_IFACE_GETACCOUNTINFO "getAccountInfo"

/* constants for org.freedesktop.sssd.dataprovider_rev */
#define DATA_PROVIDER_REV_IFACE "org.freedesktop.sssd.dataprovider_rev"
#define DATA_PROVIDER_REV_IFACE_UPDATECACHE "updateCache"
#define DATA_PROVIDER_REV_IFACE_INITGRCHECK "initgrCheck"

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

/* vtable for org.freedesktop.sssd.dataprovider */
struct data_provider_iface {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn RegisterService;
    sbus_msg_handler_fn pamHandler;
    sbus_msg_handler_fn sudoHandler;
    sbus_msg_handler_fn autofsHandler;
    sbus_msg_handler_fn hostHandler;
    sbus_msg_handler_fn getDomains;
    sbus_msg_handler_fn getAccountInfo;
};

/* vtable for org.freedesktop.sssd.dataprovider_rev */
struct data_provider_rev_iface {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn updateCache;
    sbus_msg_handler_fn initgrCheck;
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

/* interface info for org.freedesktop.sssd.dataprovider */
extern const struct sbus_interface_meta data_provider_iface_meta;

/* interface info for org.freedesktop.sssd.dataprovider_rev */
extern const struct sbus_interface_meta data_provider_rev_iface_meta;

#endif /* __DATA_PROVIDER_IFACE_XML__ */
