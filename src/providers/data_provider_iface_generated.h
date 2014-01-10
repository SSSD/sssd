/* The following declarations are auto-generated from data_provider_iface.xml */

#ifndef __DATA_PROVIDER_IFACE_XML__
#define __DATA_PROVIDER_IFACE_XML__

#include "sbus/sssd_dbus.h"

/* ------------------------------------------------------------------------
 * DBus Vtable handler structures
 *
 * These structures are filled in by implementors of the different
 * dbus interfaces to handle method calls.
 *
 * Handler functions of type sbus_msg_handler_fn accept raw messages,
 * other handlers will be typed appropriately. If a handler that is
 * set to NULL is invoked it will result in a
 * org.freedesktop.DBus.Error.NotSupported error for the caller.
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
