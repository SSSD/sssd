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

/* vtable for org.freedesktop.sssd.infopipe */
struct infopipe_iface {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn Ping;
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

#endif /* __IFP_IFACE_XML__ */
