/* The following declarations are auto-generated from proxy_iface.xml */

#ifndef __PROXY_IFACE_XML__
#define __PROXY_IFACE_XML__

#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for org.freedesktop.sssd.ProxyChild.Client */
#define IFACE_PROXY_CLIENT "org.freedesktop.sssd.ProxyChild.Client"
#define IFACE_PROXY_CLIENT_REGISTER "Register"

/* constants for org.freedesktop.sssd.ProxyChild.Auth */
#define IFACE_PROXY_AUTH "org.freedesktop.sssd.ProxyChild.Auth"
#define IFACE_PROXY_AUTH_PAM "PAM"

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

/* vtable for org.freedesktop.sssd.ProxyChild.Client */
struct iface_proxy_client {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*Register)(struct sbus_request *req, void *data, uint32_t arg_ID);
};

/* finish function for Register */
int iface_proxy_client_Register_finish(struct sbus_request *req);

/* vtable for org.freedesktop.sssd.ProxyChild.Auth */
struct iface_proxy_auth {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn PAM;
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

/* interface info for org.freedesktop.sssd.ProxyChild.Client */
extern const struct sbus_interface_meta iface_proxy_client_meta;

/* interface info for org.freedesktop.sssd.ProxyChild.Auth */
extern const struct sbus_interface_meta iface_proxy_auth_meta;

#endif /* __PROXY_IFACE_XML__ */
