/* The following declarations are auto-generated from nss_iface.xml */

#ifndef __NSS_IFACE_XML__
#define __NSS_IFACE_XML__

#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for org.freedesktop.sssd.nss.MemoryCache */
#define IFACE_NSS_MEMORYCACHE "org.freedesktop.sssd.nss.MemoryCache"
#define IFACE_NSS_MEMORYCACHE_UPDATEINITGROUPS "UpdateInitgroups"
#define IFACE_NSS_MEMORYCACHE_INVALIDATEALLUSERS "InvalidateAllUsers"
#define IFACE_NSS_MEMORYCACHE_INVALIDATEALLGROUPS "InvalidateAllGroups"
#define IFACE_NSS_MEMORYCACHE_INVALIDATEALLINITGROUPS "InvalidateAllInitgroups"

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

/* vtable for org.freedesktop.sssd.nss.MemoryCache */
struct iface_nss_memorycache {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*UpdateInitgroups)(struct sbus_request *req, void *data, const char *arg_user, const char *arg_domain, uint32_t arg_groups[], int len_groups);
    int (*InvalidateAllUsers)(struct sbus_request *req, void *data);
    int (*InvalidateAllGroups)(struct sbus_request *req, void *data);
    int (*InvalidateAllInitgroups)(struct sbus_request *req, void *data);
};

/* finish function for UpdateInitgroups */
int iface_nss_memorycache_UpdateInitgroups_finish(struct sbus_request *req);

/* finish function for InvalidateAllUsers */
int iface_nss_memorycache_InvalidateAllUsers_finish(struct sbus_request *req);

/* finish function for InvalidateAllGroups */
int iface_nss_memorycache_InvalidateAllGroups_finish(struct sbus_request *req);

/* finish function for InvalidateAllInitgroups */
int iface_nss_memorycache_InvalidateAllInitgroups_finish(struct sbus_request *req);

/* ------------------------------------------------------------------------
 * DBus Interface Metadata
 *
 * These structure definitions are filled in with the information about
 * the interfaces, methods, properties and so on.
 *
 * The actual definitions are found in the accompanying C file next
 * to this header.
 */

/* interface info for org.freedesktop.sssd.nss.MemoryCache */
extern const struct sbus_interface_meta iface_nss_memorycache_meta;

#endif /* __NSS_IFACE_XML__ */
