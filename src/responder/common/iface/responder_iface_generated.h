/* The following declarations are auto-generated from responder_iface.xml */

#ifndef __RESPONDER_IFACE_XML__
#define __RESPONDER_IFACE_XML__

#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for org.freedesktop.sssd.Responder.Domain */
#define IFACE_RESPONDER_DOMAIN "org.freedesktop.sssd.Responder.Domain"
#define IFACE_RESPONDER_DOMAIN_SETACTIVE "SetActive"
#define IFACE_RESPONDER_DOMAIN_SETINCONSISTENT "SetInconsistent"

/* constants for org.freedesktop.sssd.Responder.NegativeCache */
#define IFACE_RESPONDER_NCACHE "org.freedesktop.sssd.Responder.NegativeCache"
#define IFACE_RESPONDER_NCACHE_RESETUSERS "ResetUsers"
#define IFACE_RESPONDER_NCACHE_RESETGROUPS "ResetGroups"

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

/* vtable for org.freedesktop.sssd.Responder.Domain */
struct iface_responder_domain {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*SetActive)(struct sbus_request *req, void *data, const char *arg_name);
    int (*SetInconsistent)(struct sbus_request *req, void *data, const char *arg_name);
};

/* finish function for SetActive */
int iface_responder_domain_SetActive_finish(struct sbus_request *req);

/* finish function for SetInconsistent */
int iface_responder_domain_SetInconsistent_finish(struct sbus_request *req);

/* vtable for org.freedesktop.sssd.Responder.NegativeCache */
struct iface_responder_ncache {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*ResetUsers)(struct sbus_request *req, void *data);
    int (*ResetGroups)(struct sbus_request *req, void *data);
};

/* finish function for ResetUsers */
int iface_responder_ncache_ResetUsers_finish(struct sbus_request *req);

/* finish function for ResetGroups */
int iface_responder_ncache_ResetGroups_finish(struct sbus_request *req);

/* ------------------------------------------------------------------------
 * DBus Interface Metadata
 *
 * These structure definitions are filled in with the information about
 * the interfaces, methods, properties and so on.
 *
 * The actual definitions are found in the accompanying C file next
 * to this header.
 */

/* interface info for org.freedesktop.sssd.Responder.Domain */
extern const struct sbus_interface_meta iface_responder_domain_meta;

/* interface info for org.freedesktop.sssd.Responder.NegativeCache */
extern const struct sbus_interface_meta iface_responder_ncache_meta;

#endif /* __RESPONDER_IFACE_XML__ */
