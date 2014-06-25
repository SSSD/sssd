/* The following declarations are auto-generated from monitor_iface.xml */

#ifndef __MONITOR_IFACE_XML__
#define __MONITOR_IFACE_XML__

#include "sbus/sssd_dbus.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for org.freedesktop.sssd.monitor */
#define MON_SRV_IFACE "org.freedesktop.sssd.monitor"
#define MON_SRV_IFACE_GETVERSION "getVersion"
#define MON_SRV_IFACE_REGISTERSERVICE "RegisterService"

/* constants for org.freedesktop.sssd.service */
#define MON_CLI_IFACE "org.freedesktop.sssd.service"
#define MON_CLI_IFACE_PING "ping"
#define MON_CLI_IFACE_RESINIT "resInit"
#define MON_CLI_IFACE_SHUTDOWN "shutDown"
#define MON_CLI_IFACE_GOOFFLINE "goOffline"
#define MON_CLI_IFACE_RESETOFFLINE "resetOffline"
#define MON_CLI_IFACE_ROTATELOGS "rotateLogs"
#define MON_CLI_IFACE_CLEARMEMCACHE "clearMemcache"
#define MON_CLI_IFACE_CLEARENUMCACHE "clearEnumCache"
#define MON_CLI_IFACE_SYSBUSRECONNECT "sysbusReconnect"

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

/* vtable for org.freedesktop.sssd.monitor */
struct mon_srv_iface {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn getVersion;
    sbus_msg_handler_fn RegisterService;
};

/* vtable for org.freedesktop.sssd.service */
struct mon_cli_iface {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn ping;
    sbus_msg_handler_fn resInit;
    sbus_msg_handler_fn shutDown;
    sbus_msg_handler_fn goOffline;
    sbus_msg_handler_fn resetOffline;
    sbus_msg_handler_fn rotateLogs;
    sbus_msg_handler_fn clearMemcache;
    sbus_msg_handler_fn clearEnumCache;
    sbus_msg_handler_fn sysbusReconnect;
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

/* interface info for org.freedesktop.sssd.monitor */
extern const struct sbus_interface_meta mon_srv_iface_meta;

/* interface info for org.freedesktop.sssd.service */
extern const struct sbus_interface_meta mon_cli_iface_meta;

#endif /* __MONITOR_IFACE_XML__ */
