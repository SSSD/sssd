/* The following declarations are auto-generated from sbus_codegen_tests.xml */

#ifndef __SBUS_CODEGEN_TESTS_XML__
#define __SBUS_CODEGEN_TESTS_XML__

#include "sbus/sssd_dbus.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for com.planetexpress.Ship */
#define COM_PLANETEXPRESS_SHIP "com.planetexpress.Ship"
#define COM_PLANETEXPRESS_SHIP_MOVEUNIVERSE "MoveUniverse"
#define COM_PLANETEXPRESS_SHIP_CRASH_NOW "Crash"
#define COM_PLANETEXPRESS_SHIP_BECAMESENTIENT "BecameSentient"
#define COM_PLANETEXPRESS_SHIP_COLOR "Color"

/* constants for com.planetexpress.Pilot */
#define TEST_PILOT "com.planetexpress.Pilot"
#define TEST_PILOT_FULLNAME "FullName"

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

/* vtable for com.planetexpress.Ship */
struct com_planetexpress_Ship {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    sbus_msg_handler_fn MoveUniverse;
    sbus_msg_handler_fn crash_now;
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

/* interface info for com.planetexpress.Ship */
extern const struct sbus_interface_meta com_planetexpress_Ship_meta;

/* interface info for com.planetexpress.Pilot */
extern const struct sbus_interface_meta test_pilot_meta;

#endif /* __SBUS_CODEGEN_TESTS_XML__ */
