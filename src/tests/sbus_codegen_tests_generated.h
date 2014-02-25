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
#define COM_PLANETEXPRESS_SHIP_LAND "Land"
#define COM_PLANETEXPRESS_SHIP_BECAMESENTIENT "BecameSentient"
#define COM_PLANETEXPRESS_SHIP_COLOR "Color"

/* constants for com.planetexpress.Pilot */
#define TEST_PILOT "com.planetexpress.Pilot"
#define TEST_PILOT_BLINK "Blink"
#define TEST_PILOT_EJECT "Eject"
#define TEST_PILOT_FULLNAME "FullName"

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

/* vtable for com.planetexpress.Ship */
struct com_planetexpress_Ship {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*MoveUniverse)(struct sbus_request *req, void *data, bool arg_smoothly, uint32_t arg_speed_factor);
    int (*crash_now)(struct sbus_request *req, void *data, const char *arg_where);
    sbus_msg_handler_fn Land;
};

/* finish function for MoveUniverse */
int com_planetexpress_Ship_MoveUniverse_finish(struct sbus_request *req, const char *arg_where_we_crashed);

/* finish function for Crash */
int com_planetexpress_Ship_crash_now_finish(struct sbus_request *req);

/* vtable for com.planetexpress.Pilot */
struct test_pilot {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*Blink)(struct sbus_request *req, void *data, uint32_t arg_duration);
    int (*Eject)(struct sbus_request *req, void *data, uint8_t arg_byte, bool arg_boolean, int16_t arg_int16, uint16_t arg_uint16, int32_t arg_int32, uint32_t arg_uint32, int64_t arg_int64, uint64_t arg_uint64, double arg_double, const char *arg_string, const char *arg_object_path, uint8_t arg_byte_array[], int len_byte_array, int16_t arg_int16_array[], int len_int16_array, uint16_t arg_uint16_array[], int len_uint16_array, int32_t arg_int32_array[], int len_int32_array, uint32_t arg_uint32_array[], int len_uint32_array, int64_t arg_int64_array[], int len_int64_array, uint64_t arg_uint64_array[], int len_uint64_array, double arg_double_array[], int len_double_array, const char *arg_string_array[], int len_string_array, const char *arg_object_path_array[], int len_object_path_array);
};

/* finish function for Blink */
int test_pilot_Blink_finish(struct sbus_request *req, bool arg_crashed);

/* finish function for Eject */
int test_pilot_Eject_finish(struct sbus_request *req, uint8_t arg_byte, bool arg_boolean, int16_t arg_int16, uint16_t arg_uint16, int32_t arg_int32, uint32_t arg_uint32, int64_t arg_int64, uint64_t arg_uint64, double arg_double, const char *arg_string, const char *arg_object_path, uint8_t arg_byte_array[], int len_byte_array, int16_t arg_int16_array[], int len_int16_array, uint16_t arg_uint16_array[], int len_uint16_array, int32_t arg_int32_array[], int len_int32_array, uint32_t arg_uint32_array[], int len_uint32_array, int64_t arg_int64_array[], int len_int64_array, uint64_t arg_uint64_array[], int len_uint64_array, double arg_double_array[], int len_double_array, const char *arg_string_array[], int len_string_array, const char *arg_object_path_array[], int len_object_path_array);

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
