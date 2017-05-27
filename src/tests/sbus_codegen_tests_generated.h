/* The following declarations are auto-generated from sbus_codegen_tests.xml */

#ifndef __SBUS_CODEGEN_TESTS_XML__
#define __SBUS_CODEGEN_TESTS_XML__

#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"

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
#define TEST_PILOT_BYTE "byte"
#define TEST_PILOT_BOOLEAN "boolean"
#define TEST_PILOT_INT16 "int16"
#define TEST_PILOT_UINT16 "uint16"
#define TEST_PILOT_INT32 "int32"
#define TEST_PILOT_UINT32 "uint32"
#define TEST_PILOT_INT64 "int64"
#define TEST_PILOT_UINT64 "uint64"
#define TEST_PILOT_DOUBLE "double"
#define TEST_PILOT_STRING "string"
#define TEST_PILOT_OBJECT_PATH "object_path"
#define TEST_PILOT_NULL_STRING "null_string"
#define TEST_PILOT_NULL_PATH "null_path"
#define TEST_PILOT_BYTE_ARRAY "byte_array"
#define TEST_PILOT_INT16_ARRAY "int16_array"
#define TEST_PILOT_UINT16_ARRAY "uint16_array"
#define TEST_PILOT_INT32_ARRAY "int32_array"
#define TEST_PILOT_UINT32_ARRAY "uint32_array"
#define TEST_PILOT_INT64_ARRAY "int64_array"
#define TEST_PILOT_UINT64_ARRAY "uint64_array"
#define TEST_PILOT_DOUBLE_ARRAY "double_array"
#define TEST_PILOT_STRING_ARRAY "string_array"
#define TEST_PILOT_OBJECT_PATH_ARRAY "object_path_array"

/* constants for com.planetexpress.Special */
#define TEST_SPECIAL "com.planetexpress.Special"
#define TEST_SPECIAL_ARRAY_DICT_SAS "array_dict_sas"

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
    void (*get_Color)(struct sbus_request *, void *data, const char **);
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
    void (*get_FullName)(struct sbus_request *, void *data, const char **);
    void (*get_byte)(struct sbus_request *, void *data, uint8_t*);
    void (*get_boolean)(struct sbus_request *, void *data, bool*);
    void (*get_int16)(struct sbus_request *, void *data, int16_t*);
    void (*get_uint16)(struct sbus_request *, void *data, uint16_t*);
    void (*get_int32)(struct sbus_request *, void *data, int32_t*);
    void (*get_uint32)(struct sbus_request *, void *data, uint32_t*);
    void (*get_int64)(struct sbus_request *, void *data, int64_t*);
    void (*get_uint64)(struct sbus_request *, void *data, uint64_t*);
    void (*get_double)(struct sbus_request *, void *data, double*);
    void (*get_string)(struct sbus_request *, void *data, const char **);
    void (*get_object_path)(struct sbus_request *, void *data, const char **);
    void (*get_null_string)(struct sbus_request *, void *data, const char **);
    void (*get_null_path)(struct sbus_request *, void *data, const char **);
    void (*get_byte_array)(struct sbus_request *, void *data, uint8_t**, int *);
    void (*get_int16_array)(struct sbus_request *, void *data, int16_t**, int *);
    void (*get_uint16_array)(struct sbus_request *, void *data, uint16_t**, int *);
    void (*get_int32_array)(struct sbus_request *, void *data, int32_t**, int *);
    void (*get_uint32_array)(struct sbus_request *, void *data, uint32_t**, int *);
    void (*get_int64_array)(struct sbus_request *, void *data, int64_t**, int *);
    void (*get_uint64_array)(struct sbus_request *, void *data, uint64_t**, int *);
    void (*get_double_array)(struct sbus_request *, void *data, double**, int *);
    void (*get_string_array)(struct sbus_request *, void *data, const char ***, int *);
    void (*get_object_path_array)(struct sbus_request *, void *data, const char ***, int *);
};

/* finish function for Blink */
int test_pilot_Blink_finish(struct sbus_request *req, bool arg_crashed);

/* finish function for Eject */
int test_pilot_Eject_finish(struct sbus_request *req, uint8_t arg_byte, bool arg_boolean, int16_t arg_int16, uint16_t arg_uint16, int32_t arg_int32, uint32_t arg_uint32, int64_t arg_int64, uint64_t arg_uint64, double arg_double, const char *arg_string, const char *arg_object_path, uint8_t arg_byte_array[], int len_byte_array, int16_t arg_int16_array[], int len_int16_array, uint16_t arg_uint16_array[], int len_uint16_array, int32_t arg_int32_array[], int len_int32_array, uint32_t arg_uint32_array[], int len_uint32_array, int64_t arg_int64_array[], int len_int64_array, uint64_t arg_uint64_array[], int len_uint64_array, double arg_double_array[], int len_double_array, const char *arg_string_array[], int len_string_array, const char *arg_object_path_array[], int len_object_path_array);

/* vtable for com.planetexpress.Special */
struct test_special {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    void (*get_array_dict_sas)(struct sbus_request *, void *data, hash_table_t **);
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

/* interface info for com.planetexpress.Special */
extern const struct sbus_interface_meta test_special_meta;

#endif /* __SBUS_CODEGEN_TESTS_XML__ */
