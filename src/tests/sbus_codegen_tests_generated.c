/* The following definitions are auto-generated from sbus_codegen_tests.xml */

#include <stddef.h>

#include "dbus/dbus-protocol.h"
#include "util/util_errors.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "sbus_codegen_tests_generated.h"

/* invokes a handler with a 'bu' DBus signature */
static int invoke_bu_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'u' DBus signature */
static int invoke_u_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'ybnqiuxtdsoayanaqaiauaxatadasao' DBus signature */
static int invoke_ybnqiuxtdsoayanaqaiauaxatadasao_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for com.planetexpress.Ship.MoveUniverse */
const struct sbus_arg_meta com_planetexpress_Ship_MoveUniverse__in[] = {
    { "smoothly", "b" },
    { "speed_factor", "u" },
    { NULL, }
};

/* arguments for com.planetexpress.Ship.MoveUniverse */
const struct sbus_arg_meta com_planetexpress_Ship_MoveUniverse__out[] = {
    { "where_we_crashed", "s" },
    { NULL, }
};

int com_planetexpress_Ship_MoveUniverse_finish(struct sbus_request *req, const char *arg_where_we_crashed)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_STRING, &arg_where_we_crashed,
                                         DBUS_TYPE_INVALID);
}

/* arguments for com.planetexpress.Ship.Crash */
const struct sbus_arg_meta com_planetexpress_Ship_crash_now__in[] = {
    { "where", "s" },
    { NULL, }
};

int com_planetexpress_Ship_crash_now_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for com.planetexpress.Ship */
const struct sbus_method_meta com_planetexpress_Ship__methods[] = {
    {
        "MoveUniverse", /* name */
        com_planetexpress_Ship_MoveUniverse__in,
        com_planetexpress_Ship_MoveUniverse__out,
        offsetof(struct com_planetexpress_Ship, MoveUniverse),
        invoke_bu_method,
    },
    {
        "Crash", /* name */
        com_planetexpress_Ship_crash_now__in,
        NULL, /* no out_args */
        offsetof(struct com_planetexpress_Ship, crash_now),
        invoke_s_method,
    },
    {
        "Land", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct com_planetexpress_Ship, Land),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* arguments for com.planetexpress.Ship.BecameSentient */
const struct sbus_arg_meta com_planetexpress_Ship_BecameSentient__args[] = {
    { "gender", "s" },
    { NULL, }
};

/* signals for com.planetexpress.Ship */
const struct sbus_signal_meta com_planetexpress_Ship__signals[] = {
    {
        "BecameSentient", /* name */
        com_planetexpress_Ship_BecameSentient__args
    },
    { NULL, }
};

/* property info for com.planetexpress.Ship */
const struct sbus_property_meta com_planetexpress_Ship__properties[] = {
    {
        "Color", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct com_planetexpress_Ship, get_Color),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for com.planetexpress.Ship */
const struct sbus_interface_meta com_planetexpress_Ship_meta = {
    "com.planetexpress.Ship", /* name */
    com_planetexpress_Ship__methods,
    com_planetexpress_Ship__signals,
    com_planetexpress_Ship__properties,
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for com.planetexpress.Pilot.Blink */
const struct sbus_arg_meta test_pilot_Blink__in[] = {
    { "duration", "u" },
    { NULL, }
};

/* arguments for com.planetexpress.Pilot.Blink */
const struct sbus_arg_meta test_pilot_Blink__out[] = {
    { "crashed", "b" },
    { NULL, }
};

int test_pilot_Blink_finish(struct sbus_request *req, bool arg_crashed)
{
    dbus_bool_t cast_crashed = arg_crashed;
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_BOOLEAN, &cast_crashed,
                                         DBUS_TYPE_INVALID);
}

/* arguments for com.planetexpress.Pilot.Eject */
const struct sbus_arg_meta test_pilot_Eject__in[] = {
    { "byte", "y" },
    { "boolean", "b" },
    { "int16", "n" },
    { "uint16", "q" },
    { "int32", "i" },
    { "uint32", "u" },
    { "int64", "x" },
    { "uint64", "t" },
    { "double", "d" },
    { "string", "s" },
    { "object_path", "o" },
    { "byte_array", "ay" },
    { "int16_array", "an" },
    { "uint16_array", "aq" },
    { "int32_array", "ai" },
    { "uint32_array", "au" },
    { "int64_array", "ax" },
    { "uint64_array", "at" },
    { "double_array", "ad" },
    { "string_array", "as" },
    { "object_path_array", "ao" },
    { NULL, }
};

/* arguments for com.planetexpress.Pilot.Eject */
const struct sbus_arg_meta test_pilot_Eject__out[] = {
    { "byte", "y" },
    { "boolean", "b" },
    { "int16", "n" },
    { "uint16", "q" },
    { "int32", "i" },
    { "uint32", "u" },
    { "int64", "x" },
    { "uint64", "t" },
    { "double", "d" },
    { "string", "s" },
    { "object_path", "o" },
    { "byte_array", "ay" },
    { "int16_array", "an" },
    { "uint16_array", "aq" },
    { "int32_array", "ai" },
    { "uint32_array", "au" },
    { "int64_array", "ax" },
    { "uint64_array", "at" },
    { "double_array", "ad" },
    { "string_array", "as" },
    { "object_path_array", "ao" },
    { NULL, }
};

int test_pilot_Eject_finish(struct sbus_request *req, uint8_t arg_byte, bool arg_boolean, int16_t arg_int16, uint16_t arg_uint16, int32_t arg_int32, uint32_t arg_uint32, int64_t arg_int64, uint64_t arg_uint64, double arg_double, const char *arg_string, const char *arg_object_path, uint8_t arg_byte_array[], int len_byte_array, int16_t arg_int16_array[], int len_int16_array, uint16_t arg_uint16_array[], int len_uint16_array, int32_t arg_int32_array[], int len_int32_array, uint32_t arg_uint32_array[], int len_uint32_array, int64_t arg_int64_array[], int len_int64_array, uint64_t arg_uint64_array[], int len_uint64_array, double arg_double_array[], int len_double_array, const char *arg_string_array[], int len_string_array, const char *arg_object_path_array[], int len_object_path_array)
{
    dbus_bool_t cast_boolean = arg_boolean;
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_BYTE, &arg_byte,
                                         DBUS_TYPE_BOOLEAN, &cast_boolean,
                                         DBUS_TYPE_INT16, &arg_int16,
                                         DBUS_TYPE_UINT16, &arg_uint16,
                                         DBUS_TYPE_INT32, &arg_int32,
                                         DBUS_TYPE_UINT32, &arg_uint32,
                                         DBUS_TYPE_INT64, &arg_int64,
                                         DBUS_TYPE_UINT64, &arg_uint64,
                                         DBUS_TYPE_DOUBLE, &arg_double,
                                         DBUS_TYPE_STRING, &arg_string,
                                         DBUS_TYPE_OBJECT_PATH, &arg_object_path,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &arg_byte_array, len_byte_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_INT16, &arg_int16_array, len_int16_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_UINT16, &arg_uint16_array, len_uint16_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_INT32, &arg_int32_array, len_int32_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &arg_uint32_array, len_uint32_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_INT64, &arg_int64_array, len_int64_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_UINT64, &arg_uint64_array, len_uint64_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_DOUBLE, &arg_double_array, len_double_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arg_string_array, len_string_array,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_object_path_array, len_object_path_array,
                                         DBUS_TYPE_INVALID);
}

/* methods for com.planetexpress.Pilot */
const struct sbus_method_meta test_pilot__methods[] = {
    {
        "Blink", /* name */
        test_pilot_Blink__in,
        test_pilot_Blink__out,
        offsetof(struct test_pilot, Blink),
        invoke_u_method,
    },
    {
        "Eject", /* name */
        test_pilot_Eject__in,
        test_pilot_Eject__out,
        offsetof(struct test_pilot, Eject),
        invoke_ybnqiuxtdsoayanaqaiauaxatadasao_method,
    },
    { NULL, }
};

/* property info for com.planetexpress.Pilot */
const struct sbus_property_meta test_pilot__properties[] = {
    {
        "FullName", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE | SBUS_PROPERTY_WRITABLE,
        offsetof(struct test_pilot, get_FullName),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "byte", /* name */
        "y", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_byte),
        sbus_invoke_get_y,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "boolean", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_boolean),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "int16", /* name */
        "n", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_int16),
        sbus_invoke_get_n,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uint16", /* name */
        "q", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_uint16),
        sbus_invoke_get_q,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "int32", /* name */
        "i", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_int32),
        sbus_invoke_get_i,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uint32", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_uint32),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "int64", /* name */
        "x", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_int64),
        sbus_invoke_get_x,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uint64", /* name */
        "t", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_uint64),
        sbus_invoke_get_t,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "double", /* name */
        "d", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_double),
        sbus_invoke_get_d,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "string", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_string),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "object_path", /* name */
        "o", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_object_path),
        sbus_invoke_get_o,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "null_string", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_null_string),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "null_path", /* name */
        "o", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_null_path),
        sbus_invoke_get_o,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "byte_array", /* name */
        "ay", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_byte_array),
        sbus_invoke_get_ay,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "int16_array", /* name */
        "an", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_int16_array),
        sbus_invoke_get_an,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uint16_array", /* name */
        "aq", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_uint16_array),
        sbus_invoke_get_aq,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "int32_array", /* name */
        "ai", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_int32_array),
        sbus_invoke_get_ai,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uint32_array", /* name */
        "au", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_uint32_array),
        sbus_invoke_get_au,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "int64_array", /* name */
        "ax", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_int64_array),
        sbus_invoke_get_ax,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uint64_array", /* name */
        "at", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_uint64_array),
        sbus_invoke_get_at,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "double_array", /* name */
        "ad", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_double_array),
        sbus_invoke_get_ad,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "string_array", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_string_array),
        sbus_invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "object_path_array", /* name */
        "ao", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_pilot, get_object_path_array),
        sbus_invoke_get_ao,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for com.planetexpress.Pilot */
const struct sbus_interface_meta test_pilot_meta = {
    "com.planetexpress.Pilot", /* name */
    test_pilot__methods,
    NULL, /* no signals */
    test_pilot__properties,
    sbus_invoke_get_all, /* GetAll invoker */
};

/* property info for com.planetexpress.Special */
const struct sbus_property_meta test_special__properties[] = {
    {
        "array_dict_sas", /* name */
        "a{sas}", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct test_special, get_array_dict_sas),
        sbus_invoke_get_aDOsasDE,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for com.planetexpress.Special */
const struct sbus_interface_meta test_special_meta = {
    "com.planetexpress.Special", /* name */
    NULL, /* no methods */
    NULL, /* no signals */
    test_special__properties,
    sbus_invoke_get_all, /* GetAll invoker */
};

/* invokes a handler with a 'bu' DBus signature */
static int invoke_bu_method(struct sbus_request *dbus_req, void *function_ptr)
{
    dbus_bool_t arg_0;
    uint32_t arg_1;
    int (*handler)(struct sbus_request *, void *, bool, uint32_t) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_BOOLEAN, &arg_0,
                               DBUS_TYPE_UINT32, &arg_1,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1);
}

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * arg_0;
    int (*handler)(struct sbus_request *, void *, const char *) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_STRING, &arg_0,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0);
}

/* invokes a handler with a 'u' DBus signature */
static int invoke_u_method(struct sbus_request *dbus_req, void *function_ptr)
{
    uint32_t arg_0;
    int (*handler)(struct sbus_request *, void *, uint32_t) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_UINT32, &arg_0,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0);
}

/* invokes a handler with a 'ybnqiuxtdsoayanaqaiauaxatadasao' DBus signature */
static int invoke_ybnqiuxtdsoayanaqaiauaxatadasao_method(struct sbus_request *dbus_req, void *function_ptr)
{
    uint8_t arg_0;
    dbus_bool_t arg_1;
    int16_t arg_2;
    uint16_t arg_3;
    int32_t arg_4;
    uint32_t arg_5;
    int64_t arg_6;
    uint64_t arg_7;
    double arg_8;
    const char * arg_9;
    const char * arg_10;
    uint8_t *arg_11;
    int len_11;
    int16_t *arg_12;
    int len_12;
    uint16_t *arg_13;
    int len_13;
    int32_t *arg_14;
    int len_14;
    uint32_t *arg_15;
    int len_15;
    int64_t *arg_16;
    int len_16;
    uint64_t *arg_17;
    int len_17;
    double *arg_18;
    int len_18;
    const char * *arg_19;
    int len_19;
    const char * *arg_20;
    int len_20;
    int (*handler)(struct sbus_request *, void *, uint8_t, bool, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, double, const char *, const char *, uint8_t[], int, int16_t[], int, uint16_t[], int, int32_t[], int, uint32_t[], int, int64_t[], int, uint64_t[], int, double[], int, const char *[], int, const char *[], int) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_BYTE, &arg_0,
                               DBUS_TYPE_BOOLEAN, &arg_1,
                               DBUS_TYPE_INT16, &arg_2,
                               DBUS_TYPE_UINT16, &arg_3,
                               DBUS_TYPE_INT32, &arg_4,
                               DBUS_TYPE_UINT32, &arg_5,
                               DBUS_TYPE_INT64, &arg_6,
                               DBUS_TYPE_UINT64, &arg_7,
                               DBUS_TYPE_DOUBLE, &arg_8,
                               DBUS_TYPE_STRING, &arg_9,
                               DBUS_TYPE_OBJECT_PATH, &arg_10,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &arg_11, &len_11,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_INT16, &arg_12, &len_12,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_UINT16, &arg_13, &len_13,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_INT32, &arg_14, &len_14,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &arg_15, &len_15,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_INT64, &arg_16, &len_16,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_UINT64, &arg_17, &len_17,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_DOUBLE, &arg_18, &len_18,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arg_19, &len_19,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_20, &len_20,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1,
                     arg_2,
                     arg_3,
                     arg_4,
                     arg_5,
                     arg_6,
                     arg_7,
                     arg_8,
                     arg_9,
                     arg_10,
                     arg_11,
                     len_11,
                     arg_12,
                     len_12,
                     arg_13,
                     len_13,
                     arg_14,
                     len_14,
                     arg_15,
                     len_15,
                     arg_16,
                     len_16,
                     arg_17,
                     len_17,
                     arg_18,
                     len_18,
                     arg_19,
                     len_19,
                     arg_20,
                     len_20);
}
