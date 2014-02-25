/* The following definitions are auto-generated from sbus_codegen_tests.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus_codegen_tests_generated.h"

/* invokes a handler with a 'bu' DBus signature */
static int invoke_bu_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'u' DBus signature */
static int invoke_u_method(struct sbus_request *dbus_req, void *function_ptr);

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
        "s", /* signature */
        SBUS_PROPERTY_READABLE,
    },
    { NULL, }
};

/* interface info for com.planetexpress.Ship */
const struct sbus_interface_meta com_planetexpress_Ship_meta = {
    "com.planetexpress.Ship", /* name */
    com_planetexpress_Ship__methods,
    com_planetexpress_Ship__signals,
    com_planetexpress_Ship__properties
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

/* methods for com.planetexpress.Pilot */
const struct sbus_method_meta test_pilot__methods[] = {
    {
        "Blink", /* name */
        test_pilot_Blink__in,
        test_pilot_Blink__out,
        offsetof(struct test_pilot, Blink),
        invoke_u_method,
    },
    { NULL, }
};

/* property info for com.planetexpress.Pilot */
const struct sbus_property_meta test_pilot__properties[] = {
    {
        "FullName", /* name */
        "s", /* signature */
        SBUS_PROPERTY_READABLE | SBUS_PROPERTY_WRITABLE,
    },
    { NULL, }
};

/* interface info for com.planetexpress.Pilot */
const struct sbus_interface_meta test_pilot_meta = {
    "com.planetexpress.Pilot", /* name */
    test_pilot__methods,
    NULL, /* no signals */
    test_pilot__properties
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

    return (handler)(dbus_req, dbus_req->intf->instance_data,
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

    return (handler)(dbus_req, dbus_req->intf->instance_data,
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

    return (handler)(dbus_req, dbus_req->intf->instance_data,
                     arg_0);
}
