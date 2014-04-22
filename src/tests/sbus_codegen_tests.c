/*
   SSSD

   sbus_codegen tests.

   Authors:
        Stef Walter <stefw@redhat.com>

   Copyright (C) Red Hat, Inc 2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <check.h>
#include <talloc.h>
#include <tevent.h>
#include <popt.h>

#include "sbus/sssd_dbus_meta.h"
#include "tests/common.h"
#include "tests/sbus_codegen_tests_generated.h"
#include "util/util_errors.h"

/* The following 2 macros were taken from check's project source files (0.9.10)
 * http://check.sourceforge.net/
 */
#ifndef _ck_assert_uint
#define _ck_assert_uint(X, OP, Y) do { \
    uintmax_t _ck_x = (X); \
    uintmax_t _ck_y = (Y); \
    ck_assert_msg(_ck_x OP _ck_y, "Assertion '"#X#OP#Y"' failed: "#X"==%ju, "#Y"==%ju", _ck_x, _ck_y); \
} while (0)
#endif /* _ck_assert_uint */

#ifndef ck_assert_uint_eq
#define ck_assert_uint_eq(X, Y) _ck_assert_uint(X, ==, Y)
#endif /* ck_assert_uint_eq */

static const struct sbus_arg_meta *
find_arg(const struct sbus_arg_meta *args,
         const char *name)
{
    const struct sbus_arg_meta *arg;
    for (arg = args; arg->name != NULL; arg++) {
        if (strcmp (arg->name, name) == 0)
            return arg;
    }

    return NULL;
}

START_TEST(test_interfaces)
{
    ck_assert_str_eq(com_planetexpress_Ship_meta.name, "com.planetexpress.Ship");
    ck_assert(com_planetexpress_Ship_meta.methods != NULL);
    ck_assert(com_planetexpress_Ship_meta.signals != NULL);
    ck_assert(com_planetexpress_Ship_meta.properties != NULL);

    /* Explicit C Symbol */
    ck_assert_str_eq(test_pilot_meta.name, "com.planetexpress.Pilot");
    ck_assert(test_pilot_meta.methods != NULL);
    ck_assert(test_pilot_meta.signals == NULL); /* no signals */
    ck_assert(test_pilot_meta.properties != NULL);

}
END_TEST

START_TEST(test_methods)
{
    const struct sbus_method_meta *method;
    const struct sbus_arg_meta *arg;

    method = sbus_meta_find_method(&com_planetexpress_Ship_meta, "MoveUniverse");
    ck_assert(method != NULL);
    ck_assert_str_eq(method->name, "MoveUniverse");
    ck_assert(method->in_args != NULL);
    ck_assert(method->out_args != NULL);

    arg = find_arg(method->in_args, "smoothly");
    ck_assert(arg != NULL);
    ck_assert_str_eq(arg->name, "smoothly");
    ck_assert_str_eq(arg->type, "b");

    arg = find_arg(method->out_args, "where_we_crashed");
    ck_assert(arg != NULL);
    ck_assert_str_eq(arg->name, "where_we_crashed");
    ck_assert_str_eq(arg->type, "s");
}
END_TEST

START_TEST(test_properties)
{
    const struct sbus_property_meta *prop;

    prop = sbus_meta_find_property(&com_planetexpress_Ship_meta, "Color");
    ck_assert(prop != NULL);
    ck_assert_str_eq(prop->name, "Color");
    ck_assert_str_eq(prop->type, "s");
    ck_assert_int_eq(prop->flags, SBUS_PROPERTY_READABLE);
}
END_TEST

START_TEST(test_signals)
{
    const struct sbus_signal_meta *signal;
    const struct sbus_arg_meta *arg;

    signal = sbus_meta_find_signal(&com_planetexpress_Ship_meta, "BecameSentient");
    ck_assert(signal != NULL);
    ck_assert_str_eq(signal->name, "BecameSentient");
    ck_assert(signal->args != NULL);

    arg = find_arg(signal->args, "gender");
    ck_assert(arg != NULL);
    ck_assert_str_eq(arg->name, "gender");
    ck_assert_str_eq(arg->type, "s");
}
END_TEST

static int
mock_move_universe(struct sbus_request *dbus_req, void *data,
                   bool arg_smoothly, uint32_t arg_speed_factor)
{
    /*
     * The above arguments should match the handler signature,
     * and the below finish function should have the right signature.
     *
     * Not called, just testing compilation
     */
    ck_assert(FALSE);
    return com_planetexpress_Ship_MoveUniverse_finish(dbus_req, "here");
}

static int
mock_crash_now(struct sbus_request *dbus_req, void *data,
               const char *where)
{
    /*
     * One argument, no return value, yet a finish function should
     * have been generated.
     *
     * Not called, just testing compilation
     */
    ck_assert(FALSE);
    return com_planetexpress_Ship_crash_now_finish(dbus_req);
}

static int
mock_land(struct sbus_request *req, void *data)
{
    /*
     * Raw handler, no finish function, no special arguments.
     *
     * Not called, just testing compilation
     */
    ck_assert(FALSE);
    return 0;
}

START_TEST(test_vtable)
{
    struct com_planetexpress_Ship vtable = {
        { &com_planetexpress_Ship_meta, 0 },
        mock_move_universe,
        mock_crash_now,
        mock_land,
    };

    /*
     * These are not silly tests:
     * - Will fail compilation if c-symbol name was not respected
     * - Will fail if method order was not respected
     */
    ck_assert(vtable.crash_now == mock_crash_now);
    ck_assert(vtable.MoveUniverse == mock_move_universe);
    ck_assert(vtable.Land == mock_land);
}
END_TEST

START_TEST(test_constants)
{
    ck_assert_str_eq(COM_PLANETEXPRESS_SHIP, "com.planetexpress.Ship");
    ck_assert_str_eq(COM_PLANETEXPRESS_SHIP_MOVEUNIVERSE, "MoveUniverse");
    ck_assert_str_eq(COM_PLANETEXPRESS_SHIP_CRASH_NOW, "Crash");
    ck_assert_str_eq(COM_PLANETEXPRESS_SHIP_BECAMESENTIENT, "BecameSentient");
    ck_assert_str_eq(COM_PLANETEXPRESS_SHIP_COLOR, "Color");

    /* constants for com.planetexpress.Pilot */
    ck_assert_str_eq(TEST_PILOT, "com.planetexpress.Pilot");
    ck_assert_str_eq(TEST_PILOT_FULLNAME, "FullName");
}
END_TEST

TCase *create_defs_tests(void)
{
    TCase *tc = tcase_create("defs");

    /* Do some testing */
    tcase_add_test(tc, test_interfaces);
    tcase_add_test(tc, test_methods);
    tcase_add_test(tc, test_properties);
    tcase_add_test(tc, test_signals);
    tcase_add_test(tc, test_vtable);
    tcase_add_test(tc, test_constants);

    return tc;
}

/* This is a handler which has all the basic arguments types */
static int eject_handler(struct sbus_request *req, void *instance_data,
                         uint8_t arg_byte, bool arg_boolean,
                         int16_t arg_int16, uint16_t arg_uint16, int32_t arg_int32,
                         uint32_t arg_uint32, int64_t arg_int64, uint64_t arg_uint64,
                         double arg_double, const char *arg_string, const char *arg_object_path,
                         uint8_t arg_byte_array[], int len_byte_array,
                         int16_t arg_int16_array[], int len_int16_array,
                         uint16_t arg_uint16_array[], int len_uint16_array,
                         int32_t arg_int32_array[], int len_int32_array,
                         uint32_t arg_uint32_array[], int len_uint32_array,
                         int64_t arg_int64_array[], int len_int64_array,
                         uint64_t arg_uint64_array[], int len_uint64_array,
                         double arg_double_array[], int len_double_array,
                         const char *arg_string_array[], int len_string_array,
                         const char *arg_object_path_array[], int len_object_path_array)
{
    int i;

    /* Only called for leela, so double check here */
    ck_assert_str_eq(instance_data, "Crash into the billboard");

    /* Murge the various values for test case */
    ck_assert_uint_eq(arg_byte, 11);
    arg_byte++;
    ck_assert(arg_boolean == TRUE);
    arg_boolean = !arg_boolean;
    ck_assert_int_eq(arg_int16, -2222);
    arg_int16++;
    ck_assert_uint_eq(arg_uint16, 3333);
    arg_uint16++;
    ck_assert_int_eq(arg_int32, -44444444);
    arg_int32++;
    ck_assert_uint_eq(arg_uint32, 55555555);
    arg_uint32++;
    ck_assert(arg_int64 == -6666666666666666);
    arg_int64++;
    ck_assert(arg_uint64 == 7777777777777777);
    arg_uint64++;
    ck_assert(arg_double == 1.1);
    arg_double++;

    ck_assert_str_eq(arg_string, "hello");
    arg_string = "bears, beets, battlestar galactica";
    ck_assert_str_eq(arg_object_path, "/original/object/path");
    arg_object_path = "/another/object/path";

    arg_byte_array = talloc_memdup(req, arg_byte_array, sizeof(uint8_t) * len_byte_array);
    for (i = 0; i < len_byte_array; i++)
        arg_byte_array[i]++;

    arg_int16_array = talloc_memdup(req, arg_int16_array, sizeof(int16_t) * len_int16_array);
    for (i = 0; i < len_int16_array; i++)
        arg_int16_array[i]++;
    len_int16_array--;

    arg_uint16_array = talloc_memdup(req, arg_uint16_array, sizeof(uint16_t) * len_uint16_array);
    for (i = 0; i < len_uint16_array; i++)
        arg_uint16_array[i]++;

    arg_int32_array = talloc_memdup(req, arg_int32_array, sizeof(int32_t) * len_int32_array);
    for (i = 0; i < len_int32_array; i++)
        arg_int32_array[i]++;
    len_int32_array--;

    arg_uint32_array = talloc_memdup(req, arg_uint32_array, sizeof(uint32_t) * len_uint32_array);
    for (i = 0; i < len_uint32_array; i++)
        arg_uint32_array[i]++;

    arg_int64_array = talloc_memdup(req, arg_int64_array, sizeof(int64_t) * len_int64_array);
    for (i = 0; i < len_int64_array; i++)
        arg_int64_array[i]++;

    arg_uint64_array = talloc_memdup(req, arg_uint64_array, sizeof(uint64_t) * len_uint64_array);
    for (i = 0; i < len_uint64_array; i++)
        arg_uint64_array[i]++;

    arg_double_array = talloc_memdup(req, arg_double_array, sizeof(double) * len_double_array);
    for (i = 0; i < len_double_array; i++)
        arg_double_array[i]++;

    arg_string_array = talloc_memdup(req, arg_string_array, sizeof(char *) * len_string_array);
    for (i = 0; i < len_double_array; i++) {
        ck_assert_str_eq(arg_string_array[i], "bears");
        arg_string_array[i] = "beets";
    }
    len_string_array--;

    arg_object_path_array = talloc_memdup(req, arg_object_path_array, sizeof(char *) * len_object_path_array);
    for (i = 0; i < len_object_path_array; i++) {
        ck_assert_str_eq(arg_object_path_array[i], "/original");
        arg_object_path_array[i] = "/changed";
    }

    /* And reply with those values */
    return test_pilot_Eject_finish(req, arg_byte, arg_boolean, arg_int16,
                                   arg_uint16, arg_int32, arg_uint32,
                                   arg_int64, arg_uint64, arg_double,
                                   arg_string, arg_object_path,
                                   arg_byte_array, len_byte_array,
                                   arg_int16_array, len_int16_array,
                                   arg_uint16_array, len_uint16_array,
                                   arg_int32_array, len_int32_array,
                                   arg_uint32_array, len_uint32_array,
                                   arg_int64_array, len_int64_array,
                                   arg_uint64_array, len_uint64_array,
                                   arg_double_array, len_double_array,
                                   arg_string_array, len_string_array,
                                   arg_object_path_array, len_object_path_array);
}

#define N_ELEMENTS(arr) \
    (sizeof(arr) / sizeof(arr[0]))

struct test_pilot pilot_methods = {
    { &test_pilot_meta, 0 },
    .Eject = eject_handler,
};

static int pilot_test_server_init(struct sbus_connection *server, void *unused)
{
    int ret;

    ret = sbus_conn_add_interface(server,
                                  sbus_new_interface(server, "/test/leela",
                                                     &pilot_methods.vtable,
                                                     "Crash into the billboard"));
    ck_assert_int_eq(ret, EOK);

    return EOK;
}

START_TEST(test_marshal_basic_types)
{
    unsigned char arg_byte = 11;
    dbus_bool_t arg_boolean = TRUE;
    dbus_int16_t arg_int16 = -2222;
    dbus_uint16_t arg_uint16 = 3333;
    dbus_int32_t arg_int32 = -44444444;
    dbus_uint32_t arg_uint32 = 55555555;
    dbus_int64_t arg_int64 = -6666666666666666;
    dbus_uint64_t arg_uint64 = 7777777777777777;
    double arg_double = 1.1;
    const char *arg_string = "hello";
    const char *arg_object_path = "/original/object/path";

    unsigned char v_byte[] = { 11, 12 };
    dbus_int16_t v_int16[] = { 1, -22, 333, -4444 };
    dbus_uint16_t v_uint16[] = { 1, 2, 3, 4, 5 };
    dbus_int32_t v_int32[] = { -1, -23, 34, -56, -90000000, 78 };
    dbus_uint32_t v_uint32[] = { 11111111, 22222222, 33333333 };
    dbus_int64_t v_int64[] = { -6666666666666666, 7777777777777777 };
    dbus_uint64_t v_uint64[] = { 7777777777777777, 888888888888888888 };
    double v_double[] = { 1.1, 2.2, 3.3 };
    char *v_string[] = { "bears", "bears", "bears" };
    char *v_object_path[] = { "/original", "/original" };

    unsigned char *arr_byte = v_byte;
    dbus_int16_t *arr_int16 = v_int16;
    dbus_uint16_t *arr_uint16 = v_uint16;
    dbus_int32_t *arr_int32 = v_int32;
    dbus_uint32_t *arr_uint32 = v_uint32;
    dbus_int64_t *arr_int64 = v_int64;
    dbus_uint64_t *arr_uint64 = v_uint64;
    double *arr_double = v_double;
    char **arr_string = v_string;
    char **arr_object_path = v_object_path;

    int len_byte = N_ELEMENTS(v_byte);
    int len_int16 = N_ELEMENTS(v_int16);
    int len_uint16 = N_ELEMENTS(v_uint16);
    int len_int32 = N_ELEMENTS(v_int32);
    int len_uint32 = N_ELEMENTS(v_uint32);
    int len_int64 = N_ELEMENTS(v_int64);
    int len_uint64 = N_ELEMENTS(v_uint64);
    int len_double = N_ELEMENTS(v_double);
    int len_string = N_ELEMENTS(v_string);
    int len_object_path = N_ELEMENTS(v_object_path);

    TALLOC_CTX *ctx;
    DBusConnection *client;
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply;

    ctx = talloc_new(NULL);
    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);

    reply = test_dbus_call_sync(client,
                                "/test/leela",
                                TEST_PILOT,
                                TEST_PILOT_EJECT,
                                &error,
                                DBUS_TYPE_BYTE, &arg_byte,
                                DBUS_TYPE_BOOLEAN, &arg_boolean,
                                DBUS_TYPE_INT16, &arg_int16,
                                DBUS_TYPE_UINT16, &arg_uint16,
                                DBUS_TYPE_INT32, &arg_int32,
                                DBUS_TYPE_UINT32, &arg_uint32,
                                DBUS_TYPE_INT64, &arg_int64,
                                DBUS_TYPE_UINT64, &arg_uint64,
                                DBUS_TYPE_DOUBLE, &arg_double,
                                DBUS_TYPE_STRING, &arg_string,
                                DBUS_TYPE_OBJECT_PATH, &arg_object_path,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &arr_byte, len_byte,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_INT16, &arr_int16, len_int16,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_UINT16, &arr_uint16, len_uint16,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_INT32, &arr_int32, len_int32,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &arr_uint32, len_uint32,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_INT64, &arr_int64, len_int64,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_UINT64, &arr_uint64, len_uint64,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_DOUBLE, &arr_double, len_double,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arr_string, len_string,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arr_object_path, len_object_path,
                                DBUS_TYPE_INVALID);
    ck_assert(reply != NULL);
    ck_assert(!dbus_error_is_set(&error));
    ck_assert(dbus_message_get_args(reply, NULL,
                                    DBUS_TYPE_BYTE, &arg_byte,
                                    DBUS_TYPE_BOOLEAN, &arg_boolean,
                                    DBUS_TYPE_INT16, &arg_int16,
                                    DBUS_TYPE_UINT16, &arg_uint16,
                                    DBUS_TYPE_INT32, &arg_int32,
                                    DBUS_TYPE_UINT32, &arg_uint32,
                                    DBUS_TYPE_INT64, &arg_int64,
                                    DBUS_TYPE_UINT64, &arg_uint64,
                                    DBUS_TYPE_DOUBLE, &arg_double,
                                    DBUS_TYPE_STRING, &arg_string,
                                    DBUS_TYPE_OBJECT_PATH, &arg_object_path,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &arr_byte, &len_byte,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_INT16, &arr_int16, &len_int16,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT16, &arr_uint16, &len_uint16,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_INT32, &arr_int32, &len_int32,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &arr_uint32, &len_uint32,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_INT64, &arr_int64, &len_int64,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_UINT64, &arr_uint64, &len_uint64,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_DOUBLE, &arr_double, &len_double,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arr_string, &len_string,
                                    DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arr_object_path, &len_object_path,
                                    DBUS_TYPE_INVALID));

    ck_assert_uint_eq(arg_byte, 12);
    ck_assert(arg_boolean == FALSE);
    ck_assert_int_eq(arg_int16, -2221);
    ck_assert_uint_eq(arg_uint16, 3334);
    ck_assert_int_eq(arg_int32, -44444443);
    ck_assert_uint_eq(arg_uint32, 55555556);
    ck_assert(arg_int64 ==-6666666666666665);
    ck_assert(arg_uint64 == 7777777777777778);
    ck_assert(arg_double == 2.1);
    ck_assert_str_eq(arg_string, "bears, beets, battlestar galactica");
    ck_assert_str_eq(arg_object_path, "/another/object/path");

    ck_assert_int_eq(len_byte, 2);
    ck_assert_int_eq(arr_byte[0], 12);
    ck_assert_int_eq(arr_byte[1], 13);

    ck_assert_int_eq(len_int16, 3);
    ck_assert_int_eq(arr_int16[0], 2);
    ck_assert_int_eq(arr_int16[1], -21);
    ck_assert_int_eq(arr_int16[2], 334);

    ck_assert_int_eq(len_uint16, 5);
    ck_assert_uint_eq(arr_uint16[0], 2);
    ck_assert_uint_eq(arr_uint16[1], 3);
    ck_assert_uint_eq(arr_uint16[2], 4);
    ck_assert_uint_eq(arr_uint16[3], 5);
    ck_assert_uint_eq(arr_uint16[4], 6);

    ck_assert_int_eq(len_int32, 5);
    ck_assert_int_eq(arr_int32[0], 0);
    ck_assert_int_eq(arr_int32[1], -22);
    ck_assert_int_eq(arr_int32[2], 35);
    ck_assert_int_eq(arr_int32[3], -55);
    ck_assert_int_eq(arr_int32[4], -89999999);

    ck_assert_int_eq(len_uint32, 3);
    ck_assert_uint_eq(arr_uint32[0], 11111112);
    ck_assert_uint_eq(arr_uint32[1], 22222223);
    ck_assert_uint_eq(arr_uint32[2], 33333334);

    ck_assert_int_eq(len_int64, 2);
    ck_assert(arr_int64[0] == -6666666666666665);
    ck_assert(arr_int64[1] == 7777777777777778);

    ck_assert_int_eq(len_uint64, 2);
    ck_assert(arr_uint64[0] == 7777777777777778);
    ck_assert(arr_uint64[1] == 888888888888888889);

    ck_assert_int_eq(len_double, 3);
    ck_assert(arr_double[0] == 2.1);
    ck_assert(arr_double[1] == 3.2);
    ck_assert(arr_double[2] == 4.3);

    ck_assert_int_eq(len_string, 2);
    ck_assert_str_eq(arr_string[0], "beets");
    ck_assert_str_eq(arr_string[1], "beets");
    dbus_free_string_array(arr_string);

    ck_assert_int_eq(len_object_path, 2);
    ck_assert_str_eq(arr_object_path[0], "/changed");
    ck_assert_str_eq(arr_object_path[1], "/changed");
    dbus_free_string_array(arr_object_path);

    dbus_message_unref (reply);
    talloc_free(ctx);
}
END_TEST

TCase *create_handler_tests(void)
{
    TCase *tc = tcase_create("handler");

    tcase_add_test(tc, test_marshal_basic_types);

    return tc;
}

Suite *create_suite(void)
{
    Suite *s = suite_create("sbus_codegen");

    suite_add_tcase(s, create_defs_tests ());
    suite_add_tcase(s, create_handler_tests ());

    return s;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int failure_count;
    Suite *suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    suite = create_suite();
    sr = srunner_create(suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
