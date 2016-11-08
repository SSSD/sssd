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

#include <stdint.h>
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
    const struct sbus_signal_meta *sig;
    const struct sbus_arg_meta *arg;

    sig = sbus_meta_find_signal(&com_planetexpress_Ship_meta, "BecameSentient");
    ck_assert(sig != NULL);
    ck_assert_str_eq(sig->name, "BecameSentient");
    ck_assert(sig->args != NULL);

    arg = find_arg(sig->args, "gender");
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
        NULL,
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
    ck_assert(arg_int64 == INT64_C(-6666666666666666));
    arg_int64++;
    ck_assert(arg_uint64 == UINT64_C(7777777777777777));
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

#define getter_body(in, out) do {           \
    ck_assert(dbus_req != NULL);            \
    ck_assert(out != NULL);                 \
    *out = in;                              \
} while(0);

static const bool pilot_bool = true;
void pilot_get_boolean_handler(struct sbus_request *dbus_req,
                               void *instance_data,
                               bool *val)
{
    getter_body(pilot_bool, val);
}

static const char *pilot_full_name = "Turanga Leela";
void pilot_get_full_name_handler(struct sbus_request *dbus_req,
                                 void *instance_data,
                                 const char **name)
{
    getter_body(pilot_full_name, name);
}

static const uint8_t pilot_byte = 42;
void pilot_get_byte_handler(struct sbus_request *dbus_req,
                            void *instance_data,
                            uint8_t *byte)
{
    getter_body(pilot_byte, byte);
}

static const int16_t pilot_int16 = -123;
void pilot_get_int16_handler(struct sbus_request *dbus_req,
                             void *instance_data,
                             int16_t *int16)
{
    getter_body(pilot_int16, int16);
}

static const uint16_t pilot_uint16 = 123;
void pilot_get_uint16_handler(struct sbus_request *dbus_req,
                              void *instance_data,
                              uint16_t *uint16)
{
    getter_body(pilot_uint16, uint16);
}

static const int32_t pilot_int32 = -456;
void pilot_get_int32_handler(struct sbus_request *dbus_req,
                             void *instance_data,
                             int32_t *int32)
{
    getter_body(pilot_int32, int32);
}

static const uint32_t pilot_uint32 = 456;
void pilot_get_uint32_handler(struct sbus_request *dbus_req,
                              void *instance_data,
                              uint32_t *uint32)
{
    getter_body(pilot_uint32, uint32);
}

static const int64_t pilot_int64 = -456;
void pilot_get_int64_handler(struct sbus_request *dbus_req,
                             void *instance_data,
                             int64_t *int64)
{
    getter_body(pilot_int64, int64);
}

static const uint64_t pilot_uint64 = 456;
void pilot_get_uint64_handler(struct sbus_request *dbus_req,
                              void *instance_data,
                              uint64_t *uint64)
{
    getter_body(pilot_uint64, uint64);
}

static const double pilot_double = 3.14;
void pilot_get_double_handler(struct sbus_request *dbus_req,
                              void *instance_data,
                              double *double_val)
{
    getter_body(pilot_double, double_val);
}

static const char *pilot_string = "leela";
void pilot_get_string_handler(struct sbus_request *dbus_req,
                              void *instance_data,
                              const char **string_val)
{
    *string_val = pilot_string;
}

static const char *pilot_path = "/path/leela";
void pilot_get_objpath_handler(struct sbus_request *dbus_req,
                              void *instance_data,
                              const char **path_val)
{
    *path_val = pilot_path;
}

void pilot_get_null_string_handler(struct sbus_request *dbus_req,
                                   void *instance_data,
                                   const char **string_val)
{
    *string_val = NULL;
}

void pilot_get_null_path_handler(struct sbus_request *dbus_req,
                                 void *instance_data,
                                 const char **path_val)
{
    *path_val = NULL;
}

#define array_getter_body(in, out, outlen) do {     \
    ck_assert(dbus_req != NULL);                    \
    ck_assert(out != NULL);                         \
    ck_assert(outlen != NULL);                      \
    *out = in;                                      \
    *outlen = N_ELEMENTS(in);                       \
} while(0);

static uint8_t pilot_byte_array[] = { 42, 0 };
void pilot_get_byte_array_handler(struct sbus_request *dbus_req,
                                  void *instance_data,
                                  uint8_t **arr_out, int *arr_len)
{
    array_getter_body(pilot_byte_array, arr_out, arr_len);
}

static int16_t pilot_int16_array[] = { -123, 0 };
void pilot_get_int16_array_handler(struct sbus_request *dbus_req,
                                  void *instance_data,
                                  int16_t **arr_out, int *arr_len)
{
    array_getter_body(pilot_int16_array, arr_out, arr_len);
}

static uint16_t pilot_uint16_array[] = { 123, 0 };
void pilot_get_uint16_array_handler(struct sbus_request *dbus_req,
                                  void *instance_data,
                                  uint16_t **arr_out, int *arr_len)
{
    array_getter_body(pilot_uint16_array, arr_out, arr_len);
}

static int32_t pilot_int32_array[] = { -456, 0 };
void pilot_get_int32_array_handler(struct sbus_request *dbus_req,
                                  void *instance_data,
                                  int32_t **arr_out, int *arr_len)
{
    array_getter_body(pilot_int32_array, arr_out, arr_len);
}

static uint32_t pilot_uint32_array[] = { 456, 0 };
void pilot_get_uint32_array_handler(struct sbus_request *dbus_req,
                                  void *instance_data,
                                  uint32_t **arr_out, int *arr_len)
{
    array_getter_body(pilot_uint32_array, arr_out, arr_len);
}

static int64_t pilot_int64_array[] = { -789, 0 };
void pilot_get_int64_array_handler(struct sbus_request *dbus_req,
                                  void *instance_data,
                                  int64_t **arr_out, int *arr_len)
{
    array_getter_body(pilot_int64_array, arr_out, arr_len);
}

static uint64_t pilot_uint64_array[] = { 789, 0 };
void pilot_get_uint64_array_handler(struct sbus_request *dbus_req,
                                  void *instance_data,
                                  uint64_t **arr_out, int *arr_len)
{
    array_getter_body(pilot_uint64_array, arr_out, arr_len);
}

static double pilot_double_array[] = { 3.14, 0 };
void pilot_get_double_array_handler(struct sbus_request *dbus_req,
                                    void *instance_data,
                                    double **arr_out, int *arr_len)
{
    array_getter_body(pilot_double_array, arr_out, arr_len);
}

static const char *pilot_string_array[] = { "Turanga", "Leela" };
void pilot_get_string_array_handler(struct sbus_request *dbus_req,
                                    void *data,
                                    const char ***arr_out,
                                    int *arr_len)
{
    array_getter_body(pilot_string_array, arr_out, arr_len);
}

static const char *pilot_path_array[] = { "/some/path", "/another/path" };
void pilot_get_path_array_handler(struct sbus_request *dbus_req,
                                    void *data,
                                    const char ***arr_out,
                                    int *arr_len)
{
    array_getter_body(pilot_path_array, arr_out, arr_len);
}

void special_get_array_dict_sas(struct sbus_request *sbus_req,
                                void *data,
                                hash_table_t **_out)
{
    hash_table_t *table;
    hash_key_t key;
    hash_value_t value;
    char **values;
    errno_t ret;
    int hret;

    *_out = NULL;

    ret = sss_hash_create(sbus_req, 10, &table);
    ck_assert_int_eq(ret, EOK);

    values = talloc_zero_array(table, char *, 3);
    ck_assert(values != NULL);

    values[0] = talloc_strdup(values, "hello1");
    values[1] = talloc_strdup(values, "world1");

    ck_assert(values[0] != NULL);
    ck_assert(values[1] != NULL);

    key.type = HASH_KEY_STRING;
    key.str = talloc_strdup(table, "key1");

    value.type = HASH_VALUE_PTR;
    value.ptr = values;

    hret = hash_enter(table, &key, &value);
    ck_assert_int_eq(hret, HASH_SUCCESS);

    values = talloc_zero_array(table, char *, 3);
    ck_assert(values != NULL);

    values[0] = talloc_strdup(values, "hello2");
    values[1] = talloc_strdup(values, "world2");

    ck_assert(values[0] != NULL);
    ck_assert(values[1] != NULL);

    key.type = HASH_KEY_STRING;
    key.str = talloc_strdup(table, "key2");
    ck_assert(key.str != NULL);

    value.type = HASH_VALUE_PTR;
    value.ptr = values;

    hash_enter(table, &key, &value);
    ck_assert_int_eq(hret, HASH_SUCCESS);

    *_out = table;
}

struct test_pilot pilot_iface = {
    { &test_pilot_meta, 0 },
    .Eject = eject_handler,

    .get_FullName = pilot_get_full_name_handler,
    .get_byte = pilot_get_byte_handler,
    .get_boolean = pilot_get_boolean_handler,
    .get_int16 = pilot_get_int16_handler,
    .get_uint16 = pilot_get_uint16_handler,
    .get_int32 = pilot_get_int32_handler,
    .get_uint32 = pilot_get_uint32_handler,
    .get_int64 = pilot_get_int64_handler,
    .get_uint64 = pilot_get_uint64_handler,
    .get_double = pilot_get_double_handler,
    .get_string = pilot_get_string_handler,
    .get_object_path = pilot_get_objpath_handler,
    .get_null_string = pilot_get_null_string_handler,
    .get_null_path = pilot_get_null_path_handler,

    .get_byte_array = pilot_get_byte_array_handler,
    .get_int16_array = pilot_get_int16_array_handler,
    .get_uint16_array = pilot_get_uint16_array_handler,
    .get_int32_array = pilot_get_int32_array_handler,
    .get_uint32_array = pilot_get_uint32_array_handler,
    .get_int64_array = pilot_get_int64_array_handler,
    .get_uint64_array = pilot_get_uint64_array_handler,
    .get_double_array = pilot_get_double_array_handler,
    .get_string_array = pilot_get_string_array_handler,
    .get_object_path_array = pilot_get_path_array_handler,
};

struct test_special special_iface = {
    { &test_special_meta, 0},
    .get_array_dict_sas = special_get_array_dict_sas
};

static int pilot_test_server_init(struct sbus_connection *server, void *unused)
{
    int ret;

    ret = sbus_conn_register_iface(server, &pilot_iface.vtable, "/test/leela",
                                   discard_const("Crash into the billboard"));
    ck_assert_int_eq(ret, EOK);

    return EOK;
}

static int special_test_server_init(struct sbus_connection *server, void *unused)
{
    int ret;

    ret = sbus_conn_register_iface(server, &special_iface.vtable,
                                   "/test/special",
                                   discard_const("Crash into the billboard"));
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
    dbus_int64_t arg_int64 = INT64_C(-6666666666666666);
    dbus_uint64_t arg_uint64 = UINT64_C(7777777777777777);
    double arg_double = 1.1;
    const char *arg_string = "hello";
    const char *arg_object_path = "/original/object/path";

    unsigned char v_byte[] = { 11, 12 };
    dbus_int16_t v_int16[] = { 1, -22, 333, -4444 };
    dbus_uint16_t v_uint16[] = { 1, 2, 3, 4, 5 };
    dbus_int32_t v_int32[] = { -1, -23, 34, -56, -90000000, 78 };
    dbus_uint32_t v_uint32[] = { 11111111, 22222222, 33333333 };
    dbus_int64_t v_int64[] = { INT64_C(-6666666666666666), INT64_C(7777777777777777) };
    dbus_uint64_t v_uint64[] = { UINT64_C(7777777777777777), INT64_C(888888888888888888) };
    double v_double[] = { 1.1, 2.2, 3.3 };
    const char *v_string[] = { "bears", "bears", "bears" };
    const char *v_object_path[] = { "/original", "/original" };

    unsigned char *arr_byte = v_byte;
    dbus_int16_t *arr_int16 = v_int16;
    dbus_uint16_t *arr_uint16 = v_uint16;
    dbus_int32_t *arr_int32 = v_int32;
    dbus_uint32_t *arr_uint32 = v_uint32;
    dbus_int64_t *arr_int64 = v_int64;
    dbus_uint64_t *arr_uint64 = v_uint64;
    double *arr_double = v_double;
    char **arr_string = discard_const(v_string);
    char **arr_object_path = discard_const(v_object_path);

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
    ck_assert(ctx != NULL);

    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);
    ck_assert(client != NULL);

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
    ck_assert(arg_int64 == INT64_C(-6666666666666665));
    ck_assert(arg_uint64 == UINT64_C(7777777777777778));
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
    ck_assert(arr_int64[0] == INT64_C(-6666666666666665));
    ck_assert(arr_int64[1] == INT64_C(7777777777777778));

    ck_assert_int_eq(len_uint64, 2);
    ck_assert(arr_uint64[0] == UINT64_C(7777777777777778));
    ck_assert(arr_uint64[1] == UINT64_C(888888888888888889));

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

static void parse_get_reply(DBusMessage *reply, const int type, void *val)
{
    DBusMessageIter iter;
    DBusMessageIter variter;
    dbus_bool_t dbret;

    dbret = dbus_message_iter_init(reply, &iter);
    ck_assert(dbret == TRUE);
    ck_assert_int_eq(dbus_message_iter_get_arg_type(&iter), DBUS_TYPE_VARIANT);
    dbus_message_iter_recurse(&iter, &variter);
    ck_assert_int_eq(dbus_message_iter_get_arg_type(&variter), type);
    dbus_message_iter_get_basic(&variter, val);
}

static void call_get(DBusConnection *client,
                     const char *object_path,
                     const char *iface,
                     const char *prop,
                     int type,
                     void *val)
{
    DBusMessage *reply;
    DBusError error = DBUS_ERROR_INIT;

    reply = test_dbus_call_sync(client,
                                object_path,
                                DBUS_PROPERTIES_INTERFACE,
                                "Get",
                                &error,
                                DBUS_TYPE_STRING, &iface,
                                DBUS_TYPE_STRING, &prop,
                                DBUS_TYPE_INVALID);
    ck_assert(reply != NULL);
    parse_get_reply(reply, type, val);
}

START_TEST(test_get_basic_types)
{
    TALLOC_CTX *ctx;
    DBusConnection *client;
    dbus_bool_t bool_val;
    const char *string_val;
    const char *path_val;
    uint8_t byte_val;
    int16_t int16_val;
    uint16_t uint16_val;
    int32_t int32_val;
    uint32_t uint32_val;
    int64_t int64_val;
    uint64_t uint64_val;
    double double_val;

    ctx = talloc_new(NULL);
    ck_assert(ctx != NULL);

    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);
    ck_assert(client != NULL);

    call_get(client, "/test/leela", test_pilot_meta.name, "boolean",
             DBUS_TYPE_BOOLEAN, &bool_val);
    ck_assert(bool_val == pilot_bool);

    call_get(client, "/test/leela", test_pilot_meta.name, "FullName",
             DBUS_TYPE_STRING, &string_val);
    ck_assert_str_eq(string_val, pilot_full_name);

    call_get(client, "/test/leela", test_pilot_meta.name, "byte",
             DBUS_TYPE_BYTE, &byte_val);
    ck_assert_int_eq(byte_val, pilot_byte);

    call_get(client, "/test/leela", test_pilot_meta.name, "int16",
             DBUS_TYPE_INT16, &int16_val);
    ck_assert_int_eq(int16_val, pilot_int16);

    call_get(client, "/test/leela", test_pilot_meta.name, "uint16",
             DBUS_TYPE_UINT16, &uint16_val);
    ck_assert_int_eq(uint16_val, pilot_uint16);

    call_get(client, "/test/leela", test_pilot_meta.name, "int32",
             DBUS_TYPE_INT32, &int32_val);
    ck_assert_int_eq(int32_val, pilot_int32);

    call_get(client, "/test/leela", test_pilot_meta.name, "uint32",
             DBUS_TYPE_UINT32, &uint32_val);
    ck_assert_int_eq(uint32_val, pilot_uint32);

    call_get(client, "/test/leela", test_pilot_meta.name, "int64",
             DBUS_TYPE_INT64, &int64_val);
    ck_assert_int_eq(int64_val, pilot_int64);

    call_get(client, "/test/leela", test_pilot_meta.name, "uint64",
             DBUS_TYPE_UINT64, &uint64_val);
    ck_assert_int_eq(uint64_val, pilot_uint64);

    call_get(client, "/test/leela", test_pilot_meta.name, "double",
             DBUS_TYPE_DOUBLE, &double_val);
    ck_assert_int_eq(double_val, pilot_double);

    call_get(client, "/test/leela", test_pilot_meta.name, "string",
             DBUS_TYPE_STRING, &string_val);
    ck_assert_str_eq(string_val, pilot_string);

    call_get(client, "/test/leela", test_pilot_meta.name, "object_path",
             DBUS_TYPE_OBJECT_PATH, &path_val);
    ck_assert_str_eq(path_val, pilot_path);

    /* If a string getter returns NULL, the caller should receive "" */
    call_get(client, "/test/leela", test_pilot_meta.name, "null_string",
             DBUS_TYPE_STRING, &string_val);
    ck_assert_str_eq(string_val, "");

    /* If a string getter returns NULL, the caller should receive "/" */
    call_get(client, "/test/leela", test_pilot_meta.name, "null_path",
             DBUS_TYPE_OBJECT_PATH, &path_val);
    ck_assert_str_eq(path_val, "/");

    talloc_free(ctx);
}
END_TEST

static void parse_get_array_reply(DBusMessage *reply, const int type,
                                  void **values, int *nels)
{
    DBusMessageIter iter;
    DBusMessageIter variter;
    DBusMessageIter arriter;
    dbus_bool_t dbret;

    dbret = dbus_message_iter_init(reply, &iter);
    ck_assert(dbret == TRUE);
    ck_assert_int_eq(dbus_message_iter_get_arg_type(&iter), DBUS_TYPE_VARIANT);
    dbus_message_iter_recurse(&iter, &variter);
    ck_assert_int_eq(dbus_message_iter_get_arg_type(&variter), DBUS_TYPE_ARRAY);
    ck_assert_int_eq(dbus_message_iter_get_element_type(&variter), type);
    dbus_message_iter_recurse(&variter, &arriter);
    if (type == DBUS_TYPE_STRING || type == DBUS_TYPE_OBJECT_PATH) {
        int n = 0, i = 0;
        const char **strings;
        const char *s;

        do {
            n++;
        } while (dbus_message_iter_next(&arriter));

        /* Allocating on NULL is bad, but this is unit test */
        strings = talloc_array(NULL, const char *, n);
        ck_assert(strings != NULL);

        dbus_message_iter_recurse(&variter, &arriter);
        do {
            dbus_message_iter_get_basic(&arriter, &s);
            strings[i] = talloc_strdup(strings, s);
            ck_assert(strings[i] != NULL);
            i++;
        } while (dbus_message_iter_next(&arriter));

        *nels = n;
        *values = strings;
    } else {
        /* Fixed types are easy */
        dbus_message_iter_get_fixed_array(&arriter, values, nels);
    }
}

static void call_get_array(DBusConnection *client,
                           const char *object_path,
                           const char *iface,
                           const char *prop,
                           int type,
                           void **values,
                           int *nels)
{
    DBusMessage *reply;
    DBusError error = DBUS_ERROR_INIT;

    reply = test_dbus_call_sync(client,
                                object_path,
                                DBUS_PROPERTIES_INTERFACE,
                                "Get",
                                &error,
                                DBUS_TYPE_STRING, &iface,
                                DBUS_TYPE_STRING, &prop,
                                DBUS_TYPE_INVALID);
    ck_assert(reply != NULL);
    parse_get_array_reply(reply, type, values, nels);
}

#define _check_array(reply, len, known, fn) do {    \
    fn(len, 2);                                     \
    fn(reply[0], known[0]);                         \
    fn(reply[1], known[1]);                         \
} while(0);                                         \

#define check_int_array(reply, len, known) \
    _check_array(reply, len, known, ck_assert_int_eq)
#define check_uint_array(reply, len, known) \
    _check_array(reply, len, known, ck_assert_uint_eq)

START_TEST(test_get_basic_array_types)
{
    TALLOC_CTX *ctx;
    DBusConnection *client;
    const char **string_arr_val;
    int string_arr_len;
    const char **path_arr_val;
    int path_arr_len;
    uint8_t *byte_arr_val;
    int byte_arr_len;
    int16_t *int16_arr_val;
    int int16_arr_len;
    uint16_t *uint16_arr_val;
    int uint16_arr_len;
    int32_t *int32_arr_val;
    int int32_arr_len;
    uint32_t *uint32_arr_val;
    int uint32_arr_len;
    int64_t *int64_arr_val;
    int int64_arr_len;
    uint64_t *uint64_arr_val;
    int uint64_arr_len;
    double *double_arr_val;
    int double_arr_len;

    ctx = talloc_new(NULL);
    ck_assert(ctx != NULL);

    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);
    ck_assert(client != NULL);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "byte_array",
                   DBUS_TYPE_BYTE, (void **) &byte_arr_val, &byte_arr_len);
    check_uint_array(byte_arr_val, byte_arr_len, pilot_byte_array);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "int16_array",
                   DBUS_TYPE_INT16, (void **) &int16_arr_val, &int16_arr_len);
    check_int_array(int16_arr_val, int16_arr_len, pilot_int16_array);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "uint16_array",
                   DBUS_TYPE_UINT16, (void **) &uint16_arr_val, &uint16_arr_len);
    check_uint_array(uint16_arr_val, uint16_arr_len, pilot_uint16_array);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "int32_array",
                   DBUS_TYPE_INT32, (void **) &int32_arr_val, &int32_arr_len);
    check_int_array(int32_arr_val, int32_arr_len, pilot_int32_array);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "uint32_array",
                   DBUS_TYPE_UINT32, (void **) &uint32_arr_val, &uint32_arr_len);
    check_uint_array(uint32_arr_val, uint32_arr_len, pilot_uint32_array);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "int64_array",
                   DBUS_TYPE_INT64, (void **) &int64_arr_val, &int64_arr_len);
    check_int_array(int64_arr_val, int64_arr_len, pilot_int64_array);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "uint64_array",
                   DBUS_TYPE_UINT64, (void **) &uint64_arr_val, &uint64_arr_len);
    check_uint_array(uint64_arr_val, uint64_arr_len, pilot_uint64_array);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "double_array",
                   DBUS_TYPE_DOUBLE, (void **) &double_arr_val, &double_arr_len);
    check_int_array(double_arr_val, double_arr_len, pilot_double_array);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "string_array",
                   DBUS_TYPE_STRING, (void **) &string_arr_val, &string_arr_len);
    ck_assert_int_eq(string_arr_len, 2);
    ck_assert_str_eq(string_arr_val[0], pilot_string_array[0]);
    ck_assert_str_eq(string_arr_val[1], pilot_string_array[1]);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "string_array",
                   DBUS_TYPE_STRING, (void **) &string_arr_val, &string_arr_len);
    ck_assert_int_eq(string_arr_len, 2);
    ck_assert_str_eq(string_arr_val[0], pilot_string_array[0]);
    ck_assert_str_eq(string_arr_val[1], pilot_string_array[1]);

    call_get_array(client, "/test/leela", test_pilot_meta.name, "object_path_array",
                   DBUS_TYPE_OBJECT_PATH, (void **) &path_arr_val, &path_arr_len);
    ck_assert_int_eq(path_arr_len, 2);
    ck_assert_str_eq(path_arr_val[0], pilot_path_array[0]);
    ck_assert_str_eq(path_arr_val[1], pilot_path_array[1]);

    talloc_free(ctx);
}
END_TEST

START_TEST(test_get_array_dict_sas)
{
    TALLOC_CTX *ctx;
    DBusConnection *client;
    DBusMessage *reply;
    DBusMessageIter it_variant;
    DBusMessageIter it_array;
    DBusMessageIter it_dict;
    DBusMessageIter it_dict_entry;
    DBusMessageIter it_values;
    DBusError error = DBUS_ERROR_INIT;
    const char *prop = "array_dict_sas";
    dbus_bool_t dbret;
    const char *value;
    const char *hash_content[2][2] = {{"hello1", "world1"},
                                      {"hello2", "world2"}};
    const char **exp_values = NULL;
    int i;

    ctx = talloc_new(NULL);
    ck_assert(ctx != NULL);

    client = test_dbus_setup_mock(ctx, NULL, special_test_server_init, NULL);
    ck_assert(client != NULL);

    reply = test_dbus_call_sync(client,
                                "/test/special",
                                DBUS_PROPERTIES_INTERFACE,
                                "Get",
                                &error,
                                DBUS_TYPE_STRING, &test_special_meta.name,
                                DBUS_TYPE_STRING, &prop,
                                DBUS_TYPE_INVALID);
    ck_assert(reply != NULL);

    dbret = dbus_message_iter_init(reply, &it_variant);
    ck_assert(dbret == TRUE);

    ck_assert_int_eq(dbus_message_iter_get_arg_type(&it_variant), DBUS_TYPE_VARIANT);
    dbus_message_iter_recurse(&it_variant, &it_array);

    /* array */
    ck_assert_int_eq(dbus_message_iter_get_arg_type(&it_array), DBUS_TYPE_ARRAY);
    ck_assert_int_eq(dbus_message_iter_get_element_type(&it_array), DBUS_TYPE_DICT_ENTRY);

    /* dict entry */

    /* first item */
    dbus_message_iter_recurse(&it_array, &it_dict);
    for (i = 0; i < 2; i++) {
        dbus_message_iter_recurse(&it_dict, &it_dict_entry);
        ck_assert_int_eq(dbus_message_iter_get_arg_type(&it_dict_entry), DBUS_TYPE_STRING);

        dbus_message_iter_get_basic(&it_dict_entry, &value);
        ck_assert(value != NULL);
        if (strcmp(value, "key1") == 0) {
            exp_values = hash_content[0];
        } else if (strcmp(value, "key2") == 0) {
            exp_values = hash_content[1];
        } else {
            ck_abort_msg("Invalid key! %s", value);
        }

        dbret = dbus_message_iter_next(&it_dict_entry);
        ck_assert(dbret == TRUE);

        ck_assert_int_eq(dbus_message_iter_get_arg_type(&it_dict_entry), DBUS_TYPE_ARRAY);
        ck_assert_int_eq(dbus_message_iter_get_element_type(&it_dict_entry), DBUS_TYPE_STRING);

        dbus_message_iter_recurse(&it_dict_entry, &it_values);

        dbus_message_iter_get_basic(&it_values, &value);
        ck_assert(value != NULL);
        ck_assert_str_eq(value, exp_values[0]);

        dbret = dbus_message_iter_next(&it_values);
        dbus_message_iter_get_basic(&it_values, &value);
        ck_assert(value != NULL);
        ck_assert_str_eq(value, exp_values[1]);
        dbus_message_iter_next(&it_dict);
    }

    talloc_free(ctx);
}
END_TEST

struct prop_test {
    const char *name;
    bool handled;
    int length;
    int type;
    union prop_value {
        bool bool_val;
        const char *string_val;
        const char *path_val;
        uint8_t byte_val;
        int16_t int16_val;
        uint16_t uint16_val;
        int32_t int32_val;
        uint32_t uint32_val;
        int64_t int64_val;
        uint64_t uint64_val;
        double double_val;

        const char **string_arr_val;
        const char **path_arr_val;
        uint8_t *byte_arr_val;
        int16_t *int16_arr_val;
        uint16_t *uint16_arr_val;
        int32_t *int32_arr_val;
        uint32_t *uint32_arr_val;
        int64_t *int64_arr_val;
        uint64_t *uint64_arr_val;
        double *double_arr_val;
    } value;
};

void check_prop(DBusMessageIter *variter, struct prop_test *p)
{
    dbus_bool_t bool_val;
    const char *string_val;
    const char *path_val;
    uint8_t byte_val;
    int16_t int16_val;
    uint16_t uint16_val;
    int32_t int32_val;
    uint32_t uint32_val;
    int64_t int64_val;
    uint64_t uint64_val;
    double double_val;
    int type;

    type = dbus_message_iter_get_arg_type(variter);

    /* No property should be returned twice */
    ck_assert(p->handled == false);
    ck_assert(p->type == type);
    switch (p->type) {
        case DBUS_TYPE_BOOLEAN:
            dbus_message_iter_get_basic(variter, &bool_val);
            ck_assert(bool_val == p->value.bool_val);
            break;
        case DBUS_TYPE_STRING:
            dbus_message_iter_get_basic(variter, &string_val);
            ck_assert_str_eq(string_val, p->value.string_val);
            break;
        case DBUS_TYPE_BYTE:
            dbus_message_iter_get_basic(variter, &byte_val);
            ck_assert_int_eq(byte_val, p->value.byte_val);
            break;
        case DBUS_TYPE_INT16:
            dbus_message_iter_get_basic(variter, &int16_val);
            ck_assert_int_eq(int16_val, p->value.int16_val);
            break;
        case DBUS_TYPE_UINT16:
            dbus_message_iter_get_basic(variter, &uint16_val);
            ck_assert_int_eq(uint16_val, p->value.uint16_val);
            break;
        case DBUS_TYPE_INT32:
            dbus_message_iter_get_basic(variter, &int32_val);
            ck_assert_int_eq(int32_val, p->value.int32_val);
            break;
        case DBUS_TYPE_UINT32:
            dbus_message_iter_get_basic(variter, &uint32_val);
            ck_assert_int_eq(uint32_val, p->value.uint32_val);
            break;
        case DBUS_TYPE_INT64:
            dbus_message_iter_get_basic(variter, &int64_val);
            ck_assert_int_eq(int64_val, p->value.int64_val);
            break;
        case DBUS_TYPE_UINT64:
            dbus_message_iter_get_basic(variter, &uint64_val);
            ck_assert_int_eq(uint64_val, p->value.uint64_val);
            break;
        case DBUS_TYPE_DOUBLE:
            dbus_message_iter_get_basic(variter, &double_val);
            ck_assert_int_eq(double_val, p->value.double_val);
            break;
        case DBUS_TYPE_OBJECT_PATH:
            dbus_message_iter_get_basic(variter, &path_val);
            ck_assert_str_eq(path_val, p->value.path_val);
            break;
        default:
            /* Not handled */
            return;
    }

    /* This attribute was handled, get the next one */
    p->handled = true;
}

void check_arr_prop(DBusMessageIter *variter, struct prop_test *p)
{
    DBusMessageIter arriter;
    const char **strings = NULL;
    uint8_t *byte_arr_val;
    int16_t *int16_arr_val;
    uint16_t *uint16_arr_val;
    int32_t *int32_arr_val;
    uint32_t *uint32_arr_val;
    int64_t *int64_arr_val;
    uint64_t *uint64_arr_val;
    double *double_arr_val;
    int len;
    int type;

    ck_assert_int_eq(dbus_message_iter_get_arg_type(variter), DBUS_TYPE_ARRAY);
    type = dbus_message_iter_get_element_type(variter);
    ck_assert_int_eq(type, p->type);

    dbus_message_iter_recurse(variter, &arriter);
    if (type == DBUS_TYPE_STRING || type == DBUS_TYPE_OBJECT_PATH) {
        int n = 0, i = 0;
        const char *s;

        do {
            n++;
        } while (dbus_message_iter_next(&arriter));

        /* Allocating on NULL is bad, but this is unit test */
        strings = talloc_array(NULL, const char *, n);
        ck_assert(strings != NULL);

        dbus_message_iter_recurse(variter, &arriter);
        do {
            dbus_message_iter_get_basic(&arriter, &s);
            strings[i] = talloc_strdup(strings, s);
            ck_assert(strings[i] != NULL);
            i++;
        } while (dbus_message_iter_next(&arriter));

        len = n;
    }

    switch (p->type) {
        case DBUS_TYPE_STRING:
            ck_assert_int_eq(len, 2);
            ck_assert(strings != NULL);
            ck_assert_str_eq(strings[0], pilot_string_array[0]);
            ck_assert_str_eq(strings[1], pilot_string_array[1]);
            break;
        case DBUS_TYPE_BYTE:
            dbus_message_iter_get_fixed_array(&arriter, &byte_arr_val, &len);
            check_uint_array(byte_arr_val, len, p->value.byte_arr_val);
            break;
        case DBUS_TYPE_INT16:
            dbus_message_iter_get_fixed_array(&arriter, &int16_arr_val, &len);
            check_int_array(int16_arr_val, len, p->value.int16_arr_val);
            break;
        case DBUS_TYPE_UINT16:
            dbus_message_iter_get_fixed_array(&arriter, &uint16_arr_val, &len);
            check_uint_array(uint16_arr_val, len, p->value.uint16_arr_val);
            break;
        case DBUS_TYPE_INT32:
            dbus_message_iter_get_fixed_array(&arriter, &int32_arr_val, &len);
            check_int_array(int32_arr_val, len, p->value.int32_arr_val);
            break;
        case DBUS_TYPE_UINT32:
            dbus_message_iter_get_fixed_array(&arriter, &uint32_arr_val, &len);
            check_uint_array(uint32_arr_val, len, p->value.uint32_arr_val);
            break;
        case DBUS_TYPE_INT64:
            dbus_message_iter_get_fixed_array(&arriter, &int64_arr_val, &len);
            check_int_array(int64_arr_val, len, p->value.int64_arr_val);
            break;
        case DBUS_TYPE_UINT64:
            dbus_message_iter_get_fixed_array(&arriter, &uint64_arr_val, &len);
            check_uint_array(uint64_arr_val, len, p->value.uint64_arr_val);
            break;
        case DBUS_TYPE_DOUBLE:
            dbus_message_iter_get_fixed_array(&arriter, &double_arr_val, &len);
            check_int_array(double_arr_val, len, p->value.double_arr_val);
            break;
        case DBUS_TYPE_OBJECT_PATH:
            ck_assert_int_eq(len, 2);
            ck_assert(strings != NULL);
            ck_assert_str_eq(strings[0], pilot_path_array[0]);
            ck_assert_str_eq(strings[1], pilot_path_array[1]);
            break;
        default:
            /* Not handled */
            return;
    }


    p->handled = true;
}

START_TEST(test_getall_basic_types)
{
    DBusMessage *reply;
    DBusMessageIter iter;
    DBusMessageIter arriter;
    DBusMessageIter dictiter;
    DBusMessageIter variter;
    dbus_bool_t dbret;
    DBusError error = DBUS_ERROR_INIT;
    TALLOC_CTX *ctx;
    DBusConnection *client;
    char *attr_name;
    int i;
    int num_prop;

    struct prop_test pilot_properties[] = {
      { "boolean", false, 0, DBUS_TYPE_BOOLEAN, { .bool_val = pilot_bool } },
      { "FullName", false, 0, DBUS_TYPE_STRING, { .string_val = pilot_full_name } },
      { "byte", false, 0, DBUS_TYPE_BYTE, { .byte_val = pilot_byte } },
      { "int16", false, 0, DBUS_TYPE_INT16, { .int16_val = pilot_int16 } },
      { "uint16", false, 0, DBUS_TYPE_UINT16, { .uint16_val = pilot_uint16 } },
      { "int32", false, 0, DBUS_TYPE_INT32, { .int32_val = pilot_int32 } },
      { "uint32", false, 0, DBUS_TYPE_UINT32, { .uint32_val = pilot_uint32 } },
      { "int64", false, 0, DBUS_TYPE_INT64, { .int64_val = pilot_int64 } },
      { "uint64", false, 0, DBUS_TYPE_UINT64, { .uint64_val = pilot_uint64 } },
      { "double", false, 0, DBUS_TYPE_DOUBLE, { .double_val = pilot_double } },
      { "string", false, 0, DBUS_TYPE_STRING, { .string_val = pilot_string } },
      { "object_path", false, 0, DBUS_TYPE_OBJECT_PATH, { .path_val = pilot_path } },
      { "null_string", false, 0, DBUS_TYPE_STRING, { .string_val = "" } },
      { "null_path", false, 0, DBUS_TYPE_OBJECT_PATH, { .path_val = "/" } },

      { "byte_array", false, N_ELEMENTS(pilot_byte_array), DBUS_TYPE_BYTE, { .byte_arr_val = pilot_byte_array } },
      { "int16_array", false, N_ELEMENTS(pilot_int16_array), DBUS_TYPE_INT16, { .int16_arr_val = pilot_int16_array } },
      { "uint16_array", false, N_ELEMENTS(pilot_uint16_array), DBUS_TYPE_UINT16, { .uint16_arr_val = pilot_uint16_array } },
      { "int32_array", false, N_ELEMENTS(pilot_int32_array), DBUS_TYPE_INT32, { .int32_arr_val = pilot_int32_array } },
      { "uint32_array", false, N_ELEMENTS(pilot_uint32_array), DBUS_TYPE_UINT32, { .uint32_arr_val = pilot_uint32_array } },
      { "int64_array", false, N_ELEMENTS(pilot_int64_array), DBUS_TYPE_INT64, { .int64_arr_val = pilot_int64_array } },
      { "uint64_array", false, N_ELEMENTS(pilot_uint64_array), DBUS_TYPE_UINT64, { .uint64_arr_val = pilot_uint64_array } },
      { "double_array", false, N_ELEMENTS(pilot_double_array), DBUS_TYPE_DOUBLE, { .double_arr_val = pilot_double_array } },
      { "string_array", false, N_ELEMENTS(pilot_string_array), DBUS_TYPE_STRING, { .string_arr_val = pilot_string_array } },
      { "object_path_array", false, N_ELEMENTS(pilot_path_array), DBUS_TYPE_OBJECT_PATH, { .path_arr_val = pilot_path_array } },

      { NULL, false, 0, 0, { .bool_val = false } }};

    ctx = talloc_new(NULL);
    ck_assert(ctx != NULL);

    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);
    ck_assert(client != NULL);

    reply = test_dbus_call_sync(client,
                                "/test/leela",
                                DBUS_PROPERTIES_INTERFACE,
                                "GetAll",
                                &error,
                                DBUS_TYPE_STRING,
                                &test_pilot_meta.name,
                                DBUS_TYPE_INVALID);
    ck_assert(reply != NULL);

    /* GetAll reply is an array of dictionaries */
    dbret = dbus_message_iter_init(reply, &iter);
    ck_assert(dbret == TRUE);
    ck_assert_int_eq(dbus_message_iter_get_arg_type(&iter), DBUS_TYPE_ARRAY);

    dbus_message_iter_recurse(&iter, &arriter);
    num_prop = 0;
    do {
        ck_assert_int_eq(dbus_message_iter_get_arg_type(&arriter),
                         DBUS_TYPE_DICT_ENTRY);
        dbus_message_iter_recurse(&arriter, &dictiter);
        dbus_message_iter_get_basic(&dictiter, &attr_name);
        ck_assert(dbus_message_iter_next(&dictiter) == TRUE);
        ck_assert_int_eq(dbus_message_iter_get_arg_type(&dictiter),
                         DBUS_TYPE_VARIANT);

        dbus_message_iter_recurse(&dictiter, &variter);

        for (i=0; pilot_properties[i].name; i++) {
            if (strcmp(attr_name, pilot_properties[i].name) == 0) {
                if (dbus_message_iter_get_arg_type(&variter) == DBUS_TYPE_ARRAY) {
                    check_arr_prop(&variter, &pilot_properties[i]);
                } else {
                    check_prop(&variter, &pilot_properties[i]);
                }
                break;
            }
        }

        num_prop++;
    } while(dbus_message_iter_next(&arriter));

    /* All known properties must be handled now */
    for (i=0; pilot_properties[i].name; i++) {
        ck_assert(pilot_properties[i].handled == true);
    }
    /* Also all properties returned from the bus must be accounted for */
    ck_assert_uint_eq(num_prop, N_ELEMENTS(pilot_properties)-1);

    talloc_free(ctx);
}
END_TEST

TCase *create_handler_tests(void)
{
    TCase *tc = tcase_create("handler");

    tcase_add_test(tc, test_marshal_basic_types);
    tcase_add_test(tc, test_get_basic_types);
    tcase_add_test(tc, test_getall_basic_types);
    tcase_add_test(tc, test_get_basic_array_types);
    tcase_add_test(tc, test_get_array_dict_sas);

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
