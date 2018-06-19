/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <dbus/dbus.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "lib/sifp/sss_sifp.h"
#include "lib/sifp/sss_sifp_dbus.h"
#include "lib/sifp/sss_sifp_private.h"
#include "responder/ifp/ifp_iface/ifp_iface.h"

struct {
    sss_sifp_ctx *dbus_ctx;
    DBusMessage *reply;
} test_ctx;

DBusConnection *
__wrap_dbus_bus_get(DBusBusType type, DBusError *error)
{
    /* we won't use the connection anywhere, so we can just return NULL */
    return NULL;
}

DBusMessage *
__wrap_dbus_connection_send_with_reply_and_block(DBusConnection *connection,
                                                 DBusMessage *message,
                                                 int timeout_milliseconds,
                                                 DBusError *error)
{
    if (message == NULL || error == NULL) {
        return NULL;
    }

    return sss_mock_ptr_type(DBusMessage *);
}

static void reply_variant_basic(DBusMessage *reply,
                                const char *type,
                                const void *val)
{
    DBusMessageIter iter;
    DBusMessageIter variant_iter;
    dbus_bool_t bret;

    dbus_message_iter_init_append(reply, &iter);


    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
                                            type, &variant_iter);
    assert_true(bret);

    /* Now add the value */
    bret = dbus_message_iter_append_basic(&variant_iter, type[0], val);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&iter, &variant_iter);
    assert_true(bret);
}

static void reply_variant_array(DBusMessage *reply,
                                const char *type,
                                int num_vals,
                                uint8_t *vals,
                                unsigned int item_size)
{
    DBusMessageIter iter;
    DBusMessageIter variant_iter;
    DBusMessageIter array_iter;
    dbus_bool_t bret;
    char array_type[3];
    int i;
    void *addr;

    array_type[0] = DBUS_TYPE_ARRAY;
    array_type[1] = type[0];
    array_type[2] = '\0';

    dbus_message_iter_init_append(reply, &iter);


    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
                                            array_type, &variant_iter);
    assert_true(bret);

    bret = dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
                                            type, &array_iter);
    assert_true(bret);

    for (i = 0; i < num_vals; i++) {
        addr = vals + i*item_size;
        bret = dbus_message_iter_append_basic(&array_iter, type[0], addr);
        assert_true(bret);
    }

    bret = dbus_message_iter_close_container(&iter, &array_iter);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&iter, &variant_iter);
    assert_true(bret);
}

static int test_setup(void **state)
{
    sss_sifp_error ret;

    ret = sss_sifp_init(&test_ctx.dbus_ctx);
    assert_int_equal(ret, SSS_SIFP_OK);

    test_ctx.reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    assert_non_null(test_ctx.reply);
    return 0;
}

static int test_teardown_parser(void **state)
{
    sss_sifp_free(&test_ctx.dbus_ctx);
    assert_null(test_ctx.dbus_ctx);

    dbus_message_unref(test_ctx.reply);
    test_ctx.reply = NULL;
    return 0;
}

static int test_teardown_api(void **state)
{
    sss_sifp_free(&test_ctx.dbus_ctx);
    assert_null(test_ctx.dbus_ctx);

    /* sss_sifp is responsible for freeing the reply */
    return 0;
}

void test_sss_sifp_strdup_valid(void **state)
{
    const char *str = "test_string";
    char *dup_str = sss_sifp_strdup(test_ctx.dbus_ctx, str);
    assert_non_null(dup_str);
    assert_string_equal(str, dup_str);

    sss_sifp_free_string(test_ctx.dbus_ctx, &dup_str);
    assert_null(dup_str);
}

void test_sss_sifp_strdup_null(void **state)
{
    char *dup_str = sss_sifp_strdup(test_ctx.dbus_ctx, NULL);
    assert_null(dup_str);
}

void test_sss_sifp_strcat_valid(void **state)
{
    char *cat = sss_sifp_strcat(test_ctx.dbus_ctx, "hello ", "world");
    assert_non_null(cat);
    assert_string_equal("hello world", cat);

    sss_sifp_free_string(test_ctx.dbus_ctx, &cat);
    assert_null(cat);
}

void test_sss_sifp_strcat_left_null(void **state)
{
    char *cat = sss_sifp_strcat(test_ctx.dbus_ctx, NULL, "world");
    assert_non_null(cat);
    assert_string_equal("world", cat);

    sss_sifp_free_string(test_ctx.dbus_ctx, &cat);
    assert_null(cat);
}

void test_sss_sifp_strcat_right_null(void **state)
{
    char *cat = sss_sifp_strcat(test_ctx.dbus_ctx, "hello ", NULL);
    assert_non_null(cat);
    assert_string_equal("hello ", cat);

    sss_sifp_free_string(test_ctx.dbus_ctx, &cat);
    assert_null(cat);
}

void test_sss_sifp_strcat_both_null(void **state)
{
    char *cat = sss_sifp_strcat(test_ctx.dbus_ctx, NULL, NULL);
    assert_null(cat);
}

void test_sss_sifp_parse_object_path_valid(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    dbus_bool_t bret;
    sss_sifp_error ret;
    const char *path_in = "/object/path";
    char *path_out = NULL;

    /* prepare message */
    bret = dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path_in,
                                           DBUS_TYPE_INVALID);
    assert_true(bret);

    /* test */
    ret = sss_sifp_parse_object_path(ctx, reply, &path_out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(path_out);
    assert_string_equal(path_in, path_out);

    sss_sifp_free_string(ctx, &path_out);
    assert_null(path_out);
}

void test_sss_sifp_parse_object_path_invalid(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    dbus_bool_t bret;
    sss_sifp_error ret;
    uint16_t path_in = 10;
    char *path_out = NULL;

    /* prepare message */
    bret = dbus_message_append_args(reply, DBUS_TYPE_UINT16, &path_in,
                                           DBUS_TYPE_INVALID);
    assert_true(bret);

    /* test */
    ret = sss_sifp_parse_object_path(ctx, reply, &path_out);
    assert_int_not_equal(ret, SSS_SIFP_OK);
    assert_null(path_out);
}

void test_sss_sifp_parse_object_path_list_valid(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    dbus_bool_t bret;
    sss_sifp_error ret;
    char **path_out = NULL;
    const char *path_in[] = {"/object/path1", "/object/path2"};
    const char **paths = path_in;
    int path_in_len = 2;
    int i;

    /* prepare message */
    bret = dbus_message_append_args(reply, DBUS_TYPE_ARRAY,
                                           DBUS_TYPE_OBJECT_PATH,
                                           &paths, path_in_len,
                                           DBUS_TYPE_INVALID);
    assert_true(bret);

    /* test */
    ret = sss_sifp_parse_object_path_list(ctx, reply, &path_out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(path_out);

    for (i = 0; path_out[i] != NULL; i++) {
        assert_true(i < path_in_len);
        assert_non_null(path_out[i]);
        assert_string_equal(path_in[i], path_out[i]);
    }

    sss_sifp_free_string_array(ctx, &path_out);
    assert_null(path_out);
}

void test_sss_sifp_parse_object_path_list_invalid(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    dbus_bool_t bret;
    sss_sifp_error ret;
    char **path_out = NULL;
    const char *path_in = "/object/path";

    /* prepare message */
    bret = dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path_in,
                                           DBUS_TYPE_INVALID);
    assert_true(bret);

    /* test */
    ret = sss_sifp_parse_object_path_list(ctx, reply, &path_out);
    assert_int_not_equal(ret, SSS_SIFP_OK);
    assert_null(path_out);
}

void test_sss_sifp_parse_attr_bool(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    dbus_bool_t in = 1;
    bool out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_BOOLEAN_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_BOOL);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_bool(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_true(in == out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int16(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    int16_t in = INT16_MIN;
    int16_t out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_INT16_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT16);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int16(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint16(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    uint16_t in = UINT16_MAX;
    uint16_t out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_UINT16_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT16);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint16(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int32(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    int32_t in = INT32_MIN;
    int32_t out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_INT32_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT32);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int32(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint32(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    uint32_t in = UINT32_MAX;
    uint32_t out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_UINT32_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT32);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint32(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int64(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    int64_t in = INT64_MIN;
    int64_t out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_INT64_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT64);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int64(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint64(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    uint64_t in = UINT64_MAX;
    uint64_t out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_UINT64_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT64);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint64(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_string(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    const char *in = "test value";
    const char *out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_STRING_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_STRING);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_string(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_string_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_object_path(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    const char *in = "/object/path";
    const char *out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_OBJECT_PATH_AS_STRING, &in);

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_STRING);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_string(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_string_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_string_dict(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    DBusMessageIter iter;
    DBusMessageIter var_iter;
    DBusMessageIter array_iter;
    DBusMessageIter dict_iter;
    dbus_bool_t bret;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    struct {
        const char *key;
        const char *value;
    } data = {"key", "value"};
    hash_table_t *out;
    hash_key_t key;
    hash_value_t value;
    char **values;
    int hret;

    /* prepare message */
    dbus_message_iter_init_append(reply, &iter);

    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
                                            DBUS_TYPE_ARRAY_AS_STRING
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &var_iter);
    assert_true(bret);

    bret = dbus_message_iter_open_container(&var_iter, DBUS_TYPE_ARRAY,
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &array_iter);
    assert_true(bret);

    bret = dbus_message_iter_open_container(&array_iter,
                                            DBUS_TYPE_DICT_ENTRY,
                                            NULL, &dict_iter);
    assert_true(bret);

    bret = dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING,
                                          &data.key);
    assert_true(bret);

    bret = dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING,
                                          &data.value);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&array_iter, &dict_iter);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&var_iter, &array_iter);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&iter, &var_iter);
    assert_true(bret);

    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_STRING_DICT);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_string_dict(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(hash_count(out), 1);

    key.type = HASH_KEY_STRING;
    key.str = discard_const(data.key);
    hret = hash_lookup(out, &key, &value);
    assert_int_equal(hret, HASH_SUCCESS);
    assert_int_equal(value.type, HASH_VALUE_PTR);
    assert_non_null(value.ptr);
    values = value.ptr;
    assert_non_null(values[0]);
    assert_string_equal(values[0], data.value);
    assert_null(values[1]);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_bool_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 5;
    dbus_bool_t in_array[] = {1, 1, 0, 0, 1};
    dbus_bool_t *in = in_array;
    unsigned int out_num;
    bool *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_BOOLEAN_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(dbus_bool_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_BOOL);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_bool_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_true(in[i] == out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_bool_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    bool *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_BOOLEAN_AS_STRING, num_values,
                        NULL, sizeof(dbus_bool_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_BOOL);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_bool_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int16_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 5;
    int16_t in_array[] = {10, 15, -10, -15, 5559};
    int16_t *in = in_array;
    unsigned int out_num;
    int16_t *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_INT16_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(int16_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT16);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int16_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_int_equal(in[i], out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int16_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    int16_t *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_INT16_AS_STRING, num_values,
                        NULL, sizeof(int16_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT16);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int16_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint16_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 5;
    uint16_t in_array[] = {10, 15, 8885, 3224, 5559};
    uint16_t *in = in_array;
    unsigned int out_num;
    uint16_t *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_UINT16_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(uint16_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT16);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint16_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_int_equal(in[i], out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint16_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    uint16_t *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_UINT16_AS_STRING, num_values,
                        NULL, sizeof(uint16_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT16);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint16_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int32_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 5;
    int32_t in_array[] = {10, 15, -10, -15, 5559};
    int32_t *in = in_array;
    unsigned int out_num;
    int32_t *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_INT32_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(int32_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT32);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int32_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_int_equal(in[i], out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int32_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    int32_t *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_INT32_AS_STRING, num_values,
                        NULL, sizeof(int32_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT32);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int32_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint32_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 5;
    uint32_t in_array[] = {10, 15, 8885, 3224, 5559};
    uint32_t *in = in_array;
    unsigned int out_num;
    uint32_t *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_UINT32_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(uint32_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT32);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint32_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_int_equal(in[i], out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint32_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    uint32_t *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_UINT32_AS_STRING, num_values,
                        NULL, sizeof(uint32_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT32);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint32_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int64_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 5;
    int64_t in_array[] = {10, 15, -10, -15, 5559};
    int64_t *in = in_array;
    unsigned int out_num;
    int64_t *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_INT64_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(int64_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT64);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int64_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_int_equal(in[i], out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_int64_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    int64_t *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_INT64_AS_STRING, num_values,
                        NULL, sizeof(int64_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_INT64);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_int64_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint64_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 5;
    uint64_t in_array[] = {10, 15, 8885, 3224, 5559};
    uint64_t *in = in_array;
    unsigned int out_num;
    uint64_t *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_UINT64_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(uint64_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT64);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint64_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_int_equal(in[i], out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_uint64_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    uint64_t *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_UINT64_AS_STRING, num_values,
                        NULL, sizeof(uint64_t));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT64);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint64_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_string_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 6;
    const char *in_array[] = {"I", "don't", "like", "writing", "unit", "tests"};
    const char **in = in_array;
    unsigned int out_num;
    const char * const *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_STRING_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(const char*));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_STRING);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_string_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_string_equal(in[i], out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_string_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    const char * const *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_STRING_AS_STRING, num_values,
                        NULL, sizeof(const char*));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_STRING);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_string_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_object_path_array(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 2;
    const char *in_array[] = {"/object/path1", "/object/path2"};
    const char **in = in_array;
    unsigned int out_num;
    const char * const *out;
    unsigned int i;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_OBJECT_PATH_AS_STRING, num_values,
                        (uint8_t*)in, sizeof(const char*));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_STRING);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_string_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(num_values, out_num);

    for (i = 0; i < num_values; i++) {
        assert_string_equal(in[i], out[i]);
    }

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_object_path_array_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    unsigned int num_values = 0;
    unsigned int out_num;
    const char * const *out;

    /* prepare message */
    reply_variant_array(reply, DBUS_TYPE_OBJECT_PATH_AS_STRING, num_values,
                        NULL, sizeof(const char*));

    /* test */
    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, num_values);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_STRING);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_string_array(attrs, name, &out_num, &out);
    assert_int_equal(ret, SSS_SIFP_ATTR_NULL);
    assert_int_equal(num_values, out_num);
    assert_null(out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_string_dict_array(void **state)
{
    return;

    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    DBusMessageIter iter;
    DBusMessageIter var_iter;
    DBusMessageIter array_iter;
    DBusMessageIter dict_iter;
    DBusMessageIter val_iter;
    dbus_bool_t bret;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    static struct {
        const char *key;
        const char *values[];
    } data = {"key", {"value1", "value2", "value3"}};
    unsigned int num_values = 3;
    hash_table_t *out;
    hash_key_t key;
    hash_value_t value;
    char **values;
    unsigned int i;
    int hret;

    /* prepare message */
    dbus_message_iter_init_append(reply, &iter);

    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
                                            DBUS_TYPE_ARRAY_AS_STRING
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_ARRAY_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &var_iter);
    assert_true(bret);

    bret = dbus_message_iter_open_container(&var_iter, DBUS_TYPE_ARRAY,
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_ARRAY_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &array_iter);
    assert_true(bret);

    bret = dbus_message_iter_open_container(&array_iter,
                                            DBUS_TYPE_DICT_ENTRY,
                                            NULL, &dict_iter);
    assert_true(bret);

    bret = dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING,
                                          &data.key);
    assert_true(bret);

    bret = dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_ARRAY,
                                            DBUS_TYPE_STRING_AS_STRING,
                                            &val_iter);
    assert_true(bret);

    for (i = 0; i < num_values; i++) {
        bret = dbus_message_iter_append_basic(&val_iter, DBUS_TYPE_STRING,
                                              &data.values[i]);
        assert_true(bret);
    }

    bret = dbus_message_iter_close_container(&dict_iter, &val_iter);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&array_iter, &dict_iter);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&var_iter, &array_iter);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&iter, &var_iter);
    assert_true(bret);

    ret = sss_sifp_parse_attr(ctx, name, reply, &attrs);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_STRING_DICT);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_string_dict(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(hash_count(out), 1);

    key.type = HASH_KEY_STRING;
    key.str = discard_const(data.key);
    hret = hash_lookup(out, &key, &value);
    assert_int_equal(hret, HASH_SUCCESS);
    assert_int_equal(value.type, HASH_VALUE_PTR);
    assert_non_null(value.ptr);
    values = value.ptr;

    for (i = 0; i < num_values; i++) {
        assert_non_null(values[i]);
        assert_string_equal(values[i], data.values[i]);
    }
    assert_null(values[i]);


    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_list(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter dict_iter;
    DBusMessageIter var_iter;
    dbus_bool_t bret;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    struct {
        const char *name;
        uint32_t value;
    } data[] = {{"attr1", 1}, {"attr2", 2}, {"attr3", 3}, {NULL, 0}};
    uint32_t out;
    int i;

    /* prepare message */
    dbus_message_iter_init_append(reply, &iter);

    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_VARIANT_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &array_iter);
    assert_true(bret);

    for (i = 0; data[i].name != NULL; i++) {
        bret = dbus_message_iter_open_container(&array_iter,
                                                DBUS_TYPE_DICT_ENTRY,
                                                NULL, &dict_iter);
        assert_true(bret);

        bret = dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING,
                                              &data[i].name);
        assert_true(bret);

        bret = dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT,
                                                DBUS_TYPE_UINT32_AS_STRING,
                                                &var_iter);
        assert_true(bret);

        bret = dbus_message_iter_append_basic(&var_iter, DBUS_TYPE_UINT32,
                                              &data[i].value);
        assert_true(bret);

        bret = dbus_message_iter_close_container(&dict_iter, &var_iter);
        assert_true(bret);

        bret = dbus_message_iter_close_container(&array_iter, &dict_iter);
        assert_true(bret);
    }

    bret = dbus_message_iter_close_container(&iter, &array_iter);
    assert_true(bret);

    ret = sss_sifp_parse_attr_list(ctx, reply, &attrs);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);

    for (i = 0; data[i].name != NULL; i++) {
        assert_non_null(attrs[i]);
        assert_int_equal(attrs[i]->num_values, 1);
        assert_int_equal(attrs[i]->type, SSS_SIFP_ATTR_TYPE_UINT32);
        assert_string_equal(attrs[i]->name, data[i].name);

        ret = sss_sifp_find_attr_as_uint32(attrs, data[i].name, &out);
        assert_int_equal(ret, SSS_SIFP_OK);
        assert_int_equal(data[i].value, out);
    }

    assert_null(attrs[i]);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_parse_attr_list_empty(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    dbus_bool_t bret;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;

    /* prepare message */
    dbus_message_iter_init_append(reply, &iter);

    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_VARIANT_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &array_iter);
    assert_true(bret);

    bret = dbus_message_iter_close_container(&iter, &array_iter);
    assert_true(bret);

    ret = sss_sifp_parse_attr_list(ctx, reply, &attrs);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_null(attrs[0]);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_fetch_attr(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    const char *name = "test-attr";
    uint32_t in = UINT32_MAX;
    uint32_t out;

    /* prepare message */
    reply_variant_basic(reply, DBUS_TYPE_UINT32_AS_STRING, &in);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, reply);

    /* test */
    ret = sss_sifp_fetch_attr(ctx, "/test/object", "test.com", name, &attrs);

    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);
    assert_non_null(attrs[0]);
    assert_null(attrs[1]);

    assert_int_equal(attrs[0]->num_values, 1);
    assert_int_equal(attrs[0]->type, SSS_SIFP_ATTR_TYPE_UINT32);
    assert_string_equal(attrs[0]->name, name);

    ret = sss_sifp_find_attr_as_uint32(attrs, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_int_equal(in, out);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_fetch_all_attrs(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter dict_iter;
    DBusMessageIter var_iter;
    dbus_bool_t bret;
    sss_sifp_error ret;
    sss_sifp_attr **attrs = NULL;
    struct {
        const char *name;
        uint32_t value;
    } data[] = {{"attr1", 1}, {"attr2", 2}, {"attr3", 3}, {NULL, 0}};
    uint32_t out;
    int i;

    /* prepare message */
    dbus_message_iter_init_append(reply, &iter);

    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_VARIANT_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &array_iter);
    assert_true(bret);

    for (i = 0; data[i].name != NULL; i++) {
        bret = dbus_message_iter_open_container(&array_iter,
                                                DBUS_TYPE_DICT_ENTRY,
                                                NULL, &dict_iter);
        assert_true(bret);

        bret = dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING,
                                              &data[i].name);
        assert_true(bret);

        bret = dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT,
                                                DBUS_TYPE_UINT32_AS_STRING,
                                                &var_iter);
        assert_true(bret);

        bret = dbus_message_iter_append_basic(&var_iter, DBUS_TYPE_UINT32,
                                              &data[i].value);
        assert_true(bret);

        bret = dbus_message_iter_close_container(&dict_iter, &var_iter);
        assert_true(bret);

        bret = dbus_message_iter_close_container(&array_iter, &dict_iter);
        assert_true(bret);
    }

    bret = dbus_message_iter_close_container(&iter, &array_iter);
    assert_true(bret);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, reply);

    ret = sss_sifp_fetch_all_attrs(ctx, "/test/object", "test.com", &attrs);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(attrs);

    for (i = 0; data[i].name != NULL; i++) {
        assert_non_null(attrs[i]);
        assert_int_equal(attrs[i]->num_values, 1);
        assert_int_equal(attrs[i]->type, SSS_SIFP_ATTR_TYPE_UINT32);
        assert_string_equal(attrs[i]->name, data[i].name);

        ret = sss_sifp_find_attr_as_uint32(attrs, data[i].name, &out);
        assert_int_equal(ret, SSS_SIFP_OK);
        assert_int_equal(data[i].value, out);
    }

    assert_null(attrs[i]);

    sss_sifp_free_attrs(ctx, &attrs);
    assert_null(attrs);
}

void test_sss_sifp_fetch_object(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter dict_iter;
    DBusMessageIter var_iter;
    const char *path = "/test/object";
    const char *iface = "test.com";
    dbus_bool_t bret;
    sss_sifp_error ret;
    sss_sifp_object *object = NULL;
    struct {
        const char *name;
        const char *value;
    } data[] = {{"name", "test-object"}, {"a1", "a"}, {"a2", "b"}, {NULL, 0}};
    const char *out;
    int i;

    /* prepare message */
    dbus_message_iter_init_append(reply, &iter);

    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_VARIANT_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &array_iter);
    assert_true(bret);

    for (i = 0; data[i].name != NULL; i++) {
        bret = dbus_message_iter_open_container(&array_iter,
                                                DBUS_TYPE_DICT_ENTRY,
                                                NULL, &dict_iter);
        assert_true(bret);

        bret = dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING,
                                              &data[i].name);
        assert_true(bret);

        bret = dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT,
                                                DBUS_TYPE_STRING_AS_STRING,
                                                &var_iter);
        assert_true(bret);

        bret = dbus_message_iter_append_basic(&var_iter, DBUS_TYPE_STRING,
                                              &data[i].value);
        assert_true(bret);

        bret = dbus_message_iter_close_container(&dict_iter, &var_iter);
        assert_true(bret);

        bret = dbus_message_iter_close_container(&array_iter, &dict_iter);
        assert_true(bret);
    }

    bret = dbus_message_iter_close_container(&iter, &array_iter);
    assert_true(bret);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, reply);

    ret = sss_sifp_fetch_object(ctx, path, iface, &object);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(object);
    assert_non_null(object->attrs);
    assert_non_null(object->name);
    assert_non_null(object->object_path);
    assert_non_null(object->interface);

    assert_string_equal(object->name, "test-object");
    assert_string_equal(object->object_path, path);
    assert_string_equal(object->interface, iface);

    for (i = 0; data[i].name != NULL; i++) {
        assert_non_null(object->attrs[i]);
        assert_int_equal(object->attrs[i]->num_values, 1);
        assert_int_equal(object->attrs[i]->type, SSS_SIFP_ATTR_TYPE_STRING);
        assert_string_equal(object->attrs[i]->name, data[i].name);

        ret = sss_sifp_find_attr_as_string(object->attrs, data[i].name, &out);
        assert_int_equal(ret, SSS_SIFP_OK);
        assert_string_equal(data[i].value, out);
    }

    assert_null(object->attrs[i]);

    sss_sifp_free_object(ctx, &object);
    assert_null(object);
}

void test_sss_sifp_invoke_list_zeroargs(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    dbus_bool_t bret;
    sss_sifp_error ret;
    char **path_out = NULL;
    const char *path_in[] = {"/object/path1", "/object/path2"};
    const char **paths = path_in;
    int path_in_len = 2;
    int i;

    /* prepare message */
    bret = dbus_message_append_args(reply, DBUS_TYPE_ARRAY,
                                           DBUS_TYPE_OBJECT_PATH,
                                           &paths, path_in_len,
                                           DBUS_TYPE_INVALID);
    assert_true(bret);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, reply);

    /* test */
    ret = sss_sifp_invoke_list_ex(ctx, SSS_SIFP_PATH, SSS_SIFP_IFACE,
                                  "MyMethod", &path_out, DBUS_TYPE_INVALID);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(path_out);

    for (i = 0; path_out[i] != NULL; i++) {
        assert_true(i < path_in_len);
        assert_non_null(path_out[i]);
        assert_string_equal(path_in[i], path_out[i]);
    }

    sss_sifp_free_string_array(ctx, &path_out);
    assert_null(path_out);
}

void test_sss_sifp_invoke_list_withargs(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    dbus_bool_t bret;
    sss_sifp_error ret;
    char **path_out = NULL;
    const char *path_in[] = {"/object/path1", "/object/path2"};
    const char **paths = path_in;
    const char *arg = "first-arg";
    int path_in_len = 2;
    int i;

    /* prepare message */
    bret = dbus_message_append_args(reply, DBUS_TYPE_ARRAY,
                                           DBUS_TYPE_OBJECT_PATH,
                                           &paths, path_in_len,
                                           DBUS_TYPE_INVALID);
    assert_true(bret);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, reply);

    /* test */
    ret = sss_sifp_invoke_list_ex(ctx, SSS_SIFP_PATH, SSS_SIFP_IFACE,
                                  "MyMethod", &path_out,
                                  DBUS_TYPE_STRING, &arg,
                                  DBUS_TYPE_INVALID);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(path_out);

    for (i = 0; path_out[i] != NULL; i++) {
        assert_true(i < path_in_len);
        assert_non_null(path_out[i]);
        assert_string_equal(path_in[i], path_out[i]);
    }

    sss_sifp_free_string_array(ctx, &path_out);
    assert_null(path_out);
}

void test_sss_sifp_invoke_find_zeroargs(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    dbus_bool_t bret;
    sss_sifp_error ret;
    const char *path_in = "/object/path";
    char *path_out = NULL;

    /* prepare message */
    bret = dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path_in,
                                           DBUS_TYPE_INVALID);
    assert_true(bret);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, reply);

    /* test */
    ret = sss_sifp_invoke_find_ex(ctx, SSS_SIFP_PATH, SSS_SIFP_IFACE,
                                  "MyMethod", &path_out, DBUS_TYPE_INVALID);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(path_out);
    assert_string_equal(path_in, path_out);

    sss_sifp_free_string(ctx, &path_out);
    assert_null(path_out);
}

void test_sss_sifp_invoke_find_withargs(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *reply = test_ctx.reply;
    dbus_bool_t bret;
    sss_sifp_error ret;
    const char *path_in = "/object/path";
    char *path_out = NULL;
    const char *arg = "first-arg";

    /* prepare message */
    bret = dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path_in,
                                           DBUS_TYPE_INVALID);
    assert_true(bret);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, reply);

    /* test */
    ret = sss_sifp_invoke_find_ex(ctx, SSS_SIFP_PATH, SSS_SIFP_IFACE,
                                  "MyMethod", &path_out,
                                  DBUS_TYPE_STRING, &arg,
                                  DBUS_TYPE_INVALID);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(path_out);
    assert_string_equal(path_in, path_out);

    sss_sifp_free_string(ctx, &path_out);
    assert_null(path_out);
}

void test_sss_sifp_list_domains(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *msg_paths = NULL;
    DBusMessage *msg_ldap = NULL;
    DBusMessage *msg_ipa = NULL;
    dbus_bool_t bret;
    sss_sifp_error ret;
    const char *in[] = {SSS_SIFP_PATH "/Domains/LDAP",
                        SSS_SIFP_PATH "/Domains/IPA"};
    const char **paths = in;
    const char *names[] = {"LDAP", "IPA"};
    char **out = NULL;
    int in_len = 2;
    int i;

    msg_paths = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    assert_non_null(msg_paths);

    msg_ldap = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    assert_non_null(msg_ldap);

    msg_ipa = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    assert_non_null(msg_ipa);

    /* prepare message */
    bret = dbus_message_append_args(msg_paths, DBUS_TYPE_ARRAY,
                                               DBUS_TYPE_OBJECT_PATH,
                                               &paths, in_len,
                                               DBUS_TYPE_INVALID);
    assert_true(bret);

    reply_variant_basic(msg_ldap, DBUS_TYPE_STRING_AS_STRING, &names[0]);
    reply_variant_basic(msg_ipa, DBUS_TYPE_STRING_AS_STRING, &names[1]);

    will_return(__wrap_dbus_connection_send_with_reply_and_block, msg_paths);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, msg_ldap);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, msg_ipa);

    /* test */
    ret = sss_sifp_list_domains(ctx, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(out);

    for (i = 0; i < in_len; i++) {
        assert_non_null(out[i]);
        assert_string_equal(out[i], names[i]);
    }

    assert_null(out[i]);

    sss_sifp_free_string_array(ctx, &out);
    assert_null(out);

    /* messages are unreferenced in the library */
}

void test_sss_sifp_fetch_domain_by_name(void **state)
{
    sss_sifp_ctx *ctx = test_ctx.dbus_ctx;
    DBusMessage *msg_path = NULL;
    DBusMessage *msg_props = NULL;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    DBusMessageIter dict_iter;
    DBusMessageIter var_iter;
    dbus_bool_t bret;
    sss_sifp_error ret;
    const char *in =SSS_SIFP_PATH "/Domains/LDAP";
    const char *name = "LDAP";
    const char *prop = NULL;
    sss_sifp_object *out = NULL;
    struct {
        const char *name;
        const char *value;
    } props[] = {{"name", name}, {"a1", "a"}, {"a2", "b"}, {NULL, 0}};
    int i;


    msg_path = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    assert_non_null(msg_path);

    msg_props = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    assert_non_null(msg_props);

    /* prepare message */
    bret = dbus_message_append_args(msg_path, DBUS_TYPE_OBJECT_PATH, &in,
                                              DBUS_TYPE_INVALID);
    assert_true(bret);

    dbus_message_iter_init_append(msg_props, &iter);

    bret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                            DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                            DBUS_TYPE_STRING_AS_STRING
                                            DBUS_TYPE_VARIANT_AS_STRING
                                            DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                            &array_iter);
    assert_true(bret);

    for (i = 0; props[i].name != NULL; i++) {
        bret = dbus_message_iter_open_container(&array_iter,
                                                DBUS_TYPE_DICT_ENTRY,
                                                NULL, &dict_iter);
        assert_true(bret);

        bret = dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING,
                                              &props[i].name);
        assert_true(bret);

        bret = dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT,
                                                DBUS_TYPE_STRING_AS_STRING,
                                                &var_iter);
        assert_true(bret);

        bret = dbus_message_iter_append_basic(&var_iter, DBUS_TYPE_STRING,
                                              &props[i].value);
        assert_true(bret);

        bret = dbus_message_iter_close_container(&dict_iter, &var_iter);
        assert_true(bret);

        bret = dbus_message_iter_close_container(&array_iter, &dict_iter);
        assert_true(bret);
    }

    bret = dbus_message_iter_close_container(&iter, &array_iter);
    assert_true(bret);

    will_return(__wrap_dbus_connection_send_with_reply_and_block, msg_path);
    will_return(__wrap_dbus_connection_send_with_reply_and_block, msg_props);

    /* test */
    ret = sss_sifp_fetch_domain_by_name(ctx, name, &out);
    assert_int_equal(ret, SSS_SIFP_OK);
    assert_non_null(out);
    assert_non_null(out->attrs);
    assert_non_null(out->name);
    assert_non_null(out->object_path);
    assert_non_null(out->interface);

    assert_string_equal(out->name, name);
    assert_string_equal(out->object_path, in);
    assert_string_equal(out->interface, "org.freedesktop.sssd.infopipe.Domains");

    for (i = 0; props[i].name != NULL; i++) {
        assert_non_null(out->attrs[i]);
        assert_int_equal(out->attrs[i]->num_values, 1);
        assert_int_equal(out->attrs[i]->type, SSS_SIFP_ATTR_TYPE_STRING);
        assert_string_equal(out->attrs[i]->name, props[i].name);

        ret = sss_sifp_find_attr_as_string(out->attrs, props[i].name, &prop);
        assert_int_equal(ret, SSS_SIFP_OK);
        assert_string_equal(props[i].value, prop);
    }

    assert_null(out->attrs[i]);

    sss_sifp_free_object(ctx, &out);
    assert_null(out);

    /* messages are unreferenced in the library */
}

int main(int argc, const char *argv[])
{
    int rv;
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sss_sifp_strdup_valid,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_strdup_null,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_strcat_valid,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_strcat_left_null,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_strcat_right_null,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_strcat_both_null,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_object_path_valid,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_object_path_invalid,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_object_path_list_valid,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_object_path_list_invalid,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_bool,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_int16,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_uint16,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_int32,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_uint32,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_int64,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_uint64,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_string,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_object_path,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_string_dict,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_bool_array,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_bool_array_empty,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_int32_array,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_int32_array_empty,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_uint32_array,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_uint32_array_empty,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_int64_array,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_int64_array_empty,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_uint64_array,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_uint64_array_empty,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_string_array,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_string_array_empty,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_object_path_array,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_object_path_array_empty,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_string_dict_array,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_list,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_parse_attr_list_empty,
                                        test_setup, test_teardown_parser),
        cmocka_unit_test_setup_teardown(test_sss_sifp_fetch_attr,
                                        test_setup, test_teardown_api),
        cmocka_unit_test_setup_teardown(test_sss_sifp_fetch_all_attrs,
                                        test_setup, test_teardown_api),
        cmocka_unit_test_setup_teardown(test_sss_sifp_fetch_object,
                                        test_setup, test_teardown_api),
        cmocka_unit_test_setup_teardown(test_sss_sifp_invoke_list_zeroargs,
                                        test_setup, test_teardown_api),
        cmocka_unit_test_setup_teardown(test_sss_sifp_invoke_list_withargs,
                                        test_setup, test_teardown_api),
        cmocka_unit_test_setup_teardown(test_sss_sifp_invoke_find_zeroargs,
                                        test_setup, test_teardown_api),
        cmocka_unit_test_setup_teardown(test_sss_sifp_invoke_find_withargs,
                                        test_setup, test_teardown_api),
        cmocka_unit_test_setup_teardown(test_sss_sifp_list_domains,
                                        test_setup, test_teardown_api),
        cmocka_unit_test_setup_teardown(test_sss_sifp_fetch_domain_by_name,
                                        test_setup, test_teardown_api),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
       default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
