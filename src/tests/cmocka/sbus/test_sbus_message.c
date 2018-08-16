/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
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

#include "config.h"

#include <talloc.h>
#include <errno.h>
#include <popt.h>

#include "util/util.h"
#include "sbus/sbus_message.h"
#include "tests/cmocka/common_mock.h"
#include "tests/common.h"

#define BASE_PATH "/some/path"

struct test_ctx {
    bool msg_removed;
};

static void helper_msg_removed(void *state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(state, struct test_ctx);

    test_ctx->msg_removed = true;
}

static void helper_msg_watch(struct test_ctx *test_ctx, DBusMessage *msg)
{
    DBusFreeFunction free_fn;
    dbus_int32_t data_slot = -1;
    dbus_bool_t bret;

    assert_non_null(msg);

    bret = dbus_message_allocate_data_slot(&data_slot);
    assert_true(bret);

    free_fn = helper_msg_removed;
    bret = dbus_message_set_data(msg, data_slot, test_ctx, free_fn);
    assert_true(bret);
}

static int test_setup(void **state)
{
    struct test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);
    *state = test_ctx;

    check_leaks_push(test_ctx);

    return 0;
}

int test_teardown(void **state)
{
    struct test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct test_ctx);

    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);
    assert_true(leak_check_teardown());

    return 0;
}

void test_sbus_message_bound__null(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);

    ret = sbus_message_bound(NULL, msg);
    assert_int_equal(ret, EINVAL);

    ret = sbus_message_bound(test_ctx, NULL);
    assert_int_equal(ret, EINVAL);

    dbus_message_unref(msg);
}

void test_sbus_message_bound__unref(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    ret = sbus_message_bound(test_ctx, msg);
    assert_int_equal(ret, EOK);

    /* no memory leak should be detected in teardown */
    dbus_message_unref(msg);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_message_bound__free(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    TALLOC_CTX *tmp_ctx;
    DBusMessage *msg;
    errno_t ret;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    ret = sbus_message_bound(tmp_ctx, msg);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_message_bound_steal__null(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    ret = sbus_message_bound_steal(NULL, msg);
    assert_int_equal(ret, EINVAL);

    ret = sbus_message_bound_steal(test_ctx, NULL);
    assert_int_equal(ret, EINVAL);

    dbus_message_unref(msg);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_message_bound_steal__invalid(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    ret = sbus_message_bound_steal(test_ctx, msg);
    assert_int_equal(ret, ERR_INTERNAL);

    dbus_message_unref(msg);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_message_bound_steal__free(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    TALLOC_CTX *tmp_ctx;
    TALLOC_CTX *tmp_ctx_steal;
    DBusMessage *msg;
    errno_t ret;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    tmp_ctx_steal = talloc_new(test_ctx);
    assert_non_null(tmp_ctx_steal);

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    ret = sbus_message_bound(tmp_ctx, msg);
    assert_int_equal(ret, EOK);

    /* this will increase ref counter of message and add new talloc bound */
    ret = sbus_message_bound_steal(tmp_ctx_steal, msg);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
    assert_false(test_ctx->msg_removed);
    talloc_free(tmp_ctx_steal);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_method_create_empty__unref(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    DBusMessage *msg;

    msg = sbus_method_create_empty(NULL, "bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    assert_int_equal(dbus_message_get_type(msg), DBUS_MESSAGE_TYPE_METHOD_CALL);
    assert_string_equal(dbus_message_get_destination(msg), "bus.test");
    assert_string_equal(dbus_message_get_path(msg), "/");
    assert_string_equal(dbus_message_get_interface(msg), "iface.test");
    assert_string_equal(dbus_message_get_member(msg), "method");

    dbus_message_unref(msg);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_method_create_empty__free(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    TALLOC_CTX *tmp_ctx;
    DBusMessage *msg;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    msg = sbus_method_create_empty(tmp_ctx, "bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    assert_int_equal(dbus_message_get_type(msg), DBUS_MESSAGE_TYPE_METHOD_CALL);
    assert_string_equal(dbus_message_get_destination(msg), "bus.test");
    assert_string_equal(dbus_message_get_path(msg), "/");
    assert_string_equal(dbus_message_get_interface(msg), "iface.test");
    assert_string_equal(dbus_message_get_member(msg), "method");

    talloc_free(tmp_ctx);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_method_create__unref(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    DBusMessage *msg;
    dbus_bool_t dbret;
    uint32_t in_value = 32;
    uint32_t out_value;

    msg = sbus_method_create(NULL, "bus.test", "/", "iface.test", "method",
                             DBUS_TYPE_UINT32, &in_value);
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    assert_int_equal(dbus_message_get_type(msg), DBUS_MESSAGE_TYPE_METHOD_CALL);
    assert_string_equal(dbus_message_get_destination(msg), "bus.test");
    assert_string_equal(dbus_message_get_path(msg), "/");
    assert_string_equal(dbus_message_get_interface(msg), "iface.test");
    assert_string_equal(dbus_message_get_member(msg), "method");

    dbret = dbus_message_get_args(msg, NULL,
                                  DBUS_TYPE_UINT32, &out_value,
                                  DBUS_TYPE_INVALID);
    assert_true(dbret);
    assert_int_equal(out_value, 32);

    dbus_message_unref(msg);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_method_create__free(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    TALLOC_CTX *tmp_ctx;
    DBusMessage *msg;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    msg = sbus_method_create_empty(tmp_ctx, "bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    assert_int_equal(dbus_message_get_type(msg), DBUS_MESSAGE_TYPE_METHOD_CALL);
    assert_string_equal(dbus_message_get_destination(msg), "bus.test");
    assert_string_equal(dbus_message_get_path(msg), "/");
    assert_string_equal(dbus_message_get_interface(msg), "iface.test");
    assert_string_equal(dbus_message_get_member(msg), "method");

    talloc_free(tmp_ctx);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_signal_create_empty__unref(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    DBusMessage *msg;

    msg = sbus_signal_create_empty(NULL, "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    assert_int_equal(dbus_message_get_type(msg), DBUS_MESSAGE_TYPE_SIGNAL);
    assert_null(dbus_message_get_destination(msg));
    assert_string_equal(dbus_message_get_path(msg), "/");
    assert_string_equal(dbus_message_get_interface(msg), "iface.test");
    assert_string_equal(dbus_message_get_member(msg), "method");

    dbus_message_unref(msg);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_signal_create_empty__free(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    TALLOC_CTX *tmp_ctx;
    DBusMessage *msg;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    msg = sbus_signal_create_empty(tmp_ctx, "/", "iface.test", "method");
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    assert_int_equal(dbus_message_get_type(msg), DBUS_MESSAGE_TYPE_SIGNAL);
    assert_null(dbus_message_get_destination(msg));
    assert_string_equal(dbus_message_get_path(msg), "/");
    assert_string_equal(dbus_message_get_interface(msg), "iface.test");
    assert_string_equal(dbus_message_get_member(msg), "method");

    talloc_free(tmp_ctx);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_signal_create__unref(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    DBusMessage *msg;
    dbus_bool_t dbret;
    uint32_t in_value = 32;
    uint32_t out_value;

    msg = sbus_signal_create(NULL, "/", "iface.test", "method",
                             DBUS_TYPE_UINT32, &in_value);
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    assert_int_equal(dbus_message_get_type(msg), DBUS_MESSAGE_TYPE_SIGNAL);
    assert_null(dbus_message_get_destination(msg));
    assert_string_equal(dbus_message_get_path(msg), "/");
    assert_string_equal(dbus_message_get_interface(msg), "iface.test");
    assert_string_equal(dbus_message_get_member(msg), "method");

    dbret = dbus_message_get_args(msg, NULL,
                                  DBUS_TYPE_UINT32, &out_value,
                                  DBUS_TYPE_INVALID);
    assert_true(dbret);
    assert_int_equal(out_value, 32);

    dbus_message_unref(msg);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_signal_create__free(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    TALLOC_CTX *tmp_ctx;
    DBusMessage *msg;
    dbus_bool_t dbret;
    uint32_t in_value = 32;
    uint32_t out_value;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    msg = sbus_signal_create(tmp_ctx, "/", "iface.test", "method",
                             DBUS_TYPE_UINT32, &in_value);
    assert_non_null(msg);
    helper_msg_watch(test_ctx, msg);

    assert_int_equal(dbus_message_get_type(msg), DBUS_MESSAGE_TYPE_SIGNAL);
    assert_null(dbus_message_get_destination(msg));
    assert_string_equal(dbus_message_get_path(msg), "/");
    assert_string_equal(dbus_message_get_interface(msg), "iface.test");
    assert_string_equal(dbus_message_get_member(msg), "method");

    dbret = dbus_message_get_args(msg, NULL,
                                  DBUS_TYPE_UINT32, &out_value,
                                  DBUS_TYPE_INVALID);
    assert_true(dbret);
    assert_int_equal(out_value, 32);

    talloc_free(tmp_ctx);
    assert_true(test_ctx->msg_removed);
}

void test_sbus_reply_parse__ok(void **state)
{
    DBusMessage *msg;
    DBusMessage *reply;
    dbus_bool_t dbret;
    uint32_t in_value1 = 32;
    uint32_t in_value2 = 64;
    uint32_t out_value1;
    uint32_t out_value2;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    dbus_message_set_serial(msg, 1);

    reply = dbus_message_new_method_return(msg);
    assert_non_null(reply);

    dbret = dbus_message_append_args(reply, DBUS_TYPE_UINT32, &in_value1,
                                            DBUS_TYPE_UINT32, &in_value2,
                                            DBUS_TYPE_INVALID);
    assert_true(dbret);

    ret = sbus_reply_parse(reply, DBUS_TYPE_UINT32, &out_value1,
                                  DBUS_TYPE_UINT32, &out_value2);
    assert_int_equal(ret, EOK);
    assert_int_equal(out_value1, in_value1);
    assert_int_equal(out_value2, in_value2);

    dbus_message_unref(msg);
    dbus_message_unref(reply);
}

void test_sbus_reply_parse__error(void **state)
{
    DBusMessage *msg;
    DBusMessage *reply;
    uint32_t out_value1;
    uint32_t out_value2;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    dbus_message_set_serial(msg, 1);

    reply = dbus_message_new_error(msg, SBUS_ERROR_KILLED, "Test error!");
    assert_non_null(reply);

    ret = sbus_reply_parse(reply, DBUS_TYPE_UINT32, &out_value1,
                                  DBUS_TYPE_UINT32, &out_value2);
    assert_int_equal(ret, ERR_SBUS_KILL_CONNECTION);

    dbus_message_unref(msg);
    dbus_message_unref(reply);
}

void test_sbus_reply_parse__wrong_type(void **state)
{
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    dbus_message_set_serial(msg, 1);

    ret = sbus_reply_parse(msg);
    assert_int_not_equal(ret, EOK);

    dbus_message_unref(msg);
}

void test_sbus_reply_check__ok(void **state)
{
    DBusMessage *msg;
    DBusMessage *reply;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    dbus_message_set_serial(msg, 1);

    reply = dbus_message_new_method_return(msg);
    assert_non_null(reply);

    ret = sbus_reply_check(reply);
    assert_int_equal(ret, EOK);

    dbus_message_unref(msg);
    dbus_message_unref(reply);
}

void test_sbus_reply_check__error(void **state)
{
    DBusMessage *msg;
    DBusMessage *reply;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    dbus_message_set_serial(msg, 1);

    reply = dbus_message_new_error(msg, SBUS_ERROR_KILLED, "Test error!");
    assert_non_null(reply);

    ret = sbus_reply_check(reply);
    assert_int_equal(ret, ERR_SBUS_KILL_CONNECTION);

    dbus_message_unref(msg);
    dbus_message_unref(reply);
}

void test_sbus_reply_check__wrong_type(void **state)
{
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new_method_call("bus.test", "/", "iface.test", "method");
    assert_non_null(msg);
    dbus_message_set_serial(msg, 1);

    ret = sbus_reply_check(msg);
    assert_int_not_equal(ret, EOK);

    dbus_message_unref(msg);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sbus_message_bound__null,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_message_bound__unref,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_message_bound__free,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_message_bound_steal__null,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_message_bound_steal__invalid,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_message_bound_steal__free,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_method_create_empty__unref,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_method_create_empty__free,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_method_create__unref,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_method_create__free,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_signal_create_empty__unref,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_signal_create_empty__free,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_signal_create__unref,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_signal_create__free,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_reply_parse__ok,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_reply_parse__error,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_reply_parse__wrong_type,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_reply_check__ok,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_reply_check__error,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sbus_reply_check__wrong_type,
                                        test_setup, test_teardown),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
