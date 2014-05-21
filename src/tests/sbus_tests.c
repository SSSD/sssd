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

#include "common.h"

#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "util/util_errors.h"

/*
 * Although one would normally rely on the codegen to generate these
 * structures, we want to test this functionality *before* we test
 * the codegen in sbus_codegen_tests ... so these are hand rolled.
 */

#define PILOT_IFACE "test.Pilot"
#define PILOT_BLINK "Blink"
#define PILOT_EAT "Eat"

#define PILOT_IFACE_INTROSPECT \
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" \
        "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"                \
        "<node>\n"                                                                           \
        "  <interface name=\"test.Pilot\">\n"                                                \
        "    <method name=\"Blink\">\n"                                                      \
        "    </method>\n"                                                                    \
        "    <method name=\"Eat\">\n"                                                        \
        "    </method>\n"                                                                    \
        "  </interface>\n"                                                                   \
        " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"                        \
        "   <method name=\"Introspect\">\n"                                                  \
        "     <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"                           \
        "   </method>\n"                                                                     \
        " </interface>\n"                                                                    \
        " <interface name=\"org.freedesktop.DBus.Properties\">\n"                            \
        "   <method name=\"Get\">\n"                                                         \
        "     <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"                       \
        "     <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"                        \
        "     <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"                          \
        "   </method>\n"                                                                     \
        "   <method name=\"GetAll\">\n"                                                      \
        "     <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"                       \
        "     <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"                 \
        "   </method>\n"                                                                     \
        " </interface>\n"                                                                    \
        "</node>\n"

/* our vtable */
struct pilot_vtable {
    struct sbus_vtable vtable;
    sbus_msg_handler_fn Blink;
    sbus_msg_handler_fn Eat;
};

const struct sbus_method_meta pilot_methods[] = {
    {
        PILOT_BLINK, /* method name */
        NULL, /* in args: manually parsed */
        NULL, /* out args: manually parsed */
        offsetof(struct pilot_vtable, Blink),
        NULL
    },
    {
        PILOT_EAT, /* method name */
        NULL, /* in args: manually parsed */
        NULL, /* out args: manually parsed */
        offsetof(struct pilot_vtable, Eat),
        NULL
    },
    { NULL, }
};

const struct sbus_interface_meta pilot_meta = {
    PILOT_IFACE, /* name */
    pilot_methods,
    NULL, /* no signals */
    NULL, /* no properties */
    NULL, /* no GetAll invoker */
};

static int blink_handler(struct sbus_request *req, void *data)
{
    DBusError error = DBUS_ERROR_INIT;
    const char *path;
    dbus_int32_t duration = 0;
    dbus_bool_t crashed;

    ck_assert(req->intf->vtable->meta == &pilot_meta);
    ck_assert(data != NULL);
    ck_assert(data == req->intf->instance_data);

    path = dbus_message_get_path(req->message);
    ck_assert_str_eq(req->intf->path, path);

    if (strcmp(path, "/test/fry") == 0) {
        ck_assert_str_eq(data, "Don't crash");
    } else if (strcmp(path, "/test/leela") == 0) {
        ck_assert_str_eq(data, "Crash into the billboard");
    } else {
        ck_abort();
    }

    if (!dbus_message_get_args (req->message, &error,
                                DBUS_TYPE_INT32, &duration,
                                DBUS_TYPE_INVALID)) {
        sbus_request_fail_and_finish(req, &error);
        dbus_error_free(&error);
        return EOK;
    }

    /* Pilot crashes when eyes closed too long */
    crashed = (duration > 5);

    return sbus_request_return_and_finish(req,
                                          DBUS_TYPE_BOOLEAN, &crashed,
                                          DBUS_TYPE_INVALID);
}

static int eat_handler(struct sbus_request *req, void *data)
{
    dbus_int32_t integer;
    dbus_bool_t boolean;
    const char **array;
    int count;

    if (!sbus_request_parse_or_finish (req,
                                       DBUS_TYPE_INT32, &integer,
                                       DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &array, &count,
                                       DBUS_TYPE_BOOLEAN, &boolean,
                                       DBUS_TYPE_INVALID)) {
        return EOK; /* handled */
    }

    ck_assert_int_eq(integer, 5);
    ck_assert(boolean == TRUE);
    ck_assert_int_eq(count, 3);
    ck_assert_str_eq(array[0], "one");
    ck_assert_str_eq(array[1], "two");
    ck_assert_str_eq(array[2], "three");

    return sbus_request_return_and_finish(req, DBUS_TYPE_INVALID);
}

struct pilot_vtable pilot_impl = {
    { &pilot_meta, 0 },
    .Blink = blink_handler,
    .Eat = eat_handler,
};

static int pilot_test_server_init(struct sbus_connection *server, void *unused)
{
    int ret;

    ret = sbus_conn_add_interface(server,
                                  sbus_new_interface(server, "/test/leela",
                                                     &pilot_impl.vtable,
                                                     "Crash into the billboard"));
    ck_assert_int_eq(ret, EOK);


    ret = sbus_conn_add_interface(server,
                                  sbus_new_interface(server, "/test/fry",
                                                     &pilot_impl.vtable,
                                                     "Don't crash"));
    ck_assert_int_eq(ret, EOK);

    return EOK;
}

START_TEST(test_raw_handler)
{
    TALLOC_CTX *ctx;
    DBusConnection *client;
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply;
    dbus_bool_t crashed;
    dbus_int32_t duration;

    ctx = talloc_new(NULL);
    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);

    /* Leela crashes with a duration higher than 5 */
    duration = 10;
    reply = test_dbus_call_sync(client,
                                "/test/leela",
                                PILOT_IFACE,
                                PILOT_BLINK,
                                &error,
                                DBUS_TYPE_INT32, &duration,
                                DBUS_TYPE_INVALID);
    ck_assert(reply != NULL);
    ck_assert(!dbus_error_is_set(&error));
    ck_assert(dbus_message_get_args(reply, NULL,
                                    DBUS_TYPE_BOOLEAN, &crashed,
                                    DBUS_TYPE_INVALID));
    dbus_message_unref (reply);
    ck_assert(crashed == true);

    /* Fry daesn't crash with a duration lower than 5 */
    duration = 1;
    reply = test_dbus_call_sync(client,
                                "/test/fry",
                                PILOT_IFACE,
                                PILOT_BLINK,
                                &error,
                                DBUS_TYPE_INT32, &duration,
                                DBUS_TYPE_INVALID);
    ck_assert(reply != NULL);
    ck_assert(!dbus_error_is_set(&error));
    ck_assert(dbus_message_get_args(reply, NULL,
                                    DBUS_TYPE_BOOLEAN, &crashed,
                                    DBUS_TYPE_INVALID));
    dbus_message_unref (reply);
    ck_assert(crashed == FALSE);

    talloc_free(ctx);
}
END_TEST

START_TEST(test_request_parse_ok)
{
    const char *args[] = { "one", "two", "three" };
    const char **array;
    TALLOC_CTX *ctx;
    DBusConnection *client;
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply;
    dbus_bool_t boolean;
    dbus_int32_t integer;
    int count;

    ctx = talloc_new(NULL);
    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);

    boolean = TRUE;
    integer = 5;
    count = 3;
    array = args;
    reply = test_dbus_call_sync(client,
                                "/test/leela",
                                PILOT_IFACE,
                                PILOT_EAT,
                                &error,
                                DBUS_TYPE_INT32, &integer,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &array, count,
                                DBUS_TYPE_BOOLEAN, &boolean,
                                DBUS_TYPE_INVALID);
    ck_assert(reply != NULL);
    ck_assert(!dbus_error_is_set(&error));
    ck_assert(dbus_message_get_args(reply, NULL,
                                    DBUS_TYPE_INVALID));
    dbus_message_unref (reply);

    talloc_free(ctx);
}
END_TEST

START_TEST(test_request_parse_bad_args)
{
    TALLOC_CTX *ctx;
    DBusConnection *client;
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply;

    ctx = talloc_new(NULL);
    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);

    reply = test_dbus_call_sync(client,
                                "/test/leela",
                                PILOT_IFACE,
                                PILOT_EAT,
                                &error,
                                DBUS_TYPE_INVALID); /* bad agruments */
    ck_assert(reply == NULL);
    ck_assert(dbus_error_is_set(&error));
    ck_assert(dbus_error_has_name(&error, DBUS_ERROR_INVALID_ARGS));
    dbus_error_free(&error);

    talloc_free(ctx);
}
END_TEST

START_TEST(test_introspection)
{
    TALLOC_CTX *ctx;
    DBusConnection *client;
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply;
    char *xml;

    ctx = talloc_new(NULL);
    client = test_dbus_setup_mock(ctx, NULL, pilot_test_server_init, NULL);

    reply = test_dbus_call_sync(client,
                                "/test/leela",
                                DBUS_INTROSPECT_INTERFACE,
                                DBUS_INTROSPECT_METHOD,
                                &error,
                                DBUS_TYPE_INVALID); /* bad agruments */

    ck_assert(reply != NULL);
    ck_assert(!dbus_error_is_set(&error));
    ck_assert(dbus_message_get_args(reply, NULL,
                                    DBUS_TYPE_STRING, &xml,
                                    DBUS_TYPE_INVALID));
    ck_assert_str_eq(PILOT_IFACE_INTROSPECT, xml);

    dbus_message_unref(reply);

    talloc_free(ctx);
}
END_TEST

START_TEST(test_sbus_new_error)
{
    TALLOC_CTX *ctx;
    DBusError *error;

    ctx = talloc_new(NULL);

    error = sbus_error_new(ctx, DBUS_ERROR_IO_ERROR, "Input-output error");
    ck_assert(error != NULL);
    ck_assert(dbus_error_is_set(error));
    ck_assert(dbus_error_has_name(error, DBUS_ERROR_IO_ERROR));
    talloc_free(error);

    error = sbus_error_new(ctx, DBUS_ERROR_IO_ERROR,
                           "The answer should have been %d", 42);
    ck_assert(error != NULL);
    ck_assert(dbus_error_is_set(error));
    ck_assert(dbus_error_has_name(error, DBUS_ERROR_IO_ERROR));
    talloc_free(error);

    /* NULL message must also work */
    error = sbus_error_new(ctx, DBUS_ERROR_IO_ERROR, NULL);
    ck_assert(error != NULL);
    ck_assert(dbus_error_is_set(error));
    ck_assert(dbus_error_has_name(error, DBUS_ERROR_IO_ERROR));
    talloc_free(error);

    talloc_free(ctx);
}
END_TEST

TCase *create_sbus_tests(void)
{
    TCase *tc = tcase_create("tests");

    tcase_add_test(tc, test_raw_handler);
    tcase_add_test(tc, test_request_parse_ok);
    tcase_add_test(tc, test_request_parse_bad_args);
    tcase_add_test(tc, test_introspection);
    tcase_add_test(tc, test_sbus_new_error);

    return tc;
}

Suite *create_suite(void)
{
    Suite *s = suite_create("sbus");
    suite_add_tcase(s, create_sbus_tests());
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
