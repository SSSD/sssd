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
#include "tests/sbus_codegen_tests_generated.h"

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
    ck_assert(test_pilot_meta.methods == NULL); /* no methods */
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
mock_move_universe(DBusMessage *msg, struct sbus_connection *conn)
{
    /* not called */
    return 0;
}

static int
mock_crash_now(DBusMessage *msg, struct sbus_connection *conn)
{
    /* not called */
    return 0;
}

START_TEST(test_vtable)
{
    struct com_planetexpress_Ship vtable = {
        { &com_planetexpress_Ship_meta, 0 },
        mock_move_universe,
        mock_crash_now,
    };

    /*
     * These are not silly tests:
     * - Will fail compilation if c-symbol name was not respected
     * - Will fail if method order was not respected
     */
    ck_assert(vtable.crash_now == mock_crash_now);
    ck_assert(vtable.MoveUniverse == mock_move_universe);
}
END_TEST

Suite *create_suite(void)
{
    Suite *s = suite_create("sbus_codegen");

    TCase *tc = tcase_create("defs");

    /* Do some testing */
    tcase_add_test(tc, test_interfaces);
    tcase_add_test(tc, test_methods);
    tcase_add_test(tc, test_properties);
    tcase_add_test(tc, test_signals);
    tcase_add_test(tc, test_vtable);

    /* Add all test cases to the test suite */
    suite_add_tcase(s, tc);

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
    srunner_set_fork_status(sr, CK_FORK);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
