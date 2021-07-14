/*
   SSSD

   Reference counting tests.

   Authors:
        Martin Nagy <mnagy@redhat.com>

   Copyright (C) Red Hat, Inc 2009

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

#include "tests/common_check.h"
#include "util/util.h"

/* Interface under test */
#include "util/refcount.h"

/* Fail the test if object 'obj' does not have 'num' references. */
#define REF_ASSERT(obj, num) \
    ck_assert_msg(((obj)->DO_NOT_TOUCH_THIS_MEMBER_refcount == (num)), \
                "Reference count of " #obj " should be %d but is %d", \
                (num), (obj)->DO_NOT_TOUCH_THIS_MEMBER_refcount)

#define FILLER_SIZE 32

struct foo {
    REFCOUNT_COMMON;
    char a[FILLER_SIZE];
    char b[FILLER_SIZE];
};

struct bar {
    char a[FILLER_SIZE];
    REFCOUNT_COMMON;
    char b[FILLER_SIZE];
};

struct baz {
    char a[FILLER_SIZE];
    char b[FILLER_SIZE];
    REFCOUNT_COMMON;
};

#define SET_FILLER(target) do { \
    memset((target)->a, 'a', FILLER_SIZE); \
    memset((target)->b, 'b', FILLER_SIZE); \
} while (0)

#define CHECK_FILLER(target) do { \
    int _counter; \
    for (_counter = 0; _counter < FILLER_SIZE; _counter++) { \
        ck_assert_msg((target)->a[_counter] == 'a', "Corrupted memory in "  \
                    #target "->a[%d] of size %d", _counter, FILLER_SIZE); \
        ck_assert_msg((target)->b[_counter] == 'b', "Corrupted memory in "  \
                    #target "->b[%d] of size %d", _counter, FILLER_SIZE); \
    } \
} while (0)

struct container {
    struct foo *foo;
    struct bar *bar;
    struct baz *baz;
};

static struct container *global;

START_TEST(test_refcount_basic)
{
    struct container *containers;
    int i;

    /* First allocate our global storage place. */
    global = talloc(NULL, struct container);
    sss_ck_fail_if_msg(global == NULL, "Failed to allocate memory");

    /* Allocate foo. */
    global->foo = rc_alloc(global, struct foo);
    sss_ck_fail_if_msg(global->foo == NULL, "Failed to allocate memory");
    SET_FILLER(global->foo);
    REF_ASSERT(global->foo, 1);

    /* Allocate bar. */
    global->bar = rc_alloc(global, struct bar);
    sss_ck_fail_if_msg(global->bar == NULL, "Failed to allocate memory");
    SET_FILLER(global->bar);
    REF_ASSERT(global->bar, 1);

    /* Allocate baz. */
    global->baz = rc_alloc(global, struct baz);
    sss_ck_fail_if_msg(global->baz == NULL, "Failed to allocate memory");
    SET_FILLER(global->baz);
    REF_ASSERT(global->baz, 1);

    /* Try multiple attaches. */
    containers = talloc_array(NULL, struct container, 100);
    sss_ck_fail_if_msg(containers == NULL, "Failed to allocate memory");
    for (i = 0; i < 100; i++) {
        containers[i].foo = rc_reference(containers, struct foo, global->foo);
        containers[i].bar = rc_reference(containers, struct bar, global->bar);
        containers[i].baz = rc_reference(containers, struct baz, global->baz);
        REF_ASSERT(containers[i].foo, i + 2);
        REF_ASSERT(global->foo, i + 2);
        REF_ASSERT(containers[i].bar, i + 2);
        REF_ASSERT(global->bar, i + 2);
        REF_ASSERT(containers[i].baz, i + 2);
        REF_ASSERT(global->baz, i + 2);
    }
    talloc_free(containers);

    CHECK_FILLER(global->foo);
    CHECK_FILLER(global->bar);
    CHECK_FILLER(global->baz);

    REF_ASSERT(global->foo, 1);
    REF_ASSERT(global->bar, 1);
    REF_ASSERT(global->baz, 1);

    talloc_free(global);
}
END_TEST

START_TEST(test_refcount_swap)
{
    void *tmp_ctx;
    struct container *container1;
    struct container *container2;

    tmp_ctx = talloc_new(NULL);

    ck_leaks_push(tmp_ctx);

    container1 = talloc(tmp_ctx, struct container);
    container2 = talloc(tmp_ctx, struct container);

    /* Allocate. */
    container1->foo = rc_alloc(container1, struct foo);
    sss_ck_fail_if_msg(container1->foo == NULL, "Failed to allocate memory");
    SET_FILLER(container1->foo);

    /* Reference. */
    container2->foo = rc_reference(container2, struct foo, container1->foo);
    sss_ck_fail_if_msg(container2->foo == NULL, "Failed to allocate memory");

    /* Make sure everything is as it should be. */
    ck_assert_msg(container1->foo == container2->foo,
                "Values have to be equal. %p == %p",
                container1->foo, container2->foo);
    REF_ASSERT(container1->foo, 2);

    /* Free in reverse order. */
    talloc_free(container1);
    REF_ASSERT(container2->foo, 1);
    CHECK_FILLER(container2->foo);
    talloc_free(container2);

    ck_leaks_pop(tmp_ctx);
    talloc_free(tmp_ctx);
}
END_TEST

Suite *create_suite(void)
{
    Suite *s = suite_create("refcount");

    TCase *tc = tcase_create("REFCOUNT Tests");

    /* Do some testing */
    tcase_add_checked_fixture(tc, ck_leak_check_setup, ck_leak_check_teardown);
    tcase_add_test(tc, test_refcount_basic);
    tcase_add_test(tc, test_refcount_swap);

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
    int debug = 0;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
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

    DEBUG_CLI_INIT(debug);

    tests_set_cwd();

    suite = create_suite();
    sr = srunner_create(suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

