/*
    SSSD

    Simple access module -- Tests

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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
#include <popt.h>
#include <check.h>

#include "confdb/confdb.h"
#include "providers/simple/simple_access.h"
#include "tests/common.h"

const char *ulist_1[] = {"u1", "u2", NULL};

struct simple_ctx *ctx = NULL;

void setup_simple(void)
{
    fail_unless(ctx == NULL, "Simple context already initialized.");
    ctx = talloc_zero(NULL, struct simple_ctx);
    fail_unless(ctx != NULL, "Cannot create simple context.");

    ctx->domain = talloc_zero(ctx, struct sss_domain_info);
    fail_unless(ctx != NULL, "Cannot create domain in simple context.");
    ctx->domain->case_sensitive = true;
}

void teardown_simple(void)
{
    int ret;
    fail_unless(ctx != NULL, "Simple context already freed.");
    ret = talloc_free(ctx);
    ctx = NULL;
    fail_unless(ret == 0, "Connot free simple context.");
}

START_TEST(test_both_empty)
{
    int ret;
    bool access_granted = false;

    ctx->allow_users = NULL;
    ctx->deny_users = NULL;

    ret = simple_access_check(ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                        "while both lists are empty.");
}
END_TEST

START_TEST(test_allow_empty)
{
    int ret;
    bool access_granted = true;

    ctx->allow_users = NULL;
    ctx->deny_users = discard_const(ulist_1);

    ret = simple_access_check(ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "while user is in deny list.");

    ret = simple_access_check(ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                         "while user is not in deny list.");
}
END_TEST

START_TEST(test_deny_empty)
{
    int ret;
    bool access_granted = false;

    ctx->allow_users = discard_const(ulist_1);
    ctx->deny_users = NULL;

    ret = simple_access_check(ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                        "while user is in allow list.");

    ret = simple_access_check(ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                        "while user is not in allow list.");
}
END_TEST

START_TEST(test_both_set)
{
    int ret;
    bool access_granted = false;

    ctx->allow_users = discard_const(ulist_1);
    ctx->deny_users = discard_const(ulist_1);

    ret = simple_access_check(ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "while user is in deny list.");

    ret = simple_access_check(ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                        "while user is not in allow list.");
}
END_TEST

START_TEST(test_case)
{
    int ret;
    bool access_granted = false;

    ctx->allow_users = discard_const(ulist_1);
    ctx->deny_users = NULL;

    ret = simple_access_check(ctx, "U1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "for user with different case "
                                         "in case-sensitive domain");

    ctx->domain->case_sensitive = false;

    ret = simple_access_check(ctx, "U1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                        "for user with different case "
                                        "in case-insensitive domain");
}
END_TEST

Suite *access_simple_suite (void)
{
    Suite *s = suite_create("access_simple");

    TCase *tc_allow_deny = tcase_create("allow/deny");
    tcase_add_checked_fixture(tc_allow_deny, setup_simple, teardown_simple);
    tcase_add_test(tc_allow_deny, test_both_empty);
    tcase_add_test(tc_allow_deny, test_allow_empty);
    tcase_add_test(tc_allow_deny, test_deny_empty);
    tcase_add_test(tc_allow_deny, test_both_set);
    tcase_add_test(tc_allow_deny, test_case);
    suite_add_tcase(s, tc_allow_deny);

    return s;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int number_failed;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    tests_set_cwd();

    Suite *s = access_simple_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

