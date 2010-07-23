/*
    SSSD

    util-tests.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include <popt.h>
#include <talloc.h>
#include <check.h>
#include "util/util.h"
#include "tests/common.h"

START_TEST(test_diff_string_lists)
{
    TALLOC_CTX *test_ctx;
    char **l1;
    char **l2;
    char **l3;
    char **only_l1;
    char **only_l2;
    char **both;
    int ret;

    test_ctx = talloc_new(NULL);

    /* Test with all values returned */
    l1 = talloc_array(test_ctx, char *, 4);
    l1[0] = talloc_strdup(l1, "a");
    l1[1] = talloc_strdup(l1, "b");
    l1[2] = talloc_strdup(l1, "c");
    l1[3] = NULL;

    l2 = talloc_array(test_ctx, char *, 4);
    l2[0] = talloc_strdup(l1, "d");
    l2[1] = talloc_strdup(l1, "c");
    l2[2] = talloc_strdup(l1, "b");
    l2[3] = NULL;

    ret = diff_string_lists(test_ctx,
                            l1, l2,
                            &only_l1, &only_l2, &both);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(only_l1[1] == NULL, "only_l1 not NULL-terminated");
    fail_unless(strcmp(only_l2[0], "d") == 0, "Missing \"d\" from only_l2");
    fail_unless(only_l2[1] == NULL, "only_l2 not NULL-terminated");
    fail_unless(strcmp(both[0], "c") == 0, "Missing \"c\" from both");
    fail_unless(strcmp(both[1], "b") == 0, "Missing \"b\" from both");
    fail_unless(both[2] == NULL, "both not NULL-terminated");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    /* Test with restricted return values */
    ret = diff_string_lists(test_ctx,
                            l1, l2,
                            &only_l1, &only_l2, NULL);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(only_l1[1] == NULL, "only_l1 not NULL-terminated");
    fail_unless(strcmp(only_l2[0], "d") == 0, "Missing \"d\" from only_l2");
    fail_unless(only_l2[1] == NULL, "only_l2 not NULL-terminated");
    fail_unless(both == NULL, "Nothing returned to both");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    ret = diff_string_lists(test_ctx,
                            l1, l2,
                            &only_l1, NULL, NULL);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(only_l1[1] == NULL, "only_l1 not NULL-terminated");
    fail_unless(only_l2 == NULL, "Nothing returned to only_l2");
    fail_unless(both == NULL, "Nothing returned to both");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    ret = diff_string_lists(test_ctx,
                            l1, l2,
                            NULL, &only_l2, NULL);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l2[0], "d") == 0, "Missing \"d\" from only_l2");
    fail_unless(only_l2[1] == NULL, "only_l2 not NULL-terminated");
    fail_unless(only_l1 == NULL, "Nothing returned to only_l1");
    fail_unless(both == NULL, "Nothing returned to both");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    /* Test with no overlap */
    l3 = talloc_array(test_ctx, char *, 4);
    l3[0] = talloc_strdup(l1, "d");
    l3[1] = talloc_strdup(l1, "e");
    l3[2] = talloc_strdup(l1, "f");
    l3[3] = NULL;

    ret = diff_string_lists(test_ctx,
                            l1, l3,
                            &only_l1, &only_l2, &both);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(strcmp(only_l1[1], "b") == 0, "Missing \"b\" from only_l1");
    fail_unless(strcmp(only_l1[2], "c") == 0, "Missing \"c\" from only_l1");
    fail_unless(only_l1[3] == NULL, "only_l1 not NULL-terminated");
    fail_unless(strcmp(only_l2[0], "d") == 0, "Missing \"f\" from only_l2");
    fail_unless(strcmp(only_l2[1], "e") == 0, "Missing \"e\" from only_l2");
    fail_unless(strcmp(only_l2[2], "f") == 0, "Missing \"d\" from only_l2");
    fail_unless(only_l2[3] == NULL, "only_l2 not NULL-terminated");
    fail_unless(both[0] == NULL, "both should have zero entries");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    /* Test with 100% overlap */
    ret = diff_string_lists(test_ctx,
                            l1, l1,
                            &only_l1, &only_l2, &both);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(only_l1[0] == NULL, "only_l1 should have zero entries");
    fail_unless(only_l2[0] == NULL, "only_l2 should have zero entries");
    fail_unless(strcmp(both[0], "a") == 0, "Missing \"a\" from both");
    fail_unless(strcmp(both[1], "b") == 0, "Missing \"b\" from both");
    fail_unless(strcmp(both[2], "c") == 0, "Missing \"c\" from both");
    fail_unless(both[3] == NULL, "both is not NULL-terminated");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    /* Test with no second list */
    ret = diff_string_lists(test_ctx,
                            l1, NULL,
                            &only_l1, &only_l2, &both);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(strcmp(only_l1[1], "b") == 0, "Missing \"b\" from only_l1");
    fail_unless(strcmp(only_l1[2], "c") == 0, "Missing \"c\" from only_l1");
    fail_unless(only_l1[3] == NULL, "only_l1 not NULL-terminated");
    fail_unless(only_l2[0] == NULL, "only_l2 should have zero entries");
    fail_unless(both[0] == NULL, "both should have zero entries");

    talloc_free(test_ctx);
}
END_TEST

Suite *util_suite(void)
{
    Suite *s = suite_create("util");

    TCase *tc_util = tcase_create("util");

    tcase_add_test (tc_util, test_diff_string_lists);
    tcase_set_timeout(tc_util, 60);

    suite_add_tcase (s, tc_util);

    return s;
}

int main(int argc, const char *argv[])
{
    int opt;
    int failure_count;
    poptContext pc;
    Suite *s = util_suite();
    SRunner *sr = srunner_create (s);

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        { NULL }
    };

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

    tests_set_cwd();

    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed (sr);
    srunner_free (sr);
    if (failure_count == 0) {
        return EXIT_SUCCESS;
    }
    return  EXIT_FAILURE;
}
