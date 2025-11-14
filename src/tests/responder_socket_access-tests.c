/*
    SSSD - Test for routine to check to access to responder sockets

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2012 Red Hat

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
#include <check.h>
#include <string.h>

#include "tests/common.h"
#include "responder/common/responder.h"

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version responder_test_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return responder_test_cli_protocol_version;
}

struct s2a_data {
    const char *inp;
    int exp_ret;
    size_t exp_count;
    uid_t *exp_uids;
};

struct s2a_data s2a_data[] = {
    {"1,2,3", 0, 3, (uid_t []){1, 2, 3}},
    {"1,2,3, 4,5  , 6 , 7  ", 0, 7, (uid_t []){1, 2, 3, 4, 5, 6, 7}},
    {"1", 0, 1, (uid_t []){1}},
    {"1, +2,3", 0, 3, (uid_t []){1, 2, 3}},
    {"1, -2,3", ERANGE, 0, NULL},
    {"1, 2ab, 3, 4", EINVAL, 0, NULL},
    {"1,", EINVAL, 0, NULL},
    {"", EINVAL, 0, NULL},
    {"1, 2, 4294967295", 0, 3, (uid_t []){1, 2, 4294967295U}},
    {"1, 2, 4294967296", ERANGE, 0, NULL},
    {"1, 2, root, 4, 5", 0, 5, (uid_t []){1, 2, 0, 4, 5}},
    {NULL, EINVAL, 0, NULL},
    {NULL, -1, 0, NULL}
};

START_TEST(resp_str_to_array_test)
{
    int ret;
    size_t uid_count;
    uid_t *uids = NULL;
    size_t c;
    size_t d;

    for (c = 0; s2a_data[c].exp_ret != -1; c++) {
        ret = csv_string_to_uid_array(global_talloc_context, s2a_data[c].inp,
                                      &uid_count, &uids);
        ck_assert_msg(ret == s2a_data[c].exp_ret,
                    "csv_string_to_uid_array failed [%d][%s].", ret,
                                                                strerror(ret));
        if (ret == 0) {
            ck_assert_msg(uid_count == s2a_data[c].exp_count,
                        "Wrong number of values, expected [%zu], got [%zu].",
                        s2a_data[c].exp_count, uid_count);
            for (d = 0; d < s2a_data[c].exp_count; d++) {
                ck_assert_msg(uids[d] == s2a_data[c].exp_uids[d],
                            "Wrong value, expected [%d], got [%d].\n",
                            s2a_data[c].exp_uids[d], uids[d]);
            }
        }

        talloc_free(uids);
        uids = NULL;
    }

}
END_TEST

struct uid_check_data {
    uid_t uid;
    size_t allowed_uids_count;
    uid_t *allowed_uids;
    int exp_ret;
};

struct uid_check_data uid_check_data[] = {
    {1, 3, (uid_t []){1, 2, 3}, 0},
    {2, 3, (uid_t []){1, 2, 3}, 0},
    {3, 3, (uid_t []){1, 2, 3}, 0},
    {4, 3, (uid_t []){1, 2, 3}, EACCES},
    {4, 0, NULL, EINVAL},
    {0, 0, NULL, -1}
};

START_TEST(check_allowed_uids_test)
{
    int ret;
    size_t c;

    for (c = 0; uid_check_data[c].exp_ret != -1; c++) {
        ret = check_allowed_uids(uid_check_data[c].uid,
                                 uid_check_data[c].allowed_uids_count,
                                 uid_check_data[c].allowed_uids);
        ck_assert_msg(ret == uid_check_data[c].exp_ret,
                    "check_allowed_uids failed [%d][%s].", ret, strerror(ret));
    }
}
END_TEST

Suite *responder_test_suite(void)
{
    Suite *s = suite_create ("Responder socket access");

    TCase *tc_utils = tcase_create("Utility test");

    tcase_add_test(tc_utils, resp_str_to_array_test);
    tcase_add_test(tc_utils, check_allowed_uids_test);

    suite_add_tcase(s, tc_utils);

    return s;
}

int main(int argc, const char *argv[])
{
    int opt;
    int number_failed;
    poptContext pc;

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

    DEBUG_CLI_INIT(debug_level);
    tests_set_cwd();

    Suite *s = responder_test_suite();
    SRunner *sr = srunner_create(s);

    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
