/*
    SSSD - Test for PAC reponder functions

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

#include <check.h>

#include <stdbool.h>
#include <util/data_blob.h>
#include <gen_ndr/security.h>

#include "tests/common.h"
#include "responder/pac/pacsrv.h"

struct dom_sid test_smb_sid = {1, 5, {0, 0, 0, 0, 0, 5},
                               {21, 2127521184, 1604012920, 1887927527, 1123,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const uint32_t test_id = 1200123;

struct dom_sid test_smb_sid_2nd = {1, 5, {0, 0, 0, 0, 0, 5},
                               {21, 2127521184, 1604012920, 1887927527, 201456,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const uint32_t test_id_2nd = 1200456;

struct local_mapping_ranges test_map = {{1200000, 1399999},
                                        {1000, 200999},
                                        {201000, 400999}};


START_TEST(pac_test_local_sid_to_id)
{
    int ret;
    uint32_t id;

    ret = local_sid_to_id(&test_map, &test_smb_sid, &id);
    fail_unless(ret == EOK,
                "Failed to convert local sid to id.");
    fail_unless(id == test_id, "Wrong id returne, expected [%d], got [%d].",
                               test_id, id);
}
END_TEST

START_TEST(pac_test_seondary_local_sid_to_id)
{
    int ret;
    uint32_t id;

    ret = local_sid_to_id(&test_map, &test_smb_sid_2nd, &id);
    fail_unless(ret == EOK,
                "Failed to convert local sid to id.");
    fail_unless(id == test_id_2nd, "Wrong id returne, expected [%d], got [%d].",
                               test_id_2nd, id);
}
END_TEST


Suite *idmap_test_suite (void)
{
    Suite *s = suite_create ("PAC responder");

    TCase *tc_pac = tcase_create("PAC responder tests");
    /*tcase_add_checked_fixture(tc_init,
                              leak_check_setup,
                              leak_check_teardown);*/

    tcase_add_test(tc_pac, pac_test_local_sid_to_id);
    tcase_add_test(tc_pac, pac_test_seondary_local_sid_to_id);

    suite_add_tcase(s, tc_pac);

    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;

    tests_set_cwd();

    Suite *s = idmap_test_suite();
    SRunner *sr = srunner_create(s);

    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
