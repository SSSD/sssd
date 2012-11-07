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

START_TEST(pac_test_get_gids_to_add_and_remove)
{
    TALLOC_CTX *mem_ctx;
    int ret;
    size_t c;
    size_t add_gid_count = 0;
    gid_t *add_gids = NULL;
    size_t del_gid_count = 0;
    struct grp_info **del_gids = NULL;

    gid_t gid_list_2[] = {2};
    gid_t gid_list_3[] = {3};
    gid_t gid_list_23[] = {2, 3};

    struct grp_info grp_info_1 = {1, NULL, NULL};
    struct grp_info grp_info_2 = {2, NULL, NULL};
    struct grp_info  grp_list_1[] = {grp_info_1};
    struct grp_info  grp_list_12[] = {grp_info_1, grp_info_2};

    struct a_and_r_data {
        size_t cur_gid_count;
        struct grp_info *cur_gids;
        size_t gid_count;
        gid_t *gids;
        int exp_ret;
        size_t exp_add_gid_count;
        gid_t *exp_add_gids;
        size_t exp_del_gid_count;
        struct grp_info *exp_del_gids;
    } a_and_r_data[] = {
            {1, grp_list_1, 1, gid_list_2, EOK, 1, gid_list_2, 1, grp_list_1},
            {1, grp_list_1, 0, NULL, EOK, 0, NULL, 1, grp_list_1},
            {0, NULL, 1, gid_list_2, EOK, 1, gid_list_2, 0, NULL},
            {2, grp_list_12, 1, gid_list_2, EOK,  0, NULL, 1, grp_list_1},
            {2, grp_list_12, 2, gid_list_23, EOK, 1, gid_list_3, 1, grp_list_1},
            {0, NULL, 0, NULL, 0, 0, NULL, 0, NULL}
    };

    mem_ctx = talloc_new(NULL);
    fail_unless(mem_ctx != NULL, "talloc_new failed.");

    ret = diff_gid_lists(mem_ctx, 0, NULL, 0, NULL,
                         &add_gid_count, &add_gids,
                         &del_gid_count, &del_gids);
    fail_unless(ret == EOK, "get_gids_to_add_and_remove failed with empty " \
                            "groups.");

    ret = diff_gid_lists(mem_ctx, 1, NULL, 0, NULL,
                         &add_gid_count, &add_gids,
                         &del_gid_count, &del_gids);
    fail_unless(ret == EINVAL, "get_gids_to_add_and_remove failed with " \
                               "invalid current groups.");

    ret = diff_gid_lists(mem_ctx, 0, NULL, 1, NULL,
                         &add_gid_count, &add_gids,
                         &del_gid_count, &del_gids);
    fail_unless(ret == EINVAL, "get_gids_to_add_and_remove failed with " \
                               "invalid new groups.");

    for (c = 0; a_and_r_data[c].cur_gids != NULL ||
                a_and_r_data[c].gids != NULL; c++) {
        ret = diff_gid_lists(mem_ctx,
                             a_and_r_data[c].cur_gid_count,
                             a_and_r_data[c].cur_gids,
                             a_and_r_data[c].gid_count,
                             a_and_r_data[c].gids,
                             &add_gid_count, &add_gids,
                             &del_gid_count, &del_gids);
        fail_unless(ret == a_and_r_data[c].exp_ret,
                    "Unexpected return value for test data #%d, " \
                    "expected [%d], got [%d]",
                    c, a_and_r_data[c].exp_ret, ret);
        fail_unless(add_gid_count ==  a_and_r_data[c].exp_add_gid_count,
                    "Unexpected numer of groups to add for test data #%d, " \
                    "expected [%d], got [%d]",
                    c, a_and_r_data[c].exp_add_gid_count, add_gid_count);
        fail_unless(del_gid_count ==  a_and_r_data[c].exp_del_gid_count,
                    "Unexpected numer of groups to delete for test data #%d, " \
                    "expected [%d], got [%d]",
                    c, a_and_r_data[c].exp_del_gid_count, del_gid_count);

        /* The lists might be returned in any order, to make tests simple we
         * only look at lists with 1 element. TODO: add code to compare lists
         * with more than 1 member. */
        if (add_gid_count == 1) {
            fail_unless(add_gids[0] ==  a_and_r_data[c].exp_add_gids[0],
                        "Unexpected gid to add for test data #%d, " \
                        "expected [%d], got [%d]",
                        c, a_and_r_data[c].exp_add_gids[0], add_gids[0]);
        }

        if (del_gid_count == 1) {
            fail_unless(del_gids[0]->gid == a_and_r_data[c].exp_del_gids[0].gid,
                        "Unexpected gid to delete for test data #%d, " \
                        "expected [%d], got [%d]",
                        c, a_and_r_data[c].exp_del_gids[0].gid,
                        del_gids[0]->gid);
        }
    }

    talloc_free(mem_ctx);
}
END_TEST


Suite *idmap_test_suite (void)
{
    Suite *s = suite_create ("PAC responder");

    TCase *tc_pac = tcase_create("PAC responder tests");
    tcase_add_checked_fixture(tc_pac,
                              leak_check_setup,
                              leak_check_teardown);

    tcase_add_test(tc_pac, pac_test_local_sid_to_id);
    tcase_add_test(tc_pac, pac_test_seondary_local_sid_to_id);
    tcase_add_test(tc_pac, pac_test_get_gids_to_add_and_remove);

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
