/*
    SSSD

    find_uid - Utilities tests

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <unistd.h>
#include <sys/types.h>

#include <check.h>

#include "util/find_uid.h"
#include "tests/common.h"


START_TEST(test_check_if_uid_is_active_success)
{
    uid_t uid;
    bool result;
    int ret;

    uid = getuid();

    ret = check_if_uid_is_active(uid, &result);
    ck_assert_msg(ret == EOK, "check_if_uid_is_active failed.");
    ck_assert_msg(result, "check_if_uid_is_active did not found my uid [%d]",
                uid);
}
END_TEST

START_TEST(test_check_if_uid_is_active_fail)
{
    uid_t uid;
    bool result;
    int ret;

    uid = (uid_t) -4;

    ret = check_if_uid_is_active(uid, &result);
    ck_assert_msg(ret == EOK, "check_if_uid_is_active failed.");
    ck_assert_msg(!result, "check_if_uid_is_active found (hopefully not active) "
                         "uid [%d]", uid);
}
END_TEST

START_TEST(test_get_uid_table)
{
    uid_t uid;
    int ret;
    TALLOC_CTX *tmp_ctx;
    hash_table_t *table;
    hash_key_t key;
    hash_value_t value;

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "talloc_new failed.");

    ret = get_uid_table(tmp_ctx, &table);
    ck_assert_msg(ret == EOK, "get_uid_table failed.");

    uid = getuid();
    key.type = HASH_KEY_ULONG;
    key.ul = (unsigned long) uid;

    ret = hash_lookup(table, &key, &value);

    ck_assert_msg(ret == HASH_SUCCESS, "Cannot find my uid [%d] in the table", uid);

    uid = (uid_t) -4;
    key.type = HASH_KEY_ULONG;
    key.ul = (unsigned long) uid;

    ret = hash_lookup(table, &key, &value);

    ck_assert_msg(ret == HASH_ERROR_KEY_NOT_FOUND, "Found (hopefully not active) "
                                                 "uid [%d] in the table", uid);

    talloc_free(tmp_ctx);
}
END_TEST

Suite *find_uid_suite (void)
{
    Suite *s = suite_create ("find_uid");

    TCase *tc_find_uid = tcase_create ("find_uid");

    tcase_add_test (tc_find_uid, test_check_if_uid_is_active_success);
    tcase_add_test (tc_find_uid, test_check_if_uid_is_active_fail);
    tcase_add_test (tc_find_uid, test_get_uid_table);
    suite_add_tcase (s, tc_find_uid);

    return s;
}

int main(void)
{
    debug_level = SSSDBG_MASK_ALL;
    int number_failed;

    tests_set_cwd();

    Suite *s = find_uid_suite ();
    SRunner *sr = srunner_create (s);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
