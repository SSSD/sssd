/*
    SSSD

    Utilities tests check_and_open

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

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <check.h>

#include "util/util.h"
#include "tests/common.h"

#define SUFFIX ".symlink"

#define FILENAME_TEMPLATE "check_and_open-tests-XXXXXX"
char *filename;
uid_t uid;
gid_t gid;
mode_t mode;

void setup_check(void)
{
    int ret;
    mode_t old_umask;

    filename = strdup(FILENAME_TEMPLATE);
    ck_assert_msg(filename != NULL, "strdup failed");

    old_umask = umask(SSS_DFL_UMASK);
    ret = mkstemp(filename);
    umask(old_umask);
    ck_assert_msg(ret != -1, "mkstemp failed [%d][%s]", errno, strerror(errno));
    /* It is not guaranteed that we end up with group owner == gid due to
     * possible setgid set on a parent dir. Also, on FreeBSD all directories
     * work as if setgid is set on them by default.
     */
    fchown(ret, -1, getgid());
    close(ret);

    uid = getuid();
    gid = getgid();
    mode = (S_IRUSR | S_IWUSR);
}

void teardown_check(void)
{
    int ret;

    ck_assert_msg(filename != NULL, "unknown filename");
    ret = unlink(filename);
    free(filename);
    ck_assert_msg(ret == 0, "unlink failed [%d][%s]", errno, strerror(errno));
}

START_TEST(test_wrong_filename)
{
    int ret;

    ret = check_file("/bla/bla/bla", uid, gid, S_IFREG|mode, 0, NULL, true);
    ck_assert_msg(ret == ENOENT,
                  "check_file() succeeded on non-existing file");
}
END_TEST

START_TEST(test_symlink)
{
    int ret;
    char *newpath;
    size_t newpath_length;

    newpath_length = strlen(filename) + strlen(SUFFIX) + 1;
    newpath = malloc((newpath_length) * sizeof(char));
    ck_assert_msg(newpath != NULL, "malloc failed");

    ret = snprintf(newpath, newpath_length, "%s%s", filename, SUFFIX);
    ck_assert_msg(ret == newpath_length - 1,
                "snprintf failed: expected [%zd] got [%d]", newpath_length - 1,
                                                           ret);

    ret = symlink(filename, newpath);
    ck_assert_msg(ret == 0, "symlink failed [%d][%s]", ret, strerror(errno));

    ret = check_file(newpath, uid, gid, S_IFREG|mode, 0, NULL, false);
    unlink(newpath);

    ck_assert_msg(ret == EINVAL,
                  "check_file() succeeded on symlink");
    free(newpath);
}
END_TEST

START_TEST(test_follow_symlink)
{
    int ret;
    char *newpath;
    size_t newpath_length;

    newpath_length = strlen(filename) + strlen(SUFFIX) + 1;
    newpath = malloc((newpath_length) * sizeof(char));
    ck_assert_msg(newpath != NULL, "malloc failed");

    ret = snprintf(newpath, newpath_length, "%s%s", filename, SUFFIX);
    ck_assert_msg(ret == newpath_length - 1,
                "snprintf failed: expected [%zd] got [%d]", newpath_length - 1,
                                                           ret);

    ret = symlink(filename, newpath);
    ck_assert_msg(ret == 0, "symlink failed [%d][%s]", ret, strerror(errno));

    ret = check_file(newpath, uid, gid, S_IFREG|mode, 0, NULL, true);
    unlink(newpath);

    ck_assert_msg(ret == EOK,
                 "check_file() failed on symlink with follow=true");
    free(newpath);
}
END_TEST

START_TEST(test_wrong_uid)
{
    int ret;

    ret = check_file(filename, uid+1, gid, S_IFREG|mode, 0, NULL, true);
    ck_assert_msg(ret == EINVAL,
                  "check_file() succeeded with wrong uid");
}
END_TEST

START_TEST(test_wrong_gid)
{
    int ret;

    ret = check_file(filename, uid, gid+1, S_IFREG|mode, 0, NULL, true);
    ck_assert_msg(ret == EINVAL,
                  "check_file() succeeded with wrong gid");
}
END_TEST

START_TEST(test_wrong_permission)
{
    int ret;

    ret = check_file(filename, uid, gid, S_IFREG|mode|S_IWOTH, 0, NULL, true);
    ck_assert_msg(ret == EINVAL,
                  "check_file() succeeded with wrong mode");
}
END_TEST

START_TEST(test_ok)
{
    int ret;

    ret = check_file(filename, uid, gid, S_IFREG|mode, 0, NULL, true);
    ck_assert_msg(ret == EOK,
                  "check_file() failed");
}
END_TEST

Suite *check_and_open_suite (void)
{
    Suite *s = suite_create ("check");

    TCase *tc_file_check = tcase_create ("file_check");
    tcase_add_checked_fixture (tc_file_check,
                               setup_check,
                               teardown_check);
    tcase_add_test (tc_file_check, test_wrong_filename);
    tcase_add_test (tc_file_check, test_symlink);
    tcase_add_test (tc_file_check, test_follow_symlink);
    tcase_add_test (tc_file_check, test_wrong_uid);
    tcase_add_test (tc_file_check, test_wrong_gid);
    tcase_add_test (tc_file_check, test_wrong_permission);
    tcase_add_test (tc_file_check, test_ok);
    suite_add_tcase (s, tc_file_check);

    return s;
}

int main(void)
{
  int number_failed;

  tests_set_cwd();

  Suite *s = check_and_open_suite ();
  SRunner *sr = srunner_create (s);
  /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
  srunner_run_all(sr, CK_ENV);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
