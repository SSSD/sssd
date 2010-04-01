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

#include <stdlib.h>
#include <check.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "util/util.h"
#include "tests/common.h"

#define SUFFIX ".symlink"

#define FILENAME_TEMPLATE "check_and_open-tests-XXXXXX"
char *filename;
uid_t uid;
gid_t gid;
mode_t mode;
int fd;

void setup_check_and_open(void)
{
    int ret;

    filename = strdup(FILENAME_TEMPLATE);
    fail_unless(filename != NULL, "strdup failed");
    ret = mkstemp(filename);
    fail_unless(ret != -1, "mkstemp failed [%d][%s]", errno, strerror(errno));
    close(ret);

    uid = getuid();
    gid = getgid();
    mode = (S_IRUSR | S_IWUSR);
    fd = -1;
}

void teardown_check_and_open(void)
{
    int ret;

    if (fd != -1) {
        ret = close(fd);
        fail_unless(ret == 0, "close failed [%d][%s]", errno, strerror(errno));
    }

    fail_unless(filename != NULL, "unknown filename");
    ret = unlink(filename);
    free(filename);
    fail_unless(ret == 0, "unlink failed [%d][%s]", errno, strerror(errno));
}

START_TEST(test_wrong_filename)
{
    int ret;

    ret = check_and_open_readonly("/bla/bla/bla", &fd, uid, gid, mode, CHECK_REG);
    fail_unless(ret == ENOENT,
                "check_and_open_readonly succeeded on non-existing file");
    fail_unless(fd == -1, "check_and_open_readonly file descriptor not -1");
}
END_TEST

START_TEST(test_symlink)
{
    int ret;
    char *newpath;
    size_t newpath_length;

    newpath_length = strlen(filename) + strlen(SUFFIX) + 1;
    newpath = malloc((newpath_length) * sizeof(char));
    fail_unless(newpath != NULL, "malloc failed");

    ret = snprintf(newpath, newpath_length, "%s%s", filename, SUFFIX);
    fail_unless(ret == newpath_length - 1,
                "snprintf failed: expected [%d] got [%d]", newpath_length -1,
                                                           ret);

    ret = symlink(filename, newpath);
    fail_unless(ret == 0, "symlink failed [%d][%s]", ret, strerror(ret));

    ret = check_file(newpath, uid, gid, mode, CHECK_REG, NULL);
    unlink(newpath);

    fail_unless(ret == EINVAL,
                "check_and_open_readonly succeeded on symlink");
}
END_TEST

START_TEST(test_not_regular_file)
{
    int ret;

    ret = check_and_open_readonly("/dev/null", &fd, uid, gid, mode, CHECK_REG);
    fail_unless(ret == EINVAL,
                "check_and_open_readonly succeeded on non-regular file");
    fail_unless(fd == -1, "check_and_open_readonly file descriptor not -1");
}
END_TEST

START_TEST(test_wrong_uid)
{
    int ret;

    ret = check_and_open_readonly(filename, &fd, uid+1, gid, mode, CHECK_REG);
    fail_unless(ret == EINVAL,
                "check_and_open_readonly succeeded with wrong uid");
    fail_unless(fd == -1, "check_and_open_readonly file descriptor not -1");
}
END_TEST

START_TEST(test_wrong_gid)
{
    int ret;

    ret = check_and_open_readonly(filename, &fd, uid, gid+1, mode, CHECK_REG);
    fail_unless(ret == EINVAL,
                "check_and_open_readonly succeeded with wrong gid");
    fail_unless(fd == -1, "check_and_open_readonly file descriptor not -1");
}
END_TEST

START_TEST(test_wrong_permission)
{
    int ret;

    ret = check_and_open_readonly(filename, &fd, uid, gid, (mode|S_IWOTH),
                                  CHECK_REG);
    fail_unless(ret == EINVAL,
                "check_and_open_readonly succeeded with wrong mode");
    fail_unless(fd == -1, "check_and_open_readonly file descriptor not -1");
}
END_TEST

START_TEST(test_ok)
{
    int ret;

    ret = check_and_open_readonly(filename, &fd, uid, gid, mode, CHECK_REG);
    fail_unless(ret == EOK,
                "check_and_open_readonly failed");
    fail_unless(fd >= 0,
                "check_and_open_readonly returned illegal file descriptor");
}
END_TEST

START_TEST(test_write)
{
    int ret;
    ssize_t size;
    errno_t my_errno;

    ret = check_and_open_readonly(filename, &fd, uid, gid, mode, CHECK_REG);
    fail_unless(ret == EOK,
                "check_and_open_readonly failed");
    fail_unless(fd >= 0,
                "check_and_open_readonly returned illegal file descriptor");

    size = write(fd, "abc", 3);
    my_errno = errno;
    fail_unless(size == -1, "check_and_open_readonly file is not readonly");
    fail_unless(my_errno == EBADF,
                "write failed for other reason than readonly");
}
END_TEST

Suite *check_and_open_suite (void)
{
    Suite *s = suite_create ("check_and_open");

    TCase *tc_check_and_open_readonly = tcase_create ("check_and_open_readonly");
    tcase_add_checked_fixture (tc_check_and_open_readonly,
                               setup_check_and_open,
                               teardown_check_and_open);
    tcase_add_test (tc_check_and_open_readonly, test_wrong_filename);
    tcase_add_test (tc_check_and_open_readonly, test_not_regular_file);
    tcase_add_test (tc_check_and_open_readonly, test_symlink);
    tcase_add_test (tc_check_and_open_readonly, test_wrong_uid);
    tcase_add_test (tc_check_and_open_readonly, test_wrong_gid);
    tcase_add_test (tc_check_and_open_readonly, test_wrong_permission);
    tcase_add_test (tc_check_and_open_readonly, test_ok);
    tcase_add_test (tc_check_and_open_readonly, test_write);
    suite_add_tcase (s, tc_check_and_open_readonly);

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

