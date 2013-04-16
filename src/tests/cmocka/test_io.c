/*
    SSSD

    find_uid - Utilities tests

    Authors:
        Abhishek Singh <abhishekkumarsingh.cse@gmail.com>

    Copyright (C) 2013 Red Hat

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

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <dirent.h>
#include <unistd.h>
#include <libgen.h>

#include "limits.h"
#include "util/io.h"
#include "util/util.h"
#include "tests/common.h"

#define FILE_PATH TEST_DIR"/test_io.XXXXXX"
#define NON_EX_PATH "non-existent-path"

/* Creates a unique temporary file inside TEST_DIR and returns its path*/
static char *get_filepath(char path[])
{
    int ret;

    strncpy(path, FILE_PATH, PATH_MAX-1);
    ret = mkstemp(path);

    if (ret == -1) {
        int err = errno;
        fprintf(stderr, "mkstemp failed with path:'%s' [%s]\n",
                path, strerror(err));
    }
    assert_false(ret == -1);

    return path;
}

void setup_dirp(void **state)
{
    DIR *dirp = opendir(TEST_DIR);
    if (dirp == NULL) {
        int err = errno;
        fprintf(stderr, "Could not open directory:'%s' [%s]\n",
                TEST_DIR, strerror(err));
    }
    assert_non_null(dirp);
    *state = (void *)dirp;
}

void teardown_dirp(void **state)
{
    closedir((DIR *)*state);
}

void test_sss_open_cloexec_success(void **state)
{
    int fd;
    int ret;
    int ret_flag;
    int expec_flag;
    int flags = O_RDWR;
    char path[PATH_MAX] = {'\0'};

    fd = sss_open_cloexec(get_filepath(path), flags, &ret);
    assert_true(fd != -1);

    ret_flag = fcntl(fd, F_GETFD, 0);
    expec_flag = FD_CLOEXEC;
    assert_true(ret_flag & expec_flag);

    close(fd);
    unlink(path);
}

void test_sss_open_cloexec_fail(void **state)
{
    int fd;
    int ret;
    int flags = O_RDWR;

    fd = sss_open_cloexec(NON_EX_PATH, flags, &ret);

    assert_true(fd == -1);
    assert_int_not_equal(ret, 0);

    close(fd);
}

void test_sss_openat_cloexec_success(void **state)
{
    int fd;
    int ret;
    int ret_flag;
    int expec_flag;
    int dir_fd;
    int flags = O_RDWR;
    char path[PATH_MAX] = {'\0'};
    char *basec;
    const char *relativepath;

    dir_fd = dirfd((DIR *)*state);
    basec = strdup(get_filepath(path));
    assert_non_null(basec);
    relativepath = basename(basec);
    fd = sss_openat_cloexec(dir_fd, relativepath, flags, &ret);
    free(basec);
    assert_true(fd != -1);

    ret_flag = fcntl(fd, F_GETFD, 0);
    expec_flag = FD_CLOEXEC;
    assert_true(ret_flag & expec_flag);

    close(fd);
    unlink(path);
}

void test_sss_openat_cloexec_fail(void **state)
{
    int fd;
    int ret;
    int dir_fd;
    int flags = O_RDWR;

    dir_fd = dirfd((DIR *)*state);
    fd = sss_openat_cloexec(dir_fd, NON_EX_PATH, flags, &ret);

    assert_true(fd == -1);
    assert_int_not_equal(ret, 0);

    close(fd);
}

int main(void)
{
    const UnitTest tests[] = {
        unit_test(test_sss_open_cloexec_success),
        unit_test(test_sss_open_cloexec_fail),
        unit_test_setup_teardown(test_sss_openat_cloexec_success, setup_dirp,
                                 teardown_dirp),
        unit_test_setup_teardown(test_sss_openat_cloexec_fail, setup_dirp,
                                 teardown_dirp)
    };

    tests_set_cwd();
    return run_tests(tests);
}
