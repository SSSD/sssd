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
#include "shared/io.h"
#include "util/util.h"
#include "tests/common.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define FILE_TEMPLATE TESTS_PATH"/test_io.XXXXXX"
#define NON_EX_PATH TESTS_PATH"/non-existent-path"

/* Creates a unique temporary file inside TEST_DIR and returns its path*/
static char *get_random_filepath(const char *template)
{
    int ret;
    char *path;

    path = strdup(template);
    assert_non_null(path);

    ret = mkstemp(path);
    if (ret == -1) {
        int err = errno;
        fprintf(stderr, "mkstemp failed with path:'%s' [%s]\n",
                path, strerror(err));
    }
    assert_int_not_equal(ret, -1);

    /* We do not need this file descriptor */
    close(ret);

    return path;
}

static int test_file_setup(void **state)
{
    int ret;
    char *file_path;

    ret = mkdir(TESTS_PATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    assert_int_equal(ret, EOK);

    file_path = get_random_filepath(FILE_TEMPLATE);
    assert_non_null(file_path);

    ret = unlink(NON_EX_PATH);
    ret = errno;
    assert_int_equal(ret, ENOENT);

    *state = file_path;
    return 0;
}

static int test_file_teardown(void **state)
{
    int ret;
    char *file_path = (char *)*state;

    ret = unlink(file_path);
    assert_int_equal(ret, EOK);
    free(file_path);

    ret = rmdir(TESTS_PATH);
    assert_int_equal(ret, EOK);
    return 0;
}

struct dir_state {
    int dir_fd;
    char *basename;

    /* resources for cleanup*/
    DIR *dirp;
    char *filename;
};

static int test_dir_setup(void **state)
{
    struct dir_state *data;
    int ret;

    data = (struct dir_state *)calloc(1, sizeof(struct dir_state));
    assert_non_null(data);

    ret = mkdir(TESTS_PATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    assert_int_equal(ret, EOK);

    data->dirp = opendir(TESTS_PATH);
    if (data->dirp == NULL) {
        int err = errno;
        fprintf(stderr, "Could not open directory:'%s' [%s]\n",
                TESTS_PATH, strerror(err));
    }
    assert_non_null(data->dirp);

    data->dir_fd = dirfd(data->dirp);
    assert_int_not_equal(data->dir_fd, -1);

    data->filename = get_random_filepath(FILE_TEMPLATE);
    assert_non_null(data->filename);

    data->basename = basename(data->filename);

    ret = unlink(NON_EX_PATH);
    ret = errno;
    assert_int_equal(ret, ENOENT);

    *state = data;
    return 0;
}

static int test_dir_teardown(void **state)
{
    int ret;
    struct dir_state *data = (struct dir_state *) *state;

    ret = unlink(data->filename);
    assert_int_equal(ret, EOK);
    free(data->filename);

    ret = closedir(data->dirp);
    assert_int_equal(ret, EOK);

    ret = rmdir(TESTS_PATH);
    assert_int_equal(ret, EOK);

    free(data);
    return 0;
}

void test_sss_open_cloexec_success(void **state)
{
    int fd;
    int ret;
    int ret_flag;
    int expec_flag;
    int flags = O_RDWR;
    char *file_path = (char *) *state;

    fd = sss_open_cloexec(file_path, flags, &ret);
    assert_int_not_equal(fd, -1);

    ret_flag = fcntl(fd, F_GETFD, 0);
    expec_flag = FD_CLOEXEC;
    assert_true(ret_flag & expec_flag);

    close(fd);
}

void test_sss_open_cloexec_fail(void **state)
{
    int fd;
    int ret;
    int flags = O_RDWR;

    fd = sss_open_cloexec(NON_EX_PATH, flags, &ret);

    assert_true(fd == -1);
    assert_int_not_equal(ret, 0);
}

void test_sss_openat_cloexec_success(void **state)
{
    int fd;
    int ret;
    int ret_flag;
    int expec_flag;
    const int flags = O_RDWR;
    struct dir_state *data = (struct dir_state *) *state;

    fd = sss_openat_cloexec(data->dir_fd, data->basename, flags, &ret);
    assert_int_not_equal(fd, -1);

    ret_flag = fcntl(fd, F_GETFD, 0);
    expec_flag = FD_CLOEXEC;
    assert_true(ret_flag & expec_flag);

    close(fd);
}

void test_sss_openat_cloexec_fail(void **state)
{
    int fd;
    int ret;
    int flags = O_RDWR;
    struct dir_state *data = (struct dir_state *) *state;

    fd = sss_openat_cloexec(data->dir_fd, NON_EX_PATH, flags, &ret);
    assert_int_equal(fd, -1);
    assert_int_equal(ret, ENOENT);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sss_open_cloexec_success,
                                        test_file_setup, test_file_teardown),
        cmocka_unit_test_setup_teardown(test_sss_open_cloexec_fail,
                                        test_file_setup, test_file_teardown),
        cmocka_unit_test_setup_teardown(test_sss_openat_cloexec_success,
                                        test_dir_setup, test_dir_teardown),
        cmocka_unit_test_setup_teardown(test_sss_openat_cloexec_fail,
                                        test_dir_setup, test_dir_teardown)
    };

    tests_set_cwd();
    return cmocka_run_group_tests(tests, NULL, NULL);
}
