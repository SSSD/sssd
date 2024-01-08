/*
 * Authors:
 *   Jakub Hrozek <jhrozek@redhat.com>
 *
 * Copyright (C) 2008  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 3 or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdlib.h>
#include <check.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <talloc.h>
#include <popt.h>

#include "config.h"
#include "util/util.h"
#include "tests/common_check.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM

static char tpl_dir[] = "file-tests-dir-XXXXXX";
static char *dir_path;
static char *dst_path;
static TALLOC_CTX *test_ctx = NULL;

static void setup_files_test(void)
{
    /* create a temporary directory that we fill with stuff later on */
    test_ctx = talloc_new(NULL);
    mkdir(TESTS_PATH, 0700);
    dir_path = mkdtemp(talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, tpl_dir));
    dst_path = mkdtemp(talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, tpl_dir));
}

static void teardown_files_test(void)
{
    char *cmd = NULL;
    int ret;

    /* OK this is crude but since the functions to remove tree are under test.. */
    if (dir_path && test_ctx) {
        cmd = talloc_asprintf(test_ctx, "/bin/rm -rf %s\n", dir_path);
        ret = system(cmd);
        if (ret == -1) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Removing [%s] failed.\n", dir_path);
        }
    }
    if (dst_path && test_ctx) {
        cmd = talloc_asprintf(test_ctx, "/bin/rm -rf %s\n", dst_path);
        ret = system(cmd);
        if (ret == -1) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Removing [%s] failed.\n", dst_path);
        }
    }

    rmdir(TESTS_PATH);
    /* clean up */
    talloc_zfree(test_ctx);
}

static int create_simple_file(const char *name, const char *content)
{
    int fd;
    ssize_t size;
    int ret;

    fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    sss_ck_fail_if_msg(fd == -1, "Cannot create simple file\n");

    size = write(fd, "abc", 3);
    sss_ck_fail_if_msg(size == -1, "Cannot write to file\n");

    ret = fsync(fd);
    sss_ck_fail_if_msg(ret == -1, "Cannot sync file\n");

    ret = close(fd);
    sss_ck_fail_if_msg(ret == -1, "Cannot close file\n");

    return ret;
}

START_TEST(test_remove_tree)
{
    int ret;
    char origpath[PATH_MAX+1];

    errno = 0;
    ck_assert_msg(getcwd(origpath, PATH_MAX) == origpath, "Cannot getcwd\n");
    ck_assert_msg(errno == 0, "Cannot getcwd\n");

    DEBUG(SSSDBG_FUNC_DATA, "About to delete %s\n", dir_path);

    /* create a file */
    ret = chdir(dir_path);
    sss_ck_fail_if_msg(ret == -1, "Cannot chdir1\n");

    ret = create_simple_file("bar", "bar");
    sss_ck_fail_if_msg(ret == -1, "Cannot create file1\n");

    /* create a subdir and file inside it */
    ret = mkdir("subdir", 0700);
    sss_ck_fail_if_msg(ret == -1, "Cannot create subdir\n");

    ret = chdir("subdir");
    sss_ck_fail_if_msg(ret == -1, "Cannot chdir\n");

    ret = create_simple_file("foo", "foo");
    sss_ck_fail_if_msg(ret == -1, "Cannot create file\n");

    /* create another subdir, empty this time */
    ret = mkdir("subdir2", 0700);
    sss_ck_fail_if_msg(ret == -1, "Cannot create subdir\n");

    ret = chdir(origpath);
    sss_ck_fail_if_msg(ret == -1, "Cannot chdir2\n");

    /* go back */
    ret = chdir(origpath);
    sss_ck_fail_if_msg(ret == -1, "Cannot chdir\n");

    /* and finally wipe it out.. */
    ret = sss_remove_tree(dir_path);
    ck_assert_msg(ret == EOK, "remove_tree failed\n");

    /* check if really gone */
    ret = access(dir_path, F_OK);
    ck_assert_msg(ret == -1, "directory still there after remove_tree\n");
}
END_TEST

START_TEST(test_remove_subtree)
{
    int ret;
    char origpath[PATH_MAX+1];

    errno = 0;
    ck_assert_msg(getcwd(origpath, PATH_MAX) == origpath, "Cannot getcwd\n");
    ck_assert_msg(errno == 0, "Cannot getcwd\n");

    DEBUG(SSSDBG_FUNC_DATA, "About to delete %s\n", dir_path);

    /* create a file */
    ret = chdir(dir_path);
    sss_ck_fail_if_msg(ret == -1, "Cannot chdir1\n");

    ret = create_simple_file("bar", "bar");
    sss_ck_fail_if_msg(ret == -1, "Cannot create file1\n");

    /* create a subdir and file inside it */
    ret = mkdir("subdir", 0700);
    sss_ck_fail_if_msg(ret == -1, "Cannot create subdir\n");

    ret = chdir("subdir");
    sss_ck_fail_if_msg(ret == -1, "Cannot chdir\n");

    ret = create_simple_file("foo", "foo");
    sss_ck_fail_if_msg(ret == -1, "Cannot create file\n");

    /* create another subdir, empty this time */
    ret = mkdir("subdir2", 0700);
    sss_ck_fail_if_msg(ret == -1, "Cannot create subdir\n");

    ret = chdir(origpath);
    sss_ck_fail_if_msg(ret == -1, "Cannot chdir2\n");

    /* go back */
    ret = chdir(origpath);
    sss_ck_fail_if_msg(ret == -1, "Cannot chdir\n");

    /* and finally wipe it out.. */
    ret = sss_remove_subtree(dir_path);
    ck_assert_msg(ret == EOK, "remove_subtree failed\n");

    /* check if really gone */
    ret = access(dir_path, F_OK);
    ck_assert_msg(ret == 0, "directory was deleted\n");

    ret = rmdir(dir_path);
    ck_assert_msg(ret == 0, "unable to delete root directory\n");
}
END_TEST

START_TEST(test_create_dir)
{
    int ret;
    char origpath[PATH_MAX+1];
    char *new_dir;
    struct stat info;

    errno = 0;

    ck_assert_msg(getcwd(origpath, PATH_MAX) == origpath, "Cannot getcwd\n");
    ck_assert_msg(errno == 0, "Cannot getcwd\n");

    /* create a dir */
    ret = sss_create_dir(dir_path, "testdir", S_IRUSR | S_IXUSR);
    ck_assert_msg(ret == EOK, "cannot create dir: %s", strerror(ret));

    new_dir = talloc_asprintf(NULL, "%s/testdir", dir_path);
    ret = stat(new_dir, &info);
    ck_assert_msg(ret == EOK, "failed to stat '%s'\n", new_dir);

    /* check the dir has been created */
    ck_assert_msg(S_ISDIR(info.st_mode) != 0, "'%s' is not a dir.\n", new_dir);

    /* check the permissions are okay */
    ck_assert_msg((info.st_mode & S_IRUSR) != 0, "Read permission is not set\n");
    ck_assert_msg((info.st_mode & S_IWUSR) == 0, "Write permission is set\n");
    ck_assert_msg((info.st_mode & S_IXUSR) != 0, "Exec permission is not set\n");

    talloc_free(new_dir);
}
END_TEST

static Suite *files_suite(void)
{
    Suite *s = suite_create("files_suite");

    TCase *tc_files = tcase_create("files");
    tcase_add_checked_fixture(tc_files,
                              setup_files_test,
                              teardown_files_test);

    tcase_add_test(tc_files, test_remove_tree);
    tcase_add_test(tc_files, test_remove_subtree);
    tcase_add_test(tc_files, test_create_dir);
    suite_add_tcase(s, tc_files);

    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;
    int opt;
    poptContext pc;
    int debug = 0;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, (const char **) argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                poptBadOption(pc, 0), poptStrerror(opt));
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug);

    tests_set_cwd();

    Suite *s = files_suite();
    SRunner *sr = srunner_create(s);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

