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
#include "tools/tools_util.h"
#include "util/util.h"
#include "tests/common.h"

static char tpl_dir[] = "file-tests-dir-XXXXXX";
static char *dir_path;
static char *dst_path;
static uid_t uid;
static gid_t gid;
static TALLOC_CTX *test_ctx = NULL;

static void setup_files_test(void)
{
    /* create a temporary directory that we fill with stuff later on */
    test_ctx = talloc_new(NULL);
    dir_path = mkdtemp(talloc_strdup(test_ctx, tpl_dir));
    dst_path = mkdtemp(talloc_strdup(test_ctx, tpl_dir));

    uid = getuid();
    gid = getgid();
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
            DEBUG(1, ("Removing [%s] failed.\n", dir_path));
        }
    }
    if (dst_path && test_ctx) {
        cmd = talloc_asprintf(test_ctx, "/bin/rm -rf %s\n", dst_path);
        ret = system(cmd);
        if (ret == -1) {
            DEBUG(1, ("Removing [%s] failed.\n", dst_path));
        }
    }

    /* clean up */
    talloc_zfree(test_ctx);
}

static int create_simple_file(const char *name, const char *content)
{
    int fd;
    ssize_t size;
    int ret;

    fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    fail_if(fd == -1, "Cannot create simple file\n");

    size = write(fd, "abc", 3);
    fail_if(size == -1, "Cannot write to file\n");

    ret = fsync(fd);
    fail_if(ret == -1, "Cannot sync file\n");

    ret = close(fd);
    fail_if(ret == -1, "Cannot close file\n");

    return ret;
}

START_TEST(test_remove_tree)
{
    int ret;
    char origpath[PATH_MAX+1];

    errno = 0;
    fail_unless(getcwd(origpath, PATH_MAX) == origpath, "Cannot getcwd\n");
    fail_unless(errno == 0, "Cannot getcwd\n");

    DEBUG(5, ("About to delete %s\n", dir_path));

    /* create a file */
    ret = chdir(dir_path);
    fail_if(ret == -1, "Cannot chdir1\n");

    ret = create_simple_file("bar", "bar");
    fail_if(ret == -1, "Cannot create file1\n");

    /* create a subdir and file inside it */
    ret = mkdir("subdir", 0700);
    fail_if(ret == -1, "Cannot create subdir\n");

    ret = chdir("subdir");
    fail_if(ret == -1, "Cannot chdir\n");

    ret = create_simple_file("foo", "foo");
    fail_if(ret == -1, "Cannot create file\n");

    /* create another subdir, empty this time */
    ret = mkdir("subdir2", 0700);
    fail_if(ret == -1, "Cannot create subdir\n");

    ret = chdir(origpath);
    fail_if(ret == -1, "Cannot chdir2\n");

    /* go back */
    ret = chdir(origpath);
    fail_if(ret == -1, "Cannot chdir\n");

    /* and finally wipe it out.. */
    ret = remove_tree(dir_path);
    fail_unless(ret == EOK, "remove_tree failed\n");

    /* check if really gone */
    ret = access(dir_path, F_OK);
    fail_unless(ret == -1, "directory still there after remove_tree\n");
}
END_TEST

START_TEST(test_simple_copy)
{
    int ret;
    char origpath[PATH_MAX+1];
    char *tmp;
    int fd = -1;

    errno = 0;
    fail_unless(getcwd(origpath, PATH_MAX) == origpath, "Cannot getcwd\n");
    fail_unless(errno == 0, "Cannot getcwd\n");

    /* create a file */
    ret = chdir(dir_path);
    fail_if(ret == -1, "Cannot chdir1\n");

    ret = create_simple_file("bar", "bar");
    fail_if(ret == -1, "Cannot create file1\n");

    /* create a subdir and file inside it */
    ret = mkdir("subdir", 0700);
    fail_if(ret == -1, "Cannot create subdir\n");

    ret = chdir("subdir");
    fail_if(ret == -1, "Cannot chdir\n");

    ret = create_simple_file("foo", "foo");
    fail_if(ret == -1, "Cannot create file\n");

    /* go back */
    ret = chdir(origpath);
    fail_if(ret == -1, "Cannot chdir\n");

    /* and finally copy.. */
    DEBUG(5, ("Will copy from '%s' to '%s'\n", dir_path, dst_path));
    ret = copy_tree(dir_path, dst_path, 0700, uid, gid);
    fail_unless(ret == EOK, "copy_tree failed\n");

    /* check if really copied */
    ret = access(dst_path, F_OK);
    fail_unless(ret == 0, "destination directory not there\n");

    tmp = talloc_asprintf(test_ctx, "%s/bar", dst_path);
    ret = check_and_open_readonly(tmp, &fd, uid, gid, 0700, CHECK_REG);
    fail_unless(ret == EOK, "Cannot open %s\n");
    close(fd);
    talloc_free(tmp);
}
END_TEST

START_TEST(test_copy_symlink)
{
    int ret;
    char origpath[PATH_MAX+1];
    char *tmp;
    struct stat statbuf;

    errno = 0;
    fail_unless(getcwd(origpath, PATH_MAX) == origpath, "Cannot getcwd\n");
    fail_unless(errno == 0, "Cannot getcwd\n");

    /* create a subdir */
    ret = chdir(dir_path);
    fail_if(ret == -1, "Cannot chdir\n");

    ret = create_simple_file("footarget", "foo");
    fail_if(ret == -1, "Cannot create file\n");

    ret = symlink("footarget", "foolink");
    fail_if(ret == -1, "Cannot create symlink\n");

    /* go back */
    ret = chdir(origpath);
    fail_if(ret == -1, "Cannot chdir\n");

    /* and finally copy.. */
    DEBUG(5, ("Will copy from '%s' to '%s'\n", dir_path, dst_path));
    ret = copy_tree(dir_path, dst_path, 0700, uid, gid);
    fail_unless(ret == EOK, "copy_tree failed\n");

    /* check if really copied */
    ret = access(dst_path, F_OK);
    fail_unless(ret == 0, "destination directory not there\n");

    tmp = talloc_asprintf(test_ctx, "%s/foolink", dst_path);
    ret = lstat(tmp, &statbuf);
    fail_unless(ret == 0, "cannot stat the symlink %s\n", tmp);
    fail_unless(S_ISLNK(statbuf.st_mode), "%s not a symlink?\n", tmp);
    talloc_free(tmp);
}
END_TEST

START_TEST(test_copy_node)
{
    int ret;
    char origpath[PATH_MAX+1];
    char *tmp;
    struct stat statbuf;

    errno = 0;
    fail_unless(getcwd(origpath, PATH_MAX) == origpath, "Cannot getcwd\n");
    fail_unless(errno == 0, "Cannot getcwd\n");

    /* create a node */
    ret = chdir(dir_path);
    fail_if(ret == -1, "Cannot chdir\n");

    ret = mknod("testnode", S_IFIFO | S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH, 0);
    fail_unless(ret == 0, "cannot stat /dev/null: %s", strerror(errno));

    /* go back */
    ret = chdir(origpath);
    fail_if(ret == -1, "Cannot chdir\n");

    /* and finally copy.. */
    DEBUG(5, ("Will copy from '%s' to '%s'\n", dir_path, dst_path));
    ret = copy_tree(dir_path, dst_path, 0700, uid, gid);
    fail_unless(ret == EOK, "copy_tree failed\n");

    /* check if really copied */
    ret = access(dst_path, F_OK);
    fail_unless(ret == 0, "destination directory not there\n");

    tmp = talloc_asprintf(test_ctx, "%s/testnode", dst_path);
    ret = lstat(tmp, &statbuf);
    fail_unless(ret == 0, "cannot stat the node %s\n", tmp);
    fail_unless(S_ISFIFO(statbuf.st_mode), "%s not a char device??\n", tmp);
    talloc_free(tmp);
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
    tcase_add_test(tc_files, test_simple_copy);
    tcase_add_test(tc_files, test_copy_symlink);
    tcase_add_test(tc_files, test_copy_node);
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
        { "debug-level", 'd', POPT_ARG_INT, &debug, 0, "Set debug level", NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, (const char **) argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                poptBadOption(pc, 0), poptStrerror(opt));
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }
    poptFreeContext(pc);

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    tests_set_cwd();

    Suite *s = files_suite();
    SRunner *sr = srunner_create(s);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

