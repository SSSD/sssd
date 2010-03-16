/*
   path_utils - unit tests

   Authors:
       Jakub Hrozek <jhrozek@redhat.com>

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

#define _GNU_SOURCE /* asprintf */

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "path_utils.h"

#define fail_unless_str_equal(a, b) do { \
    fail_unless(strcmp(a, b) == 0, \
                "The strings '%s' and '%s' are different, expected same", \
                a, b); \
} while(0);

#define DIR_TEMPLATE        "test-directory-list-dir-XXXXXX"
#define SUBDIR              "test-directory-list-subdir"
#define SUBSUBDIR           "test-directory-list-subsubdir"
char *dlist_dir;
char *dlist_subdir;
char *dlist_subsubdir;

/**** get_dirname ****/
START_TEST(test_dirname)
{
    char p[PATH_MAX];
    char cwd[PATH_MAX];

    fail_unless(get_dirname(p, PATH_MAX, "/foo/bar") == SUCCESS);
    fail_unless_str_equal(p, "/foo");

    fail_unless(get_dirname(p, PATH_MAX, "/") == SUCCESS);
    fail_unless_str_equal(p, "/");

    fail_unless(get_dirname(p, PATH_MAX, "/foo") == SUCCESS);
    fail_unless_str_equal(p, "/");

    fail_unless(get_dirname(p, PATH_MAX, "//foo//bar") == SUCCESS);
    fail_unless_str_equal(p, "//foo");

    fail_unless(get_dirname(p, PATH_MAX, "//foo//") == SUCCESS);
    fail_unless_str_equal(p, "//");

    fail_unless(get_dirname(p, PATH_MAX, "foo//bar") == SUCCESS);
    fail_unless_str_equal(p, "foo");

    fail_unless(get_dirname(p, PATH_MAX, "foo//////bar") == SUCCESS);
    fail_unless_str_equal(p, "foo");

    /* if pathname does not contain a slash, dirname returns cwd */
    fail_if(getcwd(cwd, PATH_MAX) == NULL, "getcwd failed");

    fail_unless(get_dirname(p, PATH_MAX, "foo") == SUCCESS);
    fail_unless_str_equal(p, cwd);

    fail_unless(get_dirname(p, PATH_MAX, ".") == SUCCESS);
    fail_unless_str_equal(p, cwd);

    fail_unless(get_dirname(p, PATH_MAX, "..") == SUCCESS);
    fail_unless_str_equal(p, cwd);

    fail_unless(get_dirname(p, PATH_MAX, "") == SUCCESS);
    fail_unless_str_equal(p, cwd);
}
END_TEST

START_TEST(test_dirname_neg)
{
    char neg[3];
    char p[PATH_MAX];

    fail_if(get_dirname(neg, 3, "/foo/bar") == SUCCESS);
    fail_unless(get_dirname(p, PATH_MAX, NULL) == EINVAL);
}
END_TEST

/**** get_basename ****/
START_TEST(test_basename)
{
    char p[PATH_MAX];
    char cwd[PATH_MAX];

    fail_unless(get_basename(p, PATH_MAX, "/foo/bar") == SUCCESS);
    fail_unless_str_equal(p, "bar");

    fail_unless(get_basename(p, PATH_MAX, "/foo/") == SUCCESS);
    fail_unless_str_equal(p, "foo");

    fail_unless(get_basename(p, PATH_MAX, "foo") == SUCCESS);
    fail_unless_str_equal(p, "foo");

    fail_unless(get_basename(p, PATH_MAX, "/") == SUCCESS);
    fail_unless_str_equal(p, "/");

    fail_if(getcwd(cwd, PATH_MAX) == NULL, "getcwd failed");

    fail_unless(get_basename(p, PATH_MAX, ".") == SUCCESS);
    fail_unless_str_equal(p, cwd);

    fail_unless(get_basename(p, PATH_MAX, "") == SUCCESS);
    fail_unless_str_equal(p, cwd);
}
END_TEST

START_TEST(test_basename_neg)
{
    char neg[3];
    char p[PATH_MAX];

    fail_if(get_basename(neg, 3, "/foo/bar") == SUCCESS);

    fail_unless(get_basename(p, PATH_MAX, NULL) == EINVAL);
}
END_TEST

/**** is_absolute_path ****/
START_TEST(test_is_absolute_path)
{
    fail_unless(is_absolute_path("") == false);
    fail_unless(is_absolute_path("foo/bar") == false);

    fail_unless(is_absolute_path("/foo/bar") == true);
    fail_unless(is_absolute_path("/foo") == true);
    fail_unless(is_absolute_path("/") == true);
}
END_TEST

/**** get_dirname_and_basename ****/
/* Just a couple of basic tests - get_dirname_and_basename()
 * uses get_dirname() and get_basename() under the hood which
 * are tested enough in their specific tests
 */
START_TEST(test_dirname_and_basename)
{
    char dir[PATH_MAX];
    char base[PATH_MAX];
    char cwd[PATH_MAX];
    int ret;

    ret = get_directory_and_base_name(dir, PATH_MAX, base, PATH_MAX, "/foo/bar");
    fail_unless(ret == SUCCESS);
    fail_unless_str_equal(dir, "/foo");
    fail_unless_str_equal(base, "bar");

    ret = get_directory_and_base_name(dir, PATH_MAX, base, PATH_MAX, "/foo");
    fail_unless(ret == SUCCESS);
    fail_unless_str_equal(dir, "/");
    fail_unless_str_equal(base, "foo");

    ret = get_directory_and_base_name(dir, PATH_MAX, base, PATH_MAX, "/");
    fail_unless(ret == SUCCESS);
    fail_unless_str_equal(dir, "/");
    fail_unless_str_equal(base, "/");

    fail_if(getcwd(cwd, PATH_MAX) == NULL, "getcwd failed");

    ret = get_directory_and_base_name(dir, PATH_MAX, base, PATH_MAX, "foo");
    fail_unless(ret == SUCCESS);
    fail_unless_str_equal(dir, cwd);
    fail_unless_str_equal(base, "foo");

    ret = get_directory_and_base_name(dir, PATH_MAX, base, PATH_MAX, "");
    fail_unless(ret == SUCCESS);
    fail_unless_str_equal(dir, cwd);
    fail_unless_str_equal(base, "");

    ret = get_directory_and_base_name(dir, PATH_MAX, base, PATH_MAX, ".");
    fail_unless(ret == SUCCESS);
    fail_unless_str_equal(dir, cwd);
    fail_unless_str_equal(base, "");
}
END_TEST

START_TEST(test_dirname_and_basename_neg)
{
    char dir[PATH_MAX];
    char base[PATH_MAX];
    int ret;

    ret = get_directory_and_base_name(dir, PATH_MAX, base, PATH_MAX, NULL);
    fail_unless(ret == EINVAL);
}
END_TEST

/**** path_concat ****/
START_TEST(test_path_concat)
{
    char p[PATH_MAX];
    char p2[9];

    fail_unless(path_concat(p, PATH_MAX, "/foo", "bar") == SUCCESS);
    fail_unless_str_equal(p, "/foo/bar");

    fail_unless(path_concat(p, PATH_MAX, "/foo", "/bar") == SUCCESS);
    fail_unless_str_equal(p, "/foo/bar");

    fail_unless(path_concat(p, PATH_MAX, "/foo/", "/bar") == SUCCESS);
    fail_unless_str_equal(p, "/foo/bar");

    fail_unless(path_concat(p, PATH_MAX, "/foo", "") == SUCCESS);
    fail_unless_str_equal(p, "/foo");

    fail_unless(path_concat(p, PATH_MAX, "foo", NULL) == SUCCESS);
    fail_unless_str_equal(p, "foo");

    fail_unless(path_concat(p, PATH_MAX, "", "foo") == SUCCESS);
    fail_unless_str_equal(p, "foo");

    fail_unless(path_concat(p, PATH_MAX, NULL, "foo") == SUCCESS);
    fail_unless_str_equal(p, "foo");

    /* on-by-one */
    fail_unless(path_concat(p2, 9, "/foo", "bar") == SUCCESS);
    fail_unless_str_equal(p2, "/foo/bar");
}
END_TEST

START_TEST(test_path_concat_neg)
{
    char small[3];
    char small2[4];
    char p2[8];

    /* these two test different conditions */
    fail_unless(path_concat(small, 3, "/foo", "bar") == ENOBUFS);
    fail_unless(path_concat(small2, 4, "/foo", "bar") == ENOBUFS);

    /* off-by-one */
    fail_unless(path_concat(p2, 8, "/foo", "bar") == ENOBUFS);
    fail_unless_str_equal(p2, "/foo/bar");
}
END_TEST

/**** make_path_absolute ****/
START_TEST(test_make_path_absolute)
{
    char p[PATH_MAX];
    char p2[PATH_MAX];
    char cwd[PATH_MAX];
    char *buf;
    size_t buf_len;

    fail_unless(make_path_absolute(p, PATH_MAX, "/foo") == SUCCESS);
    fail_unless_str_equal(p, "/foo");

    fail_if(getcwd(cwd, PATH_MAX) == NULL, "getcwd failed");

    fail_unless(make_path_absolute(p, PATH_MAX, "foo") == SUCCESS);
    snprintf(p2, PATH_MAX, "%s/foo", cwd);
    fail_unless_str_equal(p, p2);

    fail_unless(make_path_absolute(p, PATH_MAX, "") == SUCCESS);
    fail_unless_str_equal(p, cwd);

    /* on-by-one; 2 = terminating null + path delimeter */
    buf_len = strlen(cwd) + strlen("foo") + 2;
    buf = malloc(buf_len);
    fail_if(buf == NULL);
    fail_unless(make_path_absolute(buf, buf_len, "foo") == SUCCESS);
    free(buf);
}
END_TEST

START_TEST(test_make_path_absolute_neg)
{
    char small[1];
    char cwd[PATH_MAX];
    char *small2;
    int small_len;

    fail_unless(make_path_absolute(small, 1, "/foo") == ENOBUFS);
    fail_unless(make_path_absolute(NULL, 1, "/foo") == ENOBUFS);

    /* off-by-one */
    fail_if(getcwd(cwd, PATH_MAX) == NULL, "getcwd failed");
    small_len = strlen(cwd) + strlen("foo") + 1;
    small2 = malloc(small_len);
    fail_if(small2 == NULL);
    fail_unless(make_path_absolute(small2, small_len, "foo") == ENOBUFS);
    free(small2);

    /* just enough space for cwd */
    small_len = strlen(cwd) + 1;
    small2 = malloc(small_len);
    fail_if(small2 == NULL);
    fail_unless(make_path_absolute(small2, small_len, "foo") == ENOBUFS);
    free(small2);
}
END_TEST

/**** make_normalized_absolute_path ****/
START_TEST(test_make_normalized_absolute_path)
{
    char p[PATH_MAX];
    char p2[PATH_MAX];
    char cwd[PATH_MAX];

    fail_if(getcwd(cwd, PATH_MAX) == NULL, "getcwd failed");

    fail_unless(make_normalized_absolute_path(p, PATH_MAX, "foo/baz/../bar") == SUCCESS);
    snprintf(p2, PATH_MAX, "%s/foo/bar", cwd);
    fail_unless_str_equal(p, p2);

    fail_unless(make_normalized_absolute_path(p, PATH_MAX, "/foo/../bar") == SUCCESS);
    fail_unless_str_equal(p, "/bar");

    fail_unless(make_normalized_absolute_path(p, PATH_MAX, "/foo/../baz/../bar") == SUCCESS);
    fail_unless_str_equal(p, "/bar");
}
END_TEST

START_TEST(test_make_normalized_absolute_path_neg)
{
    char small[1];

    fail_unless(make_path_absolute(small, 1, "/foo") == ENOBUFS);
    fail_unless(make_path_absolute(NULL, 1, "/foo") == ENOBUFS);
}
END_TEST

/**** split_path ****/
START_TEST(test_split_path)
{
    char **array;
    int n;

    array = split_path("/foo/bar", &n);
    fail_if(array == NULL);
    fail_unless(n == 3);
    fail_unless_str_equal(array[0], "/");
    fail_unless_str_equal(array[1], "foo");
    fail_unless_str_equal(array[2], "bar");
    free(array);

    array = split_path("/foo/../bar", &n);
    fail_if(array == NULL);
    fail_unless(n == 4);
    fail_unless_str_equal(array[0], "/");
    fail_unless_str_equal(array[1], "foo");
    fail_unless_str_equal(array[2], "..");
    fail_unless_str_equal(array[3], "bar");
    free(array);

    array = split_path("/foo/bar", NULL);
    fail_if(array == NULL);
    fail_unless_str_equal(array[0], "/");
    fail_unless_str_equal(array[1], "foo");
    fail_unless_str_equal(array[2], "bar");
    free(array);

    array = split_path("foo/bar", &n);
    fail_if(array == NULL);
    fail_unless(n == 2);
    fail_unless_str_equal(array[0], "foo");
    fail_unless_str_equal(array[1], "bar");
    free(array);

    array = split_path(".", &n);
    fail_if(array == NULL);
    fail_unless(n == 1);
    fail_unless_str_equal(array[0], ".");
    free(array);

    array = split_path("foo", &n);
    fail_if(array == NULL);
    fail_unless(n == 1);
    fail_unless_str_equal(array[0], "foo");
    free(array);

    /* one might expect { "" } or outright NULL, but we agreed not to
     * do changes beyond bugfixes at this point */
    array = split_path("", &n);
    fail_if(array == NULL);
    fail_unless(n == 0);
    fail_unless(array[0] == NULL);
    free(array);
}
END_TEST

START_TEST(test_split_path_neg)
{
    char **array;
    int n;

    array = split_path(NULL, &n);
    fail_unless(array == NULL);

    array = split_path(NULL, NULL);
    fail_unless(array == NULL);
}
END_TEST

/**** normalize_path ****/
START_TEST(test_normalize_path)
{
    char norm[PATH_MAX];
    char small[8];

    fail_unless(normalize_path(norm, PATH_MAX, "/foo/../bar") == SUCCESS);
    fail_unless_str_equal(norm, "/bar");

    fail_unless(normalize_path(norm, PATH_MAX, "/foo/../baz/../bar") == SUCCESS);
    fail_unless_str_equal(norm, "/bar");

    fail_unless(normalize_path(norm, PATH_MAX, "foo/baz/../bar") == SUCCESS);
    fail_unless_str_equal(norm, "foo/bar");

    fail_unless(normalize_path(norm, PATH_MAX, "/foo/./bar") == SUCCESS);
    fail_unless_str_equal(norm, "/foo/bar");

    fail_unless(normalize_path(norm, PATH_MAX, "/foo//bar") == SUCCESS);
    fail_unless_str_equal(norm, "/foo/bar");

    fail_unless(normalize_path(norm, PATH_MAX, "/foo//bar") == SUCCESS);
    fail_unless_str_equal(norm, "/foo/bar");

    fail_unless(normalize_path(norm, PATH_MAX, "") == SUCCESS);
    fail_unless_str_equal(norm, ".");

    fail_unless(normalize_path(norm, PATH_MAX, "/../..") == SUCCESS);
    fail_unless_str_equal(norm, "/");

    /* on-by-one */
    fail_unless(normalize_path(small, 8, "foo/baz/../bar") == SUCCESS);
    fail_unless_str_equal(small, "foo/bar");
}
END_TEST

START_TEST(test_normalize_path_neg)
{
    char norm[PATH_MAX];
    char small[4];

    fail_unless(normalize_path(norm, PATH_MAX, "foo/../..") == PATH_UTILS_ERROR_NOT_FULLY_NORMALIZED);

    /* with a buffer of 4 chars, this would test off-by-one error */
    fail_unless(normalize_path(small, 4, "/foo/../bar") == ENOBUFS);
}
END_TEST

/**** common_path_prefix ****/
START_TEST(test_common_path_prefix)
{
    char common[PATH_MAX];
    char small[5];
    int count;

    fail_unless(common_path_prefix(common, PATH_MAX, &count, "/usr/lib", "/usr/share") == SUCCESS);
    fail_unless_str_equal(common, "/usr");
    fail_unless(count == 2);

    fail_unless(common_path_prefix(common, PATH_MAX, NULL, "/usr/lib", "/usr/share") == SUCCESS);
    fail_unless_str_equal(common, "/usr");

    fail_unless(common_path_prefix(common, PATH_MAX, &count, "/usr/lib", "/usr/lab") == SUCCESS);
    fail_unless_str_equal(common, "/usr");
    fail_unless(count == 2);

    fail_unless(common_path_prefix(common, PATH_MAX, &count, "foo", "bar") == SUCCESS);
    fail_unless_str_equal(common, "");
    fail_unless(count == 0);

    fail_unless(common_path_prefix(common, PATH_MAX, &count, "/", "/") == SUCCESS);
    fail_unless_str_equal(common, "/");
    fail_unless(count == 1);

    fail_unless(common_path_prefix(common, PATH_MAX, &count, NULL, "/usr/share") == SUCCESS);
    fail_unless_str_equal(common, "");
    fail_unless(count == 0);

    /* on-by-one */
    fail_unless(common_path_prefix(small, 5, NULL, "/usr/lib", "/usr/share") == SUCCESS);
    fail_unless_str_equal(small, "/usr");
}
END_TEST

START_TEST(test_common_path_prefix_neg)
{
    char small[1];
    char small2[4];
    int count;

    fail_unless(common_path_prefix(small, 1, &count, "/usr/lib", "/usr/share") == ENOBUFS);
    fail_unless(common_path_prefix(NULL, PATH_MAX, &count, "/usr/lib", "/usr/share") == ENOBUFS);
    /* off-by-one */
    fail_unless(common_path_prefix(small2, 4, NULL, "/usr/lib", "/usr/share") == ENOBUFS);
}
END_TEST

/**** find_existing_directory_ancestor ****/
START_TEST(test_find_existing_directory_ancestor)
{
    char p[PATH_MAX];
    char cwd[PATH_MAX];

    fail_unless(find_existing_directory_ancestor(p, PATH_MAX, "/etc/passwd") == SUCCESS);
    fail_unless_str_equal(p, "/etc");

    /* if pathname does not contain a slash, the parent is cwd */
    fail_if(getcwd(cwd, PATH_MAX) == NULL, "getcwd failed");

    fail_unless(find_existing_directory_ancestor(p, PATH_MAX, "foo/bar") == SUCCESS);
    fail_unless_str_equal(p, cwd);
}
END_TEST

START_TEST(test_find_existing_directory_ancestor_neg)
{
    char small[4];
    fail_unless(find_existing_directory_ancestor(small, 4, "/etc/passwd") == ENOBUFS);
    fail_unless(find_existing_directory_ancestor(NULL, 4, "/etc/passwd") == ENOBUFS);
}
END_TEST

/**** directory_list ****/
void setup_directory_list(void)
{
    char *s = NULL;
    int ret;

    s = strdup(DIR_TEMPLATE);
    fail_unless(s != NULL, "strdup failed\n");
    dlist_dir = mkdtemp(s);
    fail_unless(dlist_dir != NULL, "mkstemp failed [%d][%s]", errno, strerror(errno));

    ret = asprintf(&dlist_subdir, "%s/%s", dlist_dir, SUBDIR);
    fail_unless(ret != 1, "strdup failed\n");
    ret = mkdir(dlist_subdir, 0700);
    fail_unless(ret != -1, "mkdir %s failed [%d][%s]", dlist_subdir, errno, strerror(errno));

    ret = asprintf(&dlist_subsubdir, "%s/%s", dlist_subdir, SUBSUBDIR);
    fail_unless(ret != 1, "strdup failed\n");
    ret = mkdir(dlist_subsubdir, 0700);
    fail_unless(ret != -1, "mkdir %s failed [%d][%s]", dlist_subsubdir, errno, strerror(errno));
}

void teardown_directory_list(void)
{
    int ret;

    if (dlist_subsubdir) {
        ret = rmdir(dlist_subsubdir);
        fail_unless(ret != -1, "unlink %s failed [%d][%s]", dlist_subsubdir, errno, strerror(errno));
        free(dlist_subsubdir);
        dlist_subsubdir = NULL;
    }

    if (dlist_subdir) {
        ret = rmdir(dlist_subdir);
        fail_unless(ret != -1, "unlink %s failed [%d][%s]", dlist_subdir, errno, strerror(errno));
        free(dlist_subdir);
        dlist_subdir = NULL;
    }

    if (dlist_dir) {
        ret = rmdir(dlist_dir);
        fail_unless(ret != -1, "unlink %s failed [%d][%s]", dlist_dir, errno, strerror(errno));
        free(dlist_dir);
        dlist_dir = NULL;
    }
}

bool dirlist_cb_nonrecursive(const char *directory, const char *base_name,
                             const char *path, struct stat *info,
                             void *user_data)
{
    int *data = (int *) user_data;

    fail_unless_str_equal(path, dlist_subdir);
    fail_unless(*data == 123);

    return true;
}

bool dirlist_cb_recursive(const char *directory, const char *base_name,
                          const char *path, struct stat *info,
                          void *user_data)
{
    bool *seen_child = (bool *) user_data;
    static bool seen_parent = false;

    if (!seen_parent) {
        fail_unless_str_equal(path, dlist_subdir);
        seen_parent = true;
    } else {
        *seen_child = true;
        fail_unless_str_equal(path, dlist_subsubdir);
        seen_parent = false;
    }

    return true;
}

START_TEST(test_directory_list)
{
    int data = 123;
    bool seen_child;

    fail_unless(directory_list(dlist_dir, false, dirlist_cb_nonrecursive, &data) == SUCCESS);

    seen_child = false;
    fail_unless(directory_list(dlist_dir, true, dirlist_cb_recursive, &seen_child) == SUCCESS);
    fail_unless(seen_child == true);

    seen_child = false;
    fail_unless(directory_list(dlist_dir, false, dirlist_cb_recursive, &seen_child) == SUCCESS);
    fail_unless(seen_child == false);
}
END_TEST

START_TEST(test_directory_list_neg)
{
    fail_if(directory_list("/not/here", false, dirlist_cb_nonrecursive, NULL) == SUCCESS);
    fail_if(directory_list("/etc/passwd", false, dirlist_cb_nonrecursive, NULL) == SUCCESS);
}
END_TEST

/**** is_ancestor_path ****/
START_TEST(test_is_ancestor_path)
{
  fail_unless(is_ancestor_path("/a/b/c", "/a/b/c/d") == true);
  /* equal, not ancestor */
  fail_unless(is_ancestor_path("/a/b/c/d", "/a/b/c/d") == false);
  fail_unless(is_ancestor_path("/a/x/c", "/a/b/c/d") == false);
  fail_unless(is_ancestor_path(NULL, "/a/b/c/d") == false);
  fail_unless(is_ancestor_path("/a/x/c", NULL) == false);
  fail_unless(is_ancestor_path(NULL, NULL) == false);
  fail_unless(is_ancestor_path("", "") == false);
}
END_TEST


Suite *path_utils_suite(void)
{
    Suite *s = suite_create("path_utils");

    TCase *tc_path_utils = tcase_create("path_utils");
    TCase *tc_directory_list = tcase_create("path_utils_directory_list");

    tcase_add_test(tc_path_utils, test_dirname);
    tcase_add_test(tc_path_utils, test_dirname_neg);

    tcase_add_test(tc_path_utils, test_basename);
    tcase_add_test(tc_path_utils, test_basename_neg);

    tcase_add_test(tc_path_utils, test_dirname_and_basename);
    tcase_add_test(tc_path_utils, test_dirname_and_basename_neg);

    tcase_add_test(tc_path_utils, test_is_absolute_path);

    tcase_add_test(tc_path_utils, test_path_concat);
    tcase_add_test(tc_path_utils, test_path_concat_neg);

    tcase_add_test(tc_path_utils, test_split_path);
    tcase_add_test(tc_path_utils, test_split_path_neg);

    tcase_add_test(tc_path_utils, test_make_path_absolute);
    tcase_add_test(tc_path_utils, test_make_path_absolute_neg);

    tcase_add_test(tc_path_utils, test_normalize_path);
    tcase_add_test(tc_path_utils, test_normalize_path_neg);

    tcase_add_test(tc_path_utils, test_make_normalized_absolute_path);
    tcase_add_test(tc_path_utils, test_make_normalized_absolute_path_neg);

    tcase_add_test(tc_path_utils, test_common_path_prefix);
    tcase_add_test(tc_path_utils, test_common_path_prefix_neg);

    tcase_add_test(tc_path_utils, test_find_existing_directory_ancestor);
    tcase_add_test(tc_path_utils, test_find_existing_directory_ancestor_neg);

    tcase_add_test(tc_path_utils, test_is_ancestor_path);

    tcase_add_checked_fixture(tc_directory_list,
                              setup_directory_list,
                              teardown_directory_list);
    tcase_add_test(tc_directory_list, test_directory_list);
    tcase_add_test(tc_directory_list, test_directory_list_neg);

    suite_add_tcase(s, tc_path_utils);
    suite_add_tcase(s, tc_directory_list);

    return s;
}

int main(void)
{
  int number_failed;

  Suite *s = path_utils_suite();
  SRunner *sr = srunner_create(s);
  /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
  srunner_run_all(sr, CK_ENV);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

