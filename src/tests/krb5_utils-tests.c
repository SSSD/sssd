/*
    SSSD

    Kerberos 5 Backend Module -- Utilities tests

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
#include <popt.h>
#include <check.h>

#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_auth.h"
#include "tests/common.h"

#define TESTS_PATH "tests_krb5_utils"

#define BASE "/abc/def"
#define FILENAME "ghi"

#define USERNAME "testuser"
#define UID "12345"
#define PRINCIPAL_NAME "testuser@EXAMPLE.COM"
#define REALM "REALM.ORG"
#define HOME_DIRECTORY "/home/testuser"
#define CCACHE_DIR "/var/tmp"
#define PID "4321"

extern struct dp_option default_krb5_opts[];

TALLOC_CTX *tmp_ctx = NULL;
struct krb5child_req *kr;

#define RMDIR(__dir__) do { \
    ret = rmdir(__dir__); \
    fail_unless(ret == EOK, "rmdir [%s] failed, [%d][%s].", __dir__, \
                errno, strerror(errno)); \
} while(0)

void setup_create_dir(void)
{
    fail_unless(tmp_ctx == NULL, "Talloc context already initialized.");
    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "Cannot create talloc context.");
}

void teardown_create_dir(void)
{
    int ret;
    fail_unless(tmp_ctx != NULL, "Talloc context already freed.");
    ret = talloc_free(tmp_ctx);
    tmp_ctx = NULL;
    fail_unless(ret == 0, "Connot free talloc context.");
}

static void check_dir(const char *dirname, uid_t uid, gid_t gid, mode_t mode)
{
    struct stat stat_buf;
    int ret;

    ret = stat(dirname, &stat_buf);
    fail_unless(ret == EOK, "stat failed [%d][%s].", errno, strerror(errno));

    fail_unless(S_ISDIR(stat_buf.st_mode), "[%s] is not a directory.", dirname);
    fail_unless(stat_buf.st_uid == uid, "uid does not match, "
                                        "expected [%d], got [%d].",
                                        uid, stat_buf.st_uid);
    fail_unless(stat_buf.st_gid == gid, "gid does not match, "
                                        "expected [%d], got [%d].",
                                        gid, stat_buf.st_gid);
    fail_unless((stat_buf.st_mode & ~S_IFMT) == mode,
                                           "mode of [%s] does not match, "
                                           "expected [%o], got [%o].", dirname,
                                            mode, (stat_buf.st_mode & ~S_IFMT));
}

START_TEST(test_pub_ccache_dir)
{
    int ret;
    char *cwd;
    char *testpath;
    char *dirname;
    char *subdirname;
    char *filename;

    fail_unless(getuid() == 0, "This test must be run as root.");

    cwd = getcwd(NULL, 0);
    fail_unless(cwd != NULL, "getcwd failed.");

    testpath = talloc_asprintf(tmp_ctx, "%s/%s", cwd, TESTS_PATH);
    free(cwd);
    fail_unless(testpath != NULL, "talloc_asprintf failed.");
    dirname = talloc_asprintf(tmp_ctx, "%s/pub_ccdir", testpath);
    fail_unless(dirname != NULL, "talloc_asprintf failed.");
    subdirname = talloc_asprintf(tmp_ctx, "%s/subdir", dirname);
    fail_unless(subdirname != NULL, "talloc_asprintf failed.");
    filename = talloc_asprintf(tmp_ctx, "%s/ccfile", subdirname);
    fail_unless(filename != NULL, "talloc_asprintf failed.");

    ret = chmod(testpath, 0754);
    fail_unless(ret == EOK, "chmod failed.");
    ret = cc_file_create(filename, NULL, 12345, 12345, false);
    fail_unless(ret == EINVAL, "cc_file_create does not return EINVAL "
                               "while x-bit is missing.");

    ret = chmod(testpath, 0755);
    fail_unless(ret == EOK, "chmod failed.");
    ret = cc_file_create(filename, NULL, 12345, 12345, false);
    fail_unless(ret == EOK, "cc_file_create failed.");

    check_dir(subdirname, 0, 0, 01777);
    RMDIR(subdirname);
    check_dir(dirname, 0, 0, 0755);
    RMDIR(dirname);
}
END_TEST

START_TEST(test_pub_ccache_dir_in_user_dir)
{
    int ret;
    char *cwd;
    char *dirname;
    char *subdirname;
    char *filename;

    fail_unless(getuid() == 0, "This test must be run as root.");

    cwd = getcwd(NULL, 0);
    fail_unless(cwd != NULL, "getcwd failed.");

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/pub_ccdir", cwd, TESTS_PATH);
    free(cwd);
    fail_unless(dirname != NULL, "talloc_asprintf failed.");
    ret = mkdir(dirname, 0700);
    fail_unless(ret == EOK, "mkdir failed.\n");
    ret = chown(dirname, 12345, 12345);
    fail_unless(ret == EOK, "chown failed.\n");
    subdirname = talloc_asprintf(tmp_ctx, "%s/subdir", dirname);
    fail_unless(subdirname != NULL, "talloc_asprintf failed.");
    filename = talloc_asprintf(tmp_ctx, "%s/ccfile", subdirname);
    fail_unless(filename != NULL, "talloc_asprintf failed.");

    ret = cc_file_create(filename, NULL, 12345, 12345, false);
    fail_unless(ret == EINVAL, "Creating public ccache dir in user dir "
                               "does not failed with EINVAL.");

    RMDIR(dirname);
}
END_TEST

START_TEST(test_priv_ccache_dir)
{
    int ret;
    char *cwd;
    char *testpath;
    char *dirname;
    char *subdir;
    char *filename;
    uid_t uid = 12345;
    gid_t gid = 12345;

    fail_unless(getuid() == 0, "This test must be run as root.");

    cwd = getcwd(NULL, 0);
    fail_unless(cwd != NULL, "getcwd failed.");

    testpath = talloc_asprintf(tmp_ctx, "%s/%s", cwd, TESTS_PATH);
    free(cwd);
    fail_unless(testpath != NULL, "talloc_asprintf failed.");
    dirname = talloc_asprintf(tmp_ctx, "%s/base", testpath);
    subdir = talloc_asprintf(tmp_ctx, "%s/priv_ccdir", dirname);
    fail_unless(subdir != NULL, "talloc_asprintf failed.");
    filename = talloc_asprintf(tmp_ctx, "%s/ccfile", subdir);
    fail_unless(filename != NULL, "talloc_asprintf failed.");

    ret = chmod(testpath, 0754);
    fail_unless(ret == EOK, "chmod failed.");
    ret = cc_file_create(filename, NULL, uid, gid, true);
    fail_unless(ret == EINVAL, "cc_file_create does not return EINVAL "
                               "while x-bit is missing.");

    ret = chmod(testpath, 0755);
    fail_unless(ret == EOK, "chmod failed.");
    ret = cc_file_create(filename, NULL, uid, gid, true);
    fail_unless(ret == EOK, "cc_file_create failed.");

    check_dir(subdir, uid, gid, 0700);
    RMDIR(subdir);
    check_dir(dirname, 0, 0, 0755);
    RMDIR(dirname);
}
END_TEST

START_TEST(test_private_ccache_dir_in_user_dir)
{
    int ret;
    char *cwd;
    char *user_dir;
    char *dn1;
    char *dn2;
    char *dn3;
    char *filename;
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (uid == 0) {
        uid = 12345;
        gid = 12345;
    }

    cwd = getcwd(NULL, 0);
    fail_unless(cwd != NULL, "getcwd failed.");

    user_dir = talloc_asprintf(tmp_ctx, "%s/%s/user", cwd, TESTS_PATH);
    free(cwd);
    fail_unless(user_dir != NULL, "talloc_asprintf failed.");
    ret = mkdir(user_dir, 0700);
    fail_unless(ret == EOK, "mkdir failed.");
    ret = chown(user_dir, uid, gid);
    fail_unless(ret == EOK, "chown failed.");

    dn1 = talloc_asprintf(tmp_ctx, "%s/a", user_dir);
    fail_unless(dn1 != NULL, "talloc_asprintf failed.");
    dn2 = talloc_asprintf(tmp_ctx, "%s/b", dn1);
    fail_unless(dn2 != NULL, "talloc_asprintf failed.");
    dn3 = talloc_asprintf(tmp_ctx, "%s/c", dn2);
    fail_unless(dn3 != NULL, "talloc_asprintf failed.");
    filename = talloc_asprintf(tmp_ctx, "%s/ccfile", dn3);
    fail_unless(filename != NULL, "talloc_asprintf failed.");

    ret = chmod(user_dir, 0600);
    fail_unless(ret == EOK, "chmod failed.");
    ret = cc_file_create(filename, NULL, uid, gid, true);
    fail_unless(ret == EINVAL, "cc_file_create does not return EINVAL "
                               "while x-bit is missing.");

    ret = chmod(user_dir, 0700);
    fail_unless(ret == EOK, "chmod failed.");
    ret = cc_file_create(filename, NULL, uid, gid, true);
    fail_unless(ret == EOK, "cc_file_create failed.");

    check_dir(dn3, uid, gid, 0700);
    RMDIR(dn3);
    check_dir(dn2, uid, gid, 0700);
    RMDIR(dn2);
    check_dir(dn1, uid, gid, 0700);
    RMDIR(dn1);
    RMDIR(user_dir);
}
END_TEST

START_TEST(test_private_ccache_dir_in_wrong_user_dir)
{
    int ret;
    char *cwd;
    char *dirname;
    char *subdirname;
    char *filename;

    fail_unless(getuid() == 0, "This test must be run as root.");

    cwd = getcwd(NULL, 0);
    fail_unless(cwd != NULL, "getcwd failed.");

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/priv_ccdir", cwd, TESTS_PATH);
    free(cwd);
    fail_unless(dirname != NULL, "talloc_asprintf failed.");
    ret = mkdir(dirname, 0700);
    fail_unless(ret == EOK, "mkdir failed.\n");
    ret = chown(dirname, 12346, 12346);
    fail_unless(ret == EOK, "chown failed.\n");
    subdirname = talloc_asprintf(tmp_ctx, "%s/subdir", dirname);
    fail_unless(subdirname != NULL, "talloc_asprintf failed.");
    filename = talloc_asprintf(tmp_ctx, "%s/ccfile", subdirname);
    fail_unless(filename != NULL, "talloc_asprintf failed.");

    ret = cc_file_create(filename, NULL, 12345, 12345, true);
    fail_unless(ret == EINVAL, "Creating private ccache dir in wrong user "
                               "dir does not failed with EINVAL.");

    RMDIR(dirname);
}
END_TEST

START_TEST(test_illegal_patterns)
{
    int ret;
    char *cwd;
    char *dirname;
    char *filename;
    uid_t uid = getuid();
    gid_t gid = getgid();
    pcre *illegal_re;
    const char *errstr;
    int errval;
    int errpos;

    illegal_re = pcre_compile2(ILLEGAL_PATH_PATTERN, 0,
                               &errval, &errstr, &errpos, NULL);
    fail_unless(illegal_re != NULL, "Invalid Regular Expression pattern at "
                                    " position %d. (Error: %d [%s])\n",
                                    errpos, errval, errstr);

    cwd = getcwd(NULL, 0);
    fail_unless(cwd != NULL, "getcwd failed.");

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/priv_ccdir", cwd, TESTS_PATH);
    free(cwd);
    fail_unless(dirname != NULL, "talloc_asprintf failed.");


    filename = talloc_asprintf(tmp_ctx, "abc/./ccfile");
    fail_unless(filename != NULL, "talloc_asprintf failed.");
    ret = create_ccache_dir(filename, illegal_re, uid, gid, true);
    fail_unless(ret == EINVAL, "create_ccache_dir allowed relative path [%s].",
                               filename);

    filename = talloc_asprintf(tmp_ctx, "%s/abc/./ccfile", dirname);
    fail_unless(filename != NULL, "talloc_asprintf failed.");
    ret = create_ccache_dir(filename, illegal_re, uid, gid, true);
    fail_unless(ret == EINVAL, "create_ccache_dir allowed "
                               "illegal pattern '/./' in filename [%s].",
                               filename);

    filename = talloc_asprintf(tmp_ctx, "%s/abc/../ccfile", dirname);
    fail_unless(filename != NULL, "talloc_asprintf failed.");
    ret = create_ccache_dir(filename, illegal_re, uid, gid, true);
    fail_unless(ret == EINVAL, "create_ccache_dir allowed "
                               "illegal pattern '/../' in filename [%s].",
                               filename);

    filename = talloc_asprintf(tmp_ctx, "%s/abc//ccfile", dirname);
    fail_unless(filename != NULL, "talloc_asprintf failed.");
    ret = create_ccache_dir(filename, illegal_re, uid, gid, true);
    fail_unless(ret == EINVAL, "create_ccache_dir allowed "
                               "illegal pattern '//' in filename [%s].",
                               filename);

}
END_TEST

#ifdef HAVE_KRB5_DIRCACHE
START_TEST(test_cc_dir_create)
{
    char *residual;
    char *dirname;
    char *cwd;
    uid_t uid = getuid();
    gid_t gid = getgid();
    pcre *illegal_re;
    errno_t ret;
    const char *errstr;
    int errval;
    int errpos;

    illegal_re = pcre_compile2(ILLEGAL_PATH_PATTERN, 0,
                               &errval, &errstr, &errpos, NULL);
    fail_unless(illegal_re != NULL, "Invalid Regular Expression pattern at "
                                    " position %d. (Error: %d [%s])\n",
                                    errpos, errval, errstr);

    cwd = getcwd(NULL, 0);
    fail_unless(cwd != NULL, "getcwd failed.");

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/user_dir",
                              cwd, TESTS_PATH);
    fail_unless(dirname != NULL, "talloc_asprintf failed.");
    residual = talloc_asprintf(tmp_ctx, "DIR:%s/%s", dirname, "ccdir");
    fail_unless(residual != NULL, "talloc_asprintf failed.");

    ret = cc_dir_create(residual, illegal_re, uid, gid, true);
    fail_unless(ret == EOK, "cc_dir_create failed\n");
    ret = rmdir(dirname);
    if (ret < 0) ret = errno;
    fail_unless(ret == 0, "Cannot remove %s: %s\n", dirname, strerror(ret));
    talloc_free(residual);

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/user_dir2",
                              cwd, TESTS_PATH);
    fail_unless(dirname != NULL, "talloc_asprintf failed.");
    residual = talloc_asprintf(tmp_ctx, "DIR:%s/%s", dirname, "ccdir/");
    fail_unless(residual != NULL, "talloc_asprintf failed.");

    ret = cc_dir_create(residual, illegal_re, uid, gid, true);
    fail_unless(ret == EOK, "cc_dir_create failed\n");
    ret = rmdir(dirname);
    if (ret < 0) ret = errno;
    fail_unless(ret == 0, "Cannot remove %s: %s\n", dirname, strerror(ret));
    talloc_free(residual);
    free(cwd);
}
END_TEST
#endif /* HAVE_KRB5_DIRCACHE */


void setup_talloc_context(void)
{
    int ret;
    int i;

    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    fail_unless(tmp_ctx == NULL, "Talloc context already initialized.");
    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "Cannot create talloc context.");

    kr = talloc_zero(tmp_ctx, struct krb5child_req);
    fail_unless(kr != NULL, "Cannot create krb5child_req structure.");

    pd = talloc_zero(tmp_ctx, struct pam_data);
    fail_unless(pd != NULL, "Cannot create pam_data structure.");

    krb5_ctx = talloc_zero(tmp_ctx, struct krb5_ctx);
    fail_unless(pd != NULL, "Cannot create krb5_ctx structure.");

    pd->user = discard_const(USERNAME);
    kr->uid = atoi(UID);
    kr->upn = discard_const(PRINCIPAL_NAME);
    pd->cli_pid = atoi(PID);

    krb5_ctx->opts = talloc_zero_array(tmp_ctx, struct dp_option, KRB5_OPTS);
    fail_unless(krb5_ctx->opts != NULL, "Cannot created options.");
    for (i = 0; i < KRB5_OPTS; i++) {
        krb5_ctx->opts[i].opt_name = default_krb5_opts[i].opt_name;
        krb5_ctx->opts[i].type = default_krb5_opts[i].type;
        krb5_ctx->opts[i].def_val = default_krb5_opts[i].def_val;
    }
    ret = dp_opt_set_string(krb5_ctx->opts, KRB5_REALM, REALM);
    fail_unless(ret == EOK, "Failed to set Realm");
    ret = dp_opt_set_string(krb5_ctx->opts, KRB5_CCACHEDIR, CCACHE_DIR);
    fail_unless(ret == EOK, "Failed to set Ccache dir");

    kr->homedir = HOME_DIRECTORY;

    kr->pd = pd;
    kr->krb5_ctx = krb5_ctx;

}

void free_talloc_context(void)
{
    int ret;
    fail_unless(tmp_ctx != NULL, "Talloc context already freed.");
    ret = talloc_free(tmp_ctx);
    tmp_ctx = NULL;
    fail_unless(ret == 0, "Connot free talloc context.");
}

static void do_test(const char *file_template, const char *dir_template,
                    const char *expected, const bool expected_private_path)
{
    char *result;
    int ret;
    bool private_path = false;

    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, dir_template);
    fail_unless(ret == EOK, "Failed to set Ccache dir");

    result = expand_ccname_template(tmp_ctx, kr, file_template, true,
                                    true, &private_path);

    fail_unless(result != NULL, "Cannot expand template [%s].", file_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
    fail_unless(private_path == expected_private_path,
                "Unexprected private path, get [%s], expected [%s].",
                private_path ? "true" : "false",
                expected_private_path ? "true" : "false");
}

START_TEST(test_multiple_substitutions)
{
    do_test(BASE"_%u_%U_%u", CCACHE_DIR, BASE"_"USERNAME"_"UID"_"USERNAME, false);
    do_test("%d/"FILENAME, BASE"_%u_%U_%u",
            BASE"_"USERNAME"_"UID"_"USERNAME"/"FILENAME, true);
}
END_TEST

START_TEST(test_username)
{
    do_test(BASE"_%u", CCACHE_DIR, BASE"_"USERNAME, false);
    do_test("%d/"FILENAME, BASE"_%u", BASE"_"USERNAME"/"FILENAME, true);
}
END_TEST

START_TEST(test_case_sensitive)
{
    char *result;
    int ret;
    bool private_path = false;
    const char *file_template = BASE"_%u";
    const char *expected_cs = BASE"_TestUser";
    const char *expected_ci = BASE"_testuser";

    kr->pd->user = discard_const("TestUser");
    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, CCACHE_DIR);
    fail_unless(ret == EOK, "Failed to set Ccache dir");

    result = expand_ccname_template(tmp_ctx, kr, file_template, true,
                                    true, &private_path);

    fail_unless(result != NULL, "Cannot expand template [%s].", file_template);
    fail_unless(strcmp(result, expected_cs) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected_cs);

    result = expand_ccname_template(tmp_ctx, kr, file_template, true,
                                    false, &private_path);

    fail_unless(result != NULL, "Cannot expand template [%s].", file_template);
    fail_unless(strcmp(result, expected_ci) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected_ci);
}
END_TEST

START_TEST(test_uid)
{
    do_test(BASE"_%U", CCACHE_DIR, BASE"_"UID, false);
    do_test("%d/"FILENAME, BASE"_%U", BASE"_"UID"/"FILENAME, true);
}
END_TEST

START_TEST(test_upn)
{
    do_test(BASE"_%p", CCACHE_DIR, BASE"_"PRINCIPAL_NAME, false);
    do_test("%d/"FILENAME, BASE"_%p", BASE"_"PRINCIPAL_NAME"/"FILENAME, true);
}
END_TEST

START_TEST(test_realm)
{
    do_test(BASE"_%r", CCACHE_DIR, BASE"_"REALM, false);
    do_test("%d/"FILENAME, BASE"_%r", BASE"_"REALM"/"FILENAME, false);
}
END_TEST

START_TEST(test_home)
{
    do_test(BASE"_%h", CCACHE_DIR, BASE"_"HOME_DIRECTORY, false);
    do_test("%d/"FILENAME, BASE"_%h", BASE"_"HOME_DIRECTORY"/"FILENAME, true);
}
END_TEST

START_TEST(test_ccache_dir)
{
    char *result;
    int ret;
    bool private_path = false;

    do_test(BASE"_%d", CCACHE_DIR, BASE"_"CCACHE_DIR, false);

    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, BASE"_%d");
    fail_unless(ret == EOK, "Failed to set Ccache dir");

    result = expand_ccname_template(tmp_ctx, kr, "%d/"FILENAME, true,
                                    true, &private_path);

    fail_unless(result == NULL, "Using %%d in ccache dir should fail.");
    fail_unless(private_path == false,
                "Unexprected private path, get [%s], expected [%s].",
                private_path ? "true" : "false", "false");
}
END_TEST

START_TEST(test_pid)
{
    char *result;
    int ret;
    bool private_path = false;

    do_test(BASE"_%P", CCACHE_DIR, BASE"_"PID, false);

    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, BASE"_%P");
    fail_unless(ret == EOK, "Failed to set Ccache dir");

    result = expand_ccname_template(tmp_ctx, kr, "%d/"FILENAME, true,
                                    true, &private_path);

    fail_unless(result == NULL, "Using %%P in ccache dir should fail.");
    fail_unless(private_path == false,
                "Unexprected private path, get [%s], expected [%s].",
                private_path ? "true" : "false", "false");
}
END_TEST

START_TEST(test_percent)
{
    do_test(BASE"_%%", CCACHE_DIR, BASE"_%", false);
    do_test("%d/"FILENAME, BASE"_%%", BASE"_%/"FILENAME, false);
}
END_TEST

START_TEST(test_unknow_template)
{
    const char *test_template = BASE"_%X";
    char *result;
    int ret;
    bool private_path = false;

    result = expand_ccname_template(tmp_ctx, kr, test_template, true,
                                    true, &private_path);

    fail_unless(result == NULL, "Unknown template [%s] should fail.",
                test_template);

    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, BASE"_%X");
    fail_unless(ret == EOK, "Failed to set Ccache dir");
    test_template = "%d/"FILENAME;
    result = expand_ccname_template(tmp_ctx, kr, test_template, true,
                                    true, &private_path);

    fail_unless(result == NULL, "Unknown template [%s] should fail.",
                test_template);
    fail_unless(private_path == false,
                "Unexprected private path, get [%s], expected [%s].",
                private_path ? "true" : "false", "false");
}
END_TEST

START_TEST(test_NULL)
{
    char *test_template = NULL;
    char *result;
    bool private_path = false;

    result = expand_ccname_template(tmp_ctx, kr, test_template, true,
                                    true, &private_path);

    fail_unless(result == NULL, "Expected NULL as a result for an empty input.",
                test_template);
    fail_unless(private_path == false,
                "Unexprected private path, get [%s], expected [%s].",
                private_path ? "true" : "false", "false");
}
END_TEST

START_TEST(test_no_substitution)
{
    const char *test_template = BASE;
    char *result;
    bool private_path = false;

    result = expand_ccname_template(tmp_ctx, kr, test_template, true,
                                    true, &private_path);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, test_template) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, test_template);
    fail_unless(private_path == false,
                "Unexprected private path, get [%s], expected [%s].",
                private_path ? "true" : "false", "false");
}
END_TEST

START_TEST(test_compare_principal_realm)
{
    int ret;
    bool different_realm;

    ret = compare_principal_realm(NULL, "a", &different_realm);
    fail_unless(ret == EINVAL, "NULL upn does not cause EINVAL.");

    ret = compare_principal_realm("a", NULL, &different_realm);
    fail_unless(ret == EINVAL, "NULL realm does not cause EINVAL.");

    ret = compare_principal_realm("a", "b", NULL);
    fail_unless(ret == EINVAL, "NULL different_realmbool " \
                               "does not cause EINVAL.");

    ret = compare_principal_realm("", "a", &different_realm);
    fail_unless(ret == EINVAL, "Empty upn does not cause EINVAL.");

    ret = compare_principal_realm("a", "", &different_realm);
    fail_unless(ret == EINVAL, "Empty realm does not cause EINVAL.");

    ret = compare_principal_realm("ABC", "ABC", &different_realm);
    fail_unless(ret == EINVAL, "Short UPN does not cause EINVAL.");

    ret = compare_principal_realm("userABC", "ABC", &different_realm);
    fail_unless(ret == EINVAL, "Missing '@' does not cause EINVAL.");

    fail_unless(different_realm == false, "Same realm but " \
                                          "different_realm is not false.");
    ret = compare_principal_realm("user@ABC", "ABC", &different_realm);
    fail_unless(ret == EOK, "Failure with same realm");
    fail_unless(different_realm == false, "Same realm but " \
                                          "different_realm is not false.");

    ret = compare_principal_realm("user@ABC", "DEF", &different_realm);
    fail_unless(ret == EOK, "Failure with different realm");
    fail_unless(different_realm == true, "Different realm but " \
                                          "different_realm is not true.");

    ret = compare_principal_realm("user@ABC", "REALMNAMELONGERTHANUPN",
                                 &different_realm);
    fail_unless(ret == EOK, "Failure with long realm name.");
    fail_unless(different_realm == true, "Realm name longer than UPN but "
                                         "different_realm is not true.");
}
END_TEST

Suite *krb5_utils_suite (void)
{
    Suite *s = suite_create ("krb5_utils");

    TCase *tc_ccname_template = tcase_create ("ccname_template");
    tcase_add_checked_fixture (tc_ccname_template, setup_talloc_context,
                               free_talloc_context);
    tcase_add_test (tc_ccname_template, test_no_substitution);
    tcase_add_test (tc_ccname_template, test_NULL);
    tcase_add_test (tc_ccname_template, test_unknow_template);
    tcase_add_test (tc_ccname_template, test_username);
    tcase_add_test (tc_ccname_template, test_case_sensitive);
    tcase_add_test (tc_ccname_template, test_uid);
    tcase_add_test (tc_ccname_template, test_upn);
    tcase_add_test (tc_ccname_template, test_realm);
    tcase_add_test (tc_ccname_template, test_home);
    tcase_add_test (tc_ccname_template, test_ccache_dir);
    tcase_add_test (tc_ccname_template, test_pid);
    tcase_add_test (tc_ccname_template, test_percent);
    tcase_add_test (tc_ccname_template, test_multiple_substitutions);
    suite_add_tcase (s, tc_ccname_template);

    TCase *tc_create_dir = tcase_create("create_dir");
    tcase_add_checked_fixture (tc_create_dir, setup_create_dir,
                               teardown_create_dir);
    tcase_add_test (tc_create_dir, test_illegal_patterns);
#ifdef HAVE_KRB5_DIRCACHE
    tcase_add_test (tc_create_dir, test_cc_dir_create);
#endif /* HAVE_KRB5_DIRCACHE */
    if (getuid() == 0) {
        tcase_add_test (tc_create_dir, test_priv_ccache_dir);
        tcase_add_test (tc_create_dir, test_private_ccache_dir_in_user_dir);
        tcase_add_test (tc_create_dir, test_pub_ccache_dir);
        tcase_add_test (tc_create_dir, test_pub_ccache_dir_in_user_dir);
        tcase_add_test (tc_create_dir, test_private_ccache_dir_in_wrong_user_dir);
    } else {
        printf("Run as root to enable more tests.\n");
    }
    suite_add_tcase (s, tc_create_dir);

    TCase *tc_krb5_helpers = tcase_create("Helper functions");
    tcase_add_test(tc_krb5_helpers, test_compare_principal_realm);
    suite_add_tcase(s, tc_krb5_helpers);

    return s;
}

int main(int argc, const char *argv[])
{
    int ret;
    int opt;
    poptContext pc;
    int number_failed;

    tests_set_cwd();

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    ret = mkdir(TESTS_PATH, 0775);
    if (ret != EOK) {
        fprintf(stderr, "Could not create empty directory [%s]. ", TESTS_PATH);
        if (errno == EEXIST) {
            fprintf(stderr, "Please remove [%s].\n", TESTS_PATH);
        } else {
            fprintf(stderr, "[%d][%s].\n", errno, strerror(errno));
        }

        return 1;
    }

    Suite *s = krb5_utils_suite ();
    SRunner *sr = srunner_create (s);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    if (number_failed == 0) {
        ret = rmdir(TESTS_PATH);
        if (ret != EOK) {
            fprintf(stderr, "Cannot remove [%s]: [%d][%s].\n", TESTS_PATH,
                            errno, strerror(errno));
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}

