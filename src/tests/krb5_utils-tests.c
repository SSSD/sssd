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
#include "providers/krb5/krb5_ccache.h"
#include "providers/krb5/krb5_auth.h"
#include "util/sss_utf8.h"
#include "tests/common.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM

#define BASE "/abc/def"
#define FILENAME "ghi"

#define USERNAME "testuser"
#define USERNAME_CASE "TestUser"
#define DOMAIN_NAME "testdomain"
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
    ck_assert_msg(ret == EOK, "rmdir [%s] failed, [%d][%s].", __dir__, \
                errno, strerror(errno)); \
} while(0)

void setup_create_dir(void)
{
    ck_assert_msg(tmp_ctx == NULL, "Talloc context already initialized.");
    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "Cannot create talloc context.");
}

void teardown_create_dir(void)
{
    int ret;
    ck_assert_msg(tmp_ctx != NULL, "Talloc context already freed.");
    ret = talloc_free(tmp_ctx);
    tmp_ctx = NULL;
    ck_assert_msg(ret == 0, "Cannot free talloc context.");
}

static void check_dir(const char *dirname, uid_t uid, gid_t gid, mode_t mode)
{
    struct stat stat_buf;
    int ret;

    ret = stat(dirname, &stat_buf);
    ck_assert_msg(ret == EOK, "stat failed [%d][%s].", errno, strerror(errno));

    ck_assert_msg(S_ISDIR(stat_buf.st_mode), "[%s] is not a directory.", dirname);
    ck_assert_msg(stat_buf.st_uid == uid, "uid does not match, "
                                        "expected [%d], got [%d].",
                                        uid, stat_buf.st_uid);
    ck_assert_msg(stat_buf.st_gid == gid, "gid does not match, "
                                        "expected [%d], got [%d].",
                                        gid, stat_buf.st_gid);
    ck_assert_msg((stat_buf.st_mode & ~S_IFMT) == mode,
                                           "mode of [%s] does not match, "
                                           "expected [%o], got [%o].", dirname,
                                            mode, (stat_buf.st_mode & ~S_IFMT));
}

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
    ck_assert_msg(cwd != NULL, "getcwd failed.");

    user_dir = talloc_asprintf(tmp_ctx, "%s/%s/user", cwd, TESTS_PATH);
    free(cwd);
    ck_assert_msg(user_dir != NULL, "talloc_asprintf failed.");
    ret = mkdir(user_dir, 0700);
    ck_assert_msg(ret == EOK, "mkdir failed.");
    ret = chown(user_dir, uid, gid);
    ck_assert_msg(ret == EOK, "chown failed.");

    dn1 = talloc_asprintf(tmp_ctx, "%s/a", user_dir);
    ck_assert_msg(dn1 != NULL, "talloc_asprintf failed.");
    dn2 = talloc_asprintf(tmp_ctx, "%s/b", dn1);
    ck_assert_msg(dn2 != NULL, "talloc_asprintf failed.");
    dn3 = talloc_asprintf(tmp_ctx, "%s/c", dn2);
    ck_assert_msg(dn3 != NULL, "talloc_asprintf failed.");
    filename = talloc_asprintf(tmp_ctx, "%s/ccfile", dn3);
    ck_assert_msg(filename != NULL, "talloc_asprintf failed.");

    ret = chmod(user_dir, 0600);
    ck_assert_msg(ret == EOK, "chmod failed.");
    ret = sss_krb5_precreate_ccache(filename, uid, gid);
    ck_assert_msg(ret == EINVAL, "sss_krb5_precreate_ccache does not return EINVAL "
                               "while x-bit is missing.");

    ret = chmod(user_dir, 0700);
    ck_assert_msg(ret == EOK, "chmod failed.");
    ret = sss_krb5_precreate_ccache(filename, uid, gid);
    ck_assert_msg(ret == EOK, "sss_krb5_precreate_ccache failed.");

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

    ck_assert_msg(getuid() == 0, "This test must be run as root.");

    cwd = getcwd(NULL, 0);
    ck_assert_msg(cwd != NULL, "getcwd failed.");

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/priv_ccdir", cwd, TESTS_PATH);
    free(cwd);
    ck_assert_msg(dirname != NULL, "talloc_asprintf failed.");
    ret = mkdir(dirname, 0700);
    ck_assert_msg(ret == EOK, "mkdir failed.\n");
    ret = chown(dirname, 12346, 12346);
    ck_assert_msg(ret == EOK, "chown failed.\n");
    subdirname = talloc_asprintf(tmp_ctx, "%s/subdir", dirname);
    ck_assert_msg(subdirname != NULL, "talloc_asprintf failed.");
    filename = talloc_asprintf(tmp_ctx, "%s/ccfile", subdirname);
    ck_assert_msg(filename != NULL, "talloc_asprintf failed.");

    ret = sss_krb5_precreate_ccache(filename, 12345, 12345);
    ck_assert_msg(ret == EINVAL, "Creating private ccache dir in wrong user "
                               "dir does not failed with EINVAL.");

    RMDIR(dirname);
}
END_TEST

START_TEST(test_illegal_patterns)
{
    char *cwd;
    char *dirname;
    char *filename;
    sss_regexp_t *illegal_re;
    int err;
    char *result = NULL;


    err = sss_regexp_new(NULL, ILLEGAL_PATH_PATTERN, 0, &illegal_re);

    ck_assert_msg(err == 0, "Invalid Regular Expression pattern error %d.\n", err);
    ck_assert_msg(illegal_re != NULL, "No error but illegal_re is NULL.\n");

    cwd = getcwd(NULL, 0);
    ck_assert_msg(cwd != NULL, "getcwd failed.");

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/priv_ccdir", cwd, TESTS_PATH);
    free(cwd);
    ck_assert_msg(dirname != NULL, "talloc_asprintf failed.");

    result = expand_ccname_template(tmp_ctx, kr, "abc/./ccfile", illegal_re, true, true);
    ck_assert_msg(result == NULL, "expand_ccname_template allowed relative path\n");

    filename = talloc_asprintf(tmp_ctx, "%s/abc/./ccfile", dirname);
    ck_assert_msg(filename != NULL, "talloc_asprintf failed.");
    result = expand_ccname_template(tmp_ctx, kr, filename, illegal_re, true, true);
    ck_assert_msg(result == NULL, "expand_ccname_template allowed "
                                "illegal pattern '/./'\n");

    filename = talloc_asprintf(tmp_ctx, "%s/abc/../ccfile", dirname);
    ck_assert_msg(filename != NULL, "talloc_asprintf failed.");
    result = expand_ccname_template(tmp_ctx, kr, filename, illegal_re, true, true);
    ck_assert_msg(result == NULL, "expand_ccname_template allowed "
                                "illegal pattern '/../' in filename [%s].",
                                filename);

    filename = talloc_asprintf(tmp_ctx, "%s/abc//ccfile", dirname);
    ck_assert_msg(filename != NULL, "talloc_asprintf failed.");
    result = expand_ccname_template(tmp_ctx, kr, filename, illegal_re, true, true);
    ck_assert_msg(result == NULL, "expand_ccname_template allowed "
                                "illegal pattern '//' in filename [%s].",
                                filename);

    talloc_free(illegal_re);
}
END_TEST

START_TEST(test_cc_dir_create)
{
    char *residual;
    char *dirname;
    char *cwd;
    uid_t uid = getuid();
    gid_t gid = getgid();
    errno_t ret;

    cwd = getcwd(NULL, 0);
    ck_assert_msg(cwd != NULL, "getcwd failed.");

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/user_dir",
                              cwd, TESTS_PATH);
    ck_assert_msg(dirname != NULL, "talloc_asprintf failed.");
    residual = talloc_asprintf(tmp_ctx, "DIR:%s/%s", dirname, "ccdir");
    ck_assert_msg(residual != NULL, "talloc_asprintf failed.");

    ret = sss_krb5_precreate_ccache(residual, uid, gid);
    ck_assert_msg(ret == EOK, "sss_krb5_precreate_ccache failed\n");
    ret = rmdir(dirname);
    if (ret < 0) ret = errno;
    ck_assert_msg(ret == 0, "Cannot remove %s: %s\n", dirname, strerror(ret));
    talloc_free(residual);

    dirname = talloc_asprintf(tmp_ctx, "%s/%s/user_dir2",
                              cwd, TESTS_PATH);
    ck_assert_msg(dirname != NULL, "talloc_asprintf failed.");
    residual = talloc_asprintf(tmp_ctx, "DIR:%s/%s", dirname, "ccdir/");
    ck_assert_msg(residual != NULL, "talloc_asprintf failed.");

    ret = sss_krb5_precreate_ccache(residual, uid, gid);
    ck_assert_msg(ret == EOK, "sss_krb5_precreate_ccache failed\n");
    ret = rmdir(dirname);
    if (ret < 0) ret = errno;
    ck_assert_msg(ret == 0, "Cannot remove %s: %s\n", dirname, strerror(ret));
    talloc_free(residual);
    free(cwd);
}
END_TEST


void setup_talloc_context(void)
{
    int ret;
    int i;

    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    ck_assert_msg(tmp_ctx == NULL, "Talloc context already initialized.");
    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "Cannot create talloc context.");

    kr = talloc_zero(tmp_ctx, struct krb5child_req);
    ck_assert_msg(kr != NULL, "Cannot create krb5child_req structure.");

    pd = create_pam_data(tmp_ctx);
    ck_assert_msg(pd != NULL, "Cannot create pam_data structure.");

    krb5_ctx = talloc_zero(tmp_ctx, struct krb5_ctx);
    ck_assert_msg(pd != NULL, "Cannot create krb5_ctx structure.");

    pd->user = sss_create_internal_fqname(pd, USERNAME, DOMAIN_NAME);
    ck_assert_msg(pd->user != NULL, "Failed to allocate memory");
    kr->uid = atoi(UID);
    kr->upn = discard_const(PRINCIPAL_NAME);
    pd->cli_pid = atoi(PID);

    krb5_ctx->opts = talloc_zero_array(tmp_ctx, struct dp_option, KRB5_OPTS);
    ck_assert_msg(krb5_ctx->opts != NULL, "Cannot created options.");
    for (i = 0; i < KRB5_OPTS; i++) {
        krb5_ctx->opts[i].opt_name = default_krb5_opts[i].opt_name;
        krb5_ctx->opts[i].type = default_krb5_opts[i].type;
        krb5_ctx->opts[i].def_val = default_krb5_opts[i].def_val;
    }
    ret = dp_opt_set_string(krb5_ctx->opts, KRB5_REALM, REALM);
    ck_assert_msg(ret == EOK, "Failed to set Realm");
    ret = dp_opt_set_string(krb5_ctx->opts, KRB5_CCACHEDIR, CCACHE_DIR);
    ck_assert_msg(ret == EOK, "Failed to set Ccache dir");

    kr->homedir = HOME_DIRECTORY;

    kr->pd = pd;
    kr->krb5_ctx = krb5_ctx;

}

void free_talloc_context(void)
{
    int ret;
    ck_assert_msg(tmp_ctx != NULL, "Talloc context already freed.");
    ret = talloc_free(tmp_ctx);
    tmp_ctx = NULL;
    ck_assert_msg(ret == 0, "Cannot free talloc context.");
}

static void do_test(const char *file_template, const char *dir_template,
                    const char *expected)
{
    char *result;
    int ret;

    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, dir_template);
    ck_assert_msg(ret == EOK, "Failed to set Ccache dir");

    result = expand_ccname_template(tmp_ctx, kr, file_template, NULL, true, true);

    ck_assert_msg(result != NULL, "Cannot expand template [%s].", file_template);
    ck_assert_msg(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}

START_TEST(test_multiple_substitutions)
{
    do_test(BASE"_%u_%U_%u", CCACHE_DIR, BASE"_"USERNAME"_"UID"_"USERNAME);
    do_test("%d/"FILENAME, BASE"_%u_%U_%u",
            BASE"_"USERNAME"_"UID"_"USERNAME"/"FILENAME);
}
END_TEST

START_TEST(test_username)
{
    do_test(BASE"_%u", CCACHE_DIR, BASE"_"USERNAME);
    do_test("%d/"FILENAME, BASE"_%u", BASE"_"USERNAME"/"FILENAME);
}
END_TEST

START_TEST(test_case_sensitive)
{
    char *result;
    int ret;
    const char *file_template = BASE"_%u";
    const char *expected_cs = BASE"_TestUser";
    const char *expected_ci = BASE"_testuser";

    kr->pd->user = sss_create_internal_fqname(kr, USERNAME_CASE, DOMAIN_NAME);
    ck_assert_msg(kr->pd->user != NULL, "Failed to allocate memory");
    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, CCACHE_DIR);
    ck_assert_msg(ret == EOK, "Failed to set Ccache dir");

    result = expand_ccname_template(tmp_ctx, kr, file_template, NULL, true, true);

    ck_assert_msg(result != NULL, "Cannot expand template [%s].", file_template);
    ck_assert_msg(strcmp(result, expected_cs) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected_cs);

    result = expand_ccname_template(tmp_ctx, kr, file_template, NULL, true, false);

    ck_assert_msg(result != NULL, "Cannot expand template [%s].", file_template);
    ck_assert_msg(strcmp(result, expected_ci) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected_ci);
}
END_TEST

START_TEST(test_uid)
{
    do_test(BASE"_%U", CCACHE_DIR, BASE"_"UID);
    do_test("%d/"FILENAME, BASE"_%U", BASE"_"UID"/"FILENAME);
}
END_TEST

START_TEST(test_upn)
{
    do_test(BASE"_%p", CCACHE_DIR, BASE"_"PRINCIPAL_NAME);
    do_test("%d/"FILENAME, BASE"_%p", BASE"_"PRINCIPAL_NAME"/"FILENAME);
}
END_TEST

START_TEST(test_realm)
{
    do_test(BASE"_%r", CCACHE_DIR, BASE"_"REALM);
    do_test("%d/"FILENAME, BASE"_%r", BASE"_"REALM"/"FILENAME);
}
END_TEST

START_TEST(test_home)
{
    do_test(BASE"_%h", CCACHE_DIR, BASE"_"HOME_DIRECTORY);
    do_test("%d/"FILENAME, BASE"_%h", BASE"_"HOME_DIRECTORY"/"FILENAME);
}
END_TEST

START_TEST(test_ccache_dir)
{
    char *result;
    int ret;

    do_test(BASE"_%d", CCACHE_DIR, BASE"_"CCACHE_DIR);

    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, BASE"_%d");
    ck_assert_msg(ret == EOK, "Failed to set Ccache dir");

    result = expand_ccname_template(tmp_ctx, kr, "%d/"FILENAME, NULL, true, true);

    ck_assert_msg(result == NULL, "Using %%d in ccache dir should fail.");
}
END_TEST

START_TEST(test_pid)
{
    char *result;
    int ret;

    do_test(BASE"_%P", CCACHE_DIR, BASE"_"PID);

    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, BASE"_%P");
    ck_assert_msg(ret == EOK, "Failed to set Ccache dir");

    result = expand_ccname_template(tmp_ctx, kr, "%d/"FILENAME, NULL, true, true);

    ck_assert_msg(result == NULL, "Using %%P in ccache dir should fail.");
}
END_TEST

START_TEST(test_percent)
{
    do_test(BASE"_%%", CCACHE_DIR, BASE"_%");
    do_test("%d/"FILENAME, BASE"_%%", BASE"_%/"FILENAME);
}
END_TEST

START_TEST(test_unknown_template)
{
    const char *test_template = BASE"_%X";
    char *result;
    int ret;

    result = expand_ccname_template(tmp_ctx, kr, test_template, NULL, true, true);

    ck_assert_msg(result == NULL, "Unknown template [%s] should fail.",
                test_template);

    ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCACHEDIR, BASE"_%X");
    ck_assert_msg(ret == EOK, "Failed to set Ccache dir");
    test_template = "%d/"FILENAME;
    result = expand_ccname_template(tmp_ctx, kr, test_template, NULL, true, true);

    ck_assert_msg(result == NULL, "Unknown template [%s] should fail.",
                test_template);
}
END_TEST

START_TEST(test_NULL)
{
    char *test_template = NULL;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template, NULL, true, true);

    ck_assert_msg(result == NULL,
                "Expected NULL as a result for an empty input for "
                "NULL template");
}
END_TEST

START_TEST(test_no_substitution)
{
    const char *test_template = BASE;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template, NULL, true, true);

    ck_assert_msg(result != NULL, "Cannot expand template [%s].", test_template);
    ck_assert_msg(strcmp(result, test_template) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, test_template);
}
END_TEST

START_TEST(test_krb5_style_expansion)
{
    char *result;
    const char *file_template;
    const char *expected;

    file_template = BASE"/%{uid}/%{USERID}/%{euid}/%{username}";
    expected = BASE"/"UID"/"UID"/"UID"/"USERNAME;
    result = expand_ccname_template(tmp_ctx, kr, file_template, NULL, true, true);

    ck_assert_msg(result != NULL, "Cannot expand template [%s].", file_template);
    ck_assert_msg(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);

    file_template = BASE"/%{unknown}";
    expected = BASE"/%{unknown}";
    result = expand_ccname_template(tmp_ctx, kr, file_template, NULL, true, true);

    ck_assert_msg(result != NULL, "Cannot expand template [%s].", file_template);
    ck_assert_msg(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_compare_principal_realm)
{
    int ret;
    bool different_realm;

    ret = compare_principal_realm(NULL, "a", &different_realm);
    ck_assert_msg(ret == EINVAL, "NULL upn does not cause EINVAL.");

    ret = compare_principal_realm("a", NULL, &different_realm);
    ck_assert_msg(ret == EINVAL, "NULL realm does not cause EINVAL.");

    ret = compare_principal_realm("a", "b", NULL);
    ck_assert_msg(ret == EINVAL, "NULL different_realmbool " \
                               "does not cause EINVAL.");

    ret = compare_principal_realm("", "a", &different_realm);
    ck_assert_msg(ret == EINVAL, "Empty upn does not cause EINVAL.");

    ret = compare_principal_realm("a", "", &different_realm);
    ck_assert_msg(ret == EINVAL, "Empty realm does not cause EINVAL.");

    ret = compare_principal_realm("ABC", "ABC", &different_realm);
    ck_assert_msg(ret == EINVAL, "Short UPN does not cause EINVAL.");

    ret = compare_principal_realm("userABC", "ABC", &different_realm);
    ck_assert_msg(ret == EINVAL, "Missing '@' does not cause EINVAL.");

    ret = compare_principal_realm("user@ABC", "ABC", &different_realm);
    ck_assert_msg(ret == EOK, "Failure with same realm");
    ck_assert_msg(different_realm == false, "Same realm but " \
                                          "different_realm is not false.");

    ret = compare_principal_realm("user@ABC", "DEF", &different_realm);
    ck_assert_msg(ret == EOK, "Failure with different realm");
    ck_assert_msg(different_realm == true, "Different realm but " \
                                          "different_realm is not true.");

    ret = compare_principal_realm("user@ABC", "REALMNAMELONGERTHANUPN",
                                 &different_realm);
    ck_assert_msg(ret == EOK, "Failure with long realm name.");
    ck_assert_msg(different_realm == true, "Realm name longer than UPN but "
                                         "different_realm is not true.");
}
END_TEST

static void
compare_map_id_name_to_krb_primary(struct map_id_name_to_krb_primary *a,
                                   const char **str,
                                   size_t len)
{
    int i = 0;
    errno_t ret;

    while (a[i].id_name != NULL && a[i].krb_primary != NULL) {
        ck_assert_msg(i < len,
                    "Index: %d mus =t be lowwer than: %zd", i, len);
        ret = sss_utf8_case_eq((const uint8_t*)a[i].id_name,
                               (const uint8_t*)str[i*2]);
        ck_assert_msg(ret == EOK,
                    "%s does not match %s", a[i].id_name, str[i*2]);

        ret = sss_utf8_case_eq((const uint8_t*)a[i].krb_primary,
                               (const uint8_t*)str[i*2+1]);
        ck_assert_msg(ret == EOK, "%s does not match %s",
                    a[i].krb_primary, str[i*2+1]);
        i++;
    }
    ck_assert_msg(len == i, "%zu != %u", len, i);
}

START_TEST(test_parse_krb5_map_user)
{
    errno_t ret;
    TALLOC_CTX *mem_ctx;
    struct map_id_name_to_krb_primary *name_to_primary;

    mem_ctx = talloc_new(NULL);

    /* empty input */
    {
        check_leaks_push(mem_ctx);
        ret = parse_krb5_map_user(mem_ctx, NULL, DOMAIN_NAME, &name_to_primary);
        ck_assert_msg(ret == EOK,
                    "parse_krb5_map_user failed with error: %d", ret);
        ck_assert_msg(name_to_primary[0].id_name == NULL,
                    "id_name must be NULL. Got: %s",
                    name_to_primary[0].id_name);
        ck_assert_msg(name_to_primary[0].krb_primary == NULL,
                    "krb_primary must be NULL. Got: %s",
                    name_to_primary[0].krb_primary);
        talloc_free(name_to_primary);

        ret = parse_krb5_map_user(mem_ctx, "", DOMAIN_NAME, &name_to_primary);
        ck_assert_msg(ret == EOK,
                    "parse_krb5_map_user failed with error: %d", ret);
        ck_assert_msg(name_to_primary[0].id_name == NULL,
                    "id_name must be NULL. Got: %s",
                    name_to_primary[0].id_name);
        ck_assert_msg(name_to_primary[0].krb_primary == NULL,
                    "krb_primary must be NULL. Got: %s",
                    name_to_primary[0].krb_primary);
        talloc_free(name_to_primary);

        ret = parse_krb5_map_user(mem_ctx, ",", DOMAIN_NAME, &name_to_primary);
        ck_assert_msg(ret == EOK,
                    "parse_krb5_map_user failed with error: %d", ret);
        ck_assert_msg(name_to_primary[0].id_name == NULL,
                    "id_name must be NULL. Got: %s",
                    name_to_primary[0].id_name);
        ck_assert_msg(name_to_primary[0].krb_primary == NULL,
                    "krb_primary must be NULL. Got: %s",
                    name_to_primary[0].krb_primary);
        talloc_free(name_to_primary);

        ret = parse_krb5_map_user(mem_ctx, ",,", DOMAIN_NAME, &name_to_primary);
        ck_assert_msg(ret == EOK,
                    "parse_krb5_map_user failed with error: %d", ret);
        ck_assert_msg(name_to_primary[0].id_name == NULL,
                    "id_name must be NULL. Got: %s",
                    name_to_primary[0].id_name);
        ck_assert_msg(name_to_primary[0].krb_primary == NULL,
                    "krb_primary must be NULL. Got: %s",
                    name_to_primary[0].krb_primary);

        talloc_free(name_to_primary);

        ck_assert_msg(check_leaks_pop(mem_ctx),
                    "check_leaks_pop failed");
    }
    /* valid input */
    {
        check_leaks_push(mem_ctx);
        const char *p = "pája:preichl,joe:juser,jdoe:ßlack";
        const char *p2 = " pája  : preichl , joe:\njuser,jdoe\t:   ßlack ";
        const char *expected[] = { "pája@testdomain", "preichl@" DOMAIN_NAME,
                                   "joe@testdomain", "juser@testdomain",
                                   "jdoe@testdomain", "ßlack@testdomain" };
        ret = parse_krb5_map_user(mem_ctx, p, DOMAIN_NAME, &name_to_primary);
        ck_assert_msg(ret == EOK,
                    "parse_krb5_map_user failed with error: %d", ret);
        compare_map_id_name_to_krb_primary(name_to_primary, expected,
                                         sizeof(expected)/sizeof(const char*)/2);
        talloc_free(name_to_primary);

        ret = parse_krb5_map_user(mem_ctx, p2, DOMAIN_NAME, &name_to_primary);
        ck_assert_msg(ret == EOK,
                    "parse_krb5_map_user failed with error: %d", ret);
        compare_map_id_name_to_krb_primary(name_to_primary,  expected,
                                         sizeof(expected)/sizeof(const char*)/2);
        talloc_free(name_to_primary);
        ck_assert_msg(check_leaks_pop(mem_ctx),
                    "check_leaks_pop failed");
    }
    /* invalid input */
    {
        check_leaks_push(mem_ctx);

        ret = parse_krb5_map_user(mem_ctx, ":", DOMAIN_NAME, &name_to_primary);
        ck_assert_msg(ret == EINVAL,
                    "parse_krb5_map_user must fail with EINVAL got: %d", ret);

        ret = parse_krb5_map_user(mem_ctx, "joe:", DOMAIN_NAME,
                                  &name_to_primary);
        ck_assert_msg(ret == EINVAL,
                    "parse_krb5_map_user must fail with EINVAL got: %d", ret);

        ret = parse_krb5_map_user(mem_ctx, ":joe", DOMAIN_NAME,
                                  &name_to_primary);
        ck_assert_msg(ret == EINVAL,
                    "parse_krb5_map_user must fail with EINVAL got: %d", ret);

        ret = parse_krb5_map_user(mem_ctx, "joe:,", DOMAIN_NAME,
                                  &name_to_primary);
        ck_assert_msg(ret == EINVAL,
                    "parse_krb5_map_user must fail with EINVAL got: %d", ret);

        ret = parse_krb5_map_user(mem_ctx, ",joe", DOMAIN_NAME,
                                  &name_to_primary);
        ck_assert_msg(ret == EINVAL,
                    "parse_krb5_map_user must fail with EINVAL got: %d", ret);

        ret = parse_krb5_map_user(mem_ctx, "joe:j:user", DOMAIN_NAME,
                                  &name_to_primary);
        ck_assert_msg(ret == EINVAL,
                    "parse_krb5_map_user must fail with EINVAL got: %d", ret);

        ck_assert_msg(check_leaks_pop(mem_ctx),
                    "check_leaks_pop failed");
    }

    talloc_free(mem_ctx);
}
END_TEST

START_TEST(test_sss_krb5_realm_has_proxy)
{
    ck_assert_msg(sss_krb5_realm_has_proxy(NULL) == false,
                "sss_krb5_realm_has_proxy did not return false");

    setenv("KRB5_CONFIG", "/dev/null", 1);
    ck_assert_msg(sss_krb5_realm_has_proxy("REALM") == false,
                "sss_krb5_realm_has_proxy did not return false");

    setenv("KRB5_CONFIG", ABS_SRC_DIR"/src/tests/krb5_proxy_check_test_data.conf", 1);
    ck_assert_msg(sss_krb5_realm_has_proxy("REALM") == false,
                "sss_krb5_realm_has_proxy did not return false");
    ck_assert_msg(sss_krb5_realm_has_proxy("REALM_PROXY") == true,
                "sss_krb5_realm_has_proxy did not return true");
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
    tcase_add_test (tc_ccname_template, test_unknown_template);
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
    tcase_add_test (tc_ccname_template, test_krb5_style_expansion);
    suite_add_tcase (s, tc_ccname_template);

    TCase *tc_create_dir = tcase_create("create_dir");
    tcase_add_checked_fixture (tc_create_dir, setup_create_dir,
                               teardown_create_dir);
    tcase_add_test (tc_create_dir, test_illegal_patterns);
    tcase_add_test (tc_create_dir, test_cc_dir_create);
    if (getuid() == 0) {
        tcase_add_test (tc_create_dir, test_private_ccache_dir_in_user_dir);
        tcase_add_test (tc_create_dir, test_private_ccache_dir_in_wrong_user_dir);
    } else {
        printf("Run as root to enable more tests.\n");
    }
    suite_add_tcase (s, tc_create_dir);

    TCase *tc_krb5_helpers = tcase_create("Helper functions");
    tcase_add_test(tc_krb5_helpers, test_compare_principal_realm);
    tcase_add_test(tc_krb5_helpers, test_parse_krb5_map_user);
    tcase_add_test(tc_krb5_helpers, test_sss_krb5_realm_has_proxy);
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

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
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

    DEBUG_CLI_INIT(debug_level);

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
