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
#include <check.h>

#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_auth.h"

#define BASE "/abc/def"

#define USERNAME "testuser"
#define UID "12345"
#define PRINCIPLE_NAME "testuser@EXAMPLE.COM"
#define REALM "REALM.ORG"
#define HOME_DIRECTORY "/home/testuser"
#define CCACHE_DIR "/var/tmp"
#define PID "4321"

extern struct dp_option default_krb5_opts[];

TALLOC_CTX *tmp_ctx = NULL;
struct krb5child_req *kr;

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
    pd->pw_uid = atoi(UID);
    pd->upn = PRINCIPLE_NAME;
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
    fail_unless(ret == 0, "Connot free talloc context.");
}

START_TEST(test_multiple_substitutions)
{
    const char *test_template = BASE"_%u_%U_%u";
    const char *expected = BASE"_"USERNAME"_"UID"_"USERNAME;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_username)
{
    const char *test_template = BASE"_%u";
    const char *expected = BASE"_"USERNAME;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_uid)
{
    const char *test_template = BASE"_%U";
    const char *expected = BASE"_"UID;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_upn)
{
    const char *test_template = BASE"_%p";
    const char *expected = BASE"_"PRINCIPLE_NAME;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_realm)
{
    const char *test_template = BASE"_%r";
    const char *expected = BASE"_"REALM;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_home)
{
    const char *test_template = BASE"_%h";
    const char *expected = BASE"_"HOME_DIRECTORY;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_ccache_dir)
{
    const char *test_template = BASE"_%d";
    const char *expected = BASE"_"CCACHE_DIR;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_pid)
{
    const char *test_template = BASE"_%P";
    const char *expected = BASE"_"PID;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_percent)
{
    const char *test_template = BASE"_%%";
    const char *expected = BASE"_%";
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, expected) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, expected);
}
END_TEST

START_TEST(test_unknow_template)
{
    const char *test_template = BASE"_%X";
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result == NULL, "Unknown template [%s] should fail.",
                test_template);
}
END_TEST

START_TEST(test_NULL)
{
    char *test_template = NULL;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result == NULL, "Expected NULL as a result for an empty input.",
                test_template);
}
END_TEST

START_TEST(test_no_substitution)
{
    const char *test_template = BASE;
    char *result;

    result = expand_ccname_template(tmp_ctx, kr, test_template);

    fail_unless(result != NULL, "Cannot expand template [%s].", test_template);
    fail_unless(strcmp(result, test_template) == 0,
                "Expansion failed, result [%s], expected [%s].",
                result, test_template);
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
    tcase_add_test (tc_ccname_template, test_uid);
    tcase_add_test (tc_ccname_template, test_upn);
    tcase_add_test (tc_ccname_template, test_realm);
    tcase_add_test (tc_ccname_template, test_home);
    tcase_add_test (tc_ccname_template, test_ccache_dir);
    tcase_add_test (tc_ccname_template, test_pid);
    tcase_add_test (tc_ccname_template, test_percent);
    tcase_add_test (tc_ccname_template, test_multiple_substitutions);
    suite_add_tcase (s, tc_ccname_template);

    return s;
}

int main(void)
{
  int number_failed;
  Suite *s = krb5_utils_suite ();
  SRunner *sr = srunner_create (s);
  /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
  srunner_run_all(sr, CK_ENV);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

