/*
    SSSD

    Simple access module -- Tests

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "confdb/confdb.h"
#include "providers/simple/simple_access.h"
#include "tests/common.h"

#define TESTS_PATH "tests_simple_access"
#define TEST_CONF_FILE "tests_conf.ldb"

const char *ulist_1[] = {"u1", "u2", NULL};
const char *glist_1[] = {"g1", "g2", NULL};

struct simple_test_ctx *test_ctx = NULL;

struct simple_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;

    struct simple_ctx *ctx;
};

void setup_simple(void)
{
    errno_t ret;
    char *conf_db;
    const char *val[2];
    val[1] = NULL;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    fail_if(ret == -1 && errno != EEXIST,
            "Could not create %s directory", TESTS_PATH);

    fail_unless(test_ctx == NULL, "Simple context already initialized.");
    test_ctx = talloc_zero(NULL, struct simple_test_ctx);
    fail_unless(test_ctx != NULL, "Cannot create simple test context.");

    test_ctx->ctx = talloc_zero(test_ctx, struct simple_ctx);
    fail_unless(test_ctx->ctx != NULL, "Cannot create simple context.");

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    fail_if(conf_db == NULL, "Out of memory, aborting!");
    DEBUG(SSSDBG_TRACE_LIBS, ("CONFDB: %s\n", conf_db));

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    fail_if(ret != EOK, "Could not initialize connection to the confdb");

    val[0] = "LOCAL";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    fail_if(ret != EOK, "Could not initialize domains placeholder");

    val[0] = "local";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    fail_if(ret != EOK, "Could not initialize provider");

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "enumerate", val);
    fail_if(ret != EOK, "Could not initialize LOCAL domain");

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "cache_credentials", val);
    fail_if(ret != EOK, "Could not initialize LOCAL domain");

    ret = sysdb_init_domain_and_sysdb(test_ctx, test_ctx->confdb, "local",
                                      TESTS_PATH,
                                      &test_ctx->ctx->domain, &test_ctx->ctx->sysdb);
    fail_if(ret != EOK, "Could not initialize connection to the sysdb (%d)", ret);
    test_ctx->ctx->domain->case_sensitive = true;
}

void teardown_simple(void)
{
    int ret;
    fail_unless(test_ctx != NULL, "Simple context already freed.");
    ret = talloc_free(test_ctx);
    test_ctx = NULL;
    fail_unless(ret == 0, "Connot free simple context.");
}

void setup_simple_group(void)
{
    errno_t ret;

    setup_simple();

    /* Add test users u1 and u2 that would be members of test groups
     * g1 and g2 respectively */
    ret = sysdb_store_user(test_ctx->ctx->sysdb,
                           "u1", NULL, 123, 0, "u1", "/home/u1",
                           "/bin/bash", NULL, NULL, NULL, -1, 0);
    fail_if(ret != EOK, "Could not add u1");

    ret = sysdb_store_user(test_ctx->ctx->sysdb,
                           "u2", NULL, 456, 0, "u1", "/home/u1",
                           "/bin/bash", NULL, NULL, NULL, -1, 0);
    fail_if(ret != EOK, "Could not add u2");

    ret = sysdb_store_user(test_ctx->ctx->sysdb,
                           "u3", NULL, 789, 0, "u1", "/home/u1",
                           "/bin/bash", NULL, NULL, NULL, -1, 0);
    fail_if(ret != EOK, "Could not add u3");

    ret = sysdb_add_group(test_ctx->ctx->sysdb,
                          "g1", 321, NULL, 0, 0);
    fail_if(ret != EOK, "Could not add g1");

    ret = sysdb_add_group(test_ctx->ctx->sysdb,
                          "g2", 654, NULL, 0, 0);
    fail_if(ret != EOK, "Could not add g2");

    ret = sysdb_add_group_member(test_ctx->ctx->sysdb,
                                 "g1", "u1", SYSDB_MEMBER_USER);
    fail_if(ret != EOK, "Could not add u1 to g1");

    ret = sysdb_add_group_member(test_ctx->ctx->sysdb,
                                 "g2", "u2", SYSDB_MEMBER_USER);
    fail_if(ret != EOK, "Could not add u2 to g2");
}

void teardown_simple_group(void)
{
    errno_t ret;

    ret = sysdb_delete_user(test_ctx->ctx->sysdb, "u1", 0);
    fail_if(ret != EOK, "Could not delete u1");
    ret = sysdb_delete_user(test_ctx->ctx->sysdb, "u2", 0);
    fail_if(ret != EOK, "Could not delete u2");
    ret = sysdb_delete_user(test_ctx->ctx->sysdb, "u3", 0);
    fail_if(ret != EOK, "Could not delete u3");
    ret = sysdb_delete_group(test_ctx->ctx->sysdb, "g1", 0);
    fail_if(ret != EOK, "Could not delete g1");
    ret = sysdb_delete_group(test_ctx->ctx->sysdb, "g2", 0);
    fail_if(ret != EOK, "Could not delete g2");

    teardown_simple();
}

START_TEST(test_both_empty)
{
    int ret;
    bool access_granted = false;

    test_ctx->ctx->allow_users = NULL;
    test_ctx->ctx->deny_users = NULL;

    ret = simple_access_check(test_ctx->ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                        "while both lists are empty.");
}
END_TEST

START_TEST(test_allow_empty)
{
    int ret;
    bool access_granted = true;

    test_ctx->ctx->allow_users = NULL;
    test_ctx->ctx->deny_users = discard_const(ulist_1);

    ret = simple_access_check(test_ctx->ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "while user is in deny list.");

    ret = simple_access_check(test_ctx->ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                         "while user is not in deny list.");
}
END_TEST

START_TEST(test_deny_empty)
{
    int ret;
    bool access_granted = false;

    test_ctx->ctx->allow_users = discard_const(ulist_1);
    test_ctx->ctx->deny_users = NULL;

    ret = simple_access_check(test_ctx->ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                        "while user is in allow list.");

    ret = simple_access_check(test_ctx->ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                        "while user is not in allow list.");
}
END_TEST

START_TEST(test_both_set)
{
    int ret;
    bool access_granted = false;

    test_ctx->ctx->allow_users = discard_const(ulist_1);
    test_ctx->ctx->deny_users = discard_const(ulist_1);

    ret = simple_access_check(test_ctx->ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "while user is in deny list.");

    ret = simple_access_check(test_ctx->ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                        "while user is not in allow list.");
}
END_TEST

START_TEST(test_case)
{
    int ret;
    bool access_granted = false;

    test_ctx->ctx->allow_users = discard_const(ulist_1);
    test_ctx->ctx->deny_users = NULL;

    ret = simple_access_check(test_ctx->ctx, "U1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "for user with different case "
                                         "in case-sensitive domain");

    test_ctx->ctx->domain->case_sensitive = false;

    ret = simple_access_check(test_ctx->ctx, "U1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                        "for user with different case "
                                        "in case-insensitive domain");
}
END_TEST

START_TEST(test_group_allow_empty)
{
    int ret;
    bool access_granted = true;

    test_ctx->ctx->allow_groups = NULL;
    test_ctx->ctx->deny_groups = discard_const(glist_1);

    ret = simple_access_check(test_ctx->ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "while group is in deny list.");

    ret = simple_access_check(test_ctx->ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                         "while group is not in deny list.");
}
END_TEST

START_TEST(test_group_deny_empty)
{
    int ret;
    bool access_granted = false;

    test_ctx->ctx->allow_groups = discard_const(glist_1);
    test_ctx->ctx->deny_groups = NULL;

    ret = simple_access_check(test_ctx->ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                        "while group is in allow list.");

    ret = simple_access_check(test_ctx->ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                        "while group is not in allow list.");
}
END_TEST

START_TEST(test_group_both_set)
{
    int ret;
    bool access_granted = false;

    test_ctx->ctx->allow_groups = discard_const(ulist_1);
    test_ctx->ctx->deny_groups = discard_const(ulist_1);

    ret = simple_access_check(test_ctx->ctx, "u1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "while group is in deny list.");

    ret = simple_access_check(test_ctx->ctx, "u3", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                        "while group is not in allow list.");
}
END_TEST

START_TEST(test_group_case)
{
    int ret;
    bool access_granted = false;

    test_ctx->ctx->allow_groups = discard_const(ulist_1);
    test_ctx->ctx->deny_groups = NULL;

    ret = simple_access_check(test_ctx->ctx, "U1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == false, "Access granted "
                                         "for group with different case "
                                         "in case-sensitive domain");

    test_ctx->ctx->domain->case_sensitive = false;

    ret = simple_access_check(test_ctx->ctx, "U1", &access_granted);
    fail_unless(ret == EOK, "access_simple_check failed.");
    fail_unless(access_granted == true, "Access denied "
                                        "for group with different case "
                                        "in case-insensitive domain");
}
END_TEST

Suite *access_simple_suite (void)
{
    Suite *s = suite_create("access_simple");

    TCase *tc_allow_deny = tcase_create("user allow/deny");
    tcase_add_checked_fixture(tc_allow_deny, setup_simple, teardown_simple);
    tcase_add_test(tc_allow_deny, test_both_empty);
    tcase_add_test(tc_allow_deny, test_allow_empty);
    tcase_add_test(tc_allow_deny, test_deny_empty);
    tcase_add_test(tc_allow_deny, test_both_set);
    tcase_add_test(tc_allow_deny, test_case);
    suite_add_tcase(s, tc_allow_deny);

    TCase *tc_grp_allow_deny = tcase_create("group allow/deny");
    tcase_add_checked_fixture(tc_grp_allow_deny,
                              setup_simple_group, teardown_simple_group);
    tcase_add_test(tc_grp_allow_deny, test_group_allow_empty);
    tcase_add_test(tc_grp_allow_deny, test_group_deny_empty);
    tcase_add_test(tc_grp_allow_deny, test_group_both_set);
    tcase_add_test(tc_grp_allow_deny, test_group_case);
    suite_add_tcase(s, tc_grp_allow_deny);

    return s;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int number_failed;
    int ret;

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

    tests_set_cwd();

    Suite *s = access_simple_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    ret = unlink(TESTS_PATH"/"TEST_CONF_FILE);
    if (ret != EOK) {
        fprintf(stderr, "Could not delete the test config ldb file (%d) (%s)\n",
                errno, strerror(errno));
        return EXIT_FAILURE;
    }
    ret = unlink(TESTS_PATH"/"LOCAL_SYSDB_FILE);
    if (ret != EOK) {
        fprintf(stderr, "Could not delete the test config ldb file (%d) (%s)\n",
                errno, strerror(errno));
        return EXIT_FAILURE;
    }

    return (number_failed==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

