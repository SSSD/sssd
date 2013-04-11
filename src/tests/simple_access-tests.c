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
#include "db/sysdb_private.h"
#include "providers/simple/simple_access.h"
#include "tests/common.h"

#define TESTS_PATH "tests_simple_access"
#define TEST_CONF_FILE "tests_conf.ldb"

const char *ulist_1[] = {"u1", "u2", NULL};
const char *glist_1[] = {"g1", "g2", NULL};
const char *glist_1_case[] = {"G1", "G2", NULL};

struct simple_test_ctx *test_ctx = NULL;

struct simple_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    bool done;
    int error;

    bool access_granted;
    struct simple_ctx *ctx;
};

static int test_loop(struct simple_test_ctx *tctx)
{
    while (!tctx->done)
        tevent_loop_once(tctx->ev);

    return tctx->error;
}

static void simple_access_check_done(struct tevent_req *req)
{
    struct simple_test_ctx *tctx =
                        tevent_req_callback_data(req, struct simple_test_ctx);


    tctx->error = simple_access_check_recv(req, &tctx->access_granted);
    talloc_free(req);
    tctx->done = true;
}

void setup_simple(void)
{
    errno_t ret;
    char *conf_db;
    const char *val[2];
    val[1] = NULL;

    fail_unless(test_ctx == NULL, "Simple context already initialized.");
    test_ctx = talloc_zero(NULL, struct simple_test_ctx);
    fail_unless(test_ctx != NULL, "Cannot create simple test context.");

    test_ctx->ev = tevent_context_init(test_ctx);
    fail_unless(test_ctx->ev != NULL, "Cannot create tevent context.");

    test_ctx->ctx = talloc_zero(test_ctx, struct simple_ctx);
    fail_unless(test_ctx->ctx != NULL, "Cannot create simple context.");

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    fail_if(ret == -1 && errno != EEXIST,
            "Could not create %s directory", TESTS_PATH);

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
    test_ctx->ctx->sysdb->mpg = false; /* Simulate an LDAP domain better */
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
    ret = sysdb_add_group(test_ctx->ctx->sysdb,
                          "pvt", 999, NULL, 0, 0);
    fail_if(ret != EOK, "Could not add private group");

    ret = sysdb_store_user(test_ctx->ctx->sysdb,
                           "u1", NULL, 123, 999, "u1", "/home/u1",
                           "/bin/bash", NULL, NULL, NULL, -1, 0);
    fail_if(ret != EOK, "Could not add u1");

    ret = sysdb_store_user(test_ctx->ctx->sysdb,
                           "u2", NULL, 456, 999, "u1", "/home/u1",
                           "/bin/bash", NULL, NULL, NULL, -1, 0);
    fail_if(ret != EOK, "Could not add u2");

    ret = sysdb_store_user(test_ctx->ctx->sysdb,
                           "u3", NULL, 789, 999, "u1", "/home/u1",
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
    ret = sysdb_delete_group(test_ctx->ctx->sysdb, "pvt", 0);
    fail_if(ret != EOK, "Could not delete pvt");

    teardown_simple();
}

START_TEST(test_both_empty)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_users = NULL;
    test_ctx->ctx->deny_users = NULL;

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == true,
                "Access denied while both lists are empty.");
}
END_TEST

START_TEST(test_allow_empty)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_users = NULL;
    test_ctx->ctx->deny_users = discard_const(ulist_1);

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted while user is in deny list.");

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u3");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == true,
                "Access denied while user is not in deny list.");
}
END_TEST

START_TEST(test_deny_empty)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_users = discard_const(ulist_1);
    test_ctx->ctx->deny_users = NULL;

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == true,
                "Access denied while user is in allow list.");

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u3");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted while user is not in allow list.");
}
END_TEST

START_TEST(test_both_set)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_users = discard_const(ulist_1);
    test_ctx->ctx->deny_users = discard_const(ulist_1);

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted while user is in deny list.");

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u3");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted while user is not in allow list.");
}
END_TEST

START_TEST(test_case)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_users = discard_const(ulist_1);
    test_ctx->ctx->deny_users = NULL;

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "U1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted for user with different case "
                "in case-sensitive domain");

    test_ctx->ctx->domain->case_sensitive = false;

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "U1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == true,
                "Access denied for user with different case "
                "in case-sensitive domain");
}
END_TEST

START_TEST(test_unknown_user)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_users = discard_const(ulist_1);
    test_ctx->ctx->deny_users = NULL;

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "foo");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted for user not present in domain");
}
END_TEST


START_TEST(test_group_allow_empty)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_groups = NULL;
    test_ctx->ctx->deny_groups = discard_const(glist_1);

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted while group is in deny list.");

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u3");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == true,
                "Access denied while group is not in deny list.");
}
END_TEST

START_TEST(test_group_deny_empty)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_groups = discard_const(glist_1);
    test_ctx->ctx->deny_groups = NULL;

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == true,
                "Access denied while user is in allow list.");

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u3");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted while user is not in allow list.");
}
END_TEST

START_TEST(test_group_both_set)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_groups = discard_const(ulist_1);
    test_ctx->ctx->deny_groups = discard_const(ulist_1);

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted while user is in deny list.");

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u3");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted while user is not in allow list.");
}
END_TEST

START_TEST(test_group_case)
{
    struct tevent_req *req;

    test_ctx->ctx->allow_groups = discard_const(glist_1_case);
    test_ctx->ctx->deny_groups = NULL;

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == false,
                "Access granted for user with different case "
                "in case-sensitive domain");

    test_ctx->ctx->domain->case_sensitive = false;

    req = simple_access_check_send(test_ctx, test_ctx->ev,
                                   test_ctx->ctx, "u1");
    fail_unless(test_ctx != NULL, "Cannot create request\n");
    tevent_req_set_callback(req, simple_access_check_done, test_ctx);

    test_loop(test_ctx);
    test_ctx->done = false;

    fail_unless(test_ctx->error == EOK, "access_simple_check failed.");
    fail_unless(test_ctx->access_granted == true,
                "Access denied for user with different case "
                "in case-sensitive domain");
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
    tcase_add_test(tc_allow_deny, test_unknown_user);
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

