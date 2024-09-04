/*
    SSSD

    Test for local authentication utilities

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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include <check.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "tests/common.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_FILE "tests_conf.ldb"

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;
};

static int setup_sysdb_tests(struct sysdb_test_ctx **ctx)
{
    struct sysdb_test_ctx *test_ctx;
    char *conf_db;
    int ret;

    const char *val[2];
    val[1] = NULL;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    if (ret == -1 && errno != EEXIST) {
        ck_abort_msg("Could not create %s directory", TESTS_PATH);
        return EFAULT;
    }

    test_ctx = talloc_zero(NULL, struct sysdb_test_ctx);
    if (test_ctx == NULL) {
        ck_abort_msg("Could not allocate memory for test context");
        return ENOMEM;
    }

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        ck_abort_msg("Could not create event context");
        talloc_free(test_ctx);
        return EIO;
    }

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    if (conf_db == NULL) {
        ck_abort_msg("Out of memory, aborting!");
        talloc_free(test_ctx);
        return ENOMEM;
    }
    DEBUG(SSSDBG_MINOR_FAILURE, "CONFDB: %s\n", conf_db);

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize connection to the confdb");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "FILES";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize domains placeholder");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "id_provider", val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize provider");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "enumerate", val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize FILES domain");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "cache_credentials", val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize FILES domain");
        talloc_free(test_ctx);
        return ret;
    }

    ret = test_domain_init(test_ctx, test_ctx->confdb, "FILES",
                           TESTS_PATH, &test_ctx->domain);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize connection to the sysdb (%d)", ret);
        talloc_free(test_ctx);
        return ret;
    }
    test_ctx->sysdb = test_ctx->domain->sysdb;

    *ctx = test_ctx;
    return EOK;
}

static void do_failed_login_test(uint32_t failed_login_attempts,
                                 time_t last_failed_login,
                                 int offline_failed_login_attempts,
                                 int offline_failed_login_delay,
                                 int expected_result,
                                 int expected_counter,
                                 time_t expected_delay)
{
    struct sysdb_test_ctx *test_ctx = NULL;
    int ret;
    const char *val[2];
    val[1] = NULL;
    struct ldb_message *ldb_msg;
    uint32_t returned_failed_login_attempts;
    time_t delayed_until;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    ck_assert_msg(ret == EOK, "Could not set up the test");

    val[0] = talloc_asprintf(test_ctx, "%u", offline_failed_login_attempts);
    ck_assert_msg(val[0] != NULL, "talloc_sprintf failed");
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/pam", CONFDB_PAM_FAILED_LOGIN_ATTEMPTS, val);
    ck_assert_msg(ret == EOK, "Could not set offline_failed_login_attempts");

    val[0] = talloc_asprintf(test_ctx, "%u", offline_failed_login_delay);
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/pam", CONFDB_PAM_FAILED_LOGIN_DELAY, val);
    ck_assert_msg(ret == EOK, "Could not set offline_failed_login_delay");

    ldb_msg = ldb_msg_new(test_ctx);
    ck_assert_msg(ldb_msg != NULL, "ldb_msg_new failed");

    ret = ldb_msg_add_fmt(ldb_msg, SYSDB_FAILED_LOGIN_ATTEMPTS, "%u",
                          failed_login_attempts);
    ck_assert_msg(ret == EOK, "ldb_msg_add_string failed");

    ret = ldb_msg_add_fmt(ldb_msg, SYSDB_LAST_FAILED_LOGIN, "%lld",
                          (long long) last_failed_login);
    ck_assert_msg(ret == EOK, "ldb_msg_add_string failed");

    ret = check_failed_login_attempts(test_ctx->confdb, ldb_msg,
                                      &returned_failed_login_attempts,
                                      &delayed_until);
    ck_assert_msg(ret == expected_result,
                "check_failed_login_attempts returned wrong error code, "
                "expected [%d], got [%d]", expected_result, ret);

    ck_assert_msg(returned_failed_login_attempts == expected_counter,
                "check_failed_login_attempts returned wrong number of failed "
                "login attempts, expected [%d], got [%d]",
                expected_counter, failed_login_attempts);

    ck_assert_msg(delayed_until == expected_delay,
                "check_failed_login_attempts wrong delay, "
                "expected [%"SPRItime"], got [%"SPRItime"]",
                expected_delay, delayed_until);

    talloc_free(test_ctx);
}

START_TEST(test_failed_login_attempts)
{
    time_t now;

    /* if offline_failed_login_attempts == 0 a login is never denied */
    do_failed_login_test(0,          0, 0, 5, EOK, 0, -1);
    do_failed_login_test(0, time(NULL), 0, 5, EOK, 0, -1);
    do_failed_login_test(2,          0, 0, 5, EOK, 2, -1);
    do_failed_login_test(2, time(NULL), 0, 5, EOK, 2, -1);

    do_failed_login_test(0,          0, 0, 0, EOK, 0, -1);
    do_failed_login_test(0, time(NULL), 0, 0, EOK, 0, -1);
    do_failed_login_test(2,          0, 0, 0, EOK, 2, -1);
    do_failed_login_test(2, time(NULL), 0, 0, EOK, 2, -1);

    /* if offline_failed_login_attempts != 0 and
     * offline_failed_login_delay == 0 a login is denied if the number of
     * failed attempts >= offline_failed_login_attempts */
    do_failed_login_test(0,          0, 2, 0, EOK, 0, -1);
    do_failed_login_test(0, time(NULL), 2, 0, EOK, 0, -1);
    do_failed_login_test(2,          0, 2, 0, ERR_AUTH_DENIED, 2, -1);
    do_failed_login_test(2, time(NULL), 2, 0, ERR_AUTH_DENIED, 2, -1);

    /* if offline_failed_login_attempts != 0 and
     * offline_failed_login_delay != 0 a login is denied only if the number of
     * failed attempts >= offline_failed_login_attempts AND the last failed
     * login attempt is not longer than offline_failed_login_delay ago */
    do_failed_login_test(0,          0, 2, 5, EOK, 0, -1);
    do_failed_login_test(0, time(NULL), 2, 5, EOK, 0, -1);
    do_failed_login_test(2,          0, 2, 5, EOK, 0, -1);
    now = time(NULL);
    do_failed_login_test(2, now, 2, 5, ERR_AUTH_DENIED, 2, (now + 5 * 60));

}
END_TEST

Suite *auth_suite (void)
{
    Suite *s = suite_create ("auth");

    TCase *tc_auth = tcase_create ("auth");

    tcase_add_test (tc_auth, test_failed_login_attempts);
    tcase_set_timeout(tc_auth, 60);

    suite_add_tcase (s, tc_auth);

    return s;
}

static int clean_db_dir(void)
{
    TALLOC_CTX *tmp_ctx;
    char *path;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = unlink(TESTS_PATH"/"TEST_CONF_FILE);
    if (ret != EOK && errno != ENOENT) {
        fprintf(stderr, "Could not delete the test config ldb file (%d) (%s)\n",
                errno, strerror(errno));
        goto done;
    }

    path = talloc_asprintf(tmp_ctx, TESTS_PATH"/"CACHE_SYSDB_FILE, "FILES");
    if (path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = unlink(path);
    if (ret != EOK && errno != ENOENT) {
        fprintf(stderr, "Could not delete cache ldb file (%d) (%s)\n",
                errno, strerror(errno));
        goto done;
    }

    path = talloc_asprintf(tmp_ctx, TESTS_PATH"/"CACHE_TIMESTAMPS_FILE, "FILES");
    if (path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = unlink(path);
    if (ret != EOK && errno != ENOENT) {
        fprintf(stderr, "Could not delete timestamps ldb file (%d) (%s)\n",
                errno, strerror(errno));
        goto done;
    }

    ret = rmdir(TESTS_PATH);
    if (ret != EOK && errno != ENOENT) {
        fprintf(stderr, "Could not delete the test directory (%d) (%s)\n",
                errno, strerror(errno));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int main(int argc, const char *argv[])
{
    int ret;
    int opt;
    int failure_count;
    poptContext pc;
    Suite *s = auth_suite ();
    SRunner *sr = srunner_create (s);

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

    tests_set_cwd();

    ret = clean_db_dir();
    if (ret != EOK) {
        fprintf(stderr, "Could not delete the db directory (%d) (%s)\n",
                errno, strerror(errno));
        return EXIT_FAILURE;
    }

    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed (sr);
    srunner_free (sr);
    if (failure_count == 0) {
        ret = clean_db_dir();
        if (ret != EOK) {
            fprintf(stderr, "Could not delete the db directory (%d) (%s)\n",
                    errno, strerror(errno));
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }
    return  EXIT_FAILURE;
}
