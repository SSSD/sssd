/*
   Authors:
    Michal Zidek <mzidek@redhat.com>
    Stephen Gallagher <sgallagh@redhat.com>

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
#include <popt.h>
#include <talloc.h>
#include <sys/stat.h>
#include <sys/types.h>


#include "config.h"
#include "tests/common_check.h"
#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "db/sysdb_services.h"
#include "db/sysdb_ssh.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_FILE "tests_conf.ldb"
#define TEST_HOSTNAME "testhost"

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

static void clean_up(void)
{
    TALLOC_CTX *tmp_ctx;
    char *path;
    int ret = 0;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return;
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
        fprintf(stderr, "Could not delete the cache ldb file (%d) (%s)\n",
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
        fprintf(stderr, "Could not delete the timestamps ldb file (%d) (%s)\n",
                errno, strerror(errno));
        goto done;
    }

    ret = rmdir(TESTS_PATH);
    if (ret != EOK && errno != ENOENT) {
        fprintf(stderr, "Could not delete the test directory (%d) (%s)\n",
                errno, strerror(errno));
        goto done;
    }

done:
    if (ret != 0) {
        fprintf(stderr, "Unable to remove all test files from %s\n",TESTS_PATH);
    }
    talloc_free(tmp_ctx);
}

struct test_data {
    struct tevent_context *ev;
    struct sysdb_test_ctx *ctx;

    const char *hostname;
    const char *alias;

    struct ldb_message *host;
    struct sysdb_attrs *attrs;
};

static int test_sysdb_store_ssh_host(struct test_data *data)
{
    int ret;
    time_t now = time(NULL);

    ret = sysdb_store_ssh_host(data->ctx->domain,
                               data->hostname,
                               data->alias,
                               data->ctx->domain->ssh_host_timeout,
                               now,
                               data->attrs);
    return ret;
}

static int test_sysdb_delete_ssh_host(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_ssh_host(data->ctx->domain, data->hostname);
    return ret;
}

static int test_sysdb_get_ssh_host(struct test_data *data)
{
    int ret;
    const char *attrs[] = { SYSDB_NAME, NULL };

    ret = sysdb_get_ssh_host(data->ctx, data->ctx->domain, data->hostname,
                             attrs, &data->host);

    return ret;
}

START_TEST (store_one_host_test)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    if (data == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->hostname = talloc_strdup(test_ctx, TEST_HOSTNAME);
    if (data->hostname == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    data->attrs = sysdb_new_attrs(test_ctx);
    if (data->attrs == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    ret = test_sysdb_store_ssh_host(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not store host into database");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (delete_existing_host_test)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    if (data == NULL) {
        ck_abort_msg("Out of memory!");
        return;
    }

    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->hostname = talloc_strdup(test_ctx, TEST_HOSTNAME);
    if (data->hostname == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    ret = test_sysdb_delete_ssh_host(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not delete host from database");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (delete_nonexistent_host_test)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    if (data == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->hostname = talloc_strdup(test_ctx, "nonexistent_host");
    if (data->hostname == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    ret = test_sysdb_delete_ssh_host(data);

    sss_ck_fail_if_msg(ret != EOK, "Deletion of nonexistent host returned code %d", ret);
    talloc_free(test_ctx);

}
END_TEST

START_TEST (sysdb_get_ssh_host_test)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    if (data == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->hostname = talloc_strdup(test_ctx, TEST_HOSTNAME);
    if (data->hostname == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    data->attrs = sysdb_new_attrs(test_ctx);
    if (data->attrs == NULL) {
        ck_abort_msg("Out of memory!");
        talloc_free(test_ctx);
        return;
    }

    ret = test_sysdb_store_ssh_host(data);
    if (ret != EOK) {
        ck_abort_msg("Could not store host '%s' to database", TEST_HOSTNAME);
        talloc_free(test_ctx);
        return;
    }

    ret = test_sysdb_get_ssh_host(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not find host '%s'",TEST_HOSTNAME);
    talloc_free(test_ctx);
}
END_TEST


Suite *create_sysdb_ssh_suite(void)
{
    Suite *s = suite_create("sysdb_ssh");
    TCase *tc_sysdb_ssh = tcase_create("SYSDB_SSH Tests");

    tcase_add_test(tc_sysdb_ssh, store_one_host_test);
    tcase_add_test(tc_sysdb_ssh, delete_existing_host_test);
    tcase_add_test(tc_sysdb_ssh, delete_nonexistent_host_test);
    tcase_add_test(tc_sysdb_ssh, sysdb_get_ssh_host_test);
    suite_add_tcase(s, tc_sysdb_ssh);
    return s;
}

int main(int argc, const char *argv[])
{
    int failcount;
    int opt;
    poptContext pc;
    Suite* s;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, (const char **) argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                poptBadOption(pc, 0), poptStrerror(opt));
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    if (!ldb_modules_path_is_set()) {
        fprintf(stderr, "Warning: LDB_MODULES_PATH is not set, "
                "will use LDB plugins installed in system paths.\n");
    }

    tests_set_cwd();

    s = create_sysdb_ssh_suite();

    sr = srunner_create(s);
    srunner_run_all(sr, CK_ENV);
    failcount = srunner_ntests_failed(sr);
    srunner_free(sr);

    clean_up();
    if (failcount != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
