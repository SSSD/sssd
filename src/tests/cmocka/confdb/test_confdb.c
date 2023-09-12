/*
    Copyright (C) 2020 Red Hat

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
#define _GNU_SOURCE

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>

#include <string.h>

#include "confdb/confdb.h"
#include "tests/cmocka/common_mock.h"
#include "tests/common.h"
#include "tests/cmocka/common_mock_be.h"


#include "confdb/confdb.c"

#define TESTS_PATH "confdb_" BASE_FILE_STEM
#define TEST_CONF_DB "test_confdb.ldb"

#define TEST_DOMAIN_ENABLED_1 "enabled_1"
#define TEST_DOMAIN_ENABLED_2 "enabled_2"
#define TEST_DOMAIN_ENABLED_3 "enabled_3"

#define TEST_DOMAIN_DISABLED_1 "disabled_1"
#define TEST_DOMAIN_DISABLED_2 "disabled_2"
#define TEST_DOMAIN_DISABLED_3 "disabled_3"


struct test_ctx {
    struct confdb_ctx *confdb;
};


static int confdb_test_setup(void **state)
{
    struct test_ctx *test_ctx;
    char *conf_db = NULL;
    int ret;
    const char *val[2];
    val[1] = NULL;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_DB);
    assert_non_null(conf_db);

    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    assert_int_equal(ret, EOK);

    talloc_free(conf_db);

    /* [sssd] */
    val[0] = TEST_DOMAIN_ENABLED_1 ", " TEST_DOMAIN_ENABLED_3 ", " TEST_DOMAIN_DISABLED_3;
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    assert_int_equal(ret, EOK);

    /* [domain/enabled_1] */
    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_ENABLED_1, "id_provider", val);
    assert_int_equal(ret, EOK);

    /* [domain/enabled_2] */
    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_ENABLED_2, "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = "true";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_ENABLED_2, "enabled", val);
    assert_int_equal(ret, EOK);

    /* [domain/enabled_3] */
    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_ENABLED_3, "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = "true";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_ENABLED_3, "enabled", val);
    assert_int_equal(ret, EOK);

    /* [domain/disabled_1] */
    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_DISABLED_1, "id_provider", val);
    assert_int_equal(ret, EOK);

    /* [domain/disabled_2] */
    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_DISABLED_2, "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = "false";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_DISABLED_2, "enabled", val);
    assert_int_equal(ret, EOK);

    /* [domain/disabled_3] */
    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_DISABLED_3, "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = "false";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/" TEST_DOMAIN_DISABLED_3, "enabled", val);
    assert_int_equal(ret, EOK);

    check_leaks_push(test_ctx);

    *state = test_ctx;
    return 0;
}


static int confdb_test_teardown(void **state)
{
    struct test_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}


static void test_confdb_get_domain_enabled(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    int ret;
    bool enabled;
    struct {
        const char* domain;
        int ret;
        bool enabled;
    } expected[] = {
        {
            TEST_DOMAIN_ENABLED_1,
            ENOENT,
            false
        },
        {
            TEST_DOMAIN_ENABLED_2,
            EOK,
            true
        },
        {
            TEST_DOMAIN_ENABLED_3,
            EOK,
            true
        },
        {
            TEST_DOMAIN_DISABLED_1,
            ENOENT,
            true
        },
        {
            TEST_DOMAIN_DISABLED_2,
            EOK,
            false
        },
        {
            TEST_DOMAIN_DISABLED_3,
            EOK,
            false
        },
        {
            "unexistingdomain",
            ENOENT,
            false
        },
        {
            NULL,
            ENOENT,
            false
        },
    };

    for (int index = 0; expected[index].domain; index++) {
        ret = confdb_get_domain_enabled(test_ctx->confdb, expected[index].domain, &enabled);
        assert_int_equal(ret, expected[index].ret);
        ret = confdb_get_domain_enabled(test_ctx->confdb, expected[index].domain, &enabled);
        if (ret == EOK) {
            if (expected[index].enabled) {
                assert_true(enabled);
            } else {
                assert_false(enabled);
            }
        }
    }
}


static void test_confdb_get_enabled_domain_list(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    TALLOC_CTX* tmp_ctx = talloc_new(NULL);
    char** result = NULL;
    int ret = EOK;

    const char* expected_enabled_domain_list[] = {
        TEST_DOMAIN_ENABLED_1,
        TEST_DOMAIN_ENABLED_2,
        TEST_DOMAIN_ENABLED_3,
        NULL
    };

    ret = confdb_get_enabled_domain_list(test_ctx->confdb, tmp_ctx, &result);
    assert_int_equal(EOK, ret);
    assert_non_null(result);
    for (int index = 0; expected_enabled_domain_list[index]; index++) {
        assert_true(string_in_list(expected_enabled_domain_list[index], result, false));
    }
    for (int index = 0; result[index]; index++) {
        assert_true(string_in_list(result[index], discard_const(expected_enabled_domain_list), false));
    }

    TALLOC_FREE(tmp_ctx);
}


int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    int no_cleanup = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_confdb_get_domain_enabled,
                                        confdb_test_setup,
                                        confdb_test_teardown),
        cmocka_unit_test_setup_teardown(test_confdb_get_enabled_domain_list,
                                        confdb_test_setup,
                                        confdb_test_teardown),
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

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, NULL);
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, NULL);
    }

    return rv;
}
