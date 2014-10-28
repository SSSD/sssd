/*
    SSSD

    sysdb_views - Tests for view and override related sysdb calls

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"

#define TESTS_PATH "tests_sysdb"
#define TEST_CONF_FILE "tests_conf.ldb"

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;
};

static int _setup_sysdb_tests(struct sysdb_test_ctx **ctx, bool enumerate)
{
    struct sysdb_test_ctx *test_ctx;
    char *conf_db;
    int ret;

    const char *val[2];
    val[1] = NULL;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    assert_true(ret == 0 || errno == EEXIST);

    test_ctx = talloc_zero(global_talloc_context, struct sysdb_test_ctx);
    assert_non_null(test_ctx);

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    assert_non_null(test_ctx->ev);

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    assert_non_null(conf_db);
    DEBUG(SSSDBG_MINOR_FAILURE, "CONFDB: %s\n", conf_db);

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    assert_int_equal(ret, EOK);

    val[0] = "LOCAL";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    assert_int_equal(ret, EOK);

    val[0] = "local";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = enumerate ? "TRUE" : "FALSE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "enumerate", val);
    assert_int_equal(ret, EOK);

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "cache_credentials", val);
    assert_int_equal(ret, EOK);

    ret = sssd_domain_init(test_ctx, test_ctx->confdb, "local",
                           TESTS_PATH, &test_ctx->domain);
    assert_int_equal(ret, EOK);

    test_ctx->sysdb = test_ctx->domain->sysdb;

    *ctx = test_ctx;
    return EOK;
}

#define setup_sysdb_tests(ctx) _setup_sysdb_tests((ctx), false)

static void test_sysdb_setup(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    ret = setup_sysdb_tests(&test_ctx);
    assert_int_equal(ret, EOK);

    *state = (void *) test_ctx;
}

static void test_sysdb_teardown(void **state)
{
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
}

void test_sysdb_add_overrides_to_object(void **state)
{
    int ret;
    struct ldb_message *orig;
    struct ldb_message *override;
    struct ldb_message_element *el;
    char *tmp_str;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    orig = ldb_msg_new(test_ctx);
    assert_non_null(orig);

    tmp_str = talloc_strdup(orig,  "ORIGNAME");
    ret = ldb_msg_add_string(orig, SYSDB_NAME, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(orig,  "ORIGGECOS");
    ret = ldb_msg_add_string(orig, SYSDB_GECOS, tmp_str);
    assert_int_equal(ret, EOK);

    override = ldb_msg_new(test_ctx);
    assert_non_null(override);

    tmp_str = talloc_strdup(override, "OVERRIDENAME");
    ret = ldb_msg_add_string(override, SYSDB_NAME, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEGECOS");
    ret = ldb_msg_add_string(override, SYSDB_GECOS, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEKEY1");
    ret = ldb_msg_add_string(override, SYSDB_SSH_PUBKEY, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEKEY2");
    ret = ldb_msg_add_string(override, SYSDB_SSH_PUBKEY, tmp_str);
    assert_int_equal(ret, EOK);


    ret = sysdb_add_overrides_to_object(test_ctx->domain, orig, override, NULL);
    assert_int_equal(ret, EOK);

    assert_string_equal(ldb_msg_find_attr_as_string(orig, SYSDB_NAME, NULL),
                        "ORIGNAME");
    assert_string_equal(ldb_msg_find_attr_as_string(orig, SYSDB_GECOS, NULL),
                        "ORIGGECOS");
    assert_string_equal(ldb_msg_find_attr_as_string(orig,
                                                    OVERRIDE_PREFIX SYSDB_NAME,
                                                    NULL),
                        "OVERRIDENAME");
    assert_string_equal(ldb_msg_find_attr_as_string(orig,
                                                    OVERRIDE_PREFIX SYSDB_GECOS,
                                                    NULL),
                        "OVERRIDEGECOS");

    el = ldb_msg_find_element(orig, OVERRIDE_PREFIX SYSDB_SSH_PUBKEY);
    assert_non_null(el);
    assert_int_equal(el->num_values, 2);
    assert_int_equal(ldb_val_string_cmp(&el->values[0], "OVERRIDEKEY1"), 0);
    assert_int_equal(ldb_val_string_cmp(&el->values[1], "OVERRIDEKEY2"), 0);
}

int main(int argc, const char *argv[])
{
    int rv;
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_sysdb_add_overrides_to_object,
                                 test_sysdb_setup, test_sysdb_teardown),
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

    DEBUG_CLI_INIT(debug_level);

    tests_set_cwd();
    rv = run_tests(tests);

    if (rv == 0 && no_cleanup == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, LOCAL_SYSDB_FILE);
    }
    return rv;
}
