/*
    SSSD

    sysdb_subdomains - Tests for subdomains and related calls

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include "tests/common.h"
#include "db/sysdb_private.h" /* for sysdb->ldb member */

#define TESTS_PATH "test_sysdb_subdomains"
#define TEST_CONF_DB "test_sysdb_subdomains.ldb"
#define TEST_DOM_NAME "test_sysdb_subdomains"
#define TEST_ID_PROVIDER "local"

struct subdom_test_ctx {
    struct sss_test_ctx *tctx;
};

static int test_sysdb_subdom_setup(void **state)
{
    struct subdom_test_ctx *test_ctx;
    struct sss_test_conf_param params[] = {
        { NULL, NULL },             /* Sentinel */
    };

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct subdom_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH,
                                         TEST_CONF_DB, TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, params);
    assert_non_null(test_ctx->tctx);

    *state = test_ctx;
    return 0;
}

static int test_sysdb_subdom_teardown(void **state)
{
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);

    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_sysdb_subdomain_create(void **state)
{
    errno_t ret;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);

    const char *const dom1[4] = { "dom1.sub", "DOM1.SUB", "dom1", "S-1" };
    const char *const dom2[4] = { "dom2.sub", "DOM2.SUB", "dom2", "S-2" };

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom1[0], dom1[1], dom1[2], dom1[3],
                                false, false, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    assert_non_null(test_ctx->tctx->dom->subdomains);
    assert_string_equal(test_ctx->tctx->dom->subdomains->name, dom1[0]);
    assert_int_equal(test_ctx->tctx->dom->subdomains->trust_direction, 0);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom2[0], dom2[1], dom2[2], dom2[3],
                                false, false, NULL, 1);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    assert_non_null(test_ctx->tctx->dom->subdomains->next);
    assert_string_equal(test_ctx->tctx->dom->subdomains->next->name, dom2[0]);
    assert_int_equal(test_ctx->tctx->dom->subdomains->next->trust_direction, 1);

    /* Reverse the trust directions */
    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom1[0], dom1[1], dom1[2], dom1[3],
                                false, false, NULL, 1);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                dom2[0], dom2[1], dom2[2], dom2[3],
                                false, false, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    assert_int_equal(test_ctx->tctx->dom->subdomains->trust_direction, 1);
    assert_int_equal(test_ctx->tctx->dom->subdomains->next->trust_direction, 0);

    ret = sysdb_subdomain_delete(test_ctx->tctx->sysdb, dom2[0]);
    assert_int_equal(ret, EOK);

    ret = sysdb_subdomain_delete(test_ctx->tctx->sysdb, dom1[0]);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    assert_true(test_ctx->tctx->dom->subdomains->disabled);
}

static void test_sysdb_master_domain_ops(void **state)
{
    errno_t ret;
    struct subdom_test_ctx *test_ctx =
        talloc_get_type(*state, struct subdom_test_ctx);


    ret = sysdb_master_domain_add_info(test_ctx->tctx->dom,
                                       "realm1", "flat1", "id1", "forest1");
    assert_int_equal(ret, EOK);

    ret = sysdb_master_domain_update(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    assert_string_equal(test_ctx->tctx->dom->realm, "realm1");
    assert_string_equal(test_ctx->tctx->dom->flat_name, "flat1");
    assert_string_equal(test_ctx->tctx->dom->domain_id, "id1");
    assert_string_equal(test_ctx->tctx->dom->forest, "forest1");

    ret = sysdb_master_domain_add_info(test_ctx->tctx->dom,
                                       "realm2", "flat2", "id2", "forest2");
    assert_int_equal(ret, EOK);

    ret = sysdb_master_domain_update(test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    assert_string_equal(test_ctx->tctx->dom->realm, "realm2");
    assert_string_equal(test_ctx->tctx->dom->flat_name, "flat2");
    assert_string_equal(test_ctx->tctx->dom->domain_id, "id2");
    assert_string_equal(test_ctx->tctx->dom->forest, "forest2");
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

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sysdb_master_domain_ops,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_subdomain_create,
                                        test_sysdb_subdom_setup,
                                        test_sysdb_subdom_teardown),
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
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, LOCAL_SYSDB_FILE);
    test_dom_suite_setup(TESTS_PATH);
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    if (rv == 0 && no_cleanup == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, LOCAL_SYSDB_FILE);
    }
    return rv;
}
