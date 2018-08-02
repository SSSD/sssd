/*
    SSSD

    sysdb_domain_resolution_order - Tests for domain resolution order calls

    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2017 Red Hat

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
#include "db/sysdb_domain_resolution_order.h"
#include "db/sysdb_private.h" /* for sysdb->ldb member */

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_sysdb_domain_resolution_order.ldb"

#define TEST_DOM_NAME "test_sysdb_domain_resolution_order"

#define TEST_ID_PROVIDER "ldap"

struct domain_resolution_order_test_ctx {
    struct sss_test_ctx *tctx;
};

static int test_sysdb_domain_resolution_order_setup(void **state)
{
    struct domain_resolution_order_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct domain_resolution_order_test_ctx);
    assert_non_null(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH,
                                         TEST_CONF_DB, TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    *state = test_ctx;
    return 0;
}

static int test_sysdb_domain_resolution_order_teardown(void **state)
{
    struct domain_resolution_order_test_ctx *test_ctx =
        talloc_get_type(*state, struct domain_resolution_order_test_ctx);

    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_sysdb_domain_resolution_order_ops(void **state)
{
    errno_t ret;
    struct domain_resolution_order_test_ctx *test_ctx =
        talloc_get_type(*state, struct domain_resolution_order_test_ctx);
    const char *domains_in = NULL;
    const char *domains_out = NULL;
    struct ldb_dn *dn;

    dn = sysdb_domain_dn(test_ctx, test_ctx->tctx->dom);
    assert_non_null(dn);

    /* Adding domainResolutionOrder for the first time */
    domains_in = "foo:bar:foobar";
    ret = sysdb_update_domain_resolution_order(test_ctx->tctx->dom->sysdb,
                                               dn, domains_in);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_domain_resolution_order(test_ctx,
                                            test_ctx->tctx->dom->sysdb, dn,
                                            &domains_out);
    assert_int_equal(ret, EOK);
    assert_true(strcmp(domains_in, domains_out) == 0);

    /* Setting the domainResolutionOrder to ":" ...
     *
     * It means, the domainResolutionOrder is set, but if there's another
     * domainResolutionOrder with lower precedence those must be ignored.
     */
    domains_in = ":";
    ret = sysdb_update_domain_resolution_order(test_ctx->tctx->dom->sysdb,
                                               dn, domains_in);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_domain_resolution_order(test_ctx,
                                            test_ctx->tctx->dom->sysdb, dn,
                                            &domains_out);
    assert_int_equal(ret, EOK);
    assert_true(strcmp(domains_in, domains_out) == 0);

    /* Changing the domainResolutionOrder */
    domains_in = "bar:foobar:foo";
    ret = sysdb_update_domain_resolution_order(test_ctx->tctx->dom->sysdb,
                                               dn, domains_in);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_domain_resolution_order(test_ctx,
                                            test_ctx->tctx->dom->sysdb, dn,
                                            &domains_out);
    assert_int_equal(ret, EOK);
    assert_true(strcmp(domains_in, domains_out) == 0);

    /* Removing the domainResolutionOrder attribute */
    domains_in = NULL;
    ret = sysdb_update_domain_resolution_order(test_ctx->tctx->dom->sysdb,
                                               dn, domains_in);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_domain_resolution_order(test_ctx,
                                            test_ctx->tctx->dom->sysdb, dn,
                                            &domains_out);
    assert_int_equal(ret, ENOENT);
    assert_true(domains_out == NULL);
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
        cmocka_unit_test_setup_teardown(test_sysdb_domain_resolution_order_ops,
                                        test_sysdb_domain_resolution_order_setup,
                                        test_sysdb_domain_resolution_order_teardown),
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
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, NULL);
    test_dom_suite_setup(TESTS_PATH);
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    if (rv == 0 && no_cleanup == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, NULL);
    }
    return rv;
}
