/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <talloc.h>
#include <errno.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "providers/ipa/ipa_dn.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_ipa_dn_conf.ldb"
#define TEST_DOM_NAME "ipa_dn_test"
#define TEST_ID_PROVIDER "ipa"

struct ipa_dn_test_ctx {
    struct sss_test_ctx *tctx;
    struct sysdb_ctx *sysdb;
};

static int ipa_dn_test_setup(void **state)
{
    struct ipa_dn_test_ctx *test_ctx = NULL;

    test_ctx = talloc_zero(NULL, struct ipa_dn_test_ctx);
    assert_non_null(test_ctx);
    *state = test_ctx;

    /* initialize domain */
    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    test_ctx->sysdb = test_ctx->tctx->sysdb;

    return 0;
}

static int ipa_dn_test_teardown(void **state)
{
    talloc_zfree(*state);
    return 0;
}

static void ipa_check_rdn_test(void **state)
{
    struct ipa_dn_test_ctx *test_ctx = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct ipa_dn_test_ctx);

    ret = ipa_check_rdn(test_ctx->sysdb, "cn=rdn,dc=example,dc=com", "cn");
    assert_int_equal(ret, EOK);

    ret = ipa_check_rdn(test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", "cn", "attr1", "value1");
    assert_int_equal(ret, EOK);

    ret = ipa_check_rdn(test_ctx->sysdb, "cn=rdn,attr1=value1,attr2=value2,dc=example,dc=com", "cn", "attr1", "value1", "attr2", "value2");
    assert_int_equal(ret, EOK);

    ret = ipa_check_rdn(test_ctx->sysdb, "cn=rdn,dc=example,dc=com", "nope");
    assert_int_equal(ret, ENOENT);

    ret = ipa_check_rdn(test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", "cn", "nope", "value1");
    assert_int_equal(ret, ENOENT);

    ret = ipa_check_rdn(test_ctx->sysdb, "cn=rdn,attr1=value1,attr2=value2,dc=example,dc=com", "cn", "attr1", "nope");
    assert_int_equal(ret, ENOENT);

    ret = ipa_check_rdn(test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", "cn", "attr1");
    assert_int_equal(ret, ENOENT);

    ret = ipa_check_rdn(test_ctx->sysdb, "cn=rdn,attr1=value1", "cn", "attr1", "value1");
    assert_int_equal(ret, ENOENT);
}

static void ipa_check_rdn_bool_test(void **state)
{
    struct ipa_dn_test_ctx *test_ctx = NULL;
    bool bret;

    test_ctx = talloc_get_type_abort(*state, struct ipa_dn_test_ctx);

    bret = ipa_check_rdn_bool(test_ctx->sysdb, "cn=rdn,dc=example,dc=com", "cn");
    assert_true(bret);

    bret = ipa_check_rdn_bool(test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", "cn", "attr1", "value1");
    assert_true(bret);

    bret = ipa_check_rdn_bool(test_ctx->sysdb, "cn=rdn,attr1=value1,attr2=value2,dc=example,dc=com", "cn", "attr1", "value1", "attr2", "value2");
    assert_true(bret);

    bret = ipa_check_rdn_bool(test_ctx->sysdb, "cn=rdn,dc=example,dc=com", "nope");
    assert_false(bret);

    bret = ipa_check_rdn_bool(test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", "cn", "nope", "value1");
    assert_false(bret);

    bret = ipa_check_rdn_bool(test_ctx->sysdb, "cn=rdn,attr1=value1,attr2=value2,dc=example,dc=com", "cn", "attr1", "nope");
    assert_false(bret);

    bret = ipa_check_rdn_bool(test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", "cn", "attr1");
    assert_false(bret);

    bret = ipa_check_rdn_bool(test_ctx->sysdb, "cn=rdn,attr1=value1", "cn", "attr1", "value1");
    assert_false(bret);
}

static void ipa_get_rdn_test(void **state)
{
    struct ipa_dn_test_ctx *test_ctx = NULL;
    const char *exprdn = "rdn";
    char *rdn = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct ipa_dn_test_ctx);

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb, "cn=rdn,dc=example,dc=com", &rdn, "cn");
    assert_int_equal(ret, EOK);
    assert_non_null(rdn);
    assert_string_equal(exprdn, rdn);

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", &rdn, "cn", "attr1", "value1");
    assert_int_equal(ret, EOK);
    assert_non_null(rdn);
    assert_string_equal(exprdn, rdn);

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb, "cn=rdn,attr1=value1,attr2=value2,dc=example,dc=com", &rdn, "cn", "attr1", "value1", "attr2", "value2");
    assert_int_equal(ret, EOK);
    assert_non_null(rdn);
    assert_string_equal(exprdn, rdn);

    rdn = NULL;

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb, "cn=rdn,dc=example,dc=com", &rdn, "nope");
    assert_int_equal(ret, ENOENT);
    assert_null(rdn);

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", &rdn, "cn", "nope", "value1");
    assert_int_equal(ret, ENOENT);
    assert_null(rdn);

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb, "cn=rdn,attr1=value1,attr2=value2,dc=example,dc=com", &rdn, "cn", "attr1", "nope");
    assert_int_equal(ret, ENOENT);
    assert_null(rdn);

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb, "cn=rdn,attr1=value1,dc=example,dc=com", &rdn, "cn", "attr1");
    assert_int_equal(ret, ENOENT);
    assert_null(rdn);

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb, "cn=rdn,attr1=value1", &rdn, "cn", "attr1", "value1");
    assert_int_equal(ret, ENOENT);
    assert_null(rdn);

    ret = ipa_get_rdn(test_ctx, test_ctx->sysdb,
                      "cn=rdn+nsuniqueid=9b1e3301-c32611e6-bdcae37a-ef905e7c,"
                      "attr1=value1,attr2=value2,dc=example,dc=com",
                      &rdn, "cn", "attr1", "value1", "attr2", "value2");
    assert_int_equal(ret, ENOENT);
    assert_null(rdn);
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
        cmocka_unit_test_setup_teardown(ipa_check_rdn_test,
                                        ipa_dn_test_setup,
                                        ipa_dn_test_teardown),
        cmocka_unit_test_setup_teardown(ipa_check_rdn_bool_test,
                                        ipa_dn_test_setup,
                                        ipa_dn_test_teardown),
        cmocka_unit_test_setup_teardown(ipa_get_rdn_test,
                                        ipa_dn_test_setup,
                                        ipa_dn_test_teardown)
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
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }
    return rv;
}
