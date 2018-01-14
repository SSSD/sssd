/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: IPA subdomain util tests

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
#include <tevent.h>
#include <errno.h>
#include <popt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>

#include "providers/ipa/ipa_subdomains.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"

struct test_ipa_subdom_ctx {
    struct ldb_context *ldb;
};

static int test_ipa_subdom_setup(void **state)
{
    struct test_ipa_subdom_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ipa_subdom_ctx);
    assert_non_null(test_ctx);

    test_ctx->ldb = ldb_init(test_ctx, NULL);
    assert_non_null(test_ctx->ldb);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_ipa_subdom_teardown(void **state)
{
    struct test_ipa_subdom_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct test_ipa_subdom_ctx);
    assert_non_null(test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static struct sysdb_attrs *dn_attrs(TALLOC_CTX *mem_ctx, const char *dn)
{
    struct sysdb_attrs *attrs;
    int rv;

    attrs = sysdb_new_attrs(mem_ctx);
    assert_non_null(attrs);

    rv = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, dn);
    assert_int_equal(rv, EOK);

    return attrs;
}

static void test_ipa_subdom_ldb_dn(void **state)
{
    struct ldb_dn *dn;
    struct sysdb_attrs *attrs;
    struct test_ipa_subdom_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct test_ipa_subdom_ctx);
    assert_non_null(test_ctx);

    attrs = dn_attrs(test_ctx, "dc=foo,dc=bar");
    assert_non_null(attrs);

    dn = ipa_subdom_ldb_dn(test_ctx, test_ctx->ldb, attrs);
    assert_non_null(dn);
    assert_string_equal(ldb_dn_get_linearized(dn), "dc=foo,dc=bar");

    talloc_free(dn);
    talloc_free(attrs);
}

static void test_ipa_subdom_ldb_dn_fail(void **state)
{
    struct ldb_dn *dn;
    struct sysdb_attrs *attrs;
    struct test_ipa_subdom_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct test_ipa_subdom_ctx);
    assert_non_null(test_ctx);

    attrs = dn_attrs(test_ctx, "notadn");
    assert_non_null(attrs);

    dn = ipa_subdom_ldb_dn(test_ctx, NULL, NULL);
    assert_null(dn);

    dn = ipa_subdom_ldb_dn(test_ctx, test_ctx->ldb, attrs);
    assert_null(dn);
    talloc_free(attrs);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);
    dn = ipa_subdom_ldb_dn(test_ctx, test_ctx->ldb, attrs);
    assert_null(dn);
    talloc_free(attrs);
}

static struct ldb_dn *get_dn(TALLOC_CTX *mem_ctx,
                             struct ldb_context *ldb,
                             const char *strdn)
{
    struct ldb_dn *dn;
    struct sysdb_attrs *attrs;

    attrs = dn_attrs(mem_ctx, strdn);
    assert_non_null(attrs);

    dn = ipa_subdom_ldb_dn(mem_ctx, ldb, attrs);
    talloc_free(attrs);
    assert_non_null(dn);

    return dn;
}

static void test_ipa_subdom_is_member_dom(void **state)
{
    struct ldb_dn *dn;
    struct test_ipa_subdom_ctx *test_ctx;
    bool is_member;

    test_ctx = talloc_get_type(*state, struct test_ipa_subdom_ctx);

    dn = get_dn(test_ctx, test_ctx->ldb,
                "cn=SUB.AD.DOM,cn=AD.DOM,cn=ad,cn=trusts,dc=example,dc=com");
    is_member = ipa_subdom_is_member_dom(dn);
    talloc_free(dn);
    assert_true(is_member);

    dn = get_dn(test_ctx, test_ctx->ldb,
                "cn=AD.DOM,cn=ad,cn=trusts,dc=example,dc=com");
    is_member = ipa_subdom_is_member_dom(dn);
    talloc_free(dn);
    assert_false(is_member);

    dn = get_dn(test_ctx, test_ctx->ldb,
                "cn=SUB.AD.DOM,cn=AD.DOM,cn=ad,cn=XXX,dc=example,dc=com");
    is_member = ipa_subdom_is_member_dom(dn);
    talloc_free(dn);
    assert_false(is_member);

    dn = get_dn(test_ctx, test_ctx->ldb,
                "cn=SUB.AD.DOM,cn=AD.DOM,cn=YYY,cn=trusts,dc=example,dc=com");
    is_member = ipa_subdom_is_member_dom(dn);
    talloc_free(dn);
    assert_false(is_member);
}

int main(int argc, const char *argv[])
{
    int rv;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ipa_subdom_ldb_dn,
                                        test_ipa_subdom_setup,
                                        test_ipa_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_ipa_subdom_ldb_dn_fail,
                                        test_ipa_subdom_setup,
                                        test_ipa_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_ipa_subdom_is_member_dom,
                                        test_ipa_subdom_setup,
                                        test_ipa_subdom_teardown),
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

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    return rv;
}
