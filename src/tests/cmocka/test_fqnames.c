/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Fully Qualified Names Tests

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

#include <popt.h>

#include "tests/cmocka/common_mock.h"

#define NAME        "name"
#define DOMNAME     "domname"
#define FLATNAME    "flatname"

struct fqdn_test_ctx {
    struct sss_domain_info *dom;

    struct sss_names_ctx *nctx;
};

void fqdn_test_setup(void **state)
{
    struct fqdn_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct fqdn_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->dom = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(test_ctx->dom);
    test_ctx->dom->name = discard_const(DOMNAME);
    test_ctx->dom->flat_name = discard_const(FLATNAME);

    check_leaks_push(test_ctx);
    *state = test_ctx;
}

void fqdn_test_teardown(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Type mismatch\n"));
        return;
    }

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
}

void test_default(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    char *fqdn;
    const int fqdn_size = 255;
    char fqdn_s[fqdn_size];

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Type mismatch\n"));
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   "(?P<name>[^@]+)@?(?P<domain>[^@]*$)",
                                   "%1$s@%2$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    fqdn = sss_tc_fqname(test_ctx, test_ctx->nctx, test_ctx->dom, NAME);
    assert_non_null(fqdn);
    assert_string_equal(fqdn, NAME"@"DOMNAME);
    talloc_free(fqdn);

    ret = sss_fqname(fqdn_s, fqdn_size, test_ctx->nctx, test_ctx->dom, NAME);
    assert_int_equal(ret + 1, sizeof(NAME"@"DOMNAME));
    assert_string_equal(fqdn_s, NAME"@"DOMNAME);

    talloc_free(test_ctx->nctx);
}

void test_all(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    char *fqdn;
    const int fqdn_size = 255;
    char fqdn_s[fqdn_size];

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Type mismatch\n"));
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   "(?P<name>[^@]+)@?(?P<domain>[^@]*$)",
                                   "%1$s@%2$s@%3$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    fqdn = sss_tc_fqname(test_ctx, test_ctx->nctx, test_ctx->dom, NAME);
    assert_non_null(fqdn);
    assert_string_equal(fqdn, NAME"@"DOMNAME"@"FLATNAME);
    talloc_free(fqdn);

    ret = sss_fqname(fqdn_s, fqdn_size, test_ctx->nctx, test_ctx->dom, NAME);
    assert_int_equal(ret + 1, sizeof(NAME"@"DOMNAME"@"FLATNAME));
    assert_string_equal(fqdn_s, NAME"@"DOMNAME"@"FLATNAME);

    talloc_free(test_ctx->nctx);
}

void test_flat(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    char *fqdn;
    const int fqdn_size = 255;
    char fqdn_s[fqdn_size];

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Type mismatch\n"));
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   "(?P<name>[^@]+)@?(?P<domain>[^@]*$)",
                                   "%1$s@%3$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    fqdn = sss_tc_fqname(test_ctx, test_ctx->nctx, test_ctx->dom, NAME);
    assert_non_null(fqdn);
    assert_string_equal(fqdn, NAME"@"FLATNAME);
    talloc_free(fqdn);

    ret = sss_fqname(fqdn_s, fqdn_size, test_ctx->nctx, test_ctx->dom, NAME);
    assert_int_equal(ret + 1, sizeof(NAME"@"FLATNAME));
    assert_string_equal(fqdn_s, NAME"@"FLATNAME);

    talloc_free(test_ctx->nctx);
}

void test_flat_fallback(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    char *fqdn;
    const int fqdn_size = 255;
    char fqdn_s[fqdn_size];

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Type mismatch\n"));
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   "(?P<name>[^@]+)@?(?P<domain>[^@]*$)",
                                   "%1$s@%3$s", &test_ctx->nctx);
    assert_int_equal(ret, EOK);

    test_ctx->dom->flat_name = NULL;

    /* If flat name is requested but does not exist, the code falls back to domain
     * name
     */
    fqdn = sss_tc_fqname(test_ctx, test_ctx->nctx, test_ctx->dom, NAME);
    assert_non_null(fqdn);
    assert_string_equal(fqdn, NAME"@"DOMNAME);
    talloc_free(fqdn);

    ret = sss_fqname(fqdn_s, fqdn_size, test_ctx->nctx, test_ctx->dom, NAME);
    assert_int_equal(ret + 1, sizeof(NAME"@"DOMNAME));
    assert_string_equal(fqdn_s, NAME"@"DOMNAME);

    talloc_free(test_ctx->nctx);
}

void test_init_nouser(void **state)
{
    struct fqdn_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct fqdn_test_ctx);
    errno_t ret;

    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Type mismatch\n"));
        return;
    }

    ret = sss_names_init_from_args(test_ctx,
                                   "(?P<name>[^@]+)@?(?P<domain>[^@]*$)",
                                   "%2$s@%3$s", &test_ctx->nctx);
    /* Initialization with no user name must fail */
    assert_int_not_equal(ret, EOK);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_default,
                                 fqdn_test_setup, fqdn_test_teardown),
        unit_test_setup_teardown(test_all,
                                 fqdn_test_setup, fqdn_test_teardown),
        unit_test_setup_teardown(test_flat,
                                 fqdn_test_setup, fqdn_test_teardown),
        unit_test_setup_teardown(test_flat_fallback,
                                 fqdn_test_setup, fqdn_test_teardown),
        unit_test_setup_teardown(test_init_nouser,
                                 fqdn_test_setup, fqdn_test_teardown),
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

    DEBUG_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();

    return run_tests(tests);
}
