/*
    Authors:
        Petr Čech <pcech@redhat.com>

    Copyright (C) 2016 Red Hat

    SSSD tests: AD subdomain tests

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

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "providers/ad/ad_common.h"

#include "providers/ad/ad_subdomains.c"
#include "providers/ad/ad_opts.c"

#define AD_DOMAIN "ad_domain.domain.test"
#define DOMAIN_1 "one.domain.test"
#define DOMAIN_2 "two.domain.test"

struct test_ad_subdom_ctx {
    struct ad_id_ctx *ad_id_ctx;
};

static struct ad_id_ctx *
test_ad_subdom_init_ad_id_ctx(TALLOC_CTX *mem_ctx)
{
    struct ad_id_ctx *ad_id_ctx;
    struct ad_options *ad_options;
    errno_t ret;

    ad_id_ctx = talloc_zero(mem_ctx, struct ad_id_ctx);
    assert_non_null(ad_id_ctx);

    ad_options = talloc_zero(ad_id_ctx, struct ad_options);
    assert_non_null(ad_options);

    ret = dp_copy_defaults(ad_options,
                           ad_basic_opts,
                           AD_OPTS_BASIC,
                           &ad_options->basic);
    assert_int_equal(ret, EOK);

    ad_id_ctx->ad_options = ad_options;

    return ad_id_ctx;
}

static int test_ad_subdom_setup(void **state)
{
    struct test_ad_subdom_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ad_subdom_ctx);
    assert_non_null(test_ctx);

    test_ctx->ad_id_ctx = NULL;

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_ad_subdom_teardown(void **state)
{
    struct test_ad_subdom_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct test_ad_subdom_ctx);
    assert_non_null(test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_ad_subdom_default(void **state)
{
    struct test_ad_subdom_ctx *test_ctx;
    const char **ad_enabled_domains = NULL;
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_ad_subdom_ctx);
    test_ctx->ad_id_ctx = test_ad_subdom_init_ad_id_ctx(test_ctx);
    assert_non_null(test_ctx->ad_id_ctx);

    ret = ad_get_enabled_domains(test_ctx, test_ctx->ad_id_ctx,
                                 AD_DOMAIN,
                                 &ad_enabled_domains);
    assert_int_equal(ret, EOK);
    assert_null(ad_enabled_domains);

    talloc_zfree(test_ctx->ad_id_ctx);
}

static void test_ad_subdom_add_one(void **state)
{
    struct test_ad_subdom_ctx *test_ctx;
    const char **ad_enabled_domains = NULL;
    int enabled_domains_count;
    int domain_count = 2;
    const char *domains[domain_count];
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_ad_subdom_ctx);
    test_ctx->ad_id_ctx = test_ad_subdom_init_ad_id_ctx(test_ctx);
    assert_non_null(test_ctx->ad_id_ctx);

    ret = dp_opt_set_string(test_ctx->ad_id_ctx->ad_options->basic,
                            AD_ENABLED_DOMAINS, DOMAIN_1);
    assert_int_equal(ret, EOK);

    ret = ad_get_enabled_domains(test_ctx, test_ctx->ad_id_ctx,
                                 AD_DOMAIN,
                                 &ad_enabled_domains);
    assert_int_equal(ret, EOK);
    assert_non_null(ad_enabled_domains);

    for (enabled_domains_count = 0;
         ad_enabled_domains[enabled_domains_count] != NULL;
         enabled_domains_count++) {
    }
    assert_int_equal(domain_count, enabled_domains_count);

    domains[0] = AD_DOMAIN;
    domains[1] = DOMAIN_1;
    assert_true(are_values_in_array(domains, domain_count,
                                    ad_enabled_domains, enabled_domains_count));

    talloc_zfree(test_ctx->ad_id_ctx);
    talloc_zfree(ad_enabled_domains);
}

static void test_ad_subdom_add_two(void **state)
{
    struct test_ad_subdom_ctx *test_ctx;
    const char **ad_enabled_domains = NULL;
    int enabled_domains_count;
    int domain_count = 3;
    const char *domains[domain_count];
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_ad_subdom_ctx);
    test_ctx->ad_id_ctx = test_ad_subdom_init_ad_id_ctx(test_ctx);
    assert_non_null(test_ctx->ad_id_ctx);

    ret = dp_opt_set_string(test_ctx->ad_id_ctx->ad_options->basic,
                            AD_ENABLED_DOMAINS, DOMAIN_1","DOMAIN_2);
    assert_int_equal(ret, EOK);

    ret = ad_get_enabled_domains(test_ctx, test_ctx->ad_id_ctx,
                                 AD_DOMAIN,
                                 &ad_enabled_domains);
    assert_int_equal(ret, EOK);
    assert_non_null(ad_enabled_domains);

    for (enabled_domains_count = 0;
         ad_enabled_domains[enabled_domains_count] != NULL;
         enabled_domains_count++) {
    }
    assert_int_equal(domain_count, enabled_domains_count);

    domains[0] = AD_DOMAIN;
    domains[1] = DOMAIN_1;
    domains[2] = DOMAIN_2;
    assert_true(are_values_in_array(domains, domain_count,
                                    ad_enabled_domains, enabled_domains_count));

    talloc_zfree(test_ctx->ad_id_ctx);
    talloc_zfree(ad_enabled_domains);
}

static void test_ad_subdom_add_master(void **state)
{
    struct test_ad_subdom_ctx *test_ctx;
    const char **ad_enabled_domains = NULL;
    int enabled_domains_count;
    int domain_count = 1;
    const char *domains[domain_count];
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_ad_subdom_ctx);
    test_ctx->ad_id_ctx = test_ad_subdom_init_ad_id_ctx(test_ctx);
    assert_non_null(test_ctx->ad_id_ctx);

    ret = dp_opt_set_string(test_ctx->ad_id_ctx->ad_options->basic,
                            AD_ENABLED_DOMAINS, AD_DOMAIN);
    assert_int_equal(ret, EOK);

    ret = ad_get_enabled_domains(test_ctx, test_ctx->ad_id_ctx,
                                 AD_DOMAIN,
                                 &ad_enabled_domains);
    assert_int_equal(ret, EOK);
    assert_non_null(ad_enabled_domains);

    for (enabled_domains_count = 0;
         ad_enabled_domains[enabled_domains_count] != NULL;
         enabled_domains_count++) {
    }
    assert_int_equal(domain_count, enabled_domains_count);

    domains[0] = AD_DOMAIN;
    assert_true(are_values_in_array(domains, domain_count,
                                    ad_enabled_domains, enabled_domains_count));

    talloc_zfree(test_ctx->ad_id_ctx);
    talloc_zfree(ad_enabled_domains);
}

static void test_ad_subdom_add_two_with_master(void **state)
{
    struct test_ad_subdom_ctx *test_ctx;
    const char **ad_enabled_domains = NULL;
    int enabled_domains_count;
    int domain_count = 3;
    const char *domains[domain_count];
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_ad_subdom_ctx);
    test_ctx->ad_id_ctx = test_ad_subdom_init_ad_id_ctx(test_ctx);
    assert_non_null(test_ctx->ad_id_ctx);

    ret = dp_opt_set_string(test_ctx->ad_id_ctx->ad_options->basic,
                            AD_ENABLED_DOMAINS,
                            DOMAIN_1","AD_DOMAIN","DOMAIN_2);
    assert_int_equal(ret, EOK);

    ret = ad_get_enabled_domains(test_ctx, test_ctx->ad_id_ctx,
                                 AD_DOMAIN,
                                 &ad_enabled_domains);
    assert_int_equal(ret, EOK);
    assert_non_null(ad_enabled_domains);

    for (enabled_domains_count = 0;
         ad_enabled_domains[enabled_domains_count] != NULL;
         enabled_domains_count++) {
    }
    assert_int_equal(domain_count, enabled_domains_count);

    domains[0] = AD_DOMAIN;
    domains[1] = DOMAIN_1;
    domains[2] = DOMAIN_2;
    assert_true(are_values_in_array(domains, domain_count,
                                    ad_enabled_domains, enabled_domains_count));

    talloc_zfree(test_ctx->ad_id_ctx);
    talloc_zfree(ad_enabled_domains);
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
        cmocka_unit_test_setup_teardown(test_ad_subdom_default,
                                        test_ad_subdom_setup,
                                        test_ad_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_ad_subdom_add_one,
                                        test_ad_subdom_setup,
                                        test_ad_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_ad_subdom_add_two,
                                        test_ad_subdom_setup,
                                        test_ad_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_ad_subdom_add_master,
                                        test_ad_subdom_setup,
                                        test_ad_subdom_teardown),
        cmocka_unit_test_setup_teardown(test_ad_subdom_add_two_with_master,
                                        test_ad_subdom_setup,
                                        test_ad_subdom_teardown),
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
