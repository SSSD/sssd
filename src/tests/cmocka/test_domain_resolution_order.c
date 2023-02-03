/*
    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2018 Red Hat

    SSSD tests: Tests for domain resolution order functions

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
#include <stdio.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "responder/common/cache_req/cache_req_domain.h"

#define DOM_COUNT 3
#define DOMAIN_1 "one.domain.test"
#define DOMAIN_2 "two.domain.test"
#define DOMAIN_3 "three.domain.test"
#define DOMAIN_RESOLUTION_ORDER DOMAIN_2":"DOMAIN_1
#define LDAP "ldap"
#define FILES "files"

struct domain_resolution_order_test_ctx {
    size_t dom_count;
    struct sss_domain_info *dom_list;
};

static void test_domain_resolution_order(void **state)
{
    struct domain_resolution_order_test_ctx *test_ctx;
    struct cache_req_domain *cr_domains = NULL;
    struct cache_req_domain *cr_domain;
    const char *expected_order[DOM_COUNT] = { DOMAIN_2, DOMAIN_1, DOMAIN_3 };
    errno_t ret;
    size_t c;

    test_ctx = talloc_get_type(*state,
                               struct domain_resolution_order_test_ctx);

    cr_domains = talloc_zero(test_ctx, struct cache_req_domain);
    ret = cache_req_domain_new_list_from_domain_resolution_order(
                                                    test_ctx,
                                                    test_ctx->dom_list,
                                                    DOMAIN_RESOLUTION_ORDER,
                                                    &cr_domains);
    assert_int_equal(ret, EOK);

    for (c = 0, cr_domain = cr_domains; cr_domain != NULL;
            cr_domain = cr_domain->next, c++) {
        assert_string_equal(expected_order[c], cr_domain->domain->name);
    }
}

#ifdef BUILD_FILES_PROVIDER
static void
test_domain_resolution_order_with_implicit_files_provider(void **state)
{
    struct domain_resolution_order_test_ctx *test_ctx;
    struct cache_req_domain *cr_domains = NULL;
    struct cache_req_domain *cr_domain;
    const char *expected_order[DOM_COUNT] = { DOMAIN_3, DOMAIN_2, DOMAIN_1 };
    errno_t ret;
    size_t c;

    test_ctx = talloc_get_type(*state,
                               struct domain_resolution_order_test_ctx);

    cr_domains = talloc_zero(test_ctx, struct cache_req_domain);
    ret = cache_req_domain_new_list_from_domain_resolution_order(
                                                    test_ctx,
                                                    test_ctx->dom_list,
                                                    DOMAIN_RESOLUTION_ORDER,
                                                    &cr_domains);
    assert_int_equal(ret, EOK);

    for (c = 0, cr_domain = cr_domains; cr_domain != NULL;
            cr_domain = cr_domain->next, c++) {
        assert_string_equal(expected_order[c], cr_domain->domain->name);
    }
}
#endif

static void test_domain_resolution_order_output_fqnames(void **state)
{
    struct domain_resolution_order_test_ctx *test_ctx;
    struct cache_req_domain *cr_domains = NULL;
    struct cache_req_domain *cr_domain;
    errno_t ret;

    test_ctx = talloc_get_type(*state,
                               struct domain_resolution_order_test_ctx);

    cr_domains = talloc_zero(test_ctx, struct cache_req_domain);
    ret = cache_req_domain_new_list_from_domain_resolution_order(
                                                    test_ctx,
                                                    test_ctx->dom_list,
                                                    DOMAIN_RESOLUTION_ORDER,
                                                    &cr_domains);
    assert_int_equal(ret, EOK);

    for (cr_domain = cr_domains; cr_domain != NULL;
            cr_domain = cr_domain->next) {
        struct sss_domain_info *dom = cr_domain->domain;
        bool expected = !is_files_provider(dom);
        bool output_fqnames = sss_domain_info_get_output_fqnames(dom);

        assert_true(expected == output_fqnames);
    }
}

static int setup_domains_list_helper(void **state, bool with_files_provider)
{
    struct domain_resolution_order_test_ctx *test_ctx;
    struct sss_domain_info *dom = NULL;
    const char *domains[DOM_COUNT] = { DOMAIN_1, DOMAIN_2, DOMAIN_3 };
    const char *providers[DOM_COUNT] = { LDAP, LDAP, LDAP };
    size_t c;

    if (with_files_provider) {
        providers[DOM_COUNT - 1] = FILES;
    }

    test_ctx = talloc_zero(global_talloc_context,
                           struct domain_resolution_order_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->dom_count = DOM_COUNT;

    for (c = 0; c < test_ctx->dom_count; c++) {
        dom = talloc_zero(test_ctx, struct sss_domain_info);
        assert_non_null(dom);

        dom->name = talloc_strdup(dom, domains[c]);
        assert_non_null(dom->name);

        dom->provider = talloc_strdup(dom, providers[c]);
        assert_non_null(dom->provider);

        DLIST_ADD(test_ctx->dom_list, dom);
    }

    *state = test_ctx;
    return 0;
}

static int setup_domains_list(void **state)
{
    return setup_domains_list_helper(state, false);
}

#ifdef BUILD_FILES_PROVIDER
static int setup_domains_list_with_implicit_files_provider(void **state)
{
    return setup_domains_list_helper(state, true);
}
#endif

static int teardown_domains_list(void **state)
{
    struct domain_resolution_order_test_ctx *test_ctx;

    test_ctx = talloc_get_type(*state,
                               struct domain_resolution_order_test_ctx);
    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Type mismatch\n");
        return 1;
    }

    talloc_free(test_ctx);
    return 0;
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_domain_resolution_order,
                                        setup_domains_list,
                                        teardown_domains_list),
#ifdef BUILD_FILES_PROVIDER
        cmocka_unit_test_setup_teardown(
                    test_domain_resolution_order_with_implicit_files_provider,
                    setup_domains_list_with_implicit_files_provider,
                    teardown_domains_list),
#endif
        cmocka_unit_test_setup_teardown(
                    test_domain_resolution_order_output_fqnames,
                    setup_domains_list,
                    teardown_domains_list),
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

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    return rv;
}
