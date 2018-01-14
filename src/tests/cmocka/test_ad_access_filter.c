/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: AD access control filter tests

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
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

/* In order to access opaque types */
#include "providers/ad/ad_access.c"

#include "tests/cmocka/common_mock.h"

#define DOM_NAME "parent_dom"

struct ad_access_test_ctx {
    struct sss_domain_info *dom;
};

static struct ad_access_test_ctx *test_ctx;

int ad_access_filter_test_setup(void **state)
{
    assert_true(leak_check_setup());
    test_ctx = talloc_zero(global_talloc_context,
                           struct ad_access_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->dom = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(test_ctx->dom);

    test_ctx->dom->name = talloc_strdup(test_ctx->dom, DOM_NAME);
    assert_non_null(test_ctx->dom->name);
    return 0;
}

int ad_access_filter_test_teardown(void **state)
{
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

struct filter_parse_result {
    const int result;
    const char *best_match;
};

static void test_parse_filter_generic(const char *filter_in,
                                      struct filter_parse_result *expected)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *best_match;

    assert_non_null(expected);

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    ret = ad_parse_access_filter(tmp_ctx, test_ctx->dom, filter_in,
                                 &best_match);
    assert_int_equal(ret, expected->result);
    if (expected->result != EOK) {
        goto done;
    }

    if (expected->best_match != NULL) {
        assert_string_equal(best_match, expected->best_match);
    } else {
        assert_true(best_match == NULL);
    }
    talloc_free(best_match);

done:
    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

/* Test that setting no filter lets all access through
 */
void test_no_filter(void **state)
{
    struct filter_parse_result expected = {
        .result = EOK,
        .best_match = NULL
    };

    test_parse_filter_generic(NULL, &expected);
}

/* Test that if one filter is provided, it is returned as-is
 */
void test_single_filter(void **state)
{
    struct filter_parse_result expected = {
        .result = EOK,
        .best_match = "(name=foo)"
    };

    test_parse_filter_generic("name=foo", &expected);
    test_parse_filter_generic("(name=foo)", &expected);
    test_parse_filter_generic(DOM_NAME":(name=foo)", &expected);
    test_parse_filter_generic("DOM:"DOM_NAME":(name=foo)", &expected);
}

/* Test that if more filters are provided, the best match is returned */
void test_filter_order(void **state)
{
    struct filter_parse_result expected = {
        .result = EOK,
        .best_match = "(name=foo)"
    };

    test_parse_filter_generic("name=foo?name=bar", &expected);
    test_parse_filter_generic(DOM_NAME":(name=foo)?name=bar", &expected);
    test_parse_filter_generic("name=bla?"DOM_NAME":(name=foo)?name=bar", &expected);
    /* Test that another foreign domain wouldn't match */
    test_parse_filter_generic("anotherdom:(name=bla)?"DOM_NAME":(name=foo)", &expected);
    test_parse_filter_generic("anotherdom:(name=bla)?(name=foo)", &expected);
}

void test_filter_no_match(void **state)
{
    struct filter_parse_result expected = {
        .result = EOK,
        .best_match = NULL
    };

    test_parse_filter_generic("anotherdom:(name=bla)?yetanother:(name=foo)", &expected);
}


int parse_test_setup(void **state)
{
    assert_true(leak_check_setup());
    return 0;
}

int parse_test_teardown(void **state)
{
    assert_true(leak_check_teardown());
    return 0;
}

struct parse_result {
    const int result;
    const char *filter;
    const char *spec;
    const int  flags;
};

static void test_parse_generic(const char *filter_in, struct parse_result *expected)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *filter;
    char *spec;
    int flags;

    assert_non_null(expected);

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    ret = parse_filter(tmp_ctx, filter_in, &filter, &spec, &flags);

    assert_int_equal(ret, expected->result);
    if (expected->result != EOK) {
        goto done;
    }

    if (expected->filter != NULL) {
        assert_string_equal(filter, expected->filter);
    } else {
        assert_true(filter == NULL);
    }
    talloc_free(filter);

    if (expected->spec != NULL) {
        assert_string_equal(spec, expected->spec);
    } else {
        assert_true(spec == NULL);
    }
    talloc_free(spec);

    assert_int_equal(flags, expected->flags);

done:
    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

void test_parse_plain(void **state)
{
    struct parse_result expected = {
        .result = EOK,
        .filter = "name=foo",
        .spec = NULL,
        .flags = AD_FILTER_GENERIC
    };

    test_parse_generic("name=foo", &expected);
}

void test_parse_dom_without_kw(void **state)
{
    struct parse_result expected = {
        .result = EOK,
        .filter = "(name=foo)",
        .spec = "mydom",
        .flags = AD_FILTER_DOMAIN
    };

    test_parse_generic("mydom:(name=foo)", &expected);

    /* Check we can handle domain called DOM */
    struct parse_result expected2 = {
        .result = EOK,
        .filter = "(name=foo)",
        .spec = "DOM",
        .flags = AD_FILTER_DOMAIN
    };

    test_parse_generic("DOM:(name=foo)", &expected2);
}

void test_parse_dom_kw(void **state)
{
    struct parse_result expected = {
        .result = EOK,
        .filter = "(name=foo)",
        .spec = "mydom",
        .flags = AD_FILTER_DOMAIN
    };

    test_parse_generic("DOM:mydom:(name=foo)", &expected);
}

void test_parse_forest_kw(void **state)
{
    struct parse_result expected = {
        .result = EOK,
        .filter = "(name=foo)",
        .spec = "myforest",
        .flags = AD_FILTER_FOREST
    };

    test_parse_generic("FOREST:myforest:(name=foo)", &expected);
}


void test_parse_malformed(void **state)
{
    struct parse_result expected = {
        .result = EINVAL,
    };

    test_parse_generic("DOM:", &expected);
    test_parse_generic("DOM::", &expected);
    test_parse_generic("DOM:mydom:", &expected);
    test_parse_generic("DOM:mydom:name=foo", &expected);
    test_parse_generic("DOM::(name=foo)", &expected);
    test_parse_generic("BLABLABLA:mydom:name=foo", &expected);
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

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_parse_plain,
                                        parse_test_setup,
                                        parse_test_teardown),

        cmocka_unit_test_setup_teardown(test_parse_dom_without_kw,
                                        parse_test_setup,
                                        parse_test_teardown),

        cmocka_unit_test_setup_teardown(test_parse_dom_kw,
                                        parse_test_setup,
                                        parse_test_teardown),

        cmocka_unit_test_setup_teardown(test_parse_forest_kw,
                                        parse_test_setup,
                                        parse_test_teardown),

        cmocka_unit_test_setup_teardown(test_parse_malformed,
                                        parse_test_setup,
                                        parse_test_teardown),

        cmocka_unit_test_setup_teardown(test_no_filter,
                                        ad_access_filter_test_setup,
                                        ad_access_filter_test_teardown),

        cmocka_unit_test_setup_teardown(test_single_filter,
                                        ad_access_filter_test_setup,
                                        ad_access_filter_test_teardown),

        cmocka_unit_test_setup_teardown(test_filter_order,
                                        ad_access_filter_test_setup,
                                        ad_access_filter_test_teardown),

        cmocka_unit_test_setup_teardown(test_filter_no_match,
                                        ad_access_filter_test_setup,
                                        ad_access_filter_test_teardown),

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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
