/*
    SSSD

    sysdb_certmap - Tests for sysdb certmap related calls

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#define TESTS_PATH "certmap_" BASE_FILE_STEM
#define TEST_CONF_DB "test_sysdb_certmap.ldb"
#define TEST_ID_PROVIDER "ldap"
#define TEST_DOM_NAME "certmap_test"

struct certmap_test_ctx {
    struct sss_test_ctx *tctx;
};

static int test_sysdb_setup(void **state)
{
    struct certmap_test_ctx *test_ctx;
    struct sss_test_conf_param params[] = {
        { NULL, NULL },             /* Sentinel */
    };

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct certmap_test_ctx);
    assert_non_null(test_ctx);
    check_leaks_push(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH,
                                         TEST_CONF_DB, TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, params);
    assert_non_null(test_ctx->tctx);

    *state = test_ctx;
    return 0;
}

static int test_sysdb_teardown(void **state)
{
    struct certmap_test_ctx *test_ctx =
        talloc_get_type(*state, struct certmap_test_ctx);

    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    talloc_free(test_ctx->tctx);
    assert_true(check_leaks_pop(test_ctx));
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_sysdb_get_certmap_not_exists(void **state)
{
    int ret;
    struct certmap_info **certmap;
    bool user_name_hint;
    struct certmap_test_ctx *ctctx = talloc_get_type(*state,
                                                     struct certmap_test_ctx);

    ret = sysdb_get_certmap(ctctx, ctctx->tctx->sysdb, &certmap,
                            &user_name_hint);
    assert_int_equal(ret, EOK);
    assert_null(certmap);
}

static void check_certmap(struct certmap_info *m, struct certmap_info *r,
                          size_t exp_domains)
{
    size_t d;

    assert_non_null(r);
    assert_non_null(m);
    assert_string_equal(m->name, r->name);

    if (r->map_rule == NULL) {
        assert_null(m->map_rule);
    } else {
        assert_string_equal(m->map_rule, r->map_rule);
    }

    if (r->match_rule == NULL) {
        assert_null(m->match_rule);
    } else {
        assert_string_equal(m->match_rule, r->match_rule);
    }

    assert_int_equal(m->priority, r->priority);
    assert_non_null(m->domains);
    if (r->domains == NULL) {
        assert_null(m->domains[0]);
    } else {
        for (d = 0; r->domains[d]; d++) {
            assert_non_null(m->domains[d]);
            assert_true(string_in_list(m->domains[d], discard_const(r->domains),
                                       true));
        }

        assert_int_equal(d, exp_domains);
    }

}

static void test_sysdb_update_certmap(void **state)
{
    int ret;
    const char *domains[] = { "dom1.test", "dom2.test", "dom3.test", NULL };
    struct certmap_info map_a = { discard_const("map_a"), 11,
                                  discard_const("abc"), discard_const("def"),
                                  NULL };
    struct certmap_info map_b = { discard_const("map_b"), UINT_MAX,
                                  discard_const("abc"), NULL, domains };
    struct certmap_info map_c = { discard_const("cn=map_c,dc=sssd,dc=org"),
                                  UINT_MAX, discard_const("abc"), NULL,
                                  domains };

    struct certmap_info *certmap_empty[] = { NULL };
    struct certmap_info *certmap_a[] = { &map_a, NULL };
    struct certmap_info *certmap_b[] = { &map_b, NULL };
    struct certmap_info *certmap_ab[] = { &map_a, &map_b, NULL };
    struct certmap_info *certmap_c[] = { &map_c, NULL };
    struct certmap_info **certmap;
    struct certmap_test_ctx *ctctx = talloc_get_type(*state,
                                                     struct certmap_test_ctx);
    bool user_name_hint;

    ret = sysdb_update_certmap(ctctx->tctx->sysdb, NULL, false);
    assert_int_equal(ret, EINVAL);

    ret = sysdb_update_certmap(ctctx->tctx->sysdb, certmap_empty, false);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_certmap(ctctx, ctctx->tctx->sysdb, &certmap,
                            &user_name_hint);
    assert_int_equal(ret, EOK);
    assert_null(certmap);

    ret = sysdb_update_certmap(ctctx->tctx->sysdb, certmap_a, false);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_certmap(ctctx, ctctx->tctx->sysdb, &certmap,
                            &user_name_hint);
    assert_int_equal(ret, EOK);
    assert_false(user_name_hint);
    assert_non_null(certmap);
    assert_non_null(certmap[0]);
    assert_string_equal(certmap[0]->name, map_a.name);
    assert_string_equal(certmap[0]->map_rule, map_a.map_rule);
    assert_string_equal(certmap[0]->match_rule, map_a.match_rule);
    assert_int_equal(certmap[0]->priority, map_a.priority);
    assert_non_null(certmap[0]->domains);
    assert_null(certmap[0]->domains[0]);
    assert_null(certmap[1]);
    check_certmap(certmap[0], &map_a, 0);
    talloc_free(certmap);

    ret = sysdb_update_certmap(ctctx->tctx->sysdb, certmap_b, true);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_certmap(ctctx, ctctx->tctx->sysdb, &certmap,
                            &user_name_hint);
    assert_int_equal(ret, EOK);
    assert_true(user_name_hint);
    assert_non_null(certmap);
    assert_non_null(certmap[0]);

    check_certmap(certmap[0], &map_b, 3);
    assert_null(certmap[1]);
    talloc_free(certmap);

    ret = sysdb_update_certmap(ctctx->tctx->sysdb, certmap_ab, false);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_certmap(ctctx, ctctx->tctx->sysdb, &certmap,
                            &user_name_hint);
    assert_int_equal(ret, EOK);
    assert_false(user_name_hint);
    assert_non_null(certmap);
    assert_non_null(certmap[0]);
    assert_non_null(certmap[1]);
    assert_null(certmap[2]);
    if (strcmp(certmap[0]->name, "map_a") == 0) {
        check_certmap(certmap[0], &map_a, 0);
        check_certmap(certmap[1], &map_b, 3);
    } else {
        check_certmap(certmap[0], &map_b, 3);
        check_certmap(certmap[1], &map_a, 0);
    }
    talloc_free(certmap);

    ret = sysdb_update_certmap(ctctx->tctx->sysdb, certmap_c, false);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_certmap(ctctx, ctctx->tctx->sysdb, &certmap,
                            &user_name_hint);
    assert_int_equal(ret, EOK);
    assert_false(user_name_hint);
    assert_non_null(certmap);
    assert_non_null(certmap[0]);
    check_certmap(certmap[0], &map_c, 3);
    assert_null(certmap[1]);
    talloc_free(certmap);
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
        cmocka_unit_test_setup_teardown(test_sysdb_get_certmap_not_exists,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_update_certmap,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
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
