/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

    SSSD tests - sdap certmap

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
#include <stdbool.h>
#include <setjmp.h>
#include <unistd.h>
#include <cmocka.h>
#include <popt.h>

#include "providers/ldap/ldap_common.h"
#include "tests/common.h"
#include "db/sysdb.h"

#define TESTS_PATH "certmap_" BASE_FILE_STEM
#define TEST_CONF_DB "test_sysdb_certmap.ldb"
#define TEST_ID_PROVIDER "ldap"
#define TEST_DOM_NAME "certmap_test"

struct certmap_info map_a = { discard_const("map_a"), 11,
                              NULL, discard_const("(abc=def)"),
                              NULL };
struct certmap_info map_b = { discard_const("map_b"), UINT_MAX,
                              NULL, NULL, NULL };
struct certmap_info *certmap[] = { &map_a, &map_b, NULL };

struct certmap_test_ctx {
    struct sss_test_ctx *tctx;
    struct sdap_id_ctx *id_ctx;
};

static int test_sysdb_setup(void **state)
{
    int ret;
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

    ret = sysdb_update_certmap(test_ctx->tctx->sysdb, certmap, false);
    assert_int_equal(ret, EOK);

    test_ctx->id_ctx = talloc_zero(test_ctx->tctx, struct sdap_id_ctx);
    assert_non_null(test_ctx->id_ctx);

    test_ctx->id_ctx->opts = talloc_zero(test_ctx->tctx, struct sdap_options);
    assert_non_null(test_ctx->id_ctx->opts);

    test_ctx->id_ctx->be = talloc_zero(test_ctx->tctx, struct be_ctx);
    assert_non_null(test_ctx->id_ctx->be);
    test_ctx->id_ctx->be->domain = test_ctx->tctx->dom;

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

static void test_sdap_certmap_init(void **state)
{
    int ret;
    struct certmap_test_ctx *test_ctx = talloc_get_type(*state,
                                                       struct certmap_test_ctx);

    ret = sdap_init_certmap(test_ctx, test_ctx->id_ctx);
    assert_int_equal(ret, EOK);

    talloc_free(test_ctx->id_ctx->opts->sdap_certmap_ctx);
}

static void test_sdap_get_sss_certmap(void **state)
{
    int ret;
    struct certmap_test_ctx *test_ctx = talloc_get_type(*state,
                                                       struct certmap_test_ctx);
    struct sss_certmap_ctx *sss_certmap_ctx;

    sss_certmap_ctx = sdap_get_sss_certmap(NULL);
    assert_null(sss_certmap_ctx);

    ret = sdap_init_certmap(test_ctx, test_ctx->id_ctx);
    assert_int_equal(ret, EOK);

    sss_certmap_ctx = sdap_get_sss_certmap(
                                      test_ctx->id_ctx->opts->sdap_certmap_ctx);
    assert_non_null(sss_certmap_ctx);

    talloc_free(test_ctx->id_ctx->opts->sdap_certmap_ctx);
}

static void test_sdap_certmap_init_twice(void **state)
{
    int ret;
    struct certmap_test_ctx *test_ctx = talloc_get_type(*state,
                                                       struct certmap_test_ctx);
    struct sdap_certmap_ctx *sdap_certmap_ref;
    struct sss_certmap_ctx *sss_certmap_ref;

    ret = sdap_init_certmap(test_ctx, test_ctx->id_ctx);
    assert_int_equal(ret, EOK);

    sdap_certmap_ref = test_ctx->id_ctx->opts->sdap_certmap_ctx;
    sss_certmap_ref = sdap_get_sss_certmap(sdap_certmap_ref);

    ret = sdap_init_certmap(test_ctx, test_ctx->id_ctx);
    assert_int_equal(ret, EOK);

    assert_ptr_equal(sdap_certmap_ref,
                     test_ctx->id_ctx->opts->sdap_certmap_ctx);
    assert_ptr_not_equal(sss_certmap_ref,
                         sdap_get_sss_certmap(sdap_certmap_ref));

    talloc_free(test_ctx->id_ctx->opts->sdap_certmap_ctx);
}


static void test_sdap_setup_certmap(void **state)
{
    int ret;
    struct certmap_test_ctx *test_ctx = talloc_get_type(*state,
                                                       struct certmap_test_ctx);
    struct sdap_certmap_ctx *sdap_certmap_ref;
    struct sss_certmap_ctx *sss_certmap_ref;

    ret = sdap_init_certmap(test_ctx, test_ctx->id_ctx);
    assert_int_equal(ret, EOK);

    sdap_certmap_ref = test_ctx->id_ctx->opts->sdap_certmap_ctx;
    sss_certmap_ref = sdap_get_sss_certmap(sdap_certmap_ref);

    ret = sdap_setup_certmap(NULL, NULL);
    assert_int_equal(ret, EINVAL);
    assert_ptr_equal(sdap_certmap_ref,
                     test_ctx->id_ctx->opts->sdap_certmap_ctx);
    assert_ptr_equal(sss_certmap_ref, sdap_get_sss_certmap(sdap_certmap_ref));

    ret = sdap_setup_certmap(NULL, certmap);
    assert_int_equal(ret, EINVAL);
    assert_ptr_equal(sdap_certmap_ref,
                     test_ctx->id_ctx->opts->sdap_certmap_ctx);
    assert_ptr_equal(sss_certmap_ref, sdap_get_sss_certmap(sdap_certmap_ref));

    ret = sdap_setup_certmap(sdap_certmap_ref, certmap);
    assert_int_equal(ret, EOK);
    assert_ptr_equal(sdap_certmap_ref,
                     test_ctx->id_ctx->opts->sdap_certmap_ctx);
    assert_ptr_not_equal(sss_certmap_ref,
                         sdap_get_sss_certmap(sdap_certmap_ref));

    talloc_free(test_ctx->id_ctx->opts->sdap_certmap_ctx);
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
        cmocka_unit_test_setup_teardown(test_sdap_certmap_init,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_get_sss_certmap,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_certmap_init_twice,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sdap_setup_certmap,
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
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
