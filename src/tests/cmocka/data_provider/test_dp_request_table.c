/*
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
#include <tevent.h>
#include <errno.h>
#include <popt.h>

#include "providers/data_provider/dp_private.h"
#include "tests/cmocka/common_mock.h"
#include "tests/common.h"

struct test_ctx {
    hash_table_t *table;
};

static int test_setup(void **state)
{
    struct test_ctx *test_ctx = NULL;
    errno_t ret;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    ret = dp_req_table_init(test_ctx, &test_ctx->table);
    assert_int_equal(ret, EOK);
    assert_non_null(test_ctx->table);

    check_leaks_push(test_ctx);

    *state = test_ctx;

    return 0;
}

static int test_teardown(void **state)
{
    struct test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);

    return 0;
}

static const char *get_req_key(struct test_ctx* test_ctx)
{
     const char *req_name;

     req_name = dp_req_table_key(test_ctx,
                                 DPT_ID, DPM_ACCOUNT_HANDLER,
                                 DP_FAST_REPLY,
                                 "custom_part");
     assert_non_null(req_name);
     return req_name;
}

static void test_add_del_req(void **state)
{
    errno_t ret;
    bool is_present;
    const char *key;
    struct dp_table_value *tv;
    struct dp_table_value *tv2;
    struct sbus_request *sbus_req;
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    struct tevent_req *req;

    req = tevent_req_create(test_ctx, &state, struct test_ctx);
    assert_non_null(req);

    key = get_req_key(test_ctx);

    is_present = dp_req_table_has_key(test_ctx->table, key);
    assert_false(is_present);

    sbus_req = talloc(test_ctx, struct sbus_request);
    assert_non_null(sbus_req);

    ret = dp_req_table_add(test_ctx->table, key, req, sbus_req);
    assert_int_equal(ret, EOK);

    is_present = dp_req_table_has_key(test_ctx->table, key);
    assert_true(is_present);

    tv = dp_req_table_lookup(test_ctx->table, key);
    assert_non_null(tv);

    dp_req_table_del(test_ctx->table, key);

    tv2 = dp_req_table_lookup(test_ctx->table, key);
    assert_null(tv2);

    is_present = dp_req_table_has_key(test_ctx->table, key);
    assert_false(is_present);

    talloc_free(discard_const(key));
    talloc_free(tv);
    talloc_free(sbus_req);
    talloc_free(req);
}

static void test_del_non_present_req(void **state)
{
    bool is_present;
    hash_table_t *table;
    const char *key;
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    table = test_ctx->table;

    key = get_req_key(test_ctx);

    is_present = dp_req_table_has_key(table, key);
    assert_false(is_present);

    dp_req_table_del(table, key);

    is_present = dp_req_table_has_key(table, key);
    assert_false(is_present);

    talloc_free(discard_const(key));
}

static void test_mult_req(void **state)
{
    errno_t ret;
    bool is_present;
    hash_table_t *table;
    const char *key;
    struct sbus_request *sbus_req;
    struct sbus_request *sbus_req2;
    struct dp_table_value *tv;
    struct dp_table_value *tv2;
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    struct tevent_req *req;

    req = tevent_req_create(test_ctx, &state, struct test_ctx);
    assert_non_null(req);

    table = test_ctx->table;

    key = get_req_key(test_ctx);

    /* Add 1st request */
    is_present = dp_req_table_has_key(table, key);
    assert_false(is_present);

    sbus_req = talloc(test_ctx, struct sbus_request);
    assert_non_null(sbus_req);

    ret = dp_req_table_add(table, key, req, sbus_req);
    assert_int_equal(ret, EOK);

    is_present = dp_req_table_has_key(table, key);
    assert_true(is_present);

    tv = dp_req_table_lookup(table, key);
    assert_non_null(tv);
    assert_ptr_equal(tv->req, req);
    assert_ptr_equal(tv->list->sbus_req, sbus_req);

    /* Add 2nd request */
    is_present = dp_req_table_has_key(table, key);
    assert_true(is_present);

    sbus_req2 = talloc(test_ctx, struct sbus_request);
    assert_non_null(sbus_req2);

    ret = dp_req_table_add(table, key, NULL, sbus_req2);
    assert_int_equal(ret, EOK);

    is_present = dp_req_table_has_key(table, key);
    assert_true(is_present);

    tv = dp_req_table_lookup(table, key);
    assert_non_null(tv);
    assert_ptr_equal(tv->req, req);
    assert_ptr_equal(tv->list->sbus_req, sbus_req2);
    assert_non_null(tv->list->next);
    assert_ptr_equal(tv->list->next->sbus_req, sbus_req);

    /* Del req */
    dp_req_table_del(table, key);
    is_present = dp_req_table_has_key(table, key);
    assert_false(is_present);

    tv2 = dp_req_table_lookup(table, key);
    assert_null(tv2);

    /* Free memory */
    talloc_free(discard_const(key));
    talloc_free(tv);
    talloc_free(sbus_req);
    talloc_free(sbus_req2);
    talloc_free(req);
}

/* This test is aimed to test 'dp_sbus_req_item_destructor()' */
static void test_destructor_req(void **state)
{
    errno_t ret;
    bool is_present;
    hash_table_t *table;
    const char *key;
    struct dp_table_value *tv;
    struct dp_table_value *tv2;
    const int N = 5;
    const int MAGIC = 3;
    struct sbus_request *sbus_req[N];
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    struct tevent_req *req;

    req = tevent_req_create(test_ctx, &state, struct test_ctx);
    assert_non_null(req);

    table = test_ctx->table;

    key = get_req_key(test_ctx);

    is_present = dp_req_table_has_key(table, key);
    assert_false(is_present);

    /* Insert N sbus_requests for req_name */
    for (int i = 0; i < N; i++) {
        sbus_req[i] = talloc(test_ctx, struct sbus_request);
        assert_non_null(sbus_req[i]);

        ret = dp_req_table_add(table, key, req, sbus_req[i]);
        assert_int_equal(ret, EOK);
    }

    /* Check */
    is_present = dp_req_table_has_key(table, key);
    assert_true(is_present);

    tv = dp_req_table_lookup(table, key);
    assert_non_null(tv);
    assert_ptr_equal(tv->req, req);

    struct dp_sbus_req_item *ri = tv->list;
    for (int i = 0; i < N; i++) {
        assert_ptr_equal(ri->sbus_req, sbus_req[N-i-1]);
        ri = ri->next;
    }
    assert_null(ri);

    /* Del one req */
    talloc_free(sbus_req[MAGIC]);

    /* Check that only magic is missing */
    is_present = dp_req_table_has_key(table, key);
    assert_true(is_present);

    tv = dp_req_table_lookup(table, key);
    assert_non_null(tv);
    assert_ptr_equal(tv->req, req);

    ri = tv->list;
    assert_ptr_equal(ri->sbus_req, sbus_req[N-1]);
    ri = ri->next;
    /* Skip deleted MAGIC request */
    assert_ptr_equal(ri->sbus_req, sbus_req[N-3]);
    ri = ri->next;
    assert_ptr_equal(ri->sbus_req, sbus_req[N-4]);
    ri = ri->next;
    assert_ptr_equal(ri->sbus_req, sbus_req[N-5]);
    ri = ri->next;
    assert_null(ri);

    /* misc */
    dp_req_table_del(table, key);
    is_present = dp_req_table_has_key(table, key);
    assert_false(is_present);

    tv2 = dp_req_table_lookup(table, key);
    assert_null(tv2);

    /* Free memory */
    for (int i = 0; i < N; i++) {
        if (i != MAGIC) {
            talloc_free(sbus_req[i]);
        }
    }

    talloc_free(discard_const(key));
    talloc_free(tv);
                     talloc_free(req);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int no_cleanup = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_add_del_req,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_del_non_present_req,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_mult_req,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_destructor_req,
                                        test_setup,
                                        test_teardown),
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
