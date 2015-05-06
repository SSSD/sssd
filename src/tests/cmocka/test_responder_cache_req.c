/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "db/sysdb.h"
#include "responder/common/responder_cache_req.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_responder_cache_req_conf.ldb"
#define TEST_DOM_NAME "responder_cache_req_test"
#define TEST_ID_PROVIDER "ldap"

#define TEST_USER_NAME "test-user"
#define TEST_UPN "upn@upndomain.com"
#define TEST_USER_ID 1000
#define TEST_GROUP_NAME "test-group"
#define TEST_GROUP_ID 1000

#define TEST_USER_NAME2 "test-user2"
#define TEST_GROUP_NAME2 "test-group2"

#define new_single_domain_test(test) \
    cmocka_unit_test_setup_teardown(test_ ## test, \
                                    test_single_domain_setup, \
                                    test_single_domain_teardown)

#define new_multi_domain_test(test) \
    cmocka_unit_test_setup_teardown(test_ ## test, \
                                    test_multi_domain_setup, \
                                    test_multi_domain_teardown)

struct cache_req_test_ctx {
    struct sss_test_ctx *tctx;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;

    struct ldb_result *result;
    struct sss_domain_info *domain;
    char *name;
    bool dp_called;
    bool create_user;
    bool create_group;
};

const char *domains[] = {"responder_cache_req_test_a",
                         "responder_cache_req_test_b",
                         "responder_cache_req_test_c",
                         "responder_cache_req_test_d",
                         NULL};

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version version[] = {
        { 0, NULL, NULL }
    };

    return version;
}

struct tevent_req *
__wrap_sss_dp_get_account_send(TALLOC_CTX *mem_ctx,
                               struct resp_ctx *rctx,
                               struct sss_domain_info *dom,
                               bool fast_reply,
                               enum sss_dp_acct_type type,
                               const char *opt_name,
                               uint32_t opt_id,
                               const char *extra)
{
    struct sysdb_attrs *attrs = NULL;
    struct cache_req_test_ctx *ctx = NULL;
    errno_t ret;

    ctx = sss_mock_ptr_type(struct cache_req_test_ctx*);
    ctx->dp_called = true;

    if (ctx->create_user) {
        attrs = sysdb_new_attrs(ctx);
        assert_non_null(attrs);

        ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, TEST_UPN);
        assert_int_equal(ret, EOK);

        ret = sysdb_store_user(ctx->tctx->dom, TEST_USER_NAME, "pwd",
                               TEST_USER_ID, 1000, NULL, NULL, NULL,
                               "cn=test-user,dc=test", attrs, NULL,
                               1000, time(NULL));
        assert_int_equal(ret, EOK);
    }

    if (ctx->create_group) {
        ret = sysdb_store_group(ctx->tctx->dom, TEST_GROUP_NAME,
                                TEST_GROUP_ID, NULL, 1000, time(NULL));
        assert_int_equal(ret, EOK);
    }

    return test_req_succeed_send(mem_ctx, rctx->ev);
}

static void cache_req_user_by_name_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_user_by_name_recv(ctx, req,
                                                   &ctx->result,
                                                   &ctx->domain,
                                                   &ctx->name);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void cache_req_user_by_id_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_user_by_id_recv(ctx, req,
                                                 &ctx->result, &ctx->domain);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void cache_req_group_by_name_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_group_by_name_recv(ctx, req,
                                                    &ctx->result,
                                                    &ctx->domain,
                                                    &ctx->name);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void cache_req_group_by_id_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_group_by_id_recv(ctx, req,
                                                  &ctx->result, &ctx->domain);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static int test_single_domain_setup(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;

    test_dom_suite_setup(TESTS_PATH);

    test_ctx = talloc_zero(NULL, struct cache_req_test_ctx);
    assert_non_null(test_ctx);
    *state = test_ctx;

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME, TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    test_ctx->rctx = mock_rctx(test_ctx, test_ctx->tctx->ev,
                               test_ctx->tctx->dom, NULL);
    assert_non_null(test_ctx->rctx);

    ret = sss_ncache_init(test_ctx, &test_ctx->ncache);
    assert_int_equal(ret, EOK);
    return 0;
}

static int test_single_domain_teardown(void **state)
{
    talloc_zfree(*state);
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    return 0;
}

static int test_multi_domain_setup(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;

    test_dom_suite_setup(TESTS_PATH);

    test_ctx = talloc_zero(NULL, struct cache_req_test_ctx);
    assert_non_null(test_ctx);
    *state = test_ctx;

    test_ctx->tctx = create_multidom_test_ctx(test_ctx, TESTS_PATH,
                                              TEST_CONF_DB, domains,
                                              TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    test_ctx->rctx = mock_rctx(test_ctx, test_ctx->tctx->ev,
                               test_ctx->tctx->dom, NULL);
    assert_non_null(test_ctx->rctx);

    ret = sss_ncache_init(test_ctx, &test_ctx->ncache);
    assert_int_equal(ret, EOK);
    return 0;
}

static int test_multi_domain_teardown(void **state)
{
    talloc_zfree(*state);
    test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    return 0;
}

void test_user_by_name_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    ret = sysdb_store_user(domain, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(name, NULL, ERR_OK);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      NULL, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    assert_non_null(test_ctx->domain);
    assert_string_equal(domain->name, test_ctx->domain->name);
}

void test_user_by_name_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(name, NULL, ERR_OK);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      NULL, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_user_by_name_multiple_domains_parse(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *fqn = NULL;
    const char *ldbname = NULL;
    uid_t uid = 2000;
    uid_t ldbuid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Add user to the first domain. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_a", true);
    assert_non_null(domain);

    ret = sysdb_store_user(domain, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    /* Add user to the last domain, with different uid. */

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    ret = sysdb_store_user(domain, name, "pwd", uid, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    /* Append domain name to the username. */
    fqn = talloc_asprintf(test_ctx, "%s@%s", name,
                          "responder_cache_req_test_d");
    assert_non_null(fqn);

    /* Test. */
    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    mock_parse_inp(name, "responder_cache_req_test_d", ERR_OK);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      NULL, fqn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));
    assert_false(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbuid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_UIDNUM, 0);
    assert_int_equal(ldbuid, uid);

    assert_non_null(test_ctx->domain);
    assert_string_equal(domain->name, test_ctx->domain->name);

    assert_non_null(test_ctx->name);
    assert_string_equal(name, test_ctx->name);
}

void test_user_by_name_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_user_by_name_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, -1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_user_by_name_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 50, time(NULL) - 26);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 50,
                                      test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_user_by_name_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sss_ncache_set_user(test_ctx->ncache, false,
                              test_ctx->tctx->dom, name);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 100, 0,
                                      test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_false(test_ctx->dp_called);
}

void test_user_by_name_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_user = true;

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 100, 0,
                                      test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_user_by_name_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 100, 0,
                                      test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_user_by_upn_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sysdb_attrs *attrs = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *upn = TEST_UPN;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, upn);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(domain, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", attrs,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      NULL, upn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    assert_non_null(test_ctx->domain);
    assert_string_equal(domain->name, test_ctx->domain->name);
}

void test_user_by_upn_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *upn = TEST_UPN;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      NULL, upn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_user_by_upn_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sysdb_attrs *attrs = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *upn = TEST_UPN;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, upn);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", attrs,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      NULL, upn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_user_by_upn_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sysdb_attrs *attrs = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *upn = TEST_UPN;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, upn);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", attrs,
                           NULL, -1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 0,
                                      NULL, upn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_user_by_upn_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs *attrs = NULL;
    const char *upn = TEST_UPN;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, upn);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", 1000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", attrs,
                           NULL, 50, time(NULL) - 26);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 10, 50,
                                      NULL, upn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_user_by_upn_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *upn = TEST_UPN;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sss_ncache_set_user(test_ctx->ncache, false,
                              test_ctx->tctx->dom, upn);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 100, 0,
                                      NULL, upn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_false(test_ctx->dp_called);
}

void test_user_by_upn_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *upn = TEST_UPN;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    test_ctx->create_user = true;

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 100, 0,
                                      NULL, upn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_user_by_upn_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *upn = TEST_UPN;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache, 100, 0,
                                      NULL, upn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_user_by_id_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    uid_t uid = TEST_USER_ID;
    const char *ldbname = NULL;
    uid_t ldbuid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    ret = sysdb_store_user(domain, name, "pwd", uid, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    req = cache_req_user_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                    test_ctx->rctx, test_ctx->ncache, 10, 0,
                                    NULL, uid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbuid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_UIDNUM, 0);
    assert_int_equal(ldbuid, uid);

    assert_non_null(test_ctx->domain);
    assert_string_equal(domain->name, test_ctx->domain->name);
}

void test_user_by_id_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    uid_t uid = TEST_USER_ID;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    req = cache_req_user_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                    test_ctx->rctx, test_ctx->ncache, 10, 0,
                                    NULL, uid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_user_by_id_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    uid_t uid = TEST_USER_ID;
    uid_t ldbuid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", uid, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_user_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                    test_ctx->rctx, test_ctx->ncache, 10, 0,
                                    test_ctx->tctx->dom->name, uid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbuid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_UIDNUM, 0);
    assert_int_equal(ldbuid, uid);
}

void test_user_by_id_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    uid_t uid = TEST_USER_ID;
    uid_t ldbuid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", uid, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, -1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_user_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                    test_ctx->rctx, test_ctx->ncache, 10, 0,
                                    test_ctx->tctx->dom->name, uid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbuid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_UIDNUM, 0);
    assert_int_equal(ldbuid, uid);
}

void test_user_by_id_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    uid_t uid = TEST_USER_ID;
    uid_t ldbuid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_user(test_ctx->tctx->dom, name, "pwd", uid, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 50, time(NULL) - 26);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    req = cache_req_user_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                    test_ctx->rctx, test_ctx->ncache, 10, 50,
                                    test_ctx->tctx->dom->name, uid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbuid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_UIDNUM, 0);
    assert_int_equal(ldbuid, uid);
}

void test_user_by_id_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    uid_t uid = TEST_USER_ID;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sss_ncache_set_uid(test_ctx->ncache, false, NULL, uid);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_user_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                    test_ctx->rctx, test_ctx->ncache, 100, 0,
                                    test_ctx->tctx->dom->name, uid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_false(test_ctx->dp_called);
}

void test_user_by_id_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_USER_NAME;
    const char *ldbname = NULL;
    uid_t uid = TEST_USER_ID;
    uid_t ldbuid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_user = true;

    req = cache_req_user_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                    test_ctx->rctx, test_ctx->ncache, 100, 0,
                                    test_ctx->tctx->dom->name, uid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbuid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_UIDNUM, 0);
    assert_int_equal(ldbuid, uid);
}

void test_user_by_id_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    uid_t uid = TEST_USER_ID;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_user_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                    test_ctx->rctx, test_ctx->ncache, 100, 0,
                                    test_ctx->tctx->dom->name, uid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_group_by_name_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    ret = sysdb_store_group(domain, name, TEST_GROUP_ID, NULL,
                            1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(name, NULL, ERR_OK);

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 10, 0,
                                       NULL, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    assert_non_null(test_ctx->domain);
    assert_string_equal(domain->name, test_ctx->domain->name);
}

void test_group_by_name_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(name, NULL, ERR_OK);

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 10, 0,
                                       NULL, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_group_by_name_multiple_domains_parse(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *fqn = NULL;
    const char *ldbname = NULL;
    uid_t gid = 2000;
    uid_t ldbgid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Add user to the first domain. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_a", true);
    assert_non_null(domain);

    ret = sysdb_store_group(domain, name, 1000, NULL,
                            1000, time(NULL));
    assert_int_equal(ret, EOK);

    /* Add user to the last domain, with different uid. */

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    ret = sysdb_store_group(domain, name, gid, NULL,
                            1000, time(NULL));
    assert_int_equal(ret, EOK);

    /* Append domain name to the username. */
    fqn = talloc_asprintf(test_ctx, "%s@%s", name,
                          "responder_cache_req_test_d");
    assert_non_null(fqn);

    /* Test. */
    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    mock_parse_inp(name, "responder_cache_req_test_d", ERR_OK);

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 10, 0,
                                       NULL, fqn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));
    assert_false(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbgid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_GIDNUM, 0);
    assert_int_equal(ldbgid, gid);

    assert_non_null(test_ctx->domain);
    assert_string_equal(domain->name, test_ctx->domain->name);

    assert_non_null(test_ctx->name);
    assert_string_equal(name, test_ctx->name);
}

void test_group_by_name_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_group(test_ctx->tctx->dom, name, TEST_GROUP_ID, NULL,
                            1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 10, 0,
                                       test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_group_by_name_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_group(test_ctx->tctx->dom, name, TEST_GROUP_ID, NULL,
                            -1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 10, 0,
                                       test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_group_by_name_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_group(test_ctx->tctx->dom, name, TEST_GROUP_ID, NULL,
                            50, time(NULL) - 26);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 10, 50,
                                       test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_group_by_name_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sss_ncache_set_group(test_ctx->ncache, false,
                               test_ctx->tctx->dom, name);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 100, 0,
                                       test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_false(test_ctx->dp_called);
}

void test_group_by_name_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_group = true;

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 100, 0,
                                       test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);
}

void test_group_by_name_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 100, 0,
                                       test_ctx->tctx->dom->name, name);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_group_by_id_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    gid_t gid = TEST_GROUP_ID;
    gid_t ldbgid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    ret = sysdb_store_group(domain, name, gid, NULL,
                            1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    req = cache_req_group_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                     test_ctx->rctx, test_ctx->ncache, 10, 0,
                                     NULL, gid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbgid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_GIDNUM, 0);
    assert_int_equal(ldbgid, gid);

    assert_non_null(test_ctx->domain);
    assert_string_equal(domain->name, test_ctx->domain->name);
}

void test_group_by_id_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    gid_t gid = TEST_GROUP_ID;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    req = cache_req_group_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                     test_ctx->rctx, test_ctx->ncache, 10, 0,
                                     NULL, gid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

void test_group_by_id_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    gid_t gid = TEST_GROUP_ID;
    gid_t ldbgid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_group(test_ctx->tctx->dom, name, gid, NULL,
                            1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_group_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                     test_ctx->rctx, test_ctx->ncache, 10, 0,
                                     test_ctx->tctx->dom->name, gid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbgid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_GIDNUM, 0);
    assert_int_equal(ldbgid, gid);
}

void test_group_by_id_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    gid_t gid = TEST_GROUP_ID;
    gid_t ldbgid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_group(test_ctx->tctx->dom, name, gid, NULL,
                            -1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_group_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                     test_ctx->rctx, test_ctx->ncache, 10, 0,
                                     test_ctx->tctx->dom->name, gid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbgid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_GIDNUM, 0);
    assert_int_equal(ldbgid, gid);
}

void test_group_by_id_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    gid_t gid = TEST_GROUP_ID;
    gid_t ldbgid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sysdb_store_group(test_ctx->tctx->dom, name, gid, NULL,
                            50, time(NULL) - 26);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    req = cache_req_group_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                     test_ctx->rctx, test_ctx->ncache, 10, 50,
                                     test_ctx->tctx->dom->name, gid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbgid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_GIDNUM, 0);
    assert_int_equal(ldbgid, gid);
}

void test_group_by_id_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    gid_t gid = TEST_GROUP_ID;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    ret = sss_ncache_set_gid(test_ctx->ncache, false, NULL, gid);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_group_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                     test_ctx->rctx, test_ctx->ncache, 100, 0,
                                     test_ctx->tctx->dom->name, gid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_false(test_ctx->dp_called);
}

void test_group_by_id_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *name = TEST_GROUP_NAME;
    const char *ldbname = NULL;
    gid_t gid = TEST_GROUP_ID;
    gid_t ldbgid;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_group = true;

    req = cache_req_group_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                     test_ctx->rctx, test_ctx->ncache, 100, 0,
                                     test_ctx->tctx->dom->name, gid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, name);

    ldbgid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_GIDNUM, 0);
    assert_int_equal(ldbgid, gid);
}

void test_group_by_id_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    gid_t gid = TEST_GROUP_ID;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_group_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
                                     test_ctx->rctx, test_ctx->ncache, 100, 0,
                                     test_ctx->tctx->dom->name, gid);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_true(test_ctx->dp_called);
}

static void cache_req_user_by_filter_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_user_by_filter_recv(ctx, req,
                                                     &ctx->result,
                                                     &ctx->domain);
    talloc_zfree(req);
    ctx->tctx->done = true;
}

void test_users_by_filter_filter_old(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_user = true;

    /* This user was updated in distant past, so it wont't be reported by
     * the filter search */
    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME2, "pwd", 1001, 1001,
                           NULL, NULL, NULL, "cn="TEST_USER_NAME2",dc=test", NULL,
                           NULL, 1000, 1);
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        test_ctx->tctx->dom->name,
                                        "test*");
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);

    ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                          SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    assert_string_equal(ldbname, TEST_USER_NAME);
}

void test_users_by_filter_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        test_ctx->tctx->dom->name,
                                        "nosuchuser*");
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));
}

static void test_users_by_filter_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        domain->name,
                                        "nosuchuser*");
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));
}

static void cache_req_group_by_filter_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_group_by_filter_recv(ctx, req,
                                                      &ctx->result,
                                                      &ctx->domain);
    talloc_zfree(req);
    ctx->tctx->done = true;
}

void test_groups_by_filter_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_group_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        test_ctx->tctx->dom->name,
                                        "nosuchgroup*");
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));
}

void test_groups_by_filter_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    req = cache_req_group_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        domain->name,
                                        "nosuchgroup*");
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));
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
        new_single_domain_test(user_by_name_cache_valid),
        new_single_domain_test(user_by_name_cache_expired),
        new_single_domain_test(user_by_name_cache_midpoint),
        new_single_domain_test(user_by_name_ncache),
        new_single_domain_test(user_by_name_missing_found),
        new_single_domain_test(user_by_name_missing_notfound),
        new_multi_domain_test(user_by_name_multiple_domains_found),
        new_multi_domain_test(user_by_name_multiple_domains_notfound),
        new_multi_domain_test(user_by_name_multiple_domains_parse),

        new_single_domain_test(user_by_upn_cache_valid),
        new_single_domain_test(user_by_upn_cache_expired),
        new_single_domain_test(user_by_upn_cache_midpoint),
        new_single_domain_test(user_by_upn_ncache),
        new_single_domain_test(user_by_upn_missing_found),
        new_single_domain_test(user_by_upn_missing_notfound),
        new_multi_domain_test(user_by_upn_multiple_domains_found),
        new_multi_domain_test(user_by_upn_multiple_domains_notfound),

        new_single_domain_test(user_by_id_cache_valid),
        new_single_domain_test(user_by_id_cache_expired),
        new_single_domain_test(user_by_id_cache_midpoint),
        new_single_domain_test(user_by_id_ncache),
        new_single_domain_test(user_by_id_missing_found),
        new_single_domain_test(user_by_id_missing_notfound),
        new_multi_domain_test(user_by_id_multiple_domains_found),
        new_multi_domain_test(user_by_id_multiple_domains_notfound),

        new_single_domain_test(group_by_name_cache_valid),
        new_single_domain_test(group_by_name_cache_expired),
        new_single_domain_test(group_by_name_cache_midpoint),
        new_single_domain_test(group_by_name_ncache),
        new_single_domain_test(group_by_name_missing_found),
        new_single_domain_test(group_by_name_missing_notfound),
        new_multi_domain_test(group_by_name_multiple_domains_found),
        new_multi_domain_test(group_by_name_multiple_domains_notfound),
        new_multi_domain_test(group_by_name_multiple_domains_parse),

        new_single_domain_test(group_by_id_cache_valid),
        new_single_domain_test(group_by_id_cache_expired),
        new_single_domain_test(group_by_id_cache_midpoint),
        new_single_domain_test(group_by_id_ncache),
        new_single_domain_test(group_by_id_missing_found),
        new_single_domain_test(group_by_id_missing_notfound),
        new_multi_domain_test(group_by_id_multiple_domains_found),
        new_multi_domain_test(group_by_id_multiple_domains_notfound),

        new_single_domain_test(users_by_filter_filter_old),
        new_single_domain_test(users_by_filter_notfound),
        new_multi_domain_test(users_by_filter_multiple_domains_notfound),
        new_single_domain_test(groups_by_filter_notfound),
        new_multi_domain_test(groups_by_filter_multiple_domains_notfound),
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

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();
    test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
