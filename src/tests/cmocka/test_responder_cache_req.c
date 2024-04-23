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
#include "responder/common/cache_req/cache_req.h"
#include "providers/ipa/ipa_subdomains.h"

#ifdef BUILD_FILES_PROVIDER
#define FILES_ID_PROVIDER "files"
#endif
#define LDAP_ID_PROVIDER "ldap"
#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_responder_cache_req_conf.ldb"
#define TEST_DOM_NAME "responder_cache_req_test"

#define TEST_USER_PREFIX "test*"
#define TEST_NO_USER_PREFIX "nosuchuser*"
#define TEST_GROUP_PREFIX "test-group*"
#define TEST_NO_GROUP_PREFIX "nosuchgroup*"

struct test_user {
    const char *short_name;
    const char *upn;
    const char *sid;
    uid_t uid;
    gid_t gid;
} users[] = {{"test-user1", "upn1@upndomain.com",
              "S-1-5-21-3623811015-3361044348-30300820-1001", 3001, 3001},
             {"test-user2", "upn2@upndomain.com",
              "S-1-5-21-3623811015-3361044348-30300820-1002", 3002, 3002}};

struct test_group {
    const char *short_name;
    const char *sid;
    gid_t gid;
} groups[] = {{"test-group1", "S-1-5-21-3623811015-3361044348-30300820-2001", 4001},
              {"test-group2", "S-1-5-21-3623811015-3361044348-30300820-2002", 4002}};

#define new_single_domain_test(test) \
    cmocka_unit_test_setup_teardown(test_ ## test, \
                                    test_single_domain_setup, \
                                    test_single_domain_teardown)

#ifdef BUILD_FILES_PROVIDER
#define new_files_domain_test(test) \
    cmocka_unit_test_setup_teardown(test_ ## test, \
                                    test_files_domain_setup, \
                                    test_single_domain_teardown)
#endif

#define new_single_domain_id_limit_test(test) \
    cmocka_unit_test_setup_teardown(test_ ## test, \
                                    test_single_domain_id_limits_setup, \
                                    test_single_domain_teardown)

#define new_multi_domain_test(test) \
    cmocka_unit_test_setup_teardown(test_ ## test, \
                                    test_multi_domain_setup, \
                                    test_multi_domain_teardown)

#define new_subdomain_test(test) \
    cmocka_unit_test_setup_teardown(test_ ## test, \
                                    test_subdomain_setup, \
                                    test_subdomain_teardown)

#define run_cache_req(ctx, send_fn, done_fn, dom, crp, lookup, expret) do { \
    TALLOC_CTX *req_mem_ctx;                                                \
    struct tevent_req *req;                                                 \
    errno_t ret;                                                            \
                                                                            \
    req_mem_ctx = talloc_new(global_talloc_context);                        \
    check_leaks_push(req_mem_ctx);                                          \
                                                                            \
    req = send_fn(req_mem_ctx, ctx->tctx->ev, ctx->rctx,                    \
                  ctx->ncache, crp,                                         \
                  (dom == NULL ? NULL : dom->name), lookup);                \
    assert_non_null(req);                                                   \
    tevent_req_set_callback(req, done_fn, ctx);                             \
                                                                            \
    ret = test_ev_loop(ctx->tctx);                                          \
    assert_int_equal(ret, expret);                                          \
    assert_true(check_leaks_pop(req_mem_ctx));                              \
                                                                            \
    talloc_free(req_mem_ctx);                                               \
} while (0)

#define run_cache_req_domtype(ctx, send_fn, done_fn, dom, crp, domtype, lookup, expret) do { \
    TALLOC_CTX *req_mem_ctx;                                                                 \
    struct tevent_req *req;                                                                  \
    errno_t ret;                                                                             \
                                                                                             \
    req_mem_ctx = talloc_new(global_talloc_context);                                         \
    check_leaks_push(req_mem_ctx);                                                           \
                                                                                             \
    req = send_fn(req_mem_ctx, ctx->tctx->ev, ctx->rctx,                                     \
                  ctx->ncache, crp,                                                          \
                  domtype,                                                                   \
                  (dom == NULL ? NULL : dom->name), lookup);                                 \
    assert_non_null(req);                                                                    \
    tevent_req_set_callback(req, done_fn, ctx);                                              \
                                                                                             \
    ret = test_ev_loop(ctx->tctx);                                                           \
    assert_int_equal(ret, expret);                                                           \
    assert_true(check_leaks_pop(req_mem_ctx));                                               \
                                                                                             \
    talloc_free(req_mem_ctx);                                                                \
} while (0)

struct cache_req_test_ctx {
    struct sss_test_ctx *tctx;
    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    struct sss_domain_info *subdomain;

    struct cache_req_result *result;
    bool dp_called;

    /* NOTE: Please, instead of adding new create_[user|group] bool,
     * use bitshift. */
    bool create_user1;
    bool create_user2;
    bool create_group1;
    bool create_group2;
    bool create_subgroup1;
    bool create_subuser1;
};

const char *domains[] = {"responder_cache_req_test_a",
                         "responder_cache_req_test_b",
                         "responder_cache_req_test_c",
                         "responder_cache_req_test_d",
                         NULL};

const char *subdomain_name = "responder_cache_req_test_a_sub";

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version version[] = {
        { 0, NULL, NULL }
    };

    return version;
}

static void cache_req_user_by_name_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_user_by_name_recv(ctx, req, &ctx->result);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void cache_req_user_by_id_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_user_by_id_recv(ctx, req, &ctx->result);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void cache_req_group_by_name_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_group_by_name_recv(ctx, req, &ctx->result);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void cache_req_group_by_id_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_group_by_id_recv(ctx, req, &ctx->result);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void cache_req_object_by_sid_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_object_by_sid_recv(ctx, req, &ctx->result);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void cache_req_object_by_id_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_object_by_id_recv(ctx, req, &ctx->result);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void prepare_user(struct sss_domain_info *domain,
                         struct test_user *user,
                         uint64_t timeout,
                         time_t transaction_time)
{
    struct sysdb_attrs *attrs;
    errno_t ret;
    char *fqname;

    attrs = sysdb_new_attrs(NULL);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, user->upn);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, user->sid);
    assert_int_equal(ret, EOK);

    fqname = sss_create_internal_fqname(attrs, user->short_name, domain->name);
    assert_non_null(fqname);

    ret = sysdb_store_user(domain, fqname, "pwd",
                           user->uid, user->gid, NULL, NULL, NULL,
                           "cn=origdn,dc=test", attrs, NULL,
                           timeout, transaction_time);
    talloc_free(fqname);
    assert_int_equal(ret, EOK);

    talloc_free(attrs);
}

static void run_user_by_name(struct cache_req_test_ctx *test_ctx,
                             struct sss_domain_info *domain,
                             int cache_refresh_percent,
                             errno_t exp_ret)
{
    run_cache_req_domtype(test_ctx, cache_req_user_by_name_send,
                          cache_req_user_by_name_test_done, domain,
                          cache_refresh_percent,
                          CACHE_REQ_POSIX_DOM,
                          users[0].short_name, exp_ret);
}

static void run_user_by_upn(struct cache_req_test_ctx *test_ctx,
                            struct sss_domain_info *domain,
                            int cache_refresh_percent,
                            errno_t exp_ret)
{
    run_cache_req_domtype(test_ctx, cache_req_user_by_name_send,
                          cache_req_user_by_name_test_done, domain,
                          cache_refresh_percent,
                          CACHE_REQ_POSIX_DOM,
                          users[0].upn, exp_ret);
}

static void run_user_by_id(struct cache_req_test_ctx *test_ctx,
                           struct sss_domain_info *domain,
                           int cache_refresh_percent,
                           errno_t exp_ret)
{
    run_cache_req(test_ctx, cache_req_user_by_id_send,
                  cache_req_user_by_id_test_done, domain,
                  cache_refresh_percent, users[0].uid, exp_ret);
}

static void
run_user_by_name_with_requested_domains(struct cache_req_test_ctx *test_ctx,
                                        struct sss_domain_info *domain,
                                        char **requested_domains,
                                        int cache_refresh_percent,
                                        errno_t exp_ret)
{
    TALLOC_CTX *req_mem_ctx;
    struct tevent_req *req;
    errno_t ret;
    struct cache_req_data *data;

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    data = cache_req_data_name(req_mem_ctx, CACHE_REQ_USER_BY_NAME,
                               users[0].short_name);
    assert_non_null(data);

    cache_req_data_set_requested_domains(data, requested_domains);

    req = cache_req_send(req_mem_ctx, test_ctx->tctx->ev, test_ctx->rctx,
                         test_ctx->ncache, cache_refresh_percent,
                         CACHE_REQ_POSIX_DOM,
                         (domain == NULL ? NULL : domain->name), data);
    assert_non_null(req);
    talloc_steal(req, data);

    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, exp_ret);
    assert_true(check_leaks_pop(req_mem_ctx));

    talloc_free(req_mem_ctx);
}

static void assert_msg_has_shortname(struct cache_req_test_ctx *test_ctx,
                                     struct ldb_message *msg,
                                     const char *check_name)
{
    const char *ldbname;
    char *shortname;
    errno_t ret;

    ldbname = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    assert_non_null(ldbname);
    ret = sss_parse_internal_fqname(test_ctx, ldbname, &shortname, NULL);
    assert_int_equal(ret, EOK);
    assert_string_equal(shortname, check_name);
    talloc_free(shortname);
}

static void check_user(struct cache_req_test_ctx *test_ctx,
                       struct test_user *user,
                       struct sss_domain_info *exp_dom)
{
    const char *ldbupn;
    const char *ldbsid;
    uid_t ldbuid;

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[0],
                             user->short_name);

    ldbupn = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                         SYSDB_UPN, NULL);
    assert_non_null(ldbupn);
    assert_string_equal(ldbupn, user->upn);

    ldbsid = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                         SYSDB_SID_STR, NULL);
    assert_non_null(ldbsid);
    assert_string_equal(ldbsid, user->sid);

    ldbuid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_UIDNUM, 0);
    assert_int_equal(ldbuid, user->uid);

    assert_non_null(test_ctx->result->domain);
    assert_string_equal(exp_dom->name, test_ctx->result->domain->name);
}

static void prepare_group(struct sss_domain_info *domain,
                          struct test_group *group,
                          uint64_t timeout,
                          time_t transaction_time)
{
    struct sysdb_attrs *attrs;
    char *fqname;
    errno_t ret;

    attrs = sysdb_new_attrs(NULL);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, group->sid);
    assert_int_equal(ret, EOK);

    fqname = sss_create_internal_fqname(attrs, group->short_name, domain->name);
    assert_non_null(fqname);

    ret = sysdb_store_group(domain, fqname, group->gid, attrs,
                            timeout, transaction_time);
    talloc_free(fqname);
    assert_int_equal(ret, EOK);

    talloc_free(attrs);
}

static void run_group_by_name(struct cache_req_test_ctx *test_ctx,
                              struct sss_domain_info *domain,
                              int cache_refresh_percent,
                              errno_t exp_ret)
{
    run_cache_req_domtype(test_ctx, cache_req_group_by_name_send,
                          cache_req_group_by_name_test_done, domain,
                          cache_refresh_percent,
                          CACHE_REQ_POSIX_DOM,
                          groups[0].short_name, exp_ret);
}

static void run_group_by_id(struct cache_req_test_ctx *test_ctx,
                            struct sss_domain_info *domain,
                            int cache_refresh_percent,
                            errno_t exp_ret)
{
    run_cache_req(test_ctx, cache_req_group_by_id_send,
                  cache_req_group_by_id_test_done, domain,
                  cache_refresh_percent, groups[0].gid, exp_ret);
}

static void check_group(struct cache_req_test_ctx *test_ctx,
                        struct test_group *group,
                        struct sss_domain_info *exp_dom)
{
    const char *ldbsid;
    gid_t ldbgid;

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);
    assert_non_null(test_ctx->result->msgs);
    assert_non_null(test_ctx->result->msgs[0]);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[0],
                             group->short_name);

    ldbsid = ldb_msg_find_attr_as_string(test_ctx->result->msgs[0],
                                         SYSDB_SID_STR, NULL);
    assert_non_null(ldbsid);
    assert_string_equal(ldbsid, group->sid);

    ldbgid = ldb_msg_find_attr_as_uint(test_ctx->result->msgs[0],
                                       SYSDB_GIDNUM, 0);
    assert_int_equal(ldbgid, group->gid);

    assert_non_null(test_ctx->result->domain);
    assert_string_equal(exp_dom->name, test_ctx->result->domain->name);
}

static void run_object_by_sid(struct cache_req_test_ctx *test_ctx,
                              struct sss_domain_info *domain,
                              const char *sid,
                              const char **attrs,
                              int cache_refresh_percent,
                              errno_t exp_ret)
{
    TALLOC_CTX *req_mem_ctx;
    struct tevent_req *req;
    errno_t ret;

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_object_by_sid_send(req_mem_ctx, test_ctx->tctx->ev,
            test_ctx->rctx, test_ctx->ncache, cache_refresh_percent,
            (domain == NULL ? NULL : domain->name), sid, attrs);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_object_by_sid_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, exp_ret);
    assert_true(check_leaks_pop(req_mem_ctx));

    talloc_free(req_mem_ctx);
}

static void run_object_by_id(struct cache_req_test_ctx *test_ctx,
                             struct sss_domain_info *domain,
                             id_t id,
                             const char **attrs,
                             int cache_refresh_percent,
                             errno_t exp_ret)
{
    TALLOC_CTX *req_mem_ctx;
    struct tevent_req *req;
    errno_t ret;

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_object_by_id_send(req_mem_ctx, test_ctx->tctx->ev,
            test_ctx->rctx, test_ctx->ncache, cache_refresh_percent,
            (domain == NULL ? NULL : domain->name), id, attrs);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_object_by_id_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, exp_ret);
    assert_true(check_leaks_pop(req_mem_ctx));

    talloc_free(req_mem_ctx);
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
    struct cache_req_test_ctx *ctx = NULL;

    ctx = sss_mock_ptr_type(struct cache_req_test_ctx*);
    ctx->dp_called = true;

    if (ctx->create_user1) {
        prepare_user(ctx->tctx->dom, &users[0], 1000, time(NULL));
    }

    if (ctx->create_user2) {
        prepare_user(ctx->tctx->dom, &users[1], 1000, time(NULL));
    }

    if (ctx->create_group1) {
        prepare_group(ctx->tctx->dom, &groups[0], 1000, time(NULL));
    }

    if (ctx->create_group2) {
        prepare_group(ctx->tctx->dom, &groups[1], 1000, time(NULL));
    }

    if (ctx->create_subgroup1) {
        struct sss_domain_info *domain = NULL;

        domain = find_domain_by_name(ctx->tctx->dom,
                                     subdomain_name,
                                     true);
        assert_non_null(domain);
        prepare_group(domain, &groups[0], 1000, time(NULL));
    }

    if (ctx->create_subuser1) {
        struct sss_domain_info *domain = NULL;

        domain = find_domain_by_name(ctx->tctx->dom,
                                     subdomain_name,
                                     true);
        assert_non_null(domain);
        prepare_user(domain, &users[0], 1000, time(NULL));
    }

    return test_req_succeed_send(mem_ctx, rctx->ev);
}

static int test_single_domain_setup_common(void **state,
                                           struct sss_test_conf_param *params,
                                           const char *id_provider)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;

    assert_true(leak_check_setup());

    test_dom_suite_setup(TESTS_PATH);

    test_ctx = talloc_zero(global_talloc_context, struct cache_req_test_ctx);
    assert_non_null(test_ctx);
    *state = test_ctx;

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME, id_provider, params);
    assert_non_null(test_ctx->tctx);

    test_ctx->rctx = mock_rctx(test_ctx, test_ctx->tctx->ev,
                               test_ctx->tctx->dom, NULL);
    assert_non_null(test_ctx->rctx);

    ret = sss_ncache_init(test_ctx, 10, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    check_leaks_push(test_ctx);

    return 0;
}

#ifdef BUILD_FILES_PROVIDER
int test_files_domain_setup(void **state)
{
    return test_single_domain_setup_common(state, NULL, FILES_ID_PROVIDER);
}
#endif

int test_single_domain_setup(void **state)
{
    return test_single_domain_setup_common(state, NULL, LDAP_ID_PROVIDER);
}

int test_single_domain_teardown(void **state)
{
    struct cache_req_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    talloc_zfree(test_ctx->result);

    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    assert_true(leak_check_teardown());
    return 0;
}

int test_single_domain_id_limits_setup(void **state)
{
    struct sss_test_conf_param params[] = {
        { "min_id", "100" },
        { "max_id", "10000" },
        { NULL, NULL },             /* Sentinel */
    };
    return test_single_domain_setup_common(state, params, LDAP_ID_PROVIDER);
}

static int test_multi_domain_setup(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;

    assert_true(leak_check_setup());

    test_dom_suite_setup(TESTS_PATH);

    test_ctx = talloc_zero(global_talloc_context, struct cache_req_test_ctx);
    assert_non_null(test_ctx);
    *state = test_ctx;

    test_ctx->tctx = create_multidom_test_ctx(test_ctx, TESTS_PATH,
                                              TEST_CONF_DB, domains,
                                              LDAP_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    test_ctx->rctx = mock_rctx(test_ctx, test_ctx->tctx->ev,
                               test_ctx->tctx->dom, NULL);
    assert_non_null(test_ctx->rctx);

    ret = sss_ncache_init(test_ctx, 10, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    reset_ldb_errstrings(test_ctx->tctx->dom);
    check_leaks_push(test_ctx);

    return 0;
}

void test_user_by_id_below_id_range(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Test. */
    run_cache_req(test_ctx, cache_req_user_by_id_send,
                  cache_req_user_by_id_test_done, test_ctx->tctx->dom,
                  0, 10, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_user_by_id_above_id_range(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Test. */
    run_cache_req(test_ctx, cache_req_user_by_id_send,
                  cache_req_user_by_id_test_done, test_ctx->tctx->dom,
                  0, 100000, ENOENT);
    assert_false(test_ctx->dp_called);
}

static int test_multi_domain_teardown(void **state)
{
    struct cache_req_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    talloc_zfree(test_ctx->result);

    reset_ldb_errstrings(test_ctx->tctx->dom);
    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);
    test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    assert_true(leak_check_teardown());
    return 0;
}

int test_subdomain_setup(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    int ret;
    const char *const testdom[4] = { subdomain_name, "TEST_A.SUB", "test_a", "S-3" };

    assert_true(leak_check_setup());

    test_dom_suite_setup(TESTS_PATH);

    test_ctx = talloc_zero(global_talloc_context, struct cache_req_test_ctx);
    assert_non_null(test_ctx);
    *state = test_ctx;

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME, LDAP_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    test_ctx->rctx = mock_rctx(test_ctx, test_ctx->tctx->ev,
                               test_ctx->tctx->dom, NULL);
    assert_non_null(test_ctx->rctx);

    ret = sss_ncache_init(test_ctx, 10, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    test_ctx->subdomain = new_subdomain(test_ctx, test_ctx->tctx->dom,
                              testdom[0], testdom[1], testdom[2], testdom[0],
                              testdom[3], MPG_DISABLED, false, NULL, NULL, 0,
                              IPA_TRUST_UNKNOWN, test_ctx->tctx->confdb, true);
    assert_non_null(test_ctx->subdomain);

    ret = sysdb_subdomain_store(test_ctx->tctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[0],
                                testdom[3], MPG_DISABLED, false, NULL, 0,
                                IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(test_ctx->tctx->dom,
                                  test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    *state = test_ctx;
    check_leaks_push(test_ctx);
    return 0;
}

int test_subdomain_teardown(void **state)
{
    struct cache_req_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    talloc_zfree(test_ctx->result);
    talloc_zfree(test_ctx->rctx->cr_domains);

    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    assert_true(leak_check_teardown());
    return 0;
}

void test_user_by_name_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_user(domain, &users[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);
}

void test_user_by_name_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, NULL, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_user_by_name_multiple_domains_parse(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    char *input_fqn;
    char *fqname;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Add user to the first domain with different uid then test user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_a", true);
    assert_non_null(domain);

    fqname = sss_create_internal_fqname(test_ctx, users[0].short_name, domain->name);
    assert_non_null(fqname);

    ret = sysdb_store_user(domain, fqname, "pwd", 2000, 1000,
                           NULL, NULL, NULL, "cn=test-user,dc=test", NULL,
                           NULL, 1000, time(NULL));
    talloc_zfree(fqname);
    assert_int_equal(ret, EOK);

    /* Add test user to the last domain. */

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_user(domain, &users[0], 1000, time(NULL));

    /* Append domain name to the username to form the qualified input.
     * We don't use the internal fqname here on purpose, because this is
     * the user's input.
     */
    input_fqn = talloc_asprintf(test_ctx, "%s@%s", users[0].short_name,
                                "responder_cache_req_test_d");
    assert_non_null(input_fqn);

    /* Mock values. */
    mock_parse_inp(users[0].short_name, "responder_cache_req_test_d", ERR_OK);

    /* Test. */
    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    req = cache_req_user_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                      test_ctx->rctx, test_ctx->ncache,
                                      CACHE_REQ_POSIX_DOM,
                                      0,
                                      NULL, input_fqn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));
    assert_false(test_ctx->dp_called);

    check_user(test_ctx, &users[0], domain);

    assert_non_null(test_ctx->result->lookup_name);
    assert_string_equal(input_fqn, test_ctx->result->lookup_name);

    talloc_free(input_fqn);
}

void test_user_by_name_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 1000, time(NULL));

    /* Mock values */
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_name_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], -1000, time(NULL));

    /* Mock values */
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Mock values. */
    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_name_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_name_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;
    char *fqname;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    fqname = sss_create_internal_fqname(test_ctx, users[0].short_name,
                                        test_ctx->tctx->dom->name);
    assert_non_null(fqname);

    ret = sss_ncache_set_user(test_ctx->ncache, false,
                              test_ctx->tctx->dom, fqname);
    talloc_free(fqname);
    assert_int_equal(ret, EOK);

    /* Mock values */
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_user_by_name_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    test_ctx->create_user1 = true;
    test_ctx->create_user2 = false;

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_name_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_user_by_name_missing_notfound_cache_first(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->rctx->cache_first = true;

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_user_by_name_missing_notfound_full_name(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(users[0].short_name, TEST_DOM_NAME, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_user_by_name_missing_notfound_cache_first_full_name(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->rctx->cache_first = true;

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(users[0].short_name, TEST_DOM_NAME, ERR_OK);

    /* Test. */
    run_user_by_name(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_user_by_name_multiple_domains_requested_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    char *requested_domains[2] = { discard_const("responder_cache_req_test_d"),
                                   NULL};

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_user(domain, &users[0], 1000, time(NULL));

    /* Mock values. */
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name_with_requested_domains(test_ctx, NULL, requested_domains,
                                            0, ERR_OK);
    /* The backend will not be called during this test because the user is
     * already cached in the requested domain. */
    check_user(test_ctx, &users[0], domain);
}

void test_user_by_name_multiple_domains_requested_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    char *requested_domains[2] = { discard_const("responder_cache_req_test_a"),
                                   NULL};

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_user(domain, &users[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(users[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_user_by_name_with_requested_domains(test_ctx, NULL, requested_domains,
                                            0, ENOENT);
    /* The requested domain is not the domain the user was added to, so we
     * expect ENOENT and that the backend is called. */
    assert_true(test_ctx->dp_called);
}


void test_user_by_upn_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_user(domain, &users[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    /* Test. */
    run_user_by_upn(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);
}

void test_user_by_upn_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    /* Test. */
    run_user_by_upn(test_ctx, NULL, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_user_by_upn_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 1000, time(NULL));

    /* Mock values. */
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    /* Test. */
    run_user_by_upn(test_ctx, NULL, 0, ERR_OK);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_upn_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], -1000, time(NULL));

    /* Mock values. */
    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    /* Test. */
    run_user_by_upn(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_upn_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    /* Test. */
    run_user_by_upn(test_ctx, NULL, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_upn_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user's UPN. */
    ret = sss_ncache_set_upn(test_ctx->ncache, false,
                             test_ctx->tctx->dom, users[0].upn);
    assert_int_equal(ret, EOK);

    /* Mock values. */
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    /* Test. */
    run_user_by_upn(test_ctx, NULL, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_user_by_upn_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    test_ctx->create_user1 = true;
    test_ctx->create_user2 = false;

    /* Test. */
    run_user_by_upn(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_upn_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);

    /* Test. */
    run_user_by_upn(test_ctx, NULL, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_user_by_id_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_user(domain, &users[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);
}

void test_user_by_id_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_user_by_id_multiple_domains_locator_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, "responder_cache_req_test_d");
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], 1000, time(NULL));

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, EOK);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 0, ERR_OK);
    /* Even though the locator tells us to skip all domains except d, the domains
     * are standalone and the result of the locator request is only valid within
     * the subdomains
     */
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_user_by_id_multiple_domains_locator_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, "responder_cache_req_test_d");
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], -1000, time(NULL));

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, EOK);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 0, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_user_by_id_sub_domains_locator_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], 1000, time(NULL));

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 0, ERR_OK);

    /* Even though the ID is present in the last domain,
     * we're not calling sss_dp_get_account_send,
     * because the locator will cause cache_req to skip
     * all domains except _d
     */
    assert_false(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_user_by_id_sub_domains_locator_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], -1000, time(NULL));

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 0, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_user_by_id_sub_domains_locator_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], 50, time(NULL) - 26);

    /* Note - DP will only be called once and we're not waiting
     * for the results (so, we're not mocking _recv)
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 50, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_user_by_id_sub_domains_locator_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    test_ctx->create_subuser1 = true;
    run_user_by_id(test_ctx, NULL, 0, ERR_OK);

    assert_true(test_ctx->dp_called);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_group_by_id_below_id_range(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Test. */
    run_cache_req(test_ctx, cache_req_group_by_id_send,
                  cache_req_group_by_id_test_done, test_ctx->tctx->dom,
                  0, 10, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_group_by_id_above_id_range(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Test. */
    run_cache_req(test_ctx, cache_req_group_by_id_send,
                  cache_req_group_by_id_test_done, test_ctx->tctx->dom,
                  0, 100000, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_user_by_id_sub_domains_locator_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    will_return(sss_dp_get_account_domain_recv, ERR_NOT_FOUND);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_user_by_id_sub_domains_locator_cache_expired_two_calls(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    test_ctx->create_subuser1 = true;
    prepare_user(domain, &users[0], -1000, time(NULL));

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_user_by_id(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    /* Request the same user again */
    test_ctx->tctx->done = false;
    talloc_zfree(test_ctx->result);

    run_user_by_id(test_ctx, NULL, 0, ERR_OK);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_user_by_id_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 1000, time(NULL));

    /* Test. */
    run_user_by_id(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_id_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], -1000, time(NULL));

    /* Mock values. */
    /* DP should be contacted. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_user_by_id(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_id_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    /* Test. */
    run_user_by_id(test_ctx, test_ctx->tctx->dom, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_id_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    ret = sss_ncache_set_uid(test_ctx->ncache, false, NULL, users[0].uid);
    assert_int_equal(ret, EOK);

    /* Test. */
    run_user_by_id(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_user_by_id_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_user1 = true;
    test_ctx->create_user2 = false;

    /* Test. */
    run_user_by_id(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_user_by_id_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_user_by_id(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_group_by_name_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(groups[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_group_by_name(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);
}

void test_group_by_name_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(groups[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_group_by_name(test_ctx, NULL, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_group_by_name_multiple_domains_parse(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    char *input_fqn;
    char *fqname;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Add group to the first domain. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_a", true);
    assert_non_null(domain);

    fqname = sss_create_internal_fqname(test_ctx, users[0].short_name, domain->name);
    assert_non_null(fqname);

    ret = sysdb_store_group(domain, fqname, 2000, NULL,
                            1000, time(NULL));
    talloc_zfree(fqname);
    assert_int_equal(ret, EOK);

    /* Add group to the last domain, with different gid. */

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_group(domain, &groups[0], 1000, time(NULL));

    /* Append domain name to the groupname.
     * We don't use the internal fqname here on purpose, because this is
     * the user's input.
     */
    input_fqn = talloc_asprintf(test_ctx, "%s@%s", groups[0].short_name,
                                "responder_cache_req_test_d");
    assert_non_null(input_fqn);

    /* Test. */
    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    mock_parse_inp(groups[0].short_name, "responder_cache_req_test_d", ERR_OK);

    req = cache_req_group_by_name_send(req_mem_ctx, test_ctx->tctx->ev,
                                       test_ctx->rctx, test_ctx->ncache, 0,
                                       CACHE_REQ_POSIX_DOM, NULL,
                                       input_fqn);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_name_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));
    assert_false(test_ctx->dp_called);

    check_group(test_ctx, &groups[0], domain);

    assert_non_null(test_ctx->result->lookup_name);
    assert_string_equal(input_fqn, test_ctx->result->lookup_name);

    talloc_free(input_fqn);
}

void test_group_by_name_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    prepare_group(test_ctx->tctx->dom, &groups[0], 1000, time(NULL));

    /* Mock values */
    mock_parse_inp(groups[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_group_by_name(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_group_by_name_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    prepare_group(test_ctx->tctx->dom, &groups[0], -1000, time(NULL));

    /* Mock values. */
    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(groups[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_group_by_name(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_group_by_name_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    prepare_group(test_ctx->tctx->dom, &groups[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_parse_inp(groups[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_group_by_name(test_ctx, test_ctx->tctx->dom, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_group_by_name_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;
    char *fqname;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    fqname = sss_create_internal_fqname(test_ctx, groups[0].short_name,
                                        test_ctx->tctx->dom->name);
    assert_non_null(fqname);

    ret = sss_ncache_set_group(test_ctx->ncache, false,
                               test_ctx->tctx->dom, fqname);
    talloc_free(fqname);
    assert_int_equal(ret, EOK);

    /* Mock values */
    mock_parse_inp(groups[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_group_by_name(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_group_by_name_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(groups[0].short_name, NULL, ERR_OK);

    test_ctx->create_group1 = true;
    test_ctx->create_group2 = false;

    /* Test. */
    run_group_by_name(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_group_by_name_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(groups[0].short_name, NULL, ERR_OK);

    /* Test. */
    run_group_by_name(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_group_by_id_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);
}

void test_group_by_id_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_group_by_id_multiple_domains_outside_id_range(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    struct sss_domain_info *domain_a = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    domain_a = find_domain_by_name(test_ctx->tctx->dom,
                                   "responder_cache_req_test_a", true);
    assert_non_null(domain_a);
    domain_a->id_min = 1;
    domain_a->id_max = 100;

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);
}

void test_group_by_id_multiple_domains_locator_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, "responder_cache_req_test_d");
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 1000, time(NULL));

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, EOK);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ERR_OK);

    /* Even though the locator tells us to skip all domains except d, the domains
     * are standalone and the result of the locator request is only valid within
     * the subdomains
     */
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_group_by_id_multiple_domains_locator_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, "responder_cache_req_test_d");
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], -1000, time(NULL));

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, EOK);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_group_by_id_sub_domains_locator_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 1000, time(NULL));

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ERR_OK);

    /* Even though the ID is present in the last domain,
     * we're not calling sss_dp_get_account_send,
     * because the locator will cause cache_req to skip
     * all domains except _d
     */
    assert_false(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_group_by_id_sub_domains_locator_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], -1000, time(NULL));

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_group_by_id_sub_domains_locator_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 50, time(NULL) - 26);

    /* Note - DP will only be called once and we're not waiting
     * for the results (so, we're not mocking _recv)
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 50, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_group_by_id_sub_domains_locator_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    test_ctx->create_subgroup1 = true;
    run_group_by_id(test_ctx, NULL, 0, ERR_OK);

    assert_true(test_ctx->dp_called);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_group_by_id_sub_domains_locator_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    will_return(sss_dp_get_account_domain_recv, ERR_NOT_FOUND);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_group_by_id_sub_domains_locator_cache_expired_two_calls(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    test_ctx->create_subgroup1 = true;
    prepare_group(domain, &groups[0], -1000, time(NULL));

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_group_by_id(test_ctx, NULL, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    /* Request the same group again */
    test_ctx->tctx->done = false;
    talloc_zfree(test_ctx->result);

    run_group_by_id(test_ctx, NULL, 0, ERR_OK);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_group_by_id_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    prepare_group(test_ctx->tctx->dom, &groups[0], 1000, time(NULL));

    /* Test. */
    run_group_by_id(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_group_by_id_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    prepare_group(test_ctx->tctx->dom, &groups[0], -1000, time(NULL));

    /* Mock values. */
    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_group_by_id(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_group_by_id_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    prepare_group(test_ctx->tctx->dom, &groups[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    /* Test. */
    run_group_by_id(test_ctx, test_ctx->tctx->dom, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_group_by_id_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. */
    ret = sss_ncache_set_gid(test_ctx->ncache, false, NULL, groups[0].gid);
    assert_int_equal(ret, EOK);

    /* Test. */
    run_group_by_id(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_group_by_id_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_group1 = true;
    test_ctx->create_group2 = false;

    /* Test. */
    run_group_by_id(test_ctx, test_ctx->tctx->dom, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_group_by_id_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_group_by_id(test_ctx, test_ctx->tctx->dom, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

static void cache_req_user_by_filter_test_done(struct tevent_req *req)
{
    struct cache_req_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct cache_req_test_ctx);

    ctx->tctx->error = cache_req_user_by_filter_recv(ctx, req, &ctx->result);
    talloc_zfree(req);
    ctx->tctx->done = true;
}

void test_user_by_recent_filter_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_user1 = true;
    test_ctx->create_user2 = false;

    prepare_user(test_ctx->tctx->dom, &users[1], 1000, time(NULL) - 1);

    req_mem_ctx = talloc_new(test_ctx->tctx);
    check_leaks_push(req_mem_ctx);

    /* Mock values */
    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(TEST_USER_PREFIX, NULL, ERR_OK);

    /* User TEST_USER is created with a DP callback. */
    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        NULL,
                                        TEST_USER_PREFIX);
    assert_non_null(req);

    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[0],
                             users[0].short_name);
}

void test_users_by_recent_filter_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    size_t num_users = 2;
    const char **user_names;
    const char *ldb_results[num_users];
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_user1 = true;
    test_ctx->create_user2 = true;

    req_mem_ctx = talloc_new(test_ctx->tctx);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(TEST_USER_PREFIX, NULL, ERR_OK);

    /* User TEST_USER1 and TEST_USER2 are created with a DP callback. */
    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        NULL,
                                        TEST_USER_PREFIX);
    assert_non_null(req);

    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 2);

    user_names = talloc_zero_array(test_ctx, const char *, num_users);
    assert_non_null(user_names);
    user_names[0] = sss_create_internal_fqname(user_names, users[0].short_name,
                                               test_ctx->result->domain->name);
    assert_non_null(user_names[0]);
    user_names[1] = sss_create_internal_fqname(user_names, users[1].short_name,
                                               test_ctx->result->domain->name);
    assert_non_null(user_names[1]);

    for (int i = 0; i < num_users; ++i) {
        ldb_results[i] = ldb_msg_find_attr_as_string(test_ctx->result->msgs[i],
                                                     SYSDB_NAME, NULL);
        assert_non_null(ldb_results[i]);
    }

    assert_string_not_equal(ldb_results[0], ldb_results[1]);

    assert_true(are_values_in_array(user_names, num_users,
                                    ldb_results, num_users));

    talloc_free(req_mem_ctx);
    talloc_free(user_names);
}

void test_users_by_filter_filter_old(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_user1 = true;
    test_ctx->create_user2 = false;

    /* This user was updated in distant past, so it won't be reported by
     * the filter search */
    prepare_user(test_ctx->tctx->dom, &users[1], 1000, 1);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(TEST_USER_PREFIX, NULL, ERR_OK);

    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        NULL,
                                        TEST_USER_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[0],
                             users[0].short_name);
}

/* This test uses a "files" provider */
void test_users_by_filter_filter_files(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_user1 = false;
    test_ctx->create_user2 = false;

    /* This user was updated in distant past but will still be reported */
    prepare_user(test_ctx->tctx->dom, &users[0], 1000, 1);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters only go to DP when /etc/passwd and /etc/group were modified */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(TEST_USER_PREFIX, NULL, ERR_OK);

    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        NULL,
                                        TEST_USER_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[0],
                             users[0].short_name);
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
    mock_parse_inp(TEST_NO_USER_PREFIX, NULL, ERR_OK);

    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        NULL,
                                        TEST_NO_USER_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));
}

/*
 * Given two users are present
 * When the users are searched by filtering domains
 * Then the two users are returned correctly.
 */
static void test_users_by_filter_multiple_domains_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    size_t num_users = 2;
    const char **input_dns = NULL;
    const char **user_names = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_user1 = true;
    test_ctx->create_user2 = true;

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    /* Generate DN for user1 */
    input_dns = talloc_zero_array(test_ctx, const char *, num_users);
    assert_non_null(input_dns);
    input_dns[0] = talloc_asprintf(input_dns, "cn=%s,dc=test",
                                    users[0].short_name);
    assert_non_null(input_dns[0]);

    /* Generate internal FQDN for user1 */
    user_names = talloc_zero_array(test_ctx, const char *, num_users);
    assert_non_null(user_names);
    user_names[0] = sss_create_internal_fqname(user_names, users[0].short_name,
                                                domain->name);
    assert_non_null(user_names[0]);

    ret = sysdb_store_user(domain, user_names[0], "pwd", 1000, 1000,
                           NULL, NULL, NULL, input_dns[0], NULL,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    /* Generate DN for user2 */
    input_dns[1] = talloc_asprintf(input_dns, "cn=%s,dc=test",
                                    users[1].short_name);
    assert_non_null(input_dns[1]);

    /* Generate internal FQDN for user2 */
    user_names[1] = sss_create_internal_fqname(user_names, users[1].short_name,
                                                domain->name);
    assert_non_null(user_names[1]);

    ret = sysdb_store_user(domain, user_names[1], "pwd", 1001, 1001,
                           NULL, NULL, NULL, input_dns[1], NULL,
                           NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(TEST_USER_PREFIX, NULL, ERR_OK);

    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        NULL,
                                        TEST_USER_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_user_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, num_users);

    for (int i = 0; i < num_users; ++i) {
        assert_msg_has_shortname(test_ctx,
                                 test_ctx->result->msgs[i],
                                 users[i].short_name);
    }

    talloc_free(user_names);
    talloc_free(input_dns);
}

void test_users_by_filter_multiple_domains_notfound(void **state)
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
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(TEST_NO_USER_PREFIX, NULL, ERR_OK);

    req = cache_req_user_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        domain->name,
                                        NULL,
                                        TEST_NO_USER_PREFIX);
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

    ctx->tctx->error = cache_req_group_by_filter_recv(ctx, req, &ctx->result);
    talloc_zfree(req);
    ctx->tctx->done = true;
}

void test_group_by_recent_filter_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_group1 = true;
    test_ctx->create_group2 = false;

    prepare_group(test_ctx->tctx->dom, &groups[1], 1001, time(NULL) - 1);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(TEST_USER_PREFIX, NULL, ERR_OK);

    /* Group TEST_GROUP is created with a DP callback. */
    req = cache_req_group_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                         test_ctx->rctx,
                                         CACHE_REQ_POSIX_DOM,
                                         test_ctx->tctx->dom->name,
                                         TEST_USER_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[0],
                             groups[0].short_name);
}

void test_groups_by_recent_filter_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    struct tevent_req *req = NULL;
    const char **group_names = NULL;
    const char **ldb_results = NULL;
    const char *ldbname = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_group1 = true;
    test_ctx->create_group2 = true;

    prepare_group(test_ctx->tctx->dom, &groups[1], 1001, time(NULL) - 1);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);
    mock_parse_inp(TEST_USER_PREFIX, NULL, ERR_OK);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Group TEST_GROUP1 and TEST_GROUP2 are created with a DP callback. */
    req = cache_req_group_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                         test_ctx->rctx,
                                         CACHE_REQ_POSIX_DOM,
                                         test_ctx->tctx->dom->name,
                                         TEST_USER_PREFIX);
    assert_non_null(req);

    tevent_req_set_callback(req, cache_req_group_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 2);

    tmp_ctx = talloc_new(req_mem_ctx);

    group_names = talloc_array(tmp_ctx, const char *, 2);
    assert_non_null(group_names);
    group_names[0] = sss_create_internal_fqname(group_names, groups[0].short_name,
                                                test_ctx->result->domain->name);
    assert_non_null(group_names[0]);
    group_names[1] = sss_create_internal_fqname(group_names, groups[1].short_name,
                                                test_ctx->result->domain->name);
    assert_non_null(group_names[1]);

    ldb_results = talloc_array(tmp_ctx, const char *, 2);
    assert_non_null(ldb_results);
    for (int i = 0; i < 2; ++i) {
        ldbname = ldb_msg_find_attr_as_string(test_ctx->result->msgs[i],
                                              SYSDB_NAME, NULL);
        assert_non_null(ldbname);
        ldb_results[i] = ldbname;
    }

    assert_string_not_equal(ldb_results[0], ldb_results[1]);

    assert_true(tc_are_values_in_array(group_names, ldb_results));

    talloc_zfree(tmp_ctx);
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
    mock_parse_inp(TEST_NO_GROUP_PREFIX, NULL, ERR_OK);

    req = cache_req_group_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        TEST_NO_GROUP_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));
}

void test_groups_by_filter_files(void **state)
{
    struct cache_req_test_ctx *test_ctx;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_group1 = true;

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(TEST_GROUP_PREFIX, NULL, ERR_OK);

    req = cache_req_group_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        TEST_GROUP_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, 1);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[0],
                             groups[0].short_name);
}

/*
 * Given two groups are present
 * When the groups are searched by filtering domains
 * Then the two groups are returned correctly.
 */
void test_groups_by_filter_multiple_domains_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    struct tevent_req *req = NULL;
    size_t num_groups = 2;
    const char **group_names = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);
    test_ctx->create_group1 = true;
    test_ctx->create_group2 = true;

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    /* Generate internal FQDN for group1 */
    group_names = talloc_zero_array(test_ctx, const char *, num_groups);
    assert_non_null(group_names);
    group_names[0] = sss_create_internal_fqname(group_names,
                                                groups[0].short_name,
                                                domain->name);
    assert_non_null(group_names[0]);

    ret = sysdb_store_group(domain, group_names[0],
                            1000, NULL, 1000, time(NULL));
    assert_int_equal(ret, EOK);

    /* Generate internal FQDN for group2 */
    group_names[1] = sss_create_internal_fqname(group_names,
                                                groups[1].short_name,
                                                domain->name);
    assert_non_null(group_names[1]);

    ret = sysdb_store_group(domain, group_names[1],
                            1001, NULL, 1001, time(NULL));
    assert_int_equal(ret, EOK);

    req_mem_ctx = talloc_new(global_talloc_context);
    check_leaks_push(req_mem_ctx);

    /* Filters always go to DP */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();
    mock_parse_inp(TEST_USER_PREFIX, NULL, ERR_OK);

    req = cache_req_group_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        test_ctx->tctx->dom->name,
                                        TEST_USER_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ERR_OK);
    assert_true(check_leaks_pop(req_mem_ctx));

    assert_non_null(test_ctx->result);
    assert_int_equal(test_ctx->result->count, num_groups);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[0],
                             groups[1].short_name);

    assert_msg_has_shortname(test_ctx,
                             test_ctx->result->msgs[1],
                             groups[0].short_name);

    talloc_free(group_names);
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
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    mock_parse_inp(TEST_NO_GROUP_PREFIX, NULL, ERR_OK);

    req = cache_req_group_by_filter_send(req_mem_ctx, test_ctx->tctx->ev,
                                        test_ctx->rctx,
                                        CACHE_REQ_POSIX_DOM,
                                        domain->name,
                                        TEST_NO_GROUP_PREFIX);
    assert_non_null(req);
    tevent_req_set_callback(req, cache_req_group_by_filter_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(check_leaks_pop(req_mem_ctx));
}

void test_object_by_sid_user_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 1000, time(NULL));

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      users[0].sid, attrs, 0, ERR_OK);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_object_by_sid_user_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], -1000, time(NULL));

    /* Mock values. */
    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      users[0].sid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_object_by_sid_user_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      users[0].sid, attrs, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_object_by_sid_user_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    ret = sss_ncache_set_sid(test_ctx->ncache, false, test_ctx->tctx->dom, users[0].sid);
    assert_int_equal(ret, EOK);

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      users[0].sid, attrs, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_object_by_sid_user_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_user1 = true;
    test_ctx->create_user2 = false;

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      users[0].sid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_object_by_sid_user_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      users[0].sid, attrs, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_object_by_sid_user_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_user(domain, &users[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_sid(test_ctx, NULL, users[0].sid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);
}

void test_object_by_sid_user_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_sid(test_ctx, NULL, users[0].sid, attrs, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_object_by_sid_group_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_group(test_ctx->tctx->dom, &groups[0], 1000, time(NULL));

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      groups[0].sid, attrs, 0, ERR_OK);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_object_by_sid_group_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_group(test_ctx->tctx->dom, &groups[0], -1000, time(NULL));

    /* Mock values. */
    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      groups[0].sid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_object_by_sid_group_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_group(test_ctx->tctx->dom, &groups[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      groups[0].sid, attrs, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_object_by_sid_group_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    ret = sss_ncache_set_sid(test_ctx->ncache, false, test_ctx->tctx->dom, groups[0].sid);
    assert_int_equal(ret, EOK);

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      groups[0].sid, attrs, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_object_by_sid_group_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_group1 = true;
    test_ctx->create_group2 = false;

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      groups[0].sid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_object_by_sid_group_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_object_by_sid(test_ctx, test_ctx->tctx->dom,
                      groups[0].sid, attrs, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_object_by_sid_group_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_group(domain, &groups[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_sid(test_ctx, NULL, groups[0].sid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);
}

void test_object_by_sid_group_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_sid(test_ctx, NULL, groups[0].sid, attrs, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_object_by_id_user_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 1000, time(NULL));

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_object_by_id_user_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], -1000, time(NULL));

    /* Mock values. */
    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_object_by_id_user_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_user(test_ctx->tctx->dom, &users[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_object_by_id_user_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. We explicitly add the UID into BOTH UID and GID
     * namespaces, because otherwise the cache_req plugin would
     * search the Data Provider anyway, because it can't be sure
     * the object can be of the other type or not
     */
    ret = sss_ncache_set_uid(test_ctx->ncache,
                             false,
                             test_ctx->tctx->dom,
                             users[0].uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_set_gid(test_ctx->ncache,
                             false,
                             test_ctx->tctx->dom,
                             users[0].uid);
    assert_int_equal(ret, EOK);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_object_by_id_user_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_user1 = true;
    test_ctx->create_user2 = false;

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], test_ctx->tctx->dom);
}

void test_object_by_id_user_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_object_by_id_user_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_user(domain, &users[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);
}

void test_object_by_id_user_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_object_by_id_group_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_group(test_ctx->tctx->dom, &groups[0], 1000, time(NULL));

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_object_by_id_group_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_group(test_ctx->tctx->dom, &groups[0], -1000, time(NULL));

    /* Mock values. */
    /* DP should be contacted */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_object_by_id_group_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    prepare_group(test_ctx->tctx->dom, &groups[0], 50, time(NULL) - 26);

    /* Mock values. */
    /* DP should be contacted without callback */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 50, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_object_by_id_group_ncache(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup group. We explicitly add the UID into BOTH UID and GID
     * namespaces, because otherwise the cache_req plugin would
     * search the Data Provider anyway, because it can't be sure
     * the object can be of the other type or not
     */
    ret = sss_ncache_set_uid(test_ctx->ncache,
                             false,
                             test_ctx->tctx->dom,
                             groups[0].gid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_set_gid(test_ctx->ncache,
                             false,
                             test_ctx->tctx->dom,
                             groups[0].gid);
    assert_int_equal(ret, EOK);

    assert_int_equal(ret, EOK);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_object_by_id_group_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    test_ctx->create_group1 = true;
    test_ctx->create_group2 = false;

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], test_ctx->tctx->dom);
}

void test_object_by_id_group_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    mock_account_recv_simple();

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_object_by_id_group_multiple_domains_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);

    prepare_group(domain, &groups[0], 1000, time(NULL));

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);
}

void test_object_by_id_group_multiple_domains_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    /* Mock values. */
    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ENOENT);
    assert_true(test_ctx->dp_called);
}

void test_object_by_id_user_multiple_domains_locator_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, "responder_cache_req_test_d");
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], 1000, time(NULL));

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, EOK);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);
    /* Even though the locator tells us to skip all domains except d, the domains
     * are standalone and the result of the locator request is only valid within
     * the subdomains
     */
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_user_multiple_domains_locator_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, "responder_cache_req_test_d");
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], -1000, time(NULL));

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, EOK);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_user_sub_domains_locator_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], 1000, time(NULL));

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);

    /* Even though the ID is present in the last domain,
     * we're not calling sss_dp_get_account_send,
     * because the locator will cause cache_req to skip
     * all domains except _d
     */
    assert_false(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_user_sub_domains_locator_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], -1000, time(NULL));

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_user_sub_domains_locator_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_user(domain, &users[0], 50, time(NULL) - 26);

    /* Note - DP will only be called once and we're not waiting
     * for the results (so, we're not mocking _recv)
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 50, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_user_sub_domains_locator_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    test_ctx->create_subuser1 = true;
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ERR_OK);

    assert_true(test_ctx->dp_called);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_user_sub_domains_locator_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    will_return(sss_dp_get_account_domain_recv, ERR_NOT_FOUND);

    /* The test won't even ask the DP for the object, just iterate
     * over the domains using the negative cache and quit
     */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_object_by_id_user_sub_domains_locator_cache_expired_two_calls(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup user. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    test_ctx->create_subuser1 = true;
    prepare_user(domain, &users[0], -1000, time(NULL));

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, EOK);
    assert_true(test_ctx->dp_called);
    check_user(test_ctx, &users[0], domain);

    /* Request the same user again */
    test_ctx->tctx->done = false;
    talloc_zfree(test_ctx->result);

    run_object_by_id(test_ctx, NULL, users[0].uid, attrs, 0, EOK);
    check_user(test_ctx, &users[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_group_multiple_domains_locator_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, "responder_cache_req_test_d");
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 1000, time(NULL));

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, EOK);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);
    /* Even though the locator tells us to skip all domains except d, the domains
     * are standalone and the result of the locator request is only valid within
     * the subdomains
     */
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_group_multiple_domains_locator_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, "responder_cache_req_test_d");
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 "responder_cache_req_test_d", true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], -1000, time(NULL));

    will_return_always(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, EOK);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);
    will_return_always(sss_dp_get_account_domain_recv, ERR_GET_ACCT_DOM_NOT_SUPPORTED);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_group_sub_domains_locator_cache_valid(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 1000, time(NULL));

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);

    /* Even though the ID is present in the last domain,
     * we're not calling sss_dp_get_account_send,
     * because the locator will cause cache_req to skip
     * all domains except _d
     */
    assert_false(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_group_sub_domains_locator_cache_expired(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], -1000, time(NULL));

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_group_sub_domains_locator_cache_midpoint(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    prepare_group(domain, &groups[0], 50, time(NULL) - 26);

    /* Note - DP will only be called once and we're not waiting
     * for the results (so, we're not mocking _recv)
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 50, ERR_OK);

    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_group_sub_domains_locator_missing_found(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    test_ctx->create_subgroup1 = true;
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ERR_OK);

    assert_true(test_ctx->dp_called);

    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
}

void test_object_by_id_group_sub_domains_locator_missing_notfound(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    will_return(sss_dp_get_account_domain_recv, ERR_NOT_FOUND);

    /* The test won't even ask the DP for the object, just iterate
     * over the domains using the negative cache and quit
     */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, ENOENT);
    assert_false(test_ctx->dp_called);
}

void test_object_by_id_group_sub_domains_locator_cache_expired_two_calls(void **state)
{
    struct cache_req_test_ctx *test_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    const char *locator_domain;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = SYSDB_PW_ATTRS;

    test_ctx = talloc_get_type_abort(*state, struct cache_req_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    /* Has to be a talloc ptr, not just const, so it's stealable inside cache_req */
    locator_domain = talloc_strdup(tmp_ctx, subdomain_name);
    assert_non_null(locator_domain);

    /* Setup group. */
    domain = find_domain_by_name(test_ctx->tctx->dom,
                                 subdomain_name,
                                 true);
    assert_non_null(domain);
    test_ctx->create_subgroup1 = true;
    prepare_group(domain, &groups[0], -1000, time(NULL));

    /* Note - DP will only be called once (so, we're not using will_return_always)
     * because the locator will tell us which domain to look into. For the recv
     * function, we use always b/c internally it mocks several values.
     */
    will_return(__wrap_sss_dp_get_account_send, test_ctx);
    will_return_always(sss_dp_get_account_recv, 0);

    will_return(sss_dp_get_account_domain_recv, EOK);
    will_return(sss_dp_get_account_domain_recv, locator_domain);

    /* Test. */
    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, EOK);
    assert_true(test_ctx->dp_called);
    check_group(test_ctx, &groups[0], domain);

    /* Request the same group again */
    test_ctx->tctx->done = false;
    talloc_zfree(test_ctx->result);

    run_object_by_id(test_ctx, NULL, groups[0].gid, attrs, 0, EOK);
    check_group(test_ctx, &groups[0], domain);

    talloc_free(tmp_ctx);
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
        new_single_domain_test(user_by_name_missing_notfound_cache_first),
        new_single_domain_test(user_by_name_missing_notfound_full_name),
        new_single_domain_test(user_by_name_missing_notfound_cache_first_full_name),
        new_multi_domain_test(user_by_name_multiple_domains_found),
        new_multi_domain_test(user_by_name_multiple_domains_notfound),
        new_multi_domain_test(user_by_name_multiple_domains_parse),
        new_multi_domain_test(user_by_name_multiple_domains_requested_domains_found),
        new_multi_domain_test(user_by_name_multiple_domains_requested_domains_notfound),

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
        new_single_domain_id_limit_test(user_by_id_below_id_range),
        new_single_domain_id_limit_test(user_by_id_above_id_range),

        new_single_domain_test(group_by_name_cache_valid),
        new_single_domain_test(group_by_name_cache_expired),
        new_single_domain_test(group_by_name_cache_midpoint),
        new_single_domain_test(group_by_name_ncache),
        new_single_domain_test(group_by_name_missing_found),
        new_single_domain_test(group_by_name_missing_notfound),
        new_multi_domain_test(group_by_name_multiple_domains_found),
        new_multi_domain_test(group_by_name_multiple_domains_notfound),
        new_multi_domain_test(group_by_name_multiple_domains_parse),
        new_single_domain_id_limit_test(group_by_id_below_id_range),
        new_single_domain_id_limit_test(group_by_id_above_id_range),

        new_single_domain_test(group_by_id_cache_valid),
        new_single_domain_test(group_by_id_cache_expired),
        new_single_domain_test(group_by_id_cache_midpoint),
        new_single_domain_test(group_by_id_ncache),
        new_single_domain_test(group_by_id_missing_found),
        new_single_domain_test(group_by_id_missing_notfound),
        new_multi_domain_test(group_by_id_multiple_domains_found),
        new_multi_domain_test(group_by_id_multiple_domains_notfound),
        new_multi_domain_test(group_by_id_multiple_domains_outside_id_range),

        new_multi_domain_test(group_by_id_multiple_domains_locator_cache_valid),
        new_multi_domain_test(group_by_id_multiple_domains_locator_cache_expired),
        new_subdomain_test(group_by_id_sub_domains_locator_cache_valid),
        new_subdomain_test(group_by_id_sub_domains_locator_cache_expired),
        new_subdomain_test(group_by_id_sub_domains_locator_cache_midpoint),
        new_subdomain_test(group_by_id_sub_domains_locator_missing_found),
        new_subdomain_test(group_by_id_sub_domains_locator_missing_notfound),
        new_subdomain_test(group_by_id_sub_domains_locator_cache_expired_two_calls),

        new_multi_domain_test(user_by_id_multiple_domains_locator_cache_valid),
        new_multi_domain_test(user_by_id_multiple_domains_locator_cache_expired),
        new_subdomain_test(user_by_id_sub_domains_locator_cache_valid),
        new_subdomain_test(user_by_id_sub_domains_locator_cache_expired),
        new_subdomain_test(user_by_id_sub_domains_locator_cache_midpoint),
        new_subdomain_test(user_by_id_sub_domains_locator_missing_found),
        new_subdomain_test(user_by_id_sub_domains_locator_missing_notfound),
        new_subdomain_test(user_by_id_sub_domains_locator_cache_expired_two_calls),

        new_single_domain_test(user_by_recent_filter_valid),
        new_single_domain_test(users_by_recent_filter_valid),
        new_single_domain_test(group_by_recent_filter_valid),
        new_single_domain_test(groups_by_recent_filter_valid),

        new_single_domain_test(users_by_filter_filter_old),
#ifdef BUILD_FILES_PROVIDER
        new_files_domain_test(users_by_filter_filter_files),
#endif
        new_single_domain_test(users_by_filter_notfound),
        new_multi_domain_test(users_by_filter_multiple_domains_valid),
        new_multi_domain_test(users_by_filter_multiple_domains_notfound),
#ifdef BUILD_FILES_PROVIDER
        new_files_domain_test(groups_by_filter_files),
#endif
        new_single_domain_test(groups_by_filter_notfound),
        new_multi_domain_test(groups_by_filter_multiple_domains_valid),
        new_multi_domain_test(groups_by_filter_multiple_domains_notfound),

        new_single_domain_test(object_by_sid_user_cache_valid),
        new_single_domain_test(object_by_sid_user_cache_expired),
        new_single_domain_test(object_by_sid_user_cache_midpoint),
        new_single_domain_test(object_by_sid_user_ncache),
        new_single_domain_test(object_by_sid_user_missing_found),
        new_single_domain_test(object_by_sid_user_missing_notfound),
        new_multi_domain_test(object_by_sid_user_multiple_domains_found),
        new_multi_domain_test(object_by_sid_user_multiple_domains_notfound),

        new_single_domain_test(object_by_sid_group_cache_valid),
        new_single_domain_test(object_by_sid_group_cache_expired),
        new_single_domain_test(object_by_sid_group_cache_midpoint),
        new_single_domain_test(object_by_sid_group_ncache),
        new_single_domain_test(object_by_sid_group_missing_found),
        new_single_domain_test(object_by_sid_group_missing_notfound),
        new_multi_domain_test(object_by_sid_group_multiple_domains_found),
        new_multi_domain_test(object_by_sid_group_multiple_domains_notfound),

        new_single_domain_test(object_by_id_user_cache_valid),
        new_single_domain_test(object_by_id_user_cache_expired),
        new_single_domain_test(object_by_id_user_cache_midpoint),
        new_single_domain_test(object_by_id_user_ncache),
        new_single_domain_test(object_by_id_user_missing_found),
        new_single_domain_test(object_by_id_user_missing_notfound),
        new_multi_domain_test(object_by_id_user_multiple_domains_found),
        new_multi_domain_test(object_by_id_user_multiple_domains_notfound),

        new_single_domain_test(object_by_id_group_cache_valid),
        new_single_domain_test(object_by_id_group_cache_expired),
        new_single_domain_test(object_by_id_group_cache_midpoint),
        new_single_domain_test(object_by_id_group_ncache),
        new_single_domain_test(object_by_id_group_missing_found),
        new_single_domain_test(object_by_id_group_missing_notfound),
        new_multi_domain_test(object_by_id_group_multiple_domains_found),
        new_multi_domain_test(object_by_id_group_multiple_domains_notfound),

        new_multi_domain_test(object_by_id_user_multiple_domains_locator_cache_valid),
        new_multi_domain_test(object_by_id_user_multiple_domains_locator_cache_expired),
        new_subdomain_test(object_by_id_user_sub_domains_locator_cache_valid),
        new_subdomain_test(object_by_id_user_sub_domains_locator_cache_expired),
        new_subdomain_test(object_by_id_user_sub_domains_locator_cache_midpoint),
        new_subdomain_test(object_by_id_user_sub_domains_locator_missing_found),
        new_subdomain_test(object_by_id_user_sub_domains_locator_missing_notfound),
        new_subdomain_test(object_by_id_user_sub_domains_locator_cache_expired_two_calls),

        new_multi_domain_test(object_by_id_group_multiple_domains_locator_cache_valid),
        new_multi_domain_test(object_by_id_group_multiple_domains_locator_cache_expired),
        new_subdomain_test(object_by_id_group_sub_domains_locator_cache_valid),
        new_subdomain_test(object_by_id_group_sub_domains_locator_cache_expired),
        new_subdomain_test(object_by_id_group_sub_domains_locator_cache_midpoint),
        new_subdomain_test(object_by_id_group_sub_domains_locator_missing_found),
        new_subdomain_test(object_by_id_group_sub_domains_locator_missing_notfound),
        new_subdomain_test(object_by_id_group_sub_domains_locator_cache_expired_two_calls),
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
    test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
