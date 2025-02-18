/*
    SSSD

    sysdb_ts - Test for sysdb timestamp cache

    Copyright (C) 2016 Red Hat

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
#include "db/sysdb_private.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "tests_conf.ldb"
#define TEST_ID_PROVIDER "ldap"

#define TEST_DOM1_NAME "test_sysdb_ts_1"

#define TEST_GROUP_NAME         "test_group"
#define TEST_GROUP_NAME_2       "test_group_2"
#define TEST_GROUP_NAME_3       "test_group_3"
#define TEST_GROUP_NAME_OLD     "test_group_old"
#define TEST_GROUP_GID          1234
#define TEST_GROUP_GID_2        1235
#define TEST_GROUP_GID_3        1236
#define TEST_GROUP_SID          "S-1-5-21-123-456-789-111"

#define TEST_USER_NAME          "test_user"
#define TEST_USER_UID           4321
#define TEST_USER_GID           4322
#define TEST_USER_SID           "S-1-5-21-123-456-789-222"
#define TEST_USER_UPN           "test_user@TEST_REALM"

#define TEST_MODSTAMP_1   "20160408132553Z"
#define TEST_MODSTAMP_2   "20160408142553Z"
#define TEST_MODSTAMP_3   "20160408152553Z"

#define TEST_CACHE_TIMEOUT      5

#define TEST_NOW_1              100
#define TEST_NOW_2              200
#define TEST_NOW_3              300
#define TEST_NOW_4              400
#define TEST_NOW_5              500
#define TEST_NOW_6              600

#define TS_FILTER_ALL           "("SYSDB_CACHE_EXPIRE"=*)"

struct sysdb_ts_test_ctx {
    struct sss_test_ctx *tctx;
};

const char *domains[] = { TEST_DOM1_NAME,
                          NULL };

static int test_sysdb_ts_setup(void **state)
{
    struct sysdb_ts_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct sysdb_ts_test_ctx);
    assert_non_null(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_multidom_test_ctx(test_ctx, TESTS_PATH,
                                              TEST_CONF_DB, domains,
                                              TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_sysdb_ts_teardown(void **state)
{
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);

    //assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM1_NAME);
    return 0;
}

static struct sysdb_attrs *create_modstamp_attrs(TALLOC_CTX *mem_ctx,
                                                 const char *modstamp)
{
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return NULL;
    }

    ret = sysdb_attrs_add_string(attrs,
                                 SYSDB_ORIG_MODSTAMP,
                                 modstamp);
    if (ret != EOK) {
        talloc_free(attrs);
        return NULL;
    }

    return attrs;
}

static struct sysdb_attrs *create_str_attrs(TALLOC_CTX *mem_ctx,
                                            const char *key,
                                            const char *value)
{
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return NULL;
    }

    ret = sysdb_attrs_add_string(attrs, key, value);
    if (ret != EOK) {
        talloc_free(attrs);
        return NULL;
    }

    return attrs;
}

static struct sysdb_attrs *create_sidstr_attrs(TALLOC_CTX *mem_ctx,
                                               const char *sid_str)
{
    return create_str_attrs(mem_ctx, SYSDB_SID_STR, sid_str);
}

static struct sysdb_attrs *create_upnstr_attrs(TALLOC_CTX *mem_ctx,
                                               const char *upn_str)
{
    return create_str_attrs(mem_ctx, SYSDB_UPN, upn_str);
}

static struct sysdb_attrs *create_ts_attrs(TALLOC_CTX *mem_ctx,
                                           time_t expiration,
                                           time_t last_update)
{
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return NULL;
    }

    ret = sysdb_attrs_add_time_t(attrs,
                                 SYSDB_CACHE_EXPIRE,
                                 expiration);
    if (ret != EOK) {
        talloc_free(attrs);
        return NULL;
    }

    ret = sysdb_attrs_add_time_t(attrs,
                                 SYSDB_LAST_UPDATE,
                                 last_update);
    if (ret != EOK) {
        talloc_free(attrs);
        return NULL;
    }

    return attrs;
}

static struct ldb_result *sysdb_getgrnam_res(TALLOC_CTX *mem_ctx,
                                             struct sss_domain_info *domain,
                                             const char *name)
{
    int ret;
    struct ldb_result *res = NULL;

    ret = sysdb_getgrnam(mem_ctx, domain, name, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);

    return res;
}

static struct ldb_result *sysdb_getpwnam_res(TALLOC_CTX *mem_ctx,
                                             struct sss_domain_info *domain,
                                             const char *name)
{
    int ret;
    struct ldb_result *res = NULL;

    ret = sysdb_getpwnam(mem_ctx, domain, name, &res);
    assert_int_equal(ret, EOK);
    assert_non_null(res);

    return res;
}

static uint64_t get_dn_cache_timestamp(struct sysdb_ts_test_ctx *test_ctx,
                                       struct ldb_dn *dn)
{
    int ret;
    uint64_t cache_expire_sysdb;
    struct ldb_result *res;

    const char *attrs[] = { SYSDB_CACHE_EXPIRE,
                            NULL,
    };

    ret = ldb_search(test_ctx->tctx->sysdb->ldb, test_ctx, &res,
                     dn, LDB_SCOPE_BASE, attrs, NULL);
    if (ret != EOK || res == NULL || res->count != 1) {
        talloc_free(res);
        return 0;
    }

    cache_expire_sysdb = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                     SYSDB_CACHE_EXPIRE,
                                                     0);
    talloc_free(res);
    return cache_expire_sysdb;
}

static uint64_t get_gr_cache_timestamp(struct sysdb_ts_test_ctx *test_ctx,
                                       const char *name)
{
    struct ldb_dn *dn;
    uint64_t cache_expire_sysdb;

    dn = sysdb_group_dn(test_ctx, test_ctx->tctx->dom, name);
    if (dn == NULL) {
        return 0;
    }

    cache_expire_sysdb = get_dn_cache_timestamp(test_ctx, dn);
    talloc_free(dn);
    return cache_expire_sysdb;
}

static uint64_t get_pw_cache_timestamp(struct sysdb_ts_test_ctx *test_ctx,
                                       const char *name)
{
    struct ldb_dn *dn;
    uint64_t cache_expire_sysdb;

    dn = sysdb_user_dn(test_ctx, test_ctx->tctx->dom, name);
    if (dn == NULL) {
        return 0;
    }

    cache_expire_sysdb = get_dn_cache_timestamp(test_ctx, dn);
    talloc_free(dn);
    return cache_expire_sysdb;
}

static uint64_t get_dn_ts_cache_timestamp(struct sysdb_ts_test_ctx *test_ctx,
                                          struct ldb_dn *dn)
{
    size_t msg_count;
    struct ldb_message **msgs;
    uint64_t cache_expire_ts;
    const char *attrs[] = { SYSDB_CACHE_EXPIRE,
                            NULL,
    };
    int ret;

    ret = sysdb_search_ts_entry(test_ctx, test_ctx->tctx->sysdb,
                                dn, LDB_SCOPE_BASE, NULL, attrs,
                                &msg_count, &msgs);
    if (ret != EOK) {
        return 0;
    }

    if (msg_count != 1) {
        return 0;
    }

    cache_expire_ts = ldb_msg_find_attr_as_uint64(msgs[0],
                                                  SYSDB_CACHE_EXPIRE, 0);
    talloc_free(msgs);
    return cache_expire_ts;
}

static uint64_t get_gr_ts_cache_timestamp(struct sysdb_ts_test_ctx *test_ctx,
                                          const char *name)
{
    struct ldb_dn *dn;
    uint64_t cache_expire_ts;

    dn = sysdb_group_dn(test_ctx, test_ctx->tctx->dom, name);
    if (dn == NULL) {
        return 0;
    }

    cache_expire_ts = get_dn_ts_cache_timestamp(test_ctx, dn);
    talloc_free(dn);
    return cache_expire_ts;
}

static uint64_t get_pw_ts_cache_timestamp(struct sysdb_ts_test_ctx *test_ctx,
                                          const char *name)
{
    struct ldb_dn *dn;
    uint64_t cache_expire_ts;

    dn = sysdb_user_dn(test_ctx, test_ctx->tctx->dom, name);
    if (dn == NULL) {
        return 0;
    }

    cache_expire_ts = get_dn_ts_cache_timestamp(test_ctx, dn);
    talloc_free(dn);
    return cache_expire_ts;
}

static void get_gr_timestamp_attrs(struct sysdb_ts_test_ctx *test_ctx,
                                   const char *name,
                                   uint64_t *cache_expire_sysdb,
                                   uint64_t *cache_expire_ts)
{
    *cache_expire_sysdb = get_gr_cache_timestamp(test_ctx, name);
    *cache_expire_ts = get_gr_ts_cache_timestamp(test_ctx, name);
}

static void get_pw_timestamp_attrs(struct sysdb_ts_test_ctx *test_ctx,
                                   const char *name,
                                   uint64_t *cache_expire_sysdb,
                                   uint64_t *cache_expire_ts)
{
    *cache_expire_sysdb = get_pw_cache_timestamp(test_ctx, name);
    *cache_expire_ts = get_pw_ts_cache_timestamp(test_ctx, name);
}

static void test_sysdb_group_update(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    struct sysdb_attrs *group_attrs = NULL;
    uint64_t cache_expire_sysdb;
    uint64_t cache_expire_ts;
    char *test_user_member = NULL;

    /* Nothing must be stored in either cache at the beginning of the test */
    res = sysdb_getgrnam_res(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    /* Store a group without a modifyTimestamp. Must not throw an error. This
     * tests that the sysdb timestamp code is able to cope with absence of an
     * attribute it operates on gracefully.
     */
    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    assert_int_equal(ret, EOK);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_1);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_1);

    /* Store a group and add a modifyTimestamp this time.
     * Since we want to write the timestamp attributes if they are not present,
     * both caches will be bumped.
     */
    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_2);
    assert_int_equal(ret, EOK);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_2);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_2);

    /* Update the same attrs and the same modifyTimestamp.
     * Only the timestamp cache must be bumped */
    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_3);
    assert_int_equal(ret, EOK);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_2);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_3);

    /* Update with different modifyTimestamp but same attrs as previously
     * saved to the timestamp cache. We should detect the 'real' attributes
     * are the same and only bump the timestamp cache
     */
    talloc_free(group_attrs);
    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_2);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_4);
    assert_int_equal(ret, EOK);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_2);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_4);

    /* Update with different modifyTimestamp and different attrs (add a
     * member as a real-world example). Both caches must be updated. */
    ret = sysdb_store_user(test_ctx->tctx->dom,
                           TEST_USER_NAME,
                           NULL,
                           TEST_USER_UID,
                           TEST_USER_GID,
                           NULL, NULL, NULL, NULL, NULL, NULL,
                           TEST_CACHE_TIMEOUT, TEST_NOW_5);
    assert_int_equal(ret, EOK);

    talloc_free(group_attrs);
    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_3);
    assert_non_null(group_attrs);

    test_user_member = sysdb_user_strdn(group_attrs,
                                        test_ctx->tctx->dom->name,
                                        TEST_USER_NAME);
    assert_non_null(test_user_member);

    ret = sysdb_attrs_add_string(group_attrs, SYSDB_MEMBER, test_user_member);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_5);
    assert_int_equal(ret, EOK);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_5);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_5);

    /* Try to save the same member again, while it's already saved. Only the
     * timestamps cache must be bumped now
     */
    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_6);
    assert_int_equal(ret, EOK);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_5);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_6);
    talloc_free(group_attrs);
}

static void test_sysdb_group_delete(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    struct sysdb_attrs *group_attrs = NULL;
    uint64_t cache_expire_sysdb;
    uint64_t cache_expire_ts;
    struct ldb_result *ts_res;

    ts_res = talloc_zero(test_ctx, struct ldb_result);
    assert_non_null(ts_res);

    /* Nothing must be stored in either cache at the beginning of the test */
    res = sysdb_getgrnam_res(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    ret = sysdb_search_ts_groups(ts_res,
                                 test_ctx->tctx->dom,
                                 TS_FILTER_ALL,
                                 sysdb_ts_cache_attrs,
                                 ts_res);
    assert_int_equal(ret, ENOENT);

    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    assert_int_equal(ret, EOK);
    talloc_free(group_attrs);

    ret = sysdb_search_ts_groups(ts_res,
                                 test_ctx->tctx->dom,
                                 TS_FILTER_ALL,
                                 sysdb_ts_cache_attrs,
                                 ts_res);
    assert_int_equal(ret, EOK);
    assert_int_equal(ts_res->count, 1);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_1);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_1);

    ret = sysdb_delete_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID);
    assert_int_equal(ret, EOK);

    /* Nothing must be stored in either cache at the end of the test */
    ret = sysdb_search_ts_groups(ts_res,
                                 test_ctx->tctx->dom,
                                 TS_FILTER_ALL,
                                 sysdb_ts_cache_attrs,
                                 ts_res);
    assert_int_equal(ret, ENOENT);

    res = sysdb_getgrnam_res(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, 0);
    assert_int_equal(cache_expire_ts, 0);

    talloc_free(ts_res);
}

static void test_sysdb_group_rename(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    uint64_t cache_expire_sysdb;
    uint64_t cache_expire_ts;
    struct ldb_result *ts_res;
    char *filter;

    ts_res = talloc_zero(test_ctx, struct ldb_result);
    assert_non_null(ts_res);

    /* Nothing must be stored in either cache at the beginning of the test */
    res = sysdb_getgrnam_res(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);
    res = sysdb_getgrnam_res(test_ctx, test_ctx->tctx->dom,
                             TEST_GROUP_NAME_OLD);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    filter = talloc_asprintf(ts_res, "(|(%s=%s)(%s=%s))",
                             SYSDB_NAME, TEST_GROUP_NAME_OLD,
                             SYSDB_NAME, TEST_GROUP_NAME);
    assert_non_null(filter);

    ret = sysdb_search_ts_groups(ts_res,
                                 test_ctx->tctx->dom,
                                 filter,
                                 sysdb_ts_cache_attrs,
                                 ts_res);
    assert_int_equal(ret, ENOENT);
    talloc_free(filter);

    /* Store an old group */
    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME_OLD,
                            TEST_GROUP_GID,
                            NULL,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    assert_int_equal(ret, EOK);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME_OLD,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_1);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_1);

    /* Replace with a new one */
    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            NULL,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    assert_int_equal(ret, EOK);

    /* The old entry must be gone from both caches */
    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME_OLD,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, 0);
    assert_int_equal(cache_expire_ts, 0);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_1);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_1);

    res = sysdb_getgrnam_res(test_ctx, test_ctx->tctx->dom,
                             TEST_GROUP_NAME_OLD);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    talloc_free(ts_res);
}

static void assert_ts_attrs_msg(struct ldb_message *msg,
                                uint64_t exp_expiration,
                                uint64_t exp_last_update)
{
    uint64_t expiration;
    uint64_t last_update;
    const char *modstamp;

    /* Attributes normally requested with getgrnam are merged */
    expiration = ldb_msg_find_attr_as_uint64(msg, SYSDB_CACHE_EXPIRE, 0);
    assert_int_equal(expiration, exp_expiration);
    last_update = ldb_msg_find_attr_as_uint64(msg, SYSDB_LAST_UPDATE, 0);
    assert_int_equal(last_update, exp_last_update);

    /* Attributes not requested are not */
    modstamp = ldb_msg_find_attr_as_string(msg, SYSDB_ORIG_MODSTAMP, NULL);
    assert_null(modstamp);
}

static void assert_ts_attrs_res(struct ldb_result *res,
                                uint64_t exp_expiration,
                                uint64_t exp_last_update)
{
    return assert_ts_attrs_msg(res->msgs[0], exp_expiration, exp_last_update);
}

static void assert_ts_attrs_msgs_list(size_t msgs_count,
                                      struct ldb_message **msgs,
                                      uint64_t exp_expiration,
                                      uint64_t exp_last_update)
{
    struct ldb_result res;

    res.count = msgs_count;
    res.msgs = msgs;
    return assert_ts_attrs_res(&res, exp_expiration, exp_last_update);
}

static void test_sysdb_getgr_merges(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct sysdb_attrs *group_attrs = NULL;
    const char **gr_fetch_attrs = SYSDB_GRSRC_ATTRS(test_ctx->tctx->dom);
    char *filter = NULL;
    struct ldb_result *res = NULL;
    size_t msgs_count;
    struct ldb_message **msgs = NULL;
    struct ldb_message *msg = NULL;

    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    talloc_free(group_attrs);
    assert_int_equal(ret, EOK);

    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_2);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_2);
    talloc_free(group_attrs);
    assert_int_equal(ret, EOK);

    ret = sysdb_getgrnam(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);

    ret = sysdb_getgrgid(test_ctx, test_ctx->tctx->dom, TEST_GROUP_GID, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);

    filter = talloc_asprintf(test_ctx, "(%s=%s)",
                             SYSDB_NAME, TEST_GROUP_NAME);
    assert_non_null(filter);
    ret = sysdb_search_groups(test_ctx, test_ctx->tctx->dom,
                              filter, gr_fetch_attrs,
                              &msgs_count, &msgs);
    talloc_free(filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(msgs_count, 1);
    assert_ts_attrs_msgs_list(msgs_count, msgs,
                              TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(msgs);

    group_attrs = create_ts_attrs(test_ctx, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    assert_non_null(group_attrs);
    ret = sysdb_set_group_attr(test_ctx->tctx->dom, TEST_GROUP_NAME,
                               group_attrs, SYSDB_MOD_REP);
    talloc_free(group_attrs);

    ret = sysdb_getgrnam(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    talloc_free(res);

    /* Make sure sysdb_search_group_by_name includes timestamp attributes */
    ret = sysdb_search_group_by_name(test_ctx, test_ctx->tctx->dom,
                                     TEST_GROUP_NAME, gr_fetch_attrs, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_ts_attrs_msg(msg, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    talloc_free(msg);

    ret = sysdb_search_group_by_gid(test_ctx, test_ctx->tctx->dom,
                                    TEST_GROUP_GID, gr_fetch_attrs, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_ts_attrs_msg(msg, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    talloc_free(msg);
}

static void test_merge_ldb_results(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    const char **gr_fetch_attrs = SYSDB_GRSRC_ATTRS(test_ctx->tctx->dom);
    char *filter;
    struct ldb_result *res;
    struct ldb_result *res1;
    struct ldb_result *res2;
    size_t msgs_count;

    res1 = talloc_zero(test_ctx, struct ldb_result);
    assert_non_null(res1);
    res2 = talloc_zero(test_ctx, struct ldb_result);
    assert_non_null(res2);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            NULL,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME_2,
                            TEST_GROUP_GID_2,
                            NULL,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_2);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME_3,
                            TEST_GROUP_GID_3,
                            NULL,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_3);
    assert_int_equal(ret, EOK);

    filter = talloc_asprintf(test_ctx, "(|(%s=%s)(%s=%s))",
                             SYSDB_NAME, TEST_GROUP_NAME,
                             SYSDB_NAME, TEST_GROUP_NAME_2);
    assert_non_null(filter);
    ret = sysdb_search_groups(res1, test_ctx->tctx->dom,
                              filter, gr_fetch_attrs,
                              &msgs_count, &res1->msgs);
    res1->count = (unsigned)msgs_count;
    talloc_free(filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res1->count, 2);

    filter = talloc_asprintf(test_ctx, "(|(%s=%s)(%s=%s))",
                             SYSDB_NAME, TEST_GROUP_NAME_2,
                             SYSDB_NAME, TEST_GROUP_NAME_3);
    assert_non_null(filter);
    ret = sysdb_search_groups(res2, test_ctx->tctx->dom,
                              filter, gr_fetch_attrs,
                              &msgs_count, &res2->msgs);
    res2->count = (unsigned)msgs_count;
    talloc_free(filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res2->count, 2);

    res = sss_merge_ldb_results(res1, res2);
    assert_non_null(res);
    assert_int_equal(res->count, 3);

    talloc_free(res1);
    talloc_free(res2);
}

static void test_group_bysid(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    const char **gr_fetch_attrs = SYSDB_GRSRC_ATTRS(test_ctx->tctx->dom);
    struct sysdb_attrs *group_attrs = NULL;
    struct ldb_result *res;
    struct ldb_message *msg = NULL;
    struct ldb_result ts_res;

    group_attrs = create_sidstr_attrs(test_ctx, TEST_GROUP_SID);
    assert_non_null(group_attrs);

    ret = sysdb_search_object_by_sid(test_ctx,
                                     test_ctx->tctx->dom,
                                     TEST_GROUP_SID,
                                     gr_fetch_attrs,
                                     &res);
    assert_int_equal(ret, ENOENT);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    talloc_free(group_attrs);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            NULL,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_2);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_object_by_sid(test_ctx,
                                     test_ctx->tctx->dom,
                                     TEST_GROUP_SID,
                                     gr_fetch_attrs,
                                     &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);

    ret = sysdb_search_group_by_sid_str(test_ctx,
                                        test_ctx->tctx->dom,
                                        TEST_GROUP_SID,
                                        gr_fetch_attrs,
                                        &msg);
    assert_int_equal(ret, EOK);
    assert_ts_attrs_msg(msg, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);

    ret = sysdb_delete_by_sid(test_ctx->tctx->dom->sysdb,
                              test_ctx->tctx->dom,
                              TEST_GROUP_SID);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_object_by_sid(test_ctx,
                                     test_ctx->tctx->dom,
                                     TEST_GROUP_SID,
                                     gr_fetch_attrs,
                                     &res);
    assert_int_equal(ret, ENOENT);

    ret = sysdb_search_ts_groups(test_ctx,
                                 test_ctx->tctx->dom,
                                 TS_FILTER_ALL,
                                 sysdb_ts_cache_attrs,
                                 &ts_res);
    assert_int_equal(ret, ENOENT);
}

static void test_sysdb_user_update(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    struct sysdb_attrs *user_attrs = NULL;
    uint64_t cache_expire_sysdb;
    uint64_t cache_expire_ts;

    /* Nothing must be stored in either cache at the beginning of the test */
    res = sysdb_getpwnam_res(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    /* Store a user without a modifyTimestamp. Must not throw an error. This
     * tests that the sysdb timestamp code is able to cope with absence of an
     * attribute it operates on gracefully.
     */
    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_1);
    assert_int_equal(ret, EOK);

    get_pw_timestamp_attrs(test_ctx, TEST_USER_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_1);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_1);

    /* Store a user and add a modifyTimestamp this time.
     * Since we want to write the timestamp attributes if they are not present,
     * both caches will be bumped.
     */
    user_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(user_attrs);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_2);
    assert_int_equal(ret, EOK);

    get_pw_timestamp_attrs(test_ctx, TEST_USER_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_2);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_2);

    /* Update with different modifyTimestamp but same attrs as previously
     * saved to the timestamp cache. We should detect the 'real' attributes
     * are the same and only bump the timestamp cache
     */
    talloc_free(user_attrs);
    user_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_2);
    assert_non_null(user_attrs);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_4);
    assert_int_equal(ret, EOK);

    get_pw_timestamp_attrs(test_ctx, TEST_USER_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_2);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_4);

    /* Update with different modifyTimestamp and different attrs (change
     * the shell as a real-world example). Both caches must be updated. */
    talloc_free(user_attrs);
    user_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_3);
    assert_non_null(user_attrs);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/zsh", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_5);
    assert_int_equal(ret, EOK);

    get_pw_timestamp_attrs(test_ctx, TEST_USER_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_5);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_5);
}

static void test_sysdb_user_delete(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    struct sysdb_attrs *user_attrs = NULL;
    uint64_t cache_expire_sysdb;
    uint64_t cache_expire_ts;
    struct ldb_result *ts_res;

    ts_res = talloc_zero(test_ctx, struct ldb_result);
    assert_non_null(ts_res);

    /* Nothing must be stored in either cache at the beginning of the test */
    res = sysdb_getpwnam_res(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    ret = sysdb_search_ts_users(ts_res,
                                test_ctx->tctx->dom,
                                TS_FILTER_ALL,
                                sysdb_ts_cache_attrs,
                                ts_res);
    assert_int_equal(ret, ENOENT);

    user_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(user_attrs);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_1);
    assert_int_equal(ret, EOK);

    get_pw_timestamp_attrs(test_ctx, TEST_USER_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_1);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_1);

    ret = sysdb_search_ts_users(ts_res,
                                test_ctx->tctx->dom,
                                TS_FILTER_ALL,
                                sysdb_ts_cache_attrs,
                                ts_res);
    assert_int_equal(ret, EOK);
    assert_int_equal(ts_res->count, 1);

    get_pw_timestamp_attrs(test_ctx, TEST_USER_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_1);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_1);

    ret = sysdb_delete_user(test_ctx->tctx->dom,
                            TEST_USER_NAME,
                            TEST_USER_UID);
    assert_int_equal(ret, EOK);

    /* Nothing must be stored in either cache at the end of the test */
    res = sysdb_getpwnam_res(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    ret = sysdb_search_ts_users(ts_res,
                                test_ctx->tctx->dom,
                                TS_FILTER_ALL,
                                sysdb_ts_cache_attrs,
                                ts_res);
    assert_int_equal(ret, ENOENT);

    get_pw_timestamp_attrs(test_ctx, TEST_USER_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, 0);
    assert_int_equal(cache_expire_ts, 0);

    talloc_free(ts_res);
}

static void test_sysdb_getpw_merges(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct sysdb_attrs *user_attrs = NULL;
    const char *pw_fetch_attrs[] = SYSDB_PW_ATTRS;
    char *filter = NULL;
    struct ldb_result *res = NULL;
    size_t msgs_count;
    struct ldb_message **msgs = NULL;
    struct ldb_message *msg = NULL;

    user_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(user_attrs);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_1);
    talloc_free(user_attrs);
    assert_int_equal(ret, EOK);

    user_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_2);
    assert_non_null(user_attrs);

    /* sysdb cache will have test_now1 and ts cache test_now2 at this point */
    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_2);
    talloc_free(user_attrs);
    assert_int_equal(ret, EOK);

    /* getpwnam must return the timestamp from the ts cache */
    ret = sysdb_getpwnam(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);

    /* getpwuid must return the timestamp from the ts cache */
    ret = sysdb_getpwuid(test_ctx, test_ctx->tctx->dom, TEST_USER_UID, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);

    filter = talloc_asprintf(test_ctx, "(%s=%s)",
                             SYSDB_NAME, TEST_USER_NAME);
    assert_non_null(filter);
    ret = sysdb_search_users(test_ctx, test_ctx->tctx->dom,
                             filter, pw_fetch_attrs,
                             &msgs_count, &msgs);
    talloc_free(filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(msgs_count, 1);
    assert_ts_attrs_msgs_list(msgs_count, msgs,
                              TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(msgs);

    /* set_user_attrs must bump the ts cache */
    user_attrs = create_ts_attrs(test_ctx, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    assert_non_null(user_attrs);
    ret = sysdb_set_user_attr(test_ctx->tctx->dom, TEST_USER_NAME,
                              user_attrs, SYSDB_MOD_REP);
    talloc_free(user_attrs);

    /* getpwnam must return the timestamp from the ts cache */
    ret = sysdb_getpwnam(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    talloc_free(res);

    ret = sysdb_initgroups(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    talloc_free(res);

    ret = sysdb_get_user_attr(test_ctx, test_ctx->tctx->dom,
                              TEST_USER_NAME, pw_fetch_attrs, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    talloc_free(res);

    /* Make sure sysdb_search_user_by_name includes timestamp attributes */
    ret = sysdb_search_user_by_name(test_ctx, test_ctx->tctx->dom,
                                     TEST_USER_NAME, pw_fetch_attrs, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_ts_attrs_msg(msg, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    talloc_free(msg);

    ret = sysdb_search_user_by_uid(test_ctx, test_ctx->tctx->dom,
                                  TEST_USER_UID, pw_fetch_attrs, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_ts_attrs_msg(msg, TEST_NOW_3 + TEST_CACHE_TIMEOUT, TEST_NOW_3);
    talloc_free(msg);
}

static void test_user_bysid(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    const char *pw_fetch_attrs[] = SYSDB_PW_ATTRS;
    struct sysdb_attrs *user_attrs = NULL;
    struct ldb_result *res;
    struct ldb_message *msg = NULL;
    struct ldb_result ts_res;

    user_attrs = create_sidstr_attrs(test_ctx, TEST_USER_SID);
    assert_non_null(user_attrs);

    ret = sysdb_search_object_by_sid(test_ctx,
                                     test_ctx->tctx->dom,
                                     TEST_USER_SID,
                                     pw_fetch_attrs,
                                     &res);
    assert_int_equal(ret, ENOENT);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_1);
    talloc_zfree(user_attrs);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_2);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_object_by_sid(test_ctx,
                                     test_ctx->tctx->dom,
                                     TEST_USER_SID,
                                     pw_fetch_attrs,
                                     &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);

    ret = sysdb_search_user_by_sid_str(test_ctx,
                                        test_ctx->tctx->dom,
                                        TEST_USER_SID,
                                        pw_fetch_attrs,
                                        &msg);
    assert_int_equal(ret, EOK);
    assert_ts_attrs_msg(msg, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);

    ret = sysdb_delete_by_sid(test_ctx->tctx->dom->sysdb,
                              test_ctx->tctx->dom,
                              TEST_USER_SID);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_object_by_sid(test_ctx,
                                     test_ctx->tctx->dom,
                                     TEST_USER_SID,
                                     pw_fetch_attrs,
                                     &res);
    assert_int_equal(ret, ENOENT);

    ret = sysdb_search_ts_users(test_ctx,
                                test_ctx->tctx->dom,
                                TS_FILTER_ALL,
                                sysdb_ts_cache_attrs,
                                &ts_res);
    assert_int_equal(ret, ENOENT);
}

static void test_user_byupn(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    const char *pw_fetch_attrs[] = SYSDB_PW_ATTRS;
    struct sysdb_attrs *user_attrs = NULL;
    struct ldb_result *res;
    struct ldb_message *msg = NULL;

    user_attrs = create_upnstr_attrs(test_ctx, TEST_USER_UPN);
    assert_non_null(user_attrs);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_1);
    talloc_zfree(user_attrs);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           user_attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_2);
    assert_int_equal(ret, EOK);

    ret = sysdb_getpwupn(test_ctx, test_ctx->tctx->dom, false, TEST_USER_UPN, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);

    ret = sysdb_search_user_by_upn_res(test_ctx, test_ctx->tctx->dom,
                                       false, TEST_USER_UPN, pw_fetch_attrs,
                                       &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->tctx->dom,
                                   false, TEST_USER_UPN, pw_fetch_attrs,
                                   &msg);
    assert_int_equal(ret, EOK);
    assert_ts_attrs_msg(msg, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);

    ret = sysdb_initgroups_by_upn(test_ctx, test_ctx->tctx->dom,
                                  TEST_USER_UPN, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_ts_attrs_res(res, TEST_NOW_2 + TEST_CACHE_TIMEOUT, TEST_NOW_2);
    talloc_free(res);
}

static void test_sysdb_zero_now(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    uint64_t cache_expire_sysdb;
    uint64_t cache_expire_ts;
    struct sysdb_attrs *attrs = NULL;

    /* Nothing must be stored in either cache at the beginning of the test */
    res = sysdb_getpwnam_res(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    res = sysdb_getgrnam_res(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(attrs);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           attrs, NULL, TEST_CACHE_TIMEOUT,
                           0);
    talloc_zfree(attrs);
    assert_int_equal(ret, EOK);

    attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            attrs,
                            TEST_CACHE_TIMEOUT,
                            0);
    talloc_zfree(attrs);
    assert_int_equal(ret, EOK);
    talloc_zfree(attrs);

    attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(attrs);

    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           attrs, NULL, TEST_CACHE_TIMEOUT,
                           0);
    talloc_zfree(attrs);
    assert_int_equal(ret, EOK);

    attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            attrs,
                            TEST_CACHE_TIMEOUT,
                            0);
    talloc_zfree(attrs);
    assert_int_equal(ret, EOK);

    /* Even though we passed zero as the timestamp, the timestamp cache should
     * have used the current time instead
     */
    get_pw_timestamp_attrs(test_ctx, TEST_USER_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_true(cache_expire_sysdb > TEST_CACHE_TIMEOUT);
    assert_true(cache_expire_ts > TEST_CACHE_TIMEOUT);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_true(cache_expire_sysdb > TEST_CACHE_TIMEOUT);
    assert_true(cache_expire_ts > TEST_CACHE_TIMEOUT);
}

static void test_sysdb_search_with_ts(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    struct ldb_dn *base_dn;
    const char *attrs[] = { SYSDB_NAME,
                            SYSDB_OBJECTCATEGORY,
                            SYSDB_GIDNUM,
                            SYSDB_CACHE_EXPIRE,
                            NULL };
    struct sysdb_attrs *group_attrs = NULL;
    char *filter;
    uint64_t cache_expire_sysdb;
    uint64_t cache_expire_ts;
    size_t count;
    struct ldb_message **msgs;

    base_dn = sysdb_base_dn(test_ctx->tctx->dom->sysdb, test_ctx);
    assert_non_null(base_dn);

    /* Nothing must be stored in either cache at the beginning of the test */
    ret = sysdb_search_with_ts_attr(test_ctx,
                                    test_ctx->tctx->dom,
                                    base_dn,
                                    LDB_SCOPE_SUBTREE,
                                    SYSDB_CACHE_TYPE_NONE,
                                    SYSDB_NAME"=*",
                                    attrs,
                                    &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    assert_int_equal(ret, EOK);
    talloc_zfree(group_attrs);

    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME_2,
                            TEST_GROUP_GID_2,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_2);
    assert_int_equal(ret, EOK);
    talloc_zfree(group_attrs);

    /* Bump the timestamps in the cache so that the ts cache
     * and sysdb differ
     */

    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_3);
    assert_int_equal(ret, EOK);

    talloc_zfree(group_attrs);


    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(group_attrs);

    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME_2,
                            TEST_GROUP_GID_2,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_4);
    assert_int_equal(ret, EOK);

    talloc_zfree(group_attrs);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_1);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_3);

    get_gr_timestamp_attrs(test_ctx, TEST_GROUP_NAME_2,
                           &cache_expire_sysdb, &cache_expire_ts);
    assert_int_equal(cache_expire_sysdb, TEST_CACHE_TIMEOUT + TEST_NOW_2);
    assert_int_equal(cache_expire_ts, TEST_CACHE_TIMEOUT + TEST_NOW_4);

    /* Search for groups that don't expire until TEST_NOW_4 */
    filter = talloc_asprintf(test_ctx, SYSDB_CACHE_EXPIRE">=%d", TEST_NOW_4);
    assert_non_null(filter);

    /* This search should yield only one group (so, it needs to search the ts
     * cache to hit the TEST_NOW_4), but should return attributes merged from
     * both caches
     */
    ret = sysdb_search_with_ts_attr(test_ctx,
                                    test_ctx->tctx->dom,
                                    base_dn,
                                    LDB_SCOPE_SUBTREE,
                                    SYSDB_CACHE_TYPE_NONE,
                                    filter,
                                    attrs,
                                    &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_int_equal(TEST_GROUP_GID_2, ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                                   SYSDB_GIDNUM, 0));
    talloc_free(res);

    /*
     * In contrast, sysdb_search_entry merges the timestamp attributes, but does
     * not search the timestamp cache
     */
    ret = sysdb_search_entry(test_ctx,
                             test_ctx->tctx->dom->sysdb,
                             base_dn,
                             LDB_SCOPE_SUBTREE,
                             filter,
                             attrs,
                             &count,
                             &msgs);
    assert_int_equal(ret, ENOENT);

    /* Should get the same result when searching by ts attrs only */
    ret = sysdb_search_with_ts_attr(test_ctx,
                                    test_ctx->tctx->dom,
                                    base_dn,
                                    LDB_SCOPE_SUBTREE,
                                    SYSDB_CACHE_TYPE_TIMESTAMP,
                                    filter,
                                    attrs,
                                    &res);
    talloc_zfree(filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_int_equal(TEST_GROUP_GID_2, ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                                   SYSDB_GIDNUM, 0));
    talloc_free(res);

    /* We can also search in sysdb only as well, we should get back ts attrs */
    filter = talloc_asprintf(test_ctx, SYSDB_GIDNUM"=%d", TEST_GROUP_GID);
    assert_non_null(filter);

    ret = sysdb_search_with_ts_attr(test_ctx,
                                    test_ctx->tctx->dom,
                                    base_dn,
                                    LDB_SCOPE_SUBTREE,
                                    SYSDB_CACHE_TYPE_PERSISTENT,
                                    filter,
                                    attrs,
                                    &res);
    talloc_zfree(filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_int_equal(TEST_GROUP_GID, ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                                 SYSDB_GIDNUM, 0));
    assert_int_equal(TEST_CACHE_TIMEOUT + TEST_NOW_3,
                     ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_CACHE_EXPIRE, 0));
    talloc_free(res);

    /* We can also search in both using an OR-filter. Note that an AND-filter is not possible
     * unless we deconstruct the filter..
     */
    filter = talloc_asprintf(test_ctx, "(|("SYSDB_GIDNUM"=%d)"
                                         "("SYSDB_CACHE_EXPIRE">=%d))",
                                         TEST_GROUP_GID, TEST_NOW_4);
    assert_non_null(filter);

    ret = sysdb_search_with_ts_attr(test_ctx,
                                    test_ctx->tctx->dom,
                                    base_dn,
                                    LDB_SCOPE_SUBTREE,
                                    SYSDB_CACHE_TYPE_NONE,
                                    filter,
                                    attrs,
                                    &res);
    talloc_zfree(filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 2);
    talloc_free(res);
}

static void test_sysdb_user_missing_ts(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                               struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    struct sysdb_attrs *attrs = NULL;

    /* Nothing must be stored in either cache at the beginning of the test */
    res = sysdb_getpwnam_res(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    /* add user to cache */
    attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(attrs);
    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_1);
    assert_int_equal(ret, EOK);
    talloc_zfree(attrs);

    /* remove timestamp */
    struct ldb_dn *userdn = sysdb_user_dn(test_ctx, test_ctx->tctx->dom, TEST_USER_NAME);
    ret = ldb_delete(test_ctx->tctx->dom->sysdb->ldb_ts, userdn);
    assert_int_equal(ret, EOK);

    /* update user */
    attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_2);
    assert_non_null(attrs);
    ret = sysdb_store_user(test_ctx->tctx->dom, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_NAME,
                           "/home/"TEST_USER_NAME, "/bin/bash", NULL,
                           attrs, NULL, TEST_CACHE_TIMEOUT,
                           TEST_NOW_2);
    assert_int_equal(ret, EOK);
    talloc_zfree(attrs);

    /* check that ts is back */
    SSS_LDB_SEARCH(ret, test_ctx->tctx->dom->sysdb->ldb_ts, test_ctx, &res, userdn,
                   LDB_SCOPE_BASE, NULL, NULL);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    talloc_zfree(res);
    talloc_zfree(userdn);
}

static void test_sysdb_group_missing_ts(void **state)
{
    int ret;
    struct sysdb_ts_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                               struct sysdb_ts_test_ctx);
    struct ldb_result *res = NULL;
    struct sysdb_attrs *group_attrs = NULL;
    struct ldb_dn *groupdn = NULL;

    /* Nothing must be stored in either cache at the beginning of the test */
    res = sysdb_getgrnam_res(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME);
    assert_int_equal(res->count, 0);
    talloc_free(res);

    /* add group to cache */
    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_1);
    assert_non_null(group_attrs);
    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_1);
    assert_int_equal(ret, EOK);
    talloc_zfree(group_attrs);

    /* remove timestamp */
    groupdn = sysdb_group_dn(test_ctx, test_ctx->tctx->dom, TEST_GROUP_NAME);
    ret = ldb_delete(test_ctx->tctx->dom->sysdb->ldb_ts, groupdn);
    assert_int_equal(ret, EOK);

    /* update group */
    group_attrs = create_modstamp_attrs(test_ctx, TEST_MODSTAMP_2);
    assert_non_null(group_attrs);
    ret = sysdb_store_group(test_ctx->tctx->dom,
                            TEST_GROUP_NAME,
                            TEST_GROUP_GID,
                            group_attrs,
                            TEST_CACHE_TIMEOUT,
                            TEST_NOW_2);
    assert_int_equal(ret, EOK);
    talloc_zfree(group_attrs);

    /* check that ts is back */
    SSS_LDB_SEARCH(ret, test_ctx->tctx->dom->sysdb->ldb_ts, test_ctx, &res, groupdn,
                   LDB_SCOPE_BASE, NULL, NULL);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    talloc_zfree(res);
    talloc_zfree(groupdn);
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
        cmocka_unit_test_setup_teardown(test_sysdb_group_update,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_group_delete,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_group_rename,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_getgr_merges,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_group_bysid,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_merge_ldb_results,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_user_update,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_user_delete,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_getpw_merges,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_user_bysid,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_user_byupn,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_zero_now,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_search_with_ts,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_user_missing_ts,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_group_missing_ts,
                                        test_sysdb_ts_setup,
                                        test_sysdb_ts_teardown),
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
    test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    test_dom_suite_setup(TESTS_PATH);
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    if (rv == 0 && no_cleanup == 0) {
        test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    }
    return rv;
}
