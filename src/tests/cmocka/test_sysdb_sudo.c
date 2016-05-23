/*
    Authors:
        Petr Čech <pcech@redhat.com>

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
#include <ldb_module.h>

#include "tests/cmocka/common_mock.h"
#include "src/db/sysdb_sudo.h"
#include "src/db/sysdb_private.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_sysdb_sudorules.ldb"
#define TEST_DOM_NAME "test_domain.test"

#define TEST_CACHE_SUDO_TIMEOUT "20"

#define TEST_USER_NON_EXIST "no_user"

#define TEST_GROUP_NAME "test_sudo_group"
#define TEST_GID 10001

struct test_user {
    const char *name;
    uid_t uid;
    gid_t gid;
} users[] = { { "test_user1", 1001, 1001 },
              { "test_user2", 1002, 1002 },
              { "test_user3", 1003, 1003 } };

struct test_rule {
    const char *name;
    const char *host;
    const char *as_user;
} rules[] = { { "test_rule1", "test_host1.test_domain.test", "root" },
              { "test_rule2", "test_host2.test_domain.test", "root" },
              { "test_rule3", "test_host3.test_domain.test", "root" } };

struct sysdb_test_ctx {
    struct sss_test_ctx *tctx;
};

static void create_groups(struct sss_domain_info *domain)
{
    errno_t ret;

    ret = sysdb_add_group(domain, TEST_GROUP_NAME, TEST_GID,
                          NULL, 30, time(NULL));
    assert_int_equal(ret, EOK);
}

static void create_users(struct sss_domain_info *domain)
{
    errno_t ret;
    int gid;

    for (int i = 0; i < 3; i++) {
        gid = (i == 0) ? 0 : TEST_GID;
        ret = sysdb_add_user(domain, users[i].name, users[i].uid, gid,
                             users[i].name, NULL, "/bin/bash", domain->name,
                             NULL, 30, time(NULL));
        assert_int_equal(ret, EOK);
    }
}

static void create_rule_attrs(struct sysdb_attrs *rule, int i)
{
    errno_t ret;

    ret = sysdb_attrs_add_string_safe(rule, SYSDB_SUDO_CACHE_AT_CN,
                                      rules[i].name);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string_safe(rule, SYSDB_SUDO_CACHE_AT_HOST,
                                      rules[i].host);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string_safe(rule, SYSDB_SUDO_CACHE_AT_RUNASUSER,
                                      rules[i].as_user);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string_safe(rule, SYSDB_SUDO_CACHE_AT_USER,
                                      users[i].name);
    assert_int_equal(ret, EOK);
}

static int get_stored_rules_count(struct sysdb_test_ctx *test_ctx)
{
    errno_t ret;
    const char *attrs[] = { SYSDB_SUDO_CACHE_AT_CN, NULL };
    struct ldb_message **msgs = NULL;
    size_t msgs_count;

    ret = sysdb_search_sudo_rules(test_ctx, test_ctx->tctx->dom,
                                  "(objectClass=sudoRule)",
                                  attrs, &msgs_count, &msgs);
    if (!(ret == EOK || ret == ENOENT)) {
        msgs_count = -1;
    }
    talloc_zfree(msgs);

    return msgs_count;
}

static int test_sysdb_setup(void **state)
{
    struct sysdb_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct sysdb_test_ctx);
    assert_non_null(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME, "ipa", NULL);
    assert_non_null(test_ctx->tctx);

    create_groups(test_ctx->tctx->dom);
    create_users(test_ctx->tctx->dom);

    reset_ldb_errstrings(test_ctx->tctx->dom);
    check_leaks_push(test_ctx);

    *state = (void *)test_ctx;
    return 0;
}

static int test_sysdb_teardown(void **state)
{
    struct sysdb_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct sysdb_test_ctx);

    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);

    reset_ldb_errstrings(test_ctx->tctx->dom);
    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);
    assert_true(leak_check_teardown());

    return 0;
}

void test_store_sudo(void **state)
{
    errno_t ret;
    char *filter;
    int uid = 0;
    char **groupnames = NULL;
    const char *attrs[] = { SYSDB_SUDO_CACHE_AT_CN, SYSDB_SUDO_CACHE_AT_HOST,
                            SYSDB_SUDO_CACHE_AT_RUNASUSER,
                            SYSDB_SUDO_CACHE_AT_USER, NULL };
    struct ldb_message **msgs = NULL;
    size_t msgs_count;
    const char *result;
    struct sysdb_attrs *rule;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    rule = sysdb_new_attrs(test_ctx);
    assert_non_null(rule);
    create_rule_attrs(rule, 0);

    ret = sysdb_sudo_store(test_ctx->tctx->dom, &rule, 1);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_sudo_filter(test_ctx, users[0].name,
                                uid, groupnames, SYSDB_SUDO_FILTER_USERNAME,
                                &filter);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_sudo_rules(test_ctx, test_ctx->tctx->dom, filter,
                                  attrs, &msgs_count, &msgs);
    assert_int_equal(ret, EOK);

    assert_int_equal(msgs_count, 1);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_CN, NULL);
    assert_non_null(result);
    assert_string_equal(result, rules[0].name);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_HOST,
                                         NULL);
    assert_non_null(result);
    assert_string_equal(result, rules[0].host);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_RUNASUSER,
                                         NULL);
    assert_non_null(result);
    assert_string_equal(result, rules[0].as_user);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_USER,
                                         NULL);
    assert_non_null(result);
    assert_string_equal(result, users[0].name);

    talloc_zfree(rule);
    talloc_zfree(filter);
    talloc_zfree(msgs);
}

void test_sudo_purge_by_filter(void **state)
{
    errno_t ret;
    struct sysdb_attrs *rule;
    char *delete_filter;
    int uid = 0;
    char **groupnames = NULL;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    rule = sysdb_new_attrs(test_ctx);
    assert_non_null(rule);
    create_rule_attrs(rule, 0);

    ret = sysdb_sudo_store(test_ctx->tctx->dom, &rule, 1);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 1);

    ret = sysdb_get_sudo_filter(test_ctx, users[0].name,
                                uid, groupnames, SYSDB_SUDO_FILTER_USERNAME,
                                &delete_filter);
    assert_int_equal(ret, EOK);
    assert_string_equal(delete_filter,
                        "(&(objectClass=sudoRule)(|(sudoUser=test_user1)))");

    ret = sysdb_sudo_purge(test_ctx->tctx->dom, delete_filter, NULL, 0);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 0);

    talloc_zfree(rule);
    talloc_zfree(delete_filter);
}

void test_sudo_purge_by_rules(void **state)
{
    errno_t ret;
    struct sysdb_attrs *rule;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    rule = sysdb_new_attrs(test_ctx);
    assert_non_null(rule);
    create_rule_attrs(rule, 0);

    ret = sysdb_sudo_store(test_ctx->tctx->dom, &rule, 1);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 1);

    ret = sysdb_sudo_purge(test_ctx->tctx->dom, NULL, &rule, 1);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 0);

    talloc_zfree(rule);
}

void test_sudo_set_get_last_full_refresh(void **state)
{
    errno_t ret;
    time_t now;
    time_t loaded_time;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    now = time(NULL);
    ret = sysdb_sudo_set_last_full_refresh(test_ctx->tctx->dom, now);
    assert_int_equal(ret, EOK);

    ret = sysdb_sudo_get_last_full_refresh(test_ctx->tctx->dom, &loaded_time);
    assert_int_equal(ret, EOK);
    assert_int_equal(now, loaded_time);
}

void test_sudo_get_filter(void **state)
{
    errno_t ret;
    char *filter;
    int uid = 0;
    char **groupnames = NULL;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    ret = sysdb_get_sudo_filter(test_ctx, users[0].name,
                                uid, groupnames, SYSDB_SUDO_FILTER_USERNAME,
                                &filter);
    assert_int_equal(ret, EOK);
    assert_string_equal(filter,
                        "(&(objectClass=sudoRule)(|(sudoUser=test_user1)))");

    talloc_zfree(filter);
}

void test_get_sudo_user_info(void **state)
{
    errno_t ret;
    char **groupnames = NULL;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    /* User 1 has group. */
    ret = sysdb_get_sudo_user_info(test_ctx, test_ctx->tctx->dom,
                                   users[1].name, 0, &groupnames);
    assert_int_equal(ret, EOK);
    assert_string_equal(groupnames[0], TEST_GROUP_NAME);

    talloc_zfree(groupnames);
}

void test_get_sudo_user_info_nogroup(void **state)
{
    errno_t ret;
    char **groupnames = NULL;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    /* User 0 hasn't group. */
    ret = sysdb_get_sudo_user_info(test_ctx, test_ctx->tctx->dom,
                                   users[0].name, 0, &groupnames);
    assert_int_equal(ret, EOK);
    assert_null(groupnames);

    talloc_zfree(groupnames);
}

void test_get_sudo_nouser(void **state)
{
    errno_t ret;
    char **groupnames = NULL;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    ret = sysdb_get_sudo_user_info(test_ctx, test_ctx->tctx->dom,
                                   TEST_USER_NON_EXIST, 0, &groupnames);
    assert_int_equal(ret, ENOENT);
}

void test_set_sudo_rule_attr_add(void **state)
{
    errno_t ret;
    struct sysdb_attrs *rule;
    struct sysdb_attrs *new_rule;
    const char *attrs[] = { SYSDB_SUDO_CACHE_AT_CN, SYSDB_SUDO_CACHE_AT_COMMAND,
                            NULL };
    char *filter;
    int uid = 0;
    char **groupnames = NULL;
    struct ldb_message **msgs = NULL;
    size_t msgs_count;
    const char *result;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    rule = sysdb_new_attrs(test_ctx);
    assert_non_null(rule);
    create_rule_attrs(rule, 0);

    ret = sysdb_sudo_store(test_ctx->tctx->dom, &rule, 1);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 1);

    new_rule = sysdb_new_attrs(test_ctx);
    assert_non_null(new_rule);
    ret = sysdb_attrs_add_string(new_rule, SYSDB_SUDO_CACHE_AT_COMMAND,
                                 "test_command");
    assert_int_equal(ret, EOK);

    ret = sysdb_set_sudo_rule_attr(test_ctx->tctx->dom, rules[0].name,
                                   new_rule, SYSDB_MOD_ADD);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_sudo_filter(test_ctx, users[0].name,
                                uid, groupnames, SYSDB_SUDO_FILTER_USERNAME,
                                &filter);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_sudo_rules(test_ctx, test_ctx->tctx->dom, filter,
                                  attrs, &msgs_count, &msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(msgs_count, 1);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_CN, NULL);
    assert_non_null(result);
    assert_string_equal(result, rules[0].name);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_COMMAND,
                                         NULL);
    assert_non_null(result);
    assert_string_equal(result, "test_command");

    talloc_zfree(rule);
    talloc_zfree(new_rule);
    talloc_zfree(filter);
    talloc_zfree(msgs);
}

void test_set_sudo_rule_attr_replace(void **state)
{
    errno_t ret;
    struct sysdb_attrs *rule;
    struct sysdb_attrs *new_rule;
    const char *attrs[] = { SYSDB_SUDO_CACHE_AT_CN, SYSDB_CACHE_EXPIRE, NULL };
    char *filter;
    int uid = 0;
    char **groupnames = NULL;
    struct ldb_message **msgs = NULL;
    size_t msgs_count;
    const char *result;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    rule = sysdb_new_attrs(test_ctx);
    assert_non_null(rule);
    create_rule_attrs(rule, 0);

    ret = sysdb_sudo_store(test_ctx->tctx->dom, &rule, 1);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 1);

    new_rule = sysdb_new_attrs(test_ctx);
    assert_non_null(new_rule);
    ret = sysdb_attrs_add_time_t(new_rule, SYSDB_CACHE_EXPIRE, 10);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_sudo_rule_attr(test_ctx->tctx->dom, rules[0].name,
                                   new_rule, SYSDB_MOD_REP);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_sudo_filter(test_ctx, users[0].name,
                                uid, groupnames, SYSDB_SUDO_FILTER_USERNAME,
                                &filter);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_sudo_rules(test_ctx, test_ctx->tctx->dom, filter,
                                  attrs, &msgs_count, &msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(msgs_count, 1);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_CN, NULL);
    assert_non_null(result);
    assert_string_equal(result, rules[0].name);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_CACHE_EXPIRE, NULL);
    assert_non_null(result);
    assert_string_equal(result, "10");

    talloc_zfree(rule);
    talloc_zfree(new_rule);
    talloc_zfree(filter);
    talloc_zfree(msgs);
}

void test_set_sudo_rule_attr_delete(void **state)
{
    errno_t ret;
    struct sysdb_attrs *rule;
    struct sysdb_attrs *new_rule;
    const char *attrs[] = { SYSDB_SUDO_CACHE_AT_CN, SYSDB_SUDO_CACHE_AT_HOST,
                            NULL };
    char *filter;
    int uid = 0;
    char **groupnames = NULL;
    struct ldb_message **msgs = NULL;
    size_t msgs_count;
    const char *result;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    rule = sysdb_new_attrs(test_ctx);
    assert_non_null(rule);
    create_rule_attrs(rule, 0);

    ret = sysdb_sudo_store(test_ctx->tctx->dom, &rule, 1);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 1);

    new_rule = sysdb_new_attrs(test_ctx);
    assert_non_null(new_rule);
    ret = sysdb_attrs_add_string(new_rule, SYSDB_SUDO_CACHE_AT_HOST,
                                 rules[0].host);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_sudo_rule_attr(test_ctx->tctx->dom, rules[0].name,
                                   new_rule, LDB_FLAG_MOD_DELETE);
    assert_int_equal(ret, EOK);

    ret = sysdb_get_sudo_filter(test_ctx, users[0].name,
                                uid, groupnames, SYSDB_SUDO_FILTER_USERNAME,
                                &filter);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_sudo_rules(test_ctx, test_ctx->tctx->dom, filter,
                                  attrs, &msgs_count, &msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(msgs_count, 1);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_CN, NULL);
    assert_non_null(result);
    assert_string_equal(result, rules[0].name);

    result = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUDO_CACHE_AT_HOST,
                                         "deleted");
    assert_non_null(result);
    assert_string_equal(result, "deleted");

    talloc_zfree(rule);
    talloc_zfree(new_rule);
    talloc_zfree(filter);
    talloc_zfree(msgs);
}

void test_search_sudo_rules(void **state)
{
    errno_t ret;
    char *filter;
    const char *attrs[] = { SYSDB_NAME, NULL };
    struct ldb_message **msgs = NULL;
    size_t msgs_count;
    size_t num_rules = 2;
    struct sysdb_attrs *tmp_rules[num_rules];
    const char *rule_names[num_rules];
    const char *db_results[num_rules];
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    tmp_rules[0] = sysdb_new_attrs(test_ctx);
    assert_non_null(tmp_rules[0]);
    create_rule_attrs(tmp_rules[0], 0);

    tmp_rules[1] = sysdb_new_attrs(test_ctx);
    assert_non_null(tmp_rules[1]);
    create_rule_attrs(tmp_rules[1], 1);

    ret = sysdb_sudo_store(test_ctx->tctx->dom, tmp_rules, 2);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 2);

    ret = sysdb_get_sudo_filter(test_ctx, NULL, 0, NULL,
                                SYSDB_SUDO_FILTER_NONE, &filter);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_sudo_rules(test_ctx, test_ctx->tctx->dom, filter,
                                  attrs, &msgs_count, &msgs);
    assert_int_equal(ret, EOK);

    assert_int_equal(msgs_count, 2);

    rule_names[0] = rules[0].name;
    rule_names[1] = rules[1].name;

    for (int i = 0; i < num_rules; ++i) {
        db_results[i] = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        assert_non_null(db_results[i]);
    }

    assert_string_not_equal(db_results[0], db_results[1]);
    assert_true(are_values_in_array(rule_names, num_rules,
                                    db_results, num_rules));

    talloc_zfree(tmp_rules[0]);
    talloc_zfree(tmp_rules[1]);
    talloc_zfree(msgs);
    talloc_zfree(filter);
}

void test_filter_rules_by_time(void **state)
{
    errno_t ret;
    time_t cur_time;
    struct sysdb_attrs *tmp_attr;
    uint32_t _num_rules;
    struct sysdb_attrs *tmp_rules[2];
    struct sysdb_attrs **_rules;
    struct sysdb_attrs **loaded_rules;
    size_t msgs_count;
    struct ldb_message **msgs = NULL;
    char buff[20];
    const char *attrs[] = { SYSDB_SUDO_CACHE_AT_CN, SYSDB_SUDO_CACHE_AT_HOST,
                            SYSDB_SUDO_CACHE_AT_RUNASUSER,
                            SYSDB_SUDO_CACHE_AT_USER,
                            SYSDB_IPA_SUDORULE_NOTBEFORE,
                            SYSDB_IPA_SUDORULE_NOTAFTER, NULL };
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    tmp_rules[0] = sysdb_new_attrs(test_ctx);
    assert_non_null(tmp_rules[0]);
    create_rule_attrs(tmp_rules[0], 0);

    tmp_rules[1] = sysdb_new_attrs(test_ctx);
    assert_non_null(tmp_rules[1]);
    create_rule_attrs(tmp_rules[1], 1);

    ret = sysdb_sudo_store(test_ctx->tctx->dom, tmp_rules, 2);
    assert_int_equal(ret, EOK);
    assert_int_equal(get_stored_rules_count(test_ctx), 2);

    /*
     * We hit DST issue of time functions,
     * so we use big time shift to avoid this.
     */

    tmp_attr = sysdb_new_attrs(test_ctx);
    assert_non_null(tmp_attr);
    cur_time = time(NULL) + 10000;
    strftime(buff, 20, "%Y%m%d%H%M%S%z", localtime(&cur_time));
    ret = sysdb_attrs_add_string(tmp_attr, SYSDB_SUDO_CACHE_AT_NOTBEFORE, buff);
    assert_int_equal(ret, EOK);
    cur_time = time(NULL) + 20000;
    strftime(buff, 20, "%Y%m%d%H%M%S%z", localtime(&cur_time));
    ret = sysdb_attrs_add_string(tmp_attr, SYSDB_SUDO_CACHE_AT_NOTAFTER, buff);
    assert_int_equal(ret, EOK);
    ret = sysdb_set_sudo_rule_attr(test_ctx->tctx->dom, rules[0].name,
                                   tmp_attr, SYSDB_MOD_ADD);
    assert_int_equal(ret, EOK);
    talloc_zfree(tmp_attr);

    tmp_attr = sysdb_new_attrs(test_ctx);
    assert_non_null(tmp_attr);
    cur_time = time(NULL) - 10000;
    strftime(buff, 20, "%Y%m%d%H%M%S%z", localtime(&cur_time));
    ret = sysdb_attrs_add_string(tmp_attr, SYSDB_SUDO_CACHE_AT_NOTBEFORE, buff);
    assert_int_equal(ret, EOK);
    cur_time = time(NULL) + 10000;
    strftime(buff, 20, "%Y%m%d%H%M%S%z", localtime(&cur_time));
    ret = sysdb_attrs_add_string(tmp_attr, SYSDB_SUDO_CACHE_AT_NOTAFTER, buff);
    assert_int_equal(ret, EOK);
    ret = sysdb_set_sudo_rule_attr(test_ctx->tctx->dom, rules[1].name,
                                   tmp_attr, SYSDB_MOD_ADD);
    assert_int_equal(ret, EOK);
    talloc_zfree(tmp_attr);

    assert_int_equal(get_stored_rules_count(test_ctx), 2);

    ret = sysdb_search_sudo_rules(test_ctx, test_ctx->tctx->dom,
                                  "(objectClass=sudoRule)",
                                  attrs, &msgs_count, &msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(msgs_count, 2);

    ret = sysdb_msg2attrs(test_ctx, 2, msgs, &loaded_rules);
    assert_int_equal(ret, EOK);

    talloc_zfree(msgs);

    ret = sysdb_sudo_filter_rules_by_time(test_ctx, 2, loaded_rules, 0,
                                          &_num_rules, &_rules);

    assert_int_equal(ret, EOK);
    assert_int_equal(_num_rules, 1);

    talloc_zfree(tmp_rules[0]);
    talloc_zfree(tmp_rules[1]);
    talloc_zfree(loaded_rules);
    talloc_zfree(_rules);
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
        /* sysdb_sudo_store() */
        cmocka_unit_test_setup_teardown(test_store_sudo,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),

        /* sysdb_sudo_purge() */
        cmocka_unit_test_setup_teardown(test_sudo_purge_by_filter,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),

        cmocka_unit_test_setup_teardown(test_sudo_purge_by_rules,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),

        /*
         * sysdb_sudo_set_last_full_refresh()
         * sysdb_sudo_get_last_full_refresh()
         */
        cmocka_unit_test_setup_teardown(test_sudo_set_get_last_full_refresh,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),

        /* sysdb_get_sudo_filter() */
        cmocka_unit_test_setup_teardown(test_sudo_get_filter,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
        /* sysdb_get_sudo_user_info() */
        cmocka_unit_test_setup_teardown(test_get_sudo_user_info,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_get_sudo_user_info_nogroup,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),

        cmocka_unit_test_setup_teardown(test_get_sudo_nouser,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),

        /* sysdb_set_sudo_rule_attr() */
        cmocka_unit_test_setup_teardown(test_set_sudo_rule_attr_add,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_set_sudo_rule_attr_replace,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_set_sudo_rule_attr_delete,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),

        /* sysdb_search_sudo_rules() */
        cmocka_unit_test_setup_teardown(test_search_sudo_rules,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),

        /* sysdb_sudo_filter_rules_by_time() */
        cmocka_unit_test_setup_teardown(test_filter_rules_by_time,
                                        test_sysdb_setup,
                                        test_sysdb_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
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
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
