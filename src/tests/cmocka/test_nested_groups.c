/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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
#include <ldb.h>
#include <errno.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_sdap.h"
#include "tests/cmocka/common_mock_be.h"
#include "tests/cmocka/common_mock_sysdb_objects.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_opts.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_ldap_nested_groups_conf.ldb"
#define TEST_DOM_NAME "ldap_nested_groups_test"
#define TEST_ID_PROVIDER "ldap"
#define TEST_EXT_MEMBER "extMember"

bool _dp_target_enabled(struct data_provider *provider,
                        const char *module_name,
                        ...)
{
    return true;
}

#define new_test(test) \
    cmocka_unit_test_setup_teardown(nested_groups_test_ ## test, \
                                    nested_groups_test_setup, \
                                    nested_groups_test_teardown)

/* put users and groups under the same container so we can easily run the
 * same tests cases for several search base scenarios */
#define OBJECT_BASE_DN "cn=objects,dc=test,dc=com"
#define GROUP_BASE_DN "cn=groups," OBJECT_BASE_DN
#define USER_BASE_DN "cn=users," OBJECT_BASE_DN
#define EXCLUDE_BASE_DN "cn=exclude," USER_BASE_DN
#define BAD_BASE_DN "cn=bad," USER_BASE_DN

struct nested_groups_test_ctx {
    struct sss_test_ctx *tctx;

    struct be_ctx *be_ctx;
    struct sdap_options *sdap_opts;
    struct sdap_handle *sdap_handle;
    struct sdap_domain *sdap_domain;
    struct sdap_idmap_ctx *idmap_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    hash_table_t *missing_external;

    struct sysdb_attrs **users;
    struct sysdb_attrs **groups;
    unsigned long num_users;
    unsigned long num_groups;

    /* External members tests */
    struct sdap_ext_member_ctx *ext_ctx;
    enum sysdb_member_type ext_member_type;
    struct sss_domain_info *ext_dom;
    struct sysdb_attrs *ext_member;
};

errno_t krb5_try_kdcip(struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct dp_option *opts,
                       int opt_id)
{
    return EOK;
}

/* Both arrays must have the same length! */
static void compare_sysdb_string_array_noorder(struct sysdb_attrs **sysdb_array,
                                               const char **string_array,
                                               size_t len)
{
    int i, ii;
    errno_t ret;
    const char *name;

    /* Check the returned groups. The order is irrelevant. */
    for (i = 0; i < len; i++) {
        ret = sysdb_attrs_get_string(sysdb_array[i], SYSDB_NAME, &name);
        assert_int_equal(ret, ERR_OK);

        for (ii = 0; ii < len; ii++) {
            if (string_array[ii] == NULL) {
                continue;
            }
            if (strcmp(name, string_array[ii]) == 0) {
                string_array[ii] = NULL;
                break;
            }
        }
    }

    for (i = 0; i < len; i++) {
        assert_null(string_array[i]);
    }
}

static void nested_groups_test_done(struct tevent_req *req)
{
    struct nested_groups_test_ctx *ctx = NULL;

    ctx = tevent_req_callback_data(req, struct nested_groups_test_ctx);

    ctx->tctx->error = sdap_nested_group_recv(ctx, req,
                                              &ctx->num_users, &ctx->users,
                                              &ctx->num_groups, &ctx->groups,
                                              &ctx->missing_external);
    talloc_zfree(req);

    ctx->tctx->done = true;
}

static void nested_groups_test_one_group_no_members(void **state)
{
    struct nested_groups_test_ctx *test_ctx = NULL;
    struct sysdb_attrs *rootgroup = NULL;
    struct tevent_req *req = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    errno_t ret;

    test_ctx = talloc_get_type_abort(*state, struct nested_groups_test_ctx);

    rootgroup = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN, 1000,
                                            "rootgroup", NULL);

    /* mock return values */
    sss_will_return_always(sdap_has_deref_support, false);

    /* run test, check for memory leaks */
    req_mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(req_mem_ctx);
    check_leaks_push(req_mem_ctx);

    req = sdap_nested_group_send(req_mem_ctx, test_ctx->tctx->ev,
                                 test_ctx->sdap_domain, test_ctx->sdap_opts,
                                 test_ctx->sdap_handle, rootgroup);
    assert_non_null(req);
    tevent_req_set_callback(req, nested_groups_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_true(check_leaks_pop(req_mem_ctx) == true);
    talloc_zfree(req_mem_ctx);
    /* check return code */
    assert_int_equal(ret, ERR_OK);

    /* check generated values */
    assert_int_equal(test_ctx->num_users, 0);
    assert_null(test_ctx->users);

    assert_int_equal(test_ctx->num_groups, 1);
    assert_non_null(test_ctx->groups);
    assert_true(rootgroup == test_ctx->groups[0]);
}

static void nested_groups_test_one_group_unique_members(void **state)
{
    struct nested_groups_test_ctx *test_ctx = NULL;
    struct sysdb_attrs *rootgroup = NULL;
    struct tevent_req *req = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    errno_t ret;
    const char *users[] = { "cn=user1,"USER_BASE_DN,
                            "cn=user2,"USER_BASE_DN,
                            NULL };
    const struct sysdb_attrs *user1_reply[2] = { NULL };
    const struct sysdb_attrs *user2_reply[2] = { NULL };
    const char * expected[] = { "user1",
                                "user2" };


    test_ctx = talloc_get_type_abort(*state, struct nested_groups_test_ctx);

    /* mock return values */
    rootgroup = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN, 1000,
                                            "rootgroup", users);

    user1_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2001, "user1");
    assert_non_null(user1_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user1_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    user2_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2002, "user2");
    assert_non_null(user2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user2_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    sss_will_return_always(sdap_has_deref_support, false);

    /* run test, check for memory leaks */
    req_mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(req_mem_ctx);
    check_leaks_push(req_mem_ctx);

    req = sdap_nested_group_send(req_mem_ctx, test_ctx->tctx->ev,
                                 test_ctx->sdap_domain, test_ctx->sdap_opts,
                                 test_ctx->sdap_handle, rootgroup);
    assert_non_null(req);
    tevent_req_set_callback(req, nested_groups_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_true(check_leaks_pop(req_mem_ctx) == true);
    talloc_zfree(req_mem_ctx);

    /* check return code */
    assert_int_equal(ret, ERR_OK);

    /* Check the users */
    assert_int_equal(test_ctx->num_users, N_ELEMENTS(expected));
    assert_int_equal(test_ctx->num_groups, 1);

    compare_sysdb_string_array_noorder(test_ctx->users,
                                       expected, N_ELEMENTS(expected));
}

static void nested_groups_test_one_group_unique_members_one_ignored(void **state)
{
    struct nested_groups_test_ctx *test_ctx = NULL;
    struct sdap_search_base **ignore;
    struct sysdb_attrs *rootgroup = NULL;
    struct tevent_req *req = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    errno_t ret;
    const char *users[] = { "cn=user1," USER_BASE_DN,
                            "cn=user2," EXCLUDE_BASE_DN,
                            NULL };
    const struct sysdb_attrs *user1_reply[2] = { NULL };
    const char * expected[] = { "user1" };


    test_ctx = talloc_get_type_abort(*state, struct nested_groups_test_ctx);

    /* mock return values */
    rootgroup = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN, 1000,
                                            "rootgroup", users);

    /* Set the exclude bases */
    ignore = talloc_zero_array(test_ctx, struct sdap_search_base *, 3);
    assert_non_null(ignore);

    ignore[0] = talloc_zero(ignore, struct sdap_search_base);
    assert_non_null(ignore[0]);
    ignore[0]->basedn = BAD_BASE_DN;
    ignore[0]->ldb_basedn = ldb_dn_new(ignore[0],
                                       sysdb_ctx_get_ldb(test_ctx->tctx->sysdb),
                                       ignore[0]->basedn);
    assert_non_null(ignore[0]->ldb_basedn);

    ignore[1] = talloc_zero(ignore, struct sdap_search_base);
    assert_non_null(ignore[1]);
    ignore[1]->basedn = EXCLUDE_BASE_DN;
    ignore[1]->ldb_basedn = ldb_dn_new(ignore[1],
                                       sysdb_ctx_get_ldb(test_ctx->tctx->sysdb),
                                       ignore[1]->basedn);
    assert_non_null(ignore[1]->ldb_basedn);

    test_ctx->sdap_domain->ignore_user_search_bases = ignore;

    user1_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2001, "user1");
    assert_non_null(user1_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user1_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    sss_will_return_always(sdap_has_deref_support, false);

    /* run test, check for memory leaks */
    req_mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(req_mem_ctx);
    check_leaks_push(req_mem_ctx);

    req = sdap_nested_group_send(req_mem_ctx, test_ctx->tctx->ev,
                                 test_ctx->sdap_domain, test_ctx->sdap_opts,
                                 test_ctx->sdap_handle, rootgroup);
    assert_non_null(req);
    tevent_req_set_callback(req, nested_groups_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_true(check_leaks_pop(req_mem_ctx));
    talloc_zfree(req_mem_ctx);

    /* check return code */
    assert_int_equal(ret, ERR_OK);

    /* Check the users */
    assert_int_equal(test_ctx->num_users, N_ELEMENTS(expected));
    assert_int_equal(test_ctx->num_groups, 1);

    compare_sysdb_string_array_noorder(test_ctx->users,
                                       expected, N_ELEMENTS(expected));
}

static void nested_groups_test_one_group_dup_users(void **state)
{
    struct nested_groups_test_ctx *test_ctx = NULL;
    struct sysdb_attrs *rootgroup = NULL;
    struct tevent_req *req = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    errno_t ret;
    const char *name;
    const char *users[] = { "cn=user1,"USER_BASE_DN,
                            "cn=user1,"USER_BASE_DN,
                            NULL };
    const struct sysdb_attrs *user1_reply[2] = { NULL };
    const struct sysdb_attrs *user2_reply[2] = { NULL };

    test_ctx = talloc_get_type_abort(*state, struct nested_groups_test_ctx);

    /* mock return values */
    rootgroup = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN, 1000,
                                            "rootgroup", users);

    user1_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2001, "user1");
    assert_non_null(user1_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user1_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    user2_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2001, "user1");
    assert_non_null(user2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user2_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    sss_will_return_always(sdap_has_deref_support, false);

    /* run test, check for memory leaks */
    req_mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(req_mem_ctx);
    check_leaks_push(req_mem_ctx);

    req = sdap_nested_group_send(req_mem_ctx, test_ctx->tctx->ev,
                                 test_ctx->sdap_domain, test_ctx->sdap_opts,
                                 test_ctx->sdap_handle, rootgroup);
    assert_non_null(req);
    tevent_req_set_callback(req, nested_groups_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_true(check_leaks_pop(req_mem_ctx) == true);
    talloc_zfree(req_mem_ctx);

    /* check return code */
    assert_int_equal(ret, ERR_OK);

    /* Check the users */
    assert_int_equal(test_ctx->num_users, 1);
    assert_int_equal(test_ctx->num_groups, 1);

    ret = sysdb_attrs_get_string(test_ctx->users[0], SYSDB_NAME, &name);
    assert_int_equal(ret, ERR_OK);
    assert_string_equal(name, "user1");
}

static void nested_groups_test_one_group_unique_group_members(void **state)
{
    struct nested_groups_test_ctx *test_ctx = NULL;
    struct sysdb_attrs *rootgroup = NULL;
    struct tevent_req *req = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    errno_t ret;
    const char *groups[] = { "cn=emptygroup1,"GROUP_BASE_DN,
                             "cn=emptygroup2,"GROUP_BASE_DN,
                             NULL };
    const struct sysdb_attrs *group1_reply[2] = { NULL };
    const struct sysdb_attrs *group2_reply[2] = { NULL };
    const char * expected[] = { "rootgroup",
                                "emptygroup1",
                                "emptygroup2" };

    test_ctx = talloc_get_type_abort(*state, struct nested_groups_test_ctx);

    /* mock return values */
    rootgroup = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN, 1000,
                                            "rootgroup", groups);

    group1_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1001, "emptygroup1", NULL);
    assert_non_null(group1_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group1_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    group2_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1002, "emptygroup2", NULL);
    assert_non_null(group2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group2_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    sss_will_return_always(sdap_has_deref_support, false);

    /* run test, check for memory leaks */
    req_mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(req_mem_ctx);
    check_leaks_push(req_mem_ctx);

    req = sdap_nested_group_send(req_mem_ctx, test_ctx->tctx->ev,
                                 test_ctx->sdap_domain, test_ctx->sdap_opts,
                                 test_ctx->sdap_handle, rootgroup);
    assert_non_null(req);
    tevent_req_set_callback(req, nested_groups_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_true(check_leaks_pop(req_mem_ctx) == true);
    talloc_zfree(req_mem_ctx);

    /* check return code */
    assert_int_equal(ret, ERR_OK);

    /* Check the users */
    assert_int_equal(test_ctx->num_users, 0);
    assert_int_equal(test_ctx->num_groups, N_ELEMENTS(expected));

    compare_sysdb_string_array_noorder(test_ctx->groups,
                                       expected, N_ELEMENTS(expected));
}

static void nested_groups_test_one_group_dup_group_members(void **state)
{
    struct nested_groups_test_ctx *test_ctx = NULL;
    struct sysdb_attrs *rootgroup = NULL;
    struct tevent_req *req = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    errno_t ret;
    const char *groups[] = { "cn=emptygroup1,"GROUP_BASE_DN,
                             "cn=emptygroup1,"GROUP_BASE_DN,
                             NULL };
    const struct sysdb_attrs *group1_reply[2] = { NULL };
    const struct sysdb_attrs *group2_reply[2] = { NULL };
    const char * expected[] = { "rootgroup",
                                "emptygroup1" };

    test_ctx = talloc_get_type_abort(*state, struct nested_groups_test_ctx);

    /* mock return values */
    rootgroup = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN, 1000,
                                            "rootgroup", groups);

    group1_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1001, "emptygroup1", NULL);
    assert_non_null(group1_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group1_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    group2_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1001, "emptygroup1", NULL);
    assert_non_null(group2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group2_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    sss_will_return_always(sdap_has_deref_support, false);

    /* run test, check for memory leaks */
    req_mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(req_mem_ctx);
    check_leaks_push(req_mem_ctx);

    req = sdap_nested_group_send(req_mem_ctx, test_ctx->tctx->ev,
                                 test_ctx->sdap_domain, test_ctx->sdap_opts,
                                 test_ctx->sdap_handle, rootgroup);
    assert_non_null(req);
    tevent_req_set_callback(req, nested_groups_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_true(check_leaks_pop(req_mem_ctx) == true);
    talloc_zfree(req_mem_ctx);

    /* check return code */
    assert_int_equal(ret, ERR_OK);

    assert_int_equal(test_ctx->num_users, 0);
    assert_int_equal(test_ctx->num_groups, N_ELEMENTS(expected));

    compare_sysdb_string_array_noorder(test_ctx->groups,
                                       expected, N_ELEMENTS(expected));
}

static void nested_groups_test_nested_chain(void **state)
{
    struct nested_groups_test_ctx *test_ctx = NULL;
    struct tevent_req *req = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    errno_t ret;
    const char *rootgroup_members[] = { "cn=user1,"USER_BASE_DN,
                                        "cn=group1,"GROUP_BASE_DN,
                                        NULL };
    const char *group1_members[] = { "cn=user2,"USER_BASE_DN,
                                     "cn=group2,"GROUP_BASE_DN,
                                     NULL };
    const char *group2_members[] = { "cn=user3,"USER_BASE_DN,
                                      NULL };
    struct sysdb_attrs *rootgroup;
    const struct sysdb_attrs *user1_reply[2] = { NULL };
    const struct sysdb_attrs *group1_reply[2] = { NULL };
    const struct sysdb_attrs *user2_reply[2] = { NULL };
    const struct sysdb_attrs *group2_reply[2] = { NULL };
    const struct sysdb_attrs *user3_reply[2] = { NULL };
    const char *expected_groups[] = { "rootgroup", "group1", "group2" };
    const char *expected_users[] = { "user1", "user2", "user3" };

    test_ctx = talloc_get_type_abort(*state, struct nested_groups_test_ctx);

    /* mock return values */
    rootgroup = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN, 1000,
                                            "rootgroup", rootgroup_members);
    assert_non_null(rootgroup);

    user1_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2001, "user1");
    assert_non_null(user1_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user1_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    group1_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1001, "group1",
                                                  group1_members);
    assert_non_null(group1_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group1_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    user2_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2002, "user2");
    assert_non_null(user2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user2_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    group2_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1002, "group2",
                                                  group2_members);
    assert_non_null(group2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group2_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    user3_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2003, "user3");
    assert_non_null(user3_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user3_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    sss_will_return_always(sdap_has_deref_support, false);

    /* run test, check for memory leaks */
    req_mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(req_mem_ctx);
    check_leaks_push(req_mem_ctx);

    req = sdap_nested_group_send(req_mem_ctx, test_ctx->tctx->ev,
                                 test_ctx->sdap_domain, test_ctx->sdap_opts,
                                 test_ctx->sdap_handle, rootgroup);
    assert_non_null(req);
    tevent_req_set_callback(req, nested_groups_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_true(check_leaks_pop(req_mem_ctx) == true);
    talloc_zfree(req_mem_ctx);

    /* check return code */
    assert_int_equal(ret, ERR_OK);

    /* Check the users */
    assert_int_equal(test_ctx->num_users, N_ELEMENTS(expected_users));
    assert_int_equal(test_ctx->num_groups, N_ELEMENTS(expected_groups));

    compare_sysdb_string_array_noorder(test_ctx->groups,
                                       expected_groups,
                                       N_ELEMENTS(expected_groups));
    compare_sysdb_string_array_noorder(test_ctx->users,
                                       expected_users,
                                       N_ELEMENTS(expected_users));
}

static void nested_groups_test_nested_chain_with_error(void **state)
{
    struct nested_groups_test_ctx *test_ctx = NULL;
    struct tevent_req *req = NULL;
    TALLOC_CTX *req_mem_ctx = NULL;
    errno_t ret;
    const char *rootgroup_members[] = { "cn=group1,"GROUP_BASE_DN,
                                        NULL };
    const char *group1_members[] = { "cn=group2,"GROUP_BASE_DN,
                                     NULL };
    const char *group2_members[] = { "cn=user1,"USER_BASE_DN,
                                      NULL };
    struct sysdb_attrs *rootgroup;
    const struct sysdb_attrs *user_reply[2] = { NULL };
    const struct sysdb_attrs *group1_reply[2] = { NULL };
    const struct sysdb_attrs *group2_reply[2] = { NULL };

    test_ctx = talloc_get_type_abort(*state, struct nested_groups_test_ctx);

    /* mock return values */
    rootgroup = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN, 1000,
                                            "rootgroup", rootgroup_members);
    assert_non_null(rootgroup);

    group1_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1001, "group1",
                                                  group1_members);
    assert_non_null(group1_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group1_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    group2_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1002, "group2",
                                                  group2_members);
    assert_non_null(group2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group2_reply);
    will_return(sdap_get_generic_recv, ERR_OK);

    user_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2001, "user1");
    assert_non_null(user_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user_reply);
    will_return(sdap_get_generic_recv, EIO);

    sss_will_return_always(sdap_has_deref_support, false);

    /* run test, check for memory leaks */
    req_mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(req_mem_ctx);
    check_leaks_push(req_mem_ctx);

    req = sdap_nested_group_send(req_mem_ctx, test_ctx->tctx->ev,
                                 test_ctx->sdap_domain, test_ctx->sdap_opts,
                                 test_ctx->sdap_handle, rootgroup);
    assert_non_null(req);
    tevent_req_set_callback(req, nested_groups_test_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_true(check_leaks_pop(req_mem_ctx) == true);
    talloc_zfree(req_mem_ctx);

    /* check return code */
    assert_int_equal(ret, EIO);
}

static int nested_groups_test_setup(void **state)
{
    errno_t ret;
    struct nested_groups_test_ctx *test_ctx = NULL;
    static struct sss_test_conf_param params[] = {
        { "ldap_schema", "rfc2307bis" }, /* enable nested groups */
        { "ldap_search_base", OBJECT_BASE_DN },
        { "ldap_user_search_base", USER_BASE_DN },
        { "ldap_group_search_base", GROUP_BASE_DN },
        { NULL, NULL }
    };

    test_ctx = talloc_zero(NULL, struct nested_groups_test_ctx);
    assert_non_null(test_ctx);
    *state = test_ctx;

    /* initialize domain */
    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, params);
    assert_non_null(test_ctx->tctx);

    /* mock SDAP */
    test_ctx->sdap_opts = mock_sdap_options_ldap(test_ctx,
                                                 test_ctx->tctx->dom,
                                                 test_ctx->tctx->confdb,
                                                 test_ctx->tctx->conf_dom_path);
    assert_non_null(test_ctx->sdap_opts);
    test_ctx->sdap_domain = test_ctx->sdap_opts->sdom;
    test_ctx->sdap_handle = mock_sdap_handle(test_ctx);
    assert_non_null(test_ctx->sdap_handle);

    test_ctx->be_ctx = mock_be_ctx(test_ctx, test_ctx->tctx);
    assert_non_null(test_ctx->be_ctx);

    test_ctx->sdap_id_ctx = mock_sdap_id_ctx(test_ctx,
                                             test_ctx->be_ctx,
                                             test_ctx->sdap_opts);
    assert_non_null(test_ctx->sdap_id_ctx);

    ret = sdap_idmap_init(test_ctx, test_ctx->sdap_id_ctx, &test_ctx->idmap_ctx);
    assert_int_equal(ret, EOK);
    test_ctx->sdap_opts->idmap_ctx = test_ctx->idmap_ctx;

    test_ctx->ext_ctx = talloc_zero(test_ctx, struct sdap_ext_member_ctx);
    assert_non_null(test_ctx->ext_ctx);

    return 0;
}

static int nested_groups_test_teardown(void **state)
{
    talloc_zfree(*state);
    return 0;
}

struct test_ext_pvt {
    struct sss_domain_info *dom_head;
};

struct test_ext_member {
    const char *sid;
    const char *short_name;
    id_t id;
    enum sysdb_member_type member_type;
} test_ext_member_table[] = {
    { "S-1-5-21-3623811015-3361044348-30300820-10001",
      "ext_user10001", 10001, SYSDB_MEMBER_USER },
    { "S-1-5-21-3623811015-3361044348-30300820-20001",
      "ext_group20001", 10001, SYSDB_MEMBER_GROUP },
    { NULL, NULL, 0, 0 },
};

struct test_resolve_ext_state {
    struct sss_domain_info *dom;
    enum sysdb_member_type member_type;
    struct sysdb_attrs *member;
};

static errno_t test_resolve_ext_save_obj(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *dom,
                                         const char *name,
                                         id_t id,
                                         enum sysdb_member_type member_type,
                                         struct sysdb_attrs **_member);

struct tevent_req *test_resolve_ext_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         const char *ext_member,
                                         void *pvt)
{
    struct tevent_req *req;
    struct test_resolve_ext_state *state;
    errno_t ret;
    struct test_ext_pvt *test_pvt = talloc_get_type(pvt, struct test_ext_pvt);
    struct sysdb_attrs *member;

    req = tevent_req_create(mem_ctx, &state, struct test_resolve_ext_state);
    if (req == NULL) {
        return NULL;
    }

    for (size_t i = 0; test_ext_member_table[i].sid; i++) {
        if (strcmp(ext_member, test_ext_member_table[i].sid) == 0) {
            ret = test_resolve_ext_save_obj(state, test_pvt->dom_head,
                                            test_ext_member_table[i].short_name,
                                            test_ext_member_table[i].id,
                                            test_ext_member_table[i].member_type,
                                            &member);
            if (ret != EOK) {
                goto immediate;
            }

            state->dom = test_pvt->dom_head;
            state->member_type = test_ext_member_table[i].member_type;
            state->member = talloc_steal(state, member);

            ret = EOK;
            goto immediate;
        }
    }

    ret = ENOENT;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t test_resolve_ext_save_obj(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *dom,
                                         const char *name,
                                         id_t id,
                                         enum sysdb_member_type member_type,
                                         struct sysdb_attrs **_member)
{
    errno_t ret;
    struct ldb_result *res;
    char *home;
    struct sysdb_attrs **members;
    TALLOC_CTX *tmp_ctx;
    char *fqdn;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    fqdn = sss_create_internal_fqname(tmp_ctx, name, dom->name);
    if (fqdn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (member_type == SYSDB_MEMBER_USER) {
        home = talloc_asprintf(tmp_ctx, "/home/%s", name);
        if (home == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_store_user(dom, fqdn, "*", id, id,
                               name, home, "/bin/bash", NULL, NULL,
                               NULL, 1000, time(NULL));
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_getpwnam(tmp_ctx, dom, fqdn, &res);
        if (ret != EOK) {
            goto done;
        }
    } else if (member_type == SYSDB_MEMBER_GROUP) {
        ret = sysdb_store_group(dom, fqdn, id, NULL, 1000, time(NULL));
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_getgrnam(tmp_ctx, dom, fqdn, &res);
        if (ret != EOK) {
            goto done;
        }
    } else {
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_msg2attrs(tmp_ctx, 1, res->msgs, &members);
    if (ret != EOK) {
        goto done;
    }

    *_member = talloc_steal(mem_ctx, members[0]);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static void test_get_enterprise_principal_string_filter(void **state)
{
    int ret;
    char *ep_filter;
    struct dp_option *no_krb5_realm_opt = default_basic_opts;

    struct dp_option *krb5_realm_opt;

    ret = dp_copy_defaults(NULL, default_basic_opts, SDAP_OPTS_BASIC,
                           &krb5_realm_opt);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_string(krb5_realm_opt, SDAP_KRB5_REALM, "TEST.DOM");
    assert_int_equal(ret, EOK);

    ep_filter = get_enterprise_principal_string_filter(NULL, NULL, NULL, NULL);
    assert_null(ep_filter);

    ep_filter = get_enterprise_principal_string_filter(NULL, "aBC", "p@d.c",
                                                       no_krb5_realm_opt);
    assert_null(ep_filter);

    ep_filter = get_enterprise_principal_string_filter(NULL, "aBC", "p",
                                                       krb5_realm_opt);
    assert_null(ep_filter);

    ep_filter = get_enterprise_principal_string_filter(NULL, "aBC", "p@d.c",
                                                       krb5_realm_opt);
    assert_non_null(ep_filter);
    assert_string_equal(ep_filter, "(aBC=p\\\\@d.c@TEST.DOM)");
    talloc_free(ep_filter);
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
        new_test(one_group_no_members),
        new_test(one_group_unique_members),
        new_test(one_group_unique_members_one_ignored),
        new_test(one_group_dup_users),
        new_test(one_group_unique_group_members),
        new_test(one_group_dup_group_members),
        new_test(nested_chain),
        new_test(nested_chain_with_error),
/*
        cmocka_unit_test_setup_teardown(nested_group_external_member_test,
                                        nested_group_external_member_setup,
                                        nested_group_external_member_teardown),
*/
        cmocka_unit_test(test_get_enterprise_principal_string_filter),
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
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }
    return rv;
}
