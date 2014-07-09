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
#include <errno.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_sdap.h"
#include "tests/cmocka/common_mock_sysdb_objects.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async_private.h"

#define TESTS_PATH "tests_ldap_nested_groups"
#define TEST_CONF_DB "test_ldap_nested_groups_conf.ldb"
#define TEST_DOM_NAME "ldap_nested_groups_test"
#define TEST_SYSDB_FILE "cache_"TEST_DOM_NAME".ldb"
#define TEST_ID_PROVIDER "ldap"

#define new_test(test) \
    unit_test_setup_teardown(nested_groups_test_ ## test, \
                             nested_groups_test_setup, \
                             nested_groups_test_teardown)

/* put users and groups under the same container so we can easily run the
 * same tests cases for several search base scenarios */
#define OBJECT_BASE_DN "cn=objects,dc=test,dc=com"
#define GROUP_BASE_DN "cn=groups," OBJECT_BASE_DN
#define USER_BASE_DN "cn=users," OBJECT_BASE_DN

#define N_ELEMENTS(arr) \
    (sizeof(arr) / sizeof(arr[0]))

struct nested_groups_test_ctx {
    struct sss_test_ctx *tctx;

    struct sdap_options *sdap_opts;
    struct sdap_handle *sdap_handle;
    struct sdap_domain *sdap_domain;

    struct sysdb_attrs **users;
    struct sysdb_attrs **groups;
    unsigned long num_users;
    unsigned long num_groups;
};

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
                                              &ctx->num_groups, &ctx->groups);
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

    user2_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2002, "user2");
    assert_non_null(user2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user2_reply);

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

    user2_reply[0] = mock_sysdb_user(test_ctx, USER_BASE_DN, 2001, "user1");
    assert_non_null(user2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, user2_reply);

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

    group2_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1002, "emptygroup2", NULL);
    assert_non_null(group2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group2_reply);

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

    group2_reply[0] = mock_sysdb_group_rfc2307bis(test_ctx, GROUP_BASE_DN,
                                                  1001, "emptygroup1", NULL);
    assert_non_null(group2_reply[0]);
    will_return(sdap_get_generic_recv, 1);
    will_return(sdap_get_generic_recv, group2_reply);

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

void nested_groups_test_setup(void **state)
{
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
}

void nested_groups_test_teardown(void **state)
{
    talloc_zfree(*state);
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

    const UnitTest tests[] = {
        new_test(one_group_no_members),
        new_test(one_group_unique_members),
        new_test(one_group_dup_users),
        new_test(one_group_unique_group_members),
        new_test(one_group_dup_group_members),
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
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    test_dom_suite_setup(TESTS_PATH);

    rv = run_tests(tests);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    }
    return rv;
}
