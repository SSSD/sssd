/*
    Authors:
        Petr Čech <pcech@redhat.com>

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pwd.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_sysdb_objects.h"
#include "tests/cmocka/common_mock_sdap.h"
#include "providers/ad/ad_common.h"

#include "providers/ad/ad_opts.c"
#include "providers/ldap/sdap_async_initgroups.c"

/* Declarations from providers/ldap/sdap_async_initgroups.c */
struct sdap_get_initgr_state;
static int sdap_search_initgr_user_in_batch(struct sdap_get_initgr_state *state,
                                            struct sysdb_attrs **users,
                                            size_t count);

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_sdap_initgr_conf.ldb"
#define TEST_ID_PROVIDER "ldap"

#define TEST_DOM1_NAME "domain.test.com"
#define TEST_DOM2_NAME "subdom1.domain.test.com"
#define TEST_DOM3_NAME "another_domain.test.com"

#define OBJECT_BASE_DN1 "dc=domain,dc=test,dc=com,cn=sysdb"
#define OBJECT_BASE_DN2 "dc=subdom1,dc=domain,dc=test,dc=com,cn=sysdb"
#define OBJECT_BASE_DN3 "dc=another_domain,dc=test,dc=com,cn=sysdb"

#define TEST_USER_1 "test_user_1"
#define TEST_USER_2 "test_user_2"
#define TEST_USER_3 "test_user_3"

const char *domains[] = { TEST_DOM1_NAME,
                          TEST_DOM2_NAME,
                          TEST_DOM3_NAME,
                          NULL };

const char *object_bases[] = { OBJECT_BASE_DN1,
                               OBJECT_BASE_DN2,
                               OBJECT_BASE_DN3,
                               NULL };

const char *test_users[] = { TEST_USER_1,
                             TEST_USER_2,
                             TEST_USER_3,
                             NULL };

/* ====================== Utilities =============================== */

struct test_sdap_initgr_ctx {
    struct sss_test_ctx *tctx;
};

static struct passwd **get_users(TALLOC_CTX *ctx)
{
    struct passwd **passwds = NULL;
    char *homedir = NULL;
    size_t user_count = 0;

    for (int i = 0; test_users[i] != NULL; i++) {
        user_count++;
    }
    passwds = talloc_array(ctx, struct passwd *, user_count);
    assert_non_null(passwds);

    for (int i = 0; i < user_count; i++) {
        passwds[i] = talloc(passwds, struct passwd);
        assert_non_null(passwds[i]);

        homedir = talloc_strdup_append(homedir, "/home/");
        homedir = talloc_strdup_append(homedir, test_users[i]);

        passwds[i]->pw_name = discard_const(test_users[i]);
        passwds[i]->pw_uid = 567 + i;
        passwds[i]->pw_gid = 890 + i;
        passwds[i]->pw_dir = talloc_strdup(passwds[i], homedir);
        passwds[i]->pw_gecos = discard_const(test_users[i]);
        passwds[i]->pw_shell = discard_const("/bin/sh");
        passwds[i]->pw_passwd = discard_const("*");

        talloc_zfree(homedir);
    }

    return passwds;
}

static struct sss_test_conf_param **get_params(TALLOC_CTX *ctx)
{
    struct sss_test_conf_param **params;
    char *user_base_dn = NULL;
    char *group_base_dn = NULL;
    size_t base_count = 0;

    for (int i = 0; object_bases[i] != NULL; i++) {
        base_count++;
    }

    params = talloc_array(ctx, struct sss_test_conf_param *, base_count + 1);
    assert_non_null(params);

    for (int i = 0; i < base_count; i++) {
        params[i] = talloc(params, struct sss_test_conf_param);
        assert_non_null(params[i]);

        user_base_dn = talloc_strdup_append(user_base_dn, "cn=users,");
        user_base_dn = talloc_strdup_append(user_base_dn, object_bases[i]);

        group_base_dn = talloc_strdup_append(group_base_dn, "cn=groups,");
        group_base_dn = talloc_strdup_append(group_base_dn, object_bases[i]);

        params[i] = talloc_array(params[i], struct sss_test_conf_param, 5);
        params[i][0].key = "ldap_schema";
        params[i][0].value = "rfc2307bis";
        params[i][1].key = "ldap_search_base";
        params[i][1].value = talloc_strdup(params[i], object_bases[i]);
        params[i][2].key = "ldap_user_search_base";
        params[i][2].value = talloc_strdup(params[i], user_base_dn);
        params[i][3].key = "ldap_group_search_base";
        params[i][3].value = talloc_strdup(params[i], group_base_dn);
        params[i][4].key = NULL;
        params[i][4].value = NULL;

        talloc_zfree(user_base_dn);
        talloc_zfree(group_base_dn);
    }

    return params;
}

struct sss_domain_info *get_domain_info(struct sss_domain_info *domain,
                                        const char *domain_name)
{
    struct sss_domain_info *dom = domain;

    while(dom != NULL) {
        if (strcmp(dom->name, domain_name) == 0) {
            break;
        }
        dom = dom->next;
    }

    return dom;
}

struct sdap_get_initgr_state *prepare_state(struct test_sdap_initgr_ctx *ctx,
                                            const char **domain_names)
{
    struct sdap_get_initgr_state *state;
    struct sss_domain_info *dom_info = NULL;
    struct sss_domain_info *recent_dom_info = NULL;

    state = talloc_zero(ctx->tctx, struct sdap_get_initgr_state);
    assert_non_null(state);

    for (int i=0; domain_names[i] != NULL; i++) {
        dom_info = get_domain_info(ctx->tctx->dom, domain_names[i]);
        assert_non_null(dom_info);

        if (i == 0) {
            state->dom = dom_info;
            recent_dom_info = state->dom;
        } else {
            recent_dom_info->next = dom_info;
            recent_dom_info = recent_dom_info->next;
        }
    }
    assert_non_null(state->dom);
    assert_non_null(recent_dom_info);
    recent_dom_info->next = NULL;

    state->opts = mock_sdap_options_ldap(state, state->dom,
                                         ctx->tctx->confdb,
                                         ctx->tctx->conf_dom_path);
    assert_non_null(state->opts);

    return state;
}

/* TODO: This function is copied from test_nss_srv.c
 *       It could be fine move both to one place,
 *       for example src/tests/common_sysdb.c
 */
static errno_t store_user(TALLOC_CTX *ctx,
                          struct sss_domain_info *dom,
                          struct passwd *user,
                          struct sysdb_attrs *attrs,
                          time_t cache_update)
{
    errno_t ret;
    char *fqname;

    fqname = sss_create_internal_fqname(ctx,
                                        user->pw_name,
                                        dom->name);
    if (fqname == NULL) {
        return ENOMEM;
    }

    /* Prime the cache with a valid user */
    ret = sysdb_store_user(dom,
                           fqname,
                           user->pw_passwd,
                           user->pw_uid,
                           user->pw_gid,
                           user->pw_gecos,
                           user->pw_dir,
                           user->pw_shell,
                           NULL, attrs,
                           NULL, 300, cache_update);
    talloc_free(fqname);

    return ret;
}

/* ====================== Setup =============================== */

static int test_sdap_initgr_setup_one_domain(void **state)
{
    struct test_sdap_initgr_ctx *test_ctx;
    struct sss_test_conf_param **params;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_sdap_initgr_ctx);
    assert_non_null(test_ctx);

    params = get_params(test_ctx);
    assert_non_null(params);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH,
                                         TEST_CONF_DB, domains[0],
                                         TEST_ID_PROVIDER, params[0]);
    assert_non_null(test_ctx->tctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_sdap_initgr_setup_multi_domains(void **state)
{
    struct test_sdap_initgr_ctx *test_ctx;
    struct sss_test_conf_param **params;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_sdap_initgr_ctx);
    assert_non_null(test_ctx);

    params = get_params(test_ctx);
    assert_non_null(params);

    test_ctx->tctx = create_multidom_test_ctx(test_ctx, TESTS_PATH,
                                              TEST_CONF_DB, domains,
                                              TEST_ID_PROVIDER, params);
    assert_non_null(test_ctx->tctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_sdap_initgr_setup_other_multi_domains(void **state)
{
    struct test_sdap_initgr_ctx *test_ctx;
    struct sss_test_conf_param **params;
    const char *domains_vith_other[] = { TEST_DOM1_NAME,
                                         TEST_DOM3_NAME,
                                         NULL };

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_sdap_initgr_ctx);
    assert_non_null(test_ctx);

    params = get_params(test_ctx);
    assert_non_null(params);

    test_ctx->tctx = create_multidom_test_ctx(test_ctx, TESTS_PATH,
                                              TEST_CONF_DB, domains_vith_other,
                                              TEST_ID_PROVIDER, params);
    assert_non_null(test_ctx->tctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_sdap_initgr_teardown(void **state)
{
    struct test_sdap_initgr_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct test_sdap_initgr_ctx);
    assert_non_null(test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

/* ====================== The tests =============================== */

static void test_user_is_on_batch(void **state)
{
    struct test_sdap_initgr_ctx *test_ctx;
    struct sdap_get_initgr_state *initgr_state;
    const char *domains_set[] = { domains[0], NULL };
    struct sss_domain_info *dom1_info = NULL;
    struct sss_domain_info *dom2_info = NULL;
    struct passwd **passwd_users;
    struct sysdb_attrs **users;
    const char *user_name;
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_sdap_initgr_ctx);
    assert_non_null(test_ctx);

    dom1_info = get_domain_info(test_ctx->tctx->dom, domains[0]);
    assert_non_null(dom1_info);
    dom2_info = get_domain_info(test_ctx->tctx->dom, domains[1]);
    assert_non_null(dom2_info);

    initgr_state = prepare_state(test_ctx, domains_set);
    assert_non_null(initgr_state);

    passwd_users = get_users(test_ctx);
    assert_non_null(passwd_users);

    ret = store_user(test_ctx, dom1_info, passwd_users[0], NULL, 0);
    assert_int_equal(ret, 0);
    ret = store_user(test_ctx, dom2_info, passwd_users[1], NULL, 0);
    assert_int_equal(ret, 0);

    users = talloc_array(test_ctx, struct sysdb_attrs *, 2);
    users[0] = mock_sysdb_user(users, object_bases[0],
                               passwd_users[0]->pw_uid,
                               passwd_users[0]->pw_name);
    users[1] = mock_sysdb_user(users, object_bases[1],
                               passwd_users[1]->pw_uid,
                               passwd_users[1]->pw_name);

    ret = sdap_search_initgr_user_in_batch(initgr_state, users, 2);
    assert_int_equal(ret, 0);

    ret = sysdb_attrs_get_string(initgr_state->orig_user, "name", &user_name);
    assert_int_equal(ret, 0);
    assert_string_equal(user_name, passwd_users[0]->pw_name);

    talloc_zfree(initgr_state);
    talloc_zfree(passwd_users);
    talloc_zfree(users);
}

static void test_user_is_from_subdomain(void **state)
{
    struct test_sdap_initgr_ctx *test_ctx;
    struct sdap_get_initgr_state *initgr_state;
    const char *domains_set[] = { domains[0], NULL };
    struct sss_domain_info *dom_info = NULL;
    struct passwd **passwd_users;
    struct sysdb_attrs **users;
    const char *user_name;
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_sdap_initgr_ctx);
    assert_non_null(test_ctx);

    dom_info = get_domain_info(test_ctx->tctx->dom, domains[0]);
    assert_non_null(dom_info);

    initgr_state = prepare_state(test_ctx, domains_set);
    assert_non_null(initgr_state);

    passwd_users = get_users(test_ctx);
    assert_non_null(passwd_users);

    ret = store_user(test_ctx, dom_info, passwd_users[0], NULL, 0);
    assert_int_equal(ret, 0);

    users = talloc_array(test_ctx, struct sysdb_attrs *, 1);
    users[0] = mock_sysdb_user(users, object_bases[1],
                               passwd_users[1]->pw_uid,
                               passwd_users[1]->pw_name);

    const char *original_dn = NULL;
    ret = sysdb_attrs_get_string(users[0], SYSDB_ORIG_DN, &original_dn);

    ret = sdap_search_initgr_user_in_batch(initgr_state, users, 1);
    assert_int_equal(ret, 0);

    ret = sysdb_attrs_get_string(initgr_state->orig_user, "name", &user_name);
    assert_int_equal(ret, 0);
    assert_string_equal(user_name, passwd_users[1]->pw_name);

    talloc_zfree(initgr_state);
    talloc_zfree(passwd_users);
    talloc_zfree(users);
}

static void test_user_is_from_another_domain(void **state)
{
    struct test_sdap_initgr_ctx *test_ctx;
    struct sdap_get_initgr_state *initgr_state;
    const char *domains_set[] = { domains[0], domains[2], NULL };
    struct sss_domain_info *dom_info = NULL;
    struct sss_domain_info *other_dom_info = NULL;
    struct sdap_domain *other_sdom = NULL;
    struct passwd **passwd_users;
    struct sysdb_attrs **users;
    errno_t ret;

    test_ctx = talloc_get_type(*state, struct test_sdap_initgr_ctx);
    assert_non_null(test_ctx);

    dom_info = get_domain_info(test_ctx->tctx->dom, domains[0]);
    assert_non_null(dom_info);

    initgr_state = prepare_state(test_ctx, domains_set);
    assert_non_null(initgr_state);

    other_dom_info = get_domain_info(test_ctx->tctx->dom, domains[2]);
    assert_non_null(other_dom_info);

    ret = sdap_domain_add(initgr_state->opts, other_dom_info, &other_sdom);
    assert_int_equal(ret, EOK);

    talloc_zfree(other_sdom->search_bases);
    other_sdom->search_bases = talloc_array(other_sdom,
                                            struct sdap_search_base *, 2);
    assert_non_null(other_sdom->search_bases);
    other_sdom->search_bases[1] = NULL;

    ret = sdap_create_search_base(other_sdom,
                                  sysdb_ctx_get_ldb(dom_info->sysdb),
                                  object_bases[2],
                                  LDAP_SCOPE_SUBTREE, NULL,
                                  &other_sdom->search_bases[0]);
    assert_int_equal(ret, EOK);

    passwd_users = get_users(test_ctx);
    assert_non_null(passwd_users);

    ret = store_user(test_ctx, dom_info, passwd_users[0], NULL, 0);
    assert_int_equal(ret, 0);

    users = talloc_array(test_ctx, struct sysdb_attrs *, 1);
    users[0] = mock_sysdb_user(users, object_bases[2],
                               passwd_users[2]->pw_uid,
                               passwd_users[2]->pw_name);

    ret = sdap_search_initgr_user_in_batch(initgr_state, users, 1);
    assert_int_equal(ret, EINVAL);

    talloc_zfree(initgr_state);
    talloc_zfree(passwd_users);
    talloc_zfree(users);
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
        cmocka_unit_test_setup_teardown(test_user_is_on_batch,
                                        test_sdap_initgr_setup_multi_domains,
                                        test_sdap_initgr_teardown),
        cmocka_unit_test_setup_teardown(test_user_is_from_subdomain,
                                        test_sdap_initgr_setup_one_domain,
                                        test_sdap_initgr_teardown),
        cmocka_unit_test_setup_teardown(test_user_is_from_another_domain,
                                        test_sdap_initgr_setup_other_multi_domains,
                                        test_sdap_initgr_teardown),
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
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0) {
        test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    }

    return rv;
}
