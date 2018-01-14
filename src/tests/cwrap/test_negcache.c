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

#include "tests/common.h"
#include "responder/common/negcache.h"
#include "responder/common/negcache_files.h"
#include "responder/common/responder.h"

#define TIMEOUT 10000

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_negcache_confdb.ldb"
#define TEST_DOM_NAME "test_domain.test"

#define TEST_LOCAL_USER_NAME_1 "foobar"
#define TEST_LOCAL_USER_NAME_2 "sssd"

#define TEST_LOCAL_USER_UID_1 10001
#define TEST_LOCAL_USER_UID_2 123

#define TEST_LOCAL_GROUP_NAME_1 "foogroup"
#define TEST_LOCAL_GROUP_NAME_2 "sssd"

#define TEST_LOCAL_GID_1 10001
#define TEST_LOCAL_GID_2 123

struct test_user {
    const char *name;
    uid_t uid;
    gid_t gid;
} users[] = { { "test_user1", 1001, 50001 },
              { "test_user2", 1002, 50002 } };

static void create_users(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain)
{
    errno_t ret;
    char *fqname;

    for (int i = 0; i < 2; i++) {
        fqname = sss_create_internal_fqname(mem_ctx,
                                            users[i].name,
                                            domain->name);
        assert_non_null(fqname);

        ret = sysdb_add_user(domain, users[i].name, users[i].uid, users[i].gid,
                             fqname, NULL, "/bin/bash", domain->name,
                             NULL, 30, time(NULL));
        talloc_free(fqname);
        assert_int_equal(ret, EOK);
    }
}

struct test_group {
    const char *name;
    gid_t gid;
} groups[] = { { "test_group1", 50001 },
               { "test_group2", 50002 } };

struct ncache_test_ctx {
    struct sss_test_ctx *tctx;
    struct sss_nc_ctx *ncache;
};

static void create_groups(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain)
{
    errno_t ret;
    char *fqname;

    for (int i = 0; i < 2; i++) {
        fqname = sss_create_internal_fqname(mem_ctx,
                                            groups[i].name,
                                            domain->name);
        assert_non_null(fqname);

        ret = sysdb_add_group(domain, fqname, groups[i].gid,
                              NULL, 30, time(NULL));
        talloc_free(fqname);
        assert_int_equal(ret, EOK);
    }
}

/* register_cli_protocol_version is required in test since it links with
 * responder_common.c module
 */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version responder_test_cli_protocol_version[] = {
        { 0, NULL, NULL }
    };

    return responder_test_cli_protocol_version;
}

static int test_ncache_setup(void **state)
{
    struct ncache_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME, "ipa", NULL);
    assert_non_null(test_ctx->tctx);

    create_groups(test_ctx, test_ctx->tctx->dom);
    create_users(test_ctx, test_ctx->tctx->dom);

    check_leaks_push(test_ctx);

    *state = (void *)test_ctx;

    return 0;
}

static int test_ncache_teardown(void **state)
{
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);

    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);

    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);
    assert_true(leak_check_teardown());

    return 0;
}

static int set_user_in_ncache(struct sss_nc_ctx *ctx, bool permanent,
                              struct sss_domain_info *dom, const char *name)
{
    char *fqdn;
    int ret;

    fqdn = sss_create_internal_fqname(ctx, name, dom->name);
    ret = sss_ncache_set_user(ctx, permanent, dom, fqdn);
    talloc_free(fqdn);
    return ret;
}

static int set_group_in_ncache(struct sss_nc_ctx *ctx, bool permanent,
                              struct sss_domain_info *dom, const char *name)
{
    char *fqdn;
    int ret;

    fqdn = sss_create_internal_fqname(ctx, name, dom->name);
    ret = sss_ncache_set_group(ctx, permanent, dom, fqdn);
    talloc_free(fqdn);
    return ret;
}

static int check_user_in_ncache(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom,
                                const char *name)
{
    char *fqdn;
    int ret;

    fqdn = sss_create_internal_fqname(ctx, name, dom->name);
    ret = sss_ncache_check_user(ctx, dom, fqdn);
    talloc_free(fqdn);
    return ret;
}

static int check_group_in_ncache(struct sss_nc_ctx *ctx,
                                 struct sss_domain_info *dom,
                                 const char *name)
{
    char *fqdn;
    int ret;

    fqdn = sss_create_internal_fqname(ctx, name, dom->name);
    ret = sss_ncache_check_group(ctx, dom, fqdn);
    talloc_free(fqdn);
    return ret;
}

/* user utils */

static void set_users(struct ncache_test_ctx *test_ctx)
{
    int ret;

    ret = set_user_in_ncache(test_ctx->ncache, false, test_ctx->tctx->dom,
                              users[0].name);
    assert_int_equal(ret, EOK);

    ret = set_user_in_ncache(test_ctx->ncache, false, test_ctx->tctx->dom,
                             TEST_LOCAL_USER_NAME_1);
    assert_int_equal(ret, EOK);
}

static void check_users(struct ncache_test_ctx *test_ctx,
                        int case_a, int case_b, int case_c, int case_d)
{
    int ret;

    ret = check_user_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                users[0].name);
    assert_int_equal(ret, case_a);

    ret = check_user_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                users[1].name);
    assert_int_equal(ret, case_b);

    ret = check_user_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                TEST_LOCAL_USER_NAME_1);
    assert_int_equal(ret, case_c);

    ret = check_user_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                TEST_LOCAL_USER_NAME_2);
    assert_int_equal(ret, case_d);
}

/* user tests */

void test_ncache_nocache_user(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, 0, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_users(test_ctx);

    check_users(test_ctx, ENOENT, ENOENT, ENOENT, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_local_user(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, 0, TIMEOUT, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_users(test_ctx);

    check_users(test_ctx, ENOENT, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_domain_user(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, TIMEOUT, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_users(test_ctx);

    check_users(test_ctx, EEXIST, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_both_user(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, TIMEOUT, TIMEOUT, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_users(test_ctx);

    check_users(test_ctx, EEXIST, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

/* uid utils */

static void set_uids(struct ncache_test_ctx *test_ctx)
{
    int ret;

    ret = sss_ncache_set_uid(test_ctx->ncache, false, test_ctx->tctx->dom,
                             users[0].uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_set_uid(test_ctx->ncache, false, test_ctx->tctx->dom,
                             TEST_LOCAL_USER_UID_1);
    assert_int_equal(ret, EOK);
}

static void check_uids(struct ncache_test_ctx *test_ctx,
                       int case_a, int case_b, int case_c, int case_d)
{
    int ret;

    ret = sss_ncache_check_uid(test_ctx->ncache, test_ctx->tctx->dom,
                               users[0].uid);
    assert_int_equal(ret, case_a);

    ret = sss_ncache_check_uid(test_ctx->ncache, test_ctx->tctx->dom,
                               users[1].uid);
    assert_int_equal(ret, case_b);

    ret = sss_ncache_check_uid(test_ctx->ncache, test_ctx->tctx->dom,
                               TEST_LOCAL_USER_UID_1);
    assert_int_equal(ret, case_c);

    ret = sss_ncache_check_uid(test_ctx->ncache, test_ctx->tctx->dom,
                               TEST_LOCAL_USER_UID_2);
    assert_int_equal(ret, case_d);
}

/* uid tests */

void test_ncache_nocache_uid(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, 0, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_uids(test_ctx);

    check_uids(test_ctx, ENOENT, ENOENT, ENOENT, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_local_uid(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, 0, TIMEOUT, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_uids(test_ctx);

    check_uids(test_ctx, ENOENT, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_domain_uid(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, TIMEOUT, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_uids(test_ctx);

    check_uids(test_ctx, EEXIST, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_both_uid(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, TIMEOUT, TIMEOUT, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_uids(test_ctx);

    check_uids(test_ctx, EEXIST, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

/* group utils */

static void set_groups(struct ncache_test_ctx *test_ctx)
{
    int ret;

    ret = set_group_in_ncache(test_ctx->ncache, false, test_ctx->tctx->dom,
                              groups[0].name);
    assert_int_equal(ret, EOK);

    ret = set_group_in_ncache(test_ctx->ncache, false, test_ctx->tctx->dom,
                              TEST_LOCAL_GROUP_NAME_1);
    assert_int_equal(ret, EOK);
}

static void check_groups(struct ncache_test_ctx *test_ctx,
                         int case_a, int case_b, int case_c, int case_d)
{
    int ret;

    ret = check_group_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                groups[0].name);
    assert_int_equal(ret, case_a);

    ret = check_group_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                groups[1].name);
    assert_int_equal(ret, case_b);

    ret = check_group_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                TEST_LOCAL_GROUP_NAME_1);
    assert_int_equal(ret, case_c);

    ret = check_group_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                TEST_LOCAL_GROUP_NAME_2);
    assert_int_equal(ret, case_d);
}

/* group tests */

void test_ncache_nocache_group(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, 0, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_groups(test_ctx);

    check_groups(test_ctx, ENOENT, ENOENT, ENOENT, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_local_group(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, 0, TIMEOUT, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_groups(test_ctx);

    check_groups(test_ctx, ENOENT, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_domain_group(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, TIMEOUT, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_groups(test_ctx);

    check_groups(test_ctx, EEXIST, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_both_group(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, TIMEOUT, TIMEOUT, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_groups(test_ctx);

    check_groups(test_ctx, EEXIST, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

/* gid utils */

static void set_gids(struct ncache_test_ctx *test_ctx)
{
    int ret;

    ret = sss_ncache_set_gid(test_ctx->ncache, false, test_ctx->tctx->dom,
                             users[0].gid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_set_gid(test_ctx->ncache, false, test_ctx->tctx->dom,
                             TEST_LOCAL_GID_1);
    assert_int_equal(ret, EOK);
}

static void check_gids(struct ncache_test_ctx *test_ctx,
                       int case_a, int case_b, int case_c, int case_d)
{
    int ret;

    ret = sss_ncache_check_gid(test_ctx->ncache, test_ctx->tctx->dom,
                               users[0].gid);
    assert_int_equal(ret, case_a);

    ret = sss_ncache_check_gid(test_ctx->ncache, test_ctx->tctx->dom,
                               users[1].gid);
    assert_int_equal(ret, case_b);

    ret = sss_ncache_check_gid(test_ctx->ncache, test_ctx->tctx->dom,
                               TEST_LOCAL_GID_1);
    assert_int_equal(ret, case_c);

    ret = sss_ncache_check_gid(test_ctx->ncache, test_ctx->tctx->dom,
                               TEST_LOCAL_GID_2);
    assert_int_equal(ret, case_d);
}

/* uid tests */

void test_ncache_nocache_gid(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, 0, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_gids(test_ctx);

    check_gids(test_ctx, ENOENT, ENOENT, ENOENT, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_local_gid(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, 0, TIMEOUT, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_gids(test_ctx);

    check_gids(test_ctx, ENOENT, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_domain_gid(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, TIMEOUT, 0, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_gids(test_ctx);

    check_gids(test_ctx, EEXIST, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
}

void test_ncache_both_gid(void **state)
{
    errno_t ret;
    struct ncache_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    ret = sss_ncache_init(test_ctx, TIMEOUT, TIMEOUT, &test_ctx->ncache);
    assert_int_equal(ret, EOK);

    set_gids(test_ctx);

    check_gids(test_ctx, EEXIST, ENOENT, EEXIST, ENOENT);

    talloc_zfree(test_ctx->ncache);
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
        /* user */
        cmocka_unit_test_setup_teardown(test_ncache_nocache_user,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_local_user,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_domain_user,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_both_user,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        /* uid */
        cmocka_unit_test_setup_teardown(test_ncache_nocache_uid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_local_uid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_domain_uid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_both_uid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        /* group */
        cmocka_unit_test_setup_teardown(test_ncache_nocache_group,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_local_group,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_domain_group,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_both_group,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        /* gid */
        cmocka_unit_test_setup_teardown(test_ncache_nocache_gid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_local_gid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_domain_gid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
        cmocka_unit_test_setup_teardown(test_ncache_both_gid,
                                        test_ncache_setup,
                                        test_ncache_teardown),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
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
