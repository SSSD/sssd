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

#define _GNU_SOURCE     /* for `fgetpwent()` in musl libc */
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>

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

struct user_descriptor_t {
    const char *name;
    uid_t uid;
};

struct group_descriptor_t {
    const char *name;
    gid_t gid;
};

struct ncache_test_ctx {
    struct sss_test_ctx *tctx;
    struct sss_nc_ctx *ncache;
    struct user_descriptor_t local_users[2];
    struct user_descriptor_t non_local_users[2];
    struct group_descriptor_t local_groups[2];
    struct group_descriptor_t non_local_groups[2];
};

static void create_users(struct ncache_test_ctx *test_ctx)
{
    errno_t ret;
    char *fqname;
    struct sss_domain_info *domain = test_ctx->tctx->dom;
    const struct user_descriptor_t *users = test_ctx->non_local_users;
    const struct group_descriptor_t *groups = test_ctx->non_local_groups;

    for (int i = 0; i < 2; i++) {
        fqname = sss_create_internal_fqname(test_ctx,
                                            users[i].name,
                                            domain->name);
        assert_non_null(fqname);

        ret = sysdb_add_user(domain, users[i].name, users[i].uid, groups[i].gid,
                             fqname, NULL, "/bin/bash", domain->name,
                             NULL, 30, time(NULL));
        talloc_free(fqname);
        assert_int_equal(ret, EOK);
    }
}

static void create_groups(struct ncache_test_ctx *test_ctx)
{
    errno_t ret;
    char *fqname;
    struct sss_domain_info *domain = test_ctx->tctx->dom;
    const struct group_descriptor_t *groups = test_ctx->non_local_groups;

    for (int i = 0; i < 2; i++) {
        fqname = sss_create_internal_fqname(test_ctx,
                                            groups[i].name,
                                            domain->name);
        assert_non_null(fqname);

        ret = sysdb_add_group(domain, fqname, groups[i].gid,
                              NULL, 30, time(NULL));
        talloc_free(fqname);
        assert_int_equal(ret, EOK);
    }
}

static void find_local_users(struct ncache_test_ctx *test_ctx)
{
    int i;
    FILE *passwd_file;
    const struct passwd *pwd;

    passwd_file = fopen("/etc/passwd", "r");
    assert_non_null(passwd_file);

    for (i = 0; i < 2; /*no-op*/) {
        pwd = fgetpwent(passwd_file);
        assert_non_null(pwd);
        if (pwd->pw_uid == 0) {
            /* skip root */
            continue;
        }
        test_ctx->local_users[i].uid = pwd->pw_uid;
        test_ctx->local_users[i].name = talloc_strdup(test_ctx, pwd->pw_name);
        assert_non_null(test_ctx->local_users[i].name);
        ++i;
    }

    fclose(passwd_file);
}

static void find_local_groups(struct ncache_test_ctx *test_ctx)
{
    int i;
    FILE *group_file;
    const struct group *grp;

    group_file = fopen("/etc/group", "r");
    assert_non_null(group_file);

    for (i = 0; i < 2; /* no-op */) {
        grp = fgetgrent(group_file);
        assert_non_null(grp);
        if (grp->gr_gid == 0) {
            /* skip root */
            continue;
        }
        test_ctx->local_groups[i].gid = grp->gr_gid;
        test_ctx->local_groups[i].name = talloc_strdup(test_ctx, grp->gr_name);
        assert_non_null(test_ctx->local_groups[i].name);
        ++i;
    }

    fclose(group_file);
}

static void find_non_local_users(struct ncache_test_ctx *test_ctx)
{
    int i;
    int k;
    uid_t uid;
    char *name;

    for (i = 0, k = 1; (k < 100) && (i < 2); ++k) {
        uid = 65534-k;
        if (getpwuid(uid)) {
            continue;
        }
        test_ctx->non_local_users[i].uid = uid;
        ++i;
    }
    assert_int_equal(i, 2);

    for (i = 0, k = 0; (k < 100) && (i < 2); ++k) {
        name = talloc_asprintf(test_ctx, "nctestuser%d", k);
        if (getpwnam(name)) {
            talloc_free(name);
            continue;
        }
        test_ctx->non_local_users[i].name = name;
        ++i;
    }
    assert_int_equal(i, 2);
}

static void find_non_local_groups(struct ncache_test_ctx *test_ctx)
{
    int i = 0;
    int k;
    gid_t gid;
    char *name;

    for (i = 0, k = 1; (k < 100) && (i < 2); ++k) {
        gid = 65534-k;
        if (getgrgid(gid)) {
            continue;
        }
        test_ctx->non_local_groups[i].gid = gid;
        ++i;
    }
    assert_int_equal(i, 2);

    for (i = 0, k = 0; (k < 100) && (i < 2); ++k) {
        name = talloc_asprintf(test_ctx, "nctestgroup%d", k);
        if (getgrnam(name)) {
            talloc_free(name);
            continue;
        }
        test_ctx->non_local_groups[i].name = name;
        ++i;
    }
    assert_int_equal(i, 2);
}

int test_ncache_setup(void **state)
{
    struct ncache_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct ncache_test_ctx);
    assert_non_null(test_ctx);

    find_local_users(test_ctx);
    find_local_groups(test_ctx);
    find_non_local_users(test_ctx);
    find_non_local_groups(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME, "ipa", NULL);
    assert_non_null(test_ctx->tctx);

    create_groups(test_ctx);
    create_users(test_ctx);

    check_leaks_push(test_ctx);

    *state = (void *)test_ctx;

    return 0;
}

int test_ncache_teardown(void **state)
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
                             test_ctx->non_local_users[0].name);
    assert_int_equal(ret, EOK);

    ret = set_user_in_ncache(test_ctx->ncache, false, test_ctx->tctx->dom,
                             test_ctx->local_users[0].name);
    assert_int_equal(ret, EOK);
}

static void check_users(struct ncache_test_ctx *test_ctx,
                        int case_a, int case_b, int case_c, int case_d)
{
    int ret;

    ret = check_user_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                test_ctx->non_local_users[0].name);
    assert_int_equal(ret, case_a);

    ret = check_user_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                test_ctx->non_local_users[1].name);
    assert_int_equal(ret, case_b);

    ret = check_user_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                test_ctx->local_users[0].name);
    assert_int_equal(ret, case_c);

    ret = check_user_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                test_ctx->local_users[1].name);
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
                             test_ctx->non_local_users[0].uid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_set_uid(test_ctx->ncache, false, test_ctx->tctx->dom,
                             test_ctx->local_users[0].uid);
    assert_int_equal(ret, EOK);
}

static void check_uids(struct ncache_test_ctx *test_ctx,
                       int case_a, int case_b, int case_c, int case_d)
{
    int ret;

    ret = sss_ncache_check_uid(test_ctx->ncache, test_ctx->tctx->dom,
                               test_ctx->non_local_users[0].uid);
    assert_int_equal(ret, case_a);

    ret = sss_ncache_check_uid(test_ctx->ncache, test_ctx->tctx->dom,
                               test_ctx->non_local_users[1].uid);
    assert_int_equal(ret, case_b);

    ret = sss_ncache_check_uid(test_ctx->ncache, test_ctx->tctx->dom,
                               test_ctx->local_users[0].uid);
    assert_int_equal(ret, case_c);

    ret = sss_ncache_check_uid(test_ctx->ncache, test_ctx->tctx->dom,
                               test_ctx->local_users[1].uid);
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
                              test_ctx->non_local_groups[0].name);
    assert_int_equal(ret, EOK);

    ret = set_group_in_ncache(test_ctx->ncache, false, test_ctx->tctx->dom,
                              test_ctx->local_groups[0].name);
    assert_int_equal(ret, EOK);
}

static void check_groups(struct ncache_test_ctx *test_ctx,
                         int case_a, int case_b, int case_c, int case_d)
{
    int ret;

    ret = check_group_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                test_ctx->non_local_groups[0].name);
    assert_int_equal(ret, case_a);

    ret = check_group_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                test_ctx->non_local_groups[1].name);
    assert_int_equal(ret, case_b);

    ret = check_group_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                test_ctx->local_groups[0].name);
    assert_int_equal(ret, case_c);

    ret = check_group_in_ncache(test_ctx->ncache, test_ctx->tctx->dom,
                                test_ctx->local_groups[1].name);
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
                             test_ctx->non_local_groups[0].gid);
    assert_int_equal(ret, EOK);

    ret = sss_ncache_set_gid(test_ctx->ncache, false, test_ctx->tctx->dom,
                             test_ctx->local_groups[0].gid);
    assert_int_equal(ret, EOK);
}

static void check_gids(struct ncache_test_ctx *test_ctx,
                       int case_a, int case_b, int case_c, int case_d)
{
    int ret;

    ret = sss_ncache_check_gid(test_ctx->ncache, test_ctx->tctx->dom,
                               test_ctx->non_local_groups[0].gid);
    assert_int_equal(ret, case_a);

    ret = sss_ncache_check_gid(test_ctx->ncache, test_ctx->tctx->dom,
                               test_ctx->non_local_groups[1].gid);
    assert_int_equal(ret, case_b);

    ret = sss_ncache_check_gid(test_ctx->ncache, test_ctx->tctx->dom,
                               test_ctx->local_groups[0].gid);
    assert_int_equal(ret, case_c);

    ret = sss_ncache_check_gid(test_ctx->ncache, test_ctx->tctx->dom,
                               test_ctx->local_groups[1].gid);
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
