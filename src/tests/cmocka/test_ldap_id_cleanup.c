/*
    Authors:
        Pavel Reichl <preichl@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests - id cleanup

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
#include <stdlib.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/types.h>
#include <cmocka.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "providers/ldap/ldap_auth.h"
#include "tests/cmocka/test_expire_common.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ipa/ipa_opts.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_FILE "tests_conf.ldb"

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;
    struct sdap_options *opts;
    struct sdap_id_ctx *id_ctx;
};

static int _setup_sysdb_tests(struct sysdb_test_ctx **ctx, bool enumerate)
{
    struct sysdb_test_ctx *test_ctx;
    char *conf_db;
    int ret;

    const char *val[2];
    val[1] = NULL;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    assert_true(ret == 0 || errno == EEXIST);

    test_ctx = talloc_zero(global_talloc_context, struct sysdb_test_ctx);
    assert_non_null(test_ctx);

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    assert_non_null(test_ctx->ev);

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    assert_non_null(conf_db);
    DEBUG(SSSDBG_MINOR_FAILURE, "CONFDB: %s\n", conf_db);

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    assert_int_equal(ret, EOK);

    val[0] = "FILES";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    assert_int_equal(ret, EOK);

    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = enumerate ? "TRUE" : "FALSE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "enumerate", val);
    assert_int_equal(ret, EOK);

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "cache_credentials", val);
    assert_int_equal(ret, EOK);

    ret = sssd_domain_init(test_ctx, test_ctx->confdb, "FILES",
                           TESTS_PATH, &test_ctx->domain);
    assert_int_equal(ret, EOK);

    test_ctx->id_ctx = talloc_zero(test_ctx, struct sdap_id_ctx);
    assert_non_null(test_ctx->id_ctx);

    test_ctx->domain->has_views = true;
    test_ctx->sysdb = test_ctx->domain->sysdb;

    *ctx = test_ctx;
    return EOK;
}

#define setup_sysdb_tests(ctx) _setup_sysdb_tests((ctx), false)

static int test_sysdb_setup(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    ret = setup_sysdb_tests(&test_ctx);
    assert_int_equal(ret, EOK);

    test_ctx->domain->mpg_mode = MPG_DISABLED;

    /* set options */
    test_ctx->opts = talloc_zero(test_ctx, struct sdap_options);
    assert_non_null(test_ctx->opts);

    ret = sdap_copy_map(test_ctx->opts, rfc2307_user_map,
                        SDAP_OPTS_USER, &test_ctx->opts->user_map);
    assert_int_equal(ret, ERR_OK);

    ret = dp_copy_defaults(test_ctx->opts, default_basic_opts,
                           SDAP_OPTS_BASIC, &test_ctx->opts->basic);
    assert_int_equal(ret, ERR_OK);

    dp_opt_set_int(test_ctx->opts->basic, SDAP_ACCOUNT_CACHE_EXPIRATION, 1);

    test_ctx->id_ctx->opts = test_ctx->opts;

    *state = (void *) test_ctx;
    return 0;
}

static int test_sysdb_teardown(void **state)
{
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static errno_t invalidate_group(TALLOC_CTX *ctx,
                                struct sss_domain_info *domain,
                                const char *name)
{
    struct sysdb_attrs *sys_attrs = NULL;
    errno_t ret;

    sys_attrs = sysdb_new_attrs(ctx);
    if (sys_attrs) {
        ret = sysdb_attrs_add_time_t(sys_attrs,
                                     SYSDB_CACHE_EXPIRE, 1);
        if (ret == EOK) {
            ret = sysdb_set_group_attr(domain, name, sys_attrs,
                                       SYSDB_MOD_REP);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not add expiration time to attributes\n");
        }
        talloc_zfree(sys_attrs);
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not create sysdb attributes\n");
        ret = ENOMEM;
    }
    return ret;
}

static void test_id_cleanup_exp_group(void **state)
{
    errno_t ret;
    struct ldb_message *msg;
    struct sdap_domain sdom;
    char *special_grp;
    char *empty_special_grp;
    char *empty_grp;
    char *grp;
    char *test_user;
    char *test_user2;
    /* This timeout can be bigger because we will call invalidate_group
     * to expire entries without waiting. */
    const uint64_t CACHE_TIMEOUT = 30;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                            struct sysdb_test_ctx);

    special_grp = sss_create_internal_fqname(test_ctx,
                                             "special_gr*o/u\\p(2016)",
                                             test_ctx->domain->name);
    assert_non_null(special_grp);

    empty_special_grp = sss_create_internal_fqname(test_ctx,
                                                   "empty_gr*o/u\\p(2016)",
                                                   test_ctx->domain->name);
    assert_non_null(empty_special_grp);

    empty_grp = sss_create_internal_fqname(test_ctx, "empty_grp",
                                           test_ctx->domain->name);
    assert_non_null(empty_grp);

    grp = sss_create_internal_fqname(test_ctx, "grp", test_ctx->domain->name);
    assert_non_null(grp);

    test_user = sss_create_internal_fqname(test_ctx, "test_user",
                                           test_ctx->domain->name);
    assert_non_null(test_user);
    test_user2 = sss_create_internal_fqname(test_ctx, "test_user2",
                                            test_ctx->domain->name);
    assert_non_null(test_user2);

    ret = sysdb_store_group(test_ctx->domain, special_grp,
                            10002, NULL, CACHE_TIMEOUT, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_group(test_ctx->domain, empty_special_grp,
                            10003, NULL, CACHE_TIMEOUT, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_group(test_ctx->domain, grp,
                            10004, NULL, CACHE_TIMEOUT, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_group(test_ctx->domain, empty_grp,
                            10005, NULL, CACHE_TIMEOUT, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->domain, test_user, NULL,
                           10001, 10002, "Test user",
                           NULL, NULL, NULL, NULL, NULL,
                           0, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->domain, test_user2, NULL,
                           10002, 10004, "Test user",
                           NULL, NULL, NULL, NULL, NULL,
                           0, 0);
    assert_int_equal(ret, EOK);

    sdom.dom = test_ctx->domain;

    /* not expired */
    ret = ldap_id_cleanup(test_ctx->id_ctx, &sdom);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     special_grp, NULL, &msg);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     empty_special_grp, NULL, &msg);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     grp, NULL, &msg);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     empty_grp, NULL, &msg);
    assert_int_equal(ret, EOK);

    /* let records to expire */
    invalidate_group(test_ctx, test_ctx->domain, special_grp);
    invalidate_group(test_ctx, test_ctx->domain, empty_special_grp);
    invalidate_group(test_ctx, test_ctx->domain, grp);
    invalidate_group(test_ctx, test_ctx->domain, empty_grp);

    ret = ldap_id_cleanup(test_ctx->id_ctx, &sdom);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     special_grp, NULL, &msg);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     empty_special_grp, NULL, &msg);
    assert_int_equal(ret, ENOENT);

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     grp, NULL, &msg);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     empty_grp, NULL, &msg);
    assert_int_equal(ret, ENOENT);
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
        { "no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
          _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_id_cleanup_exp_group,
                                        test_sysdb_setup, test_sysdb_teardown),
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
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, "FILES");
    test_dom_suite_setup(TESTS_PATH);
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    if (rv == 0 && no_cleanup == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, "FILES");
    }
    return rv;
}
