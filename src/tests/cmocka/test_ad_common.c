/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: AD access control filter tests

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
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

/* In order to access opaque types */
#include "providers/ad/ad_common.c"

#include "tests/cmocka/common_mock.h"

#define DOMNAME     "domname"
#define SUBDOMNAME  "sub."DOMNAME
#define REALMNAME   DOMNAME
#define HOST_NAME   "ad."REALMNAME

struct ad_common_test_ctx {
    struct ad_id_ctx *ad_ctx;
    struct ad_id_ctx *subdom_ad_ctx;

    struct sss_domain_info *dom;
    struct sss_domain_info *subdom;
};

static void
ad_common_test_setup(void **state)
{
    struct ad_common_test_ctx *test_ctx;
    errno_t ret;
    struct sdap_domain *sdom;
    struct ad_id_ctx *ad_ctx;
    struct ad_id_ctx *subdom_ad_ctx;
    struct sdap_id_conn_ctx *subdom_ldap_ctx;

    assert_true(leak_check_setup());
    check_leaks_push(global_talloc_context);

    test_ctx = talloc_zero(global_talloc_context, struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->dom = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(test_ctx->dom);
    test_ctx->dom->name = discard_const(DOMNAME);

    test_ctx->subdom = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(test_ctx->subdom);
    test_ctx->subdom->name = discard_const(SUBDOMNAME);
    test_ctx->subdom->parent = test_ctx->dom;

    ad_ctx = talloc_zero(test_ctx, struct ad_id_ctx);
    assert_non_null(ad_ctx);

    ad_ctx->ad_options = ad_create_default_options(ad_ctx,
                                                   REALMNAME, HOST_NAME);
    assert_non_null(ad_ctx->ad_options);

    ad_ctx->gc_ctx = talloc_zero(ad_ctx, struct sdap_id_conn_ctx);
    assert_non_null(ad_ctx->gc_ctx);

    ad_ctx->ldap_ctx = talloc_zero(ad_ctx, struct sdap_id_conn_ctx);
    assert_non_null(ad_ctx->ldap_ctx);

    ad_ctx->sdap_id_ctx = talloc_zero(ad_ctx, struct sdap_id_ctx);
    assert_non_null(ad_ctx->sdap_id_ctx);

    ad_ctx->sdap_id_ctx->opts = talloc_zero(ad_ctx->sdap_id_ctx,
                                            struct sdap_options);
    assert_non_null(ad_ctx->sdap_id_ctx->opts);

    ret = sdap_domain_add(ad_ctx->sdap_id_ctx->opts, test_ctx->dom, &sdom);
    assert_int_equal(ret, EOK);

    subdom_ad_ctx = talloc_zero(test_ctx, struct ad_id_ctx);
    assert_non_null(subdom_ad_ctx);

    subdom_ldap_ctx = talloc_zero(subdom_ad_ctx, struct sdap_id_conn_ctx);
    assert_non_null(subdom_ldap_ctx);
    subdom_ad_ctx->ldap_ctx = subdom_ldap_ctx;

    ret = sdap_domain_add(ad_ctx->sdap_id_ctx->opts, test_ctx->subdom, &sdom);
    assert_int_equal(ret, EOK);
    sdom->pvt = subdom_ad_ctx;

    test_ctx->ad_ctx = ad_ctx;
    test_ctx->subdom_ad_ctx = subdom_ad_ctx;

    check_leaks_push(test_ctx);
    *state = test_ctx;
}

static void
ad_common_test_teardown(void **state)
{
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(check_leaks_pop(global_talloc_context) == true);
    assert_true(leak_check_teardown());
}

errno_t
__wrap_sdap_set_sasl_options(struct sdap_options *id_opts,
                             char *default_primary,
                             char *default_realm,
                             const char *keytab_path)
{
    /* Pretend SASL is fine */
    return EOK;
}

void test_ldap_conn_list(void **state)
{
    struct sdap_id_conn_ctx *conn;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    conn = ad_get_dom_ldap_conn(test_ctx->ad_ctx, test_ctx->dom);
    assert_true(conn == test_ctx->ad_ctx->ldap_ctx);

    conn = ad_get_dom_ldap_conn(test_ctx->ad_ctx, test_ctx->subdom);
    assert_true(conn == test_ctx->subdom_ad_ctx->ldap_ctx);
}

void test_conn_list(void **state)
{
    struct sdap_id_conn_ctx **conn_list;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    assert_true(dp_opt_get_bool(test_ctx->ad_ctx->ad_options->basic,
                                AD_ENABLE_GC));
    conn_list = ad_gc_conn_list(test_ctx, test_ctx->ad_ctx, test_ctx->dom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->gc_ctx);
    /* If there is a fallback, we should ignore the offline mode */
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_true(conn_list[1] == test_ctx->ad_ctx->ldap_ctx);
    assert_false(conn_list[1]->ignore_mark_offline);
    assert_null(conn_list[2]);
    talloc_free(conn_list);

    conn_list = ad_gc_conn_list(test_ctx, test_ctx->ad_ctx, test_ctx->subdom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->gc_ctx);
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_true(conn_list[1] == test_ctx->subdom_ad_ctx->ldap_ctx);
    assert_false(conn_list[1]->ignore_mark_offline);
    talloc_free(conn_list);

    dp_opt_set_bool(test_ctx->ad_ctx->ad_options->basic, AD_ENABLE_GC, false);
    assert_false(dp_opt_get_bool(test_ctx->ad_ctx->ad_options->basic,
                                 AD_ENABLE_GC));

    conn_list = ad_gc_conn_list(test_ctx, test_ctx->ad_ctx, test_ctx->dom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->ldap_ctx);
    assert_false(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);

    conn_list = ad_gc_conn_list(test_ctx, test_ctx->ad_ctx, test_ctx->subdom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->subdom_ad_ctx->ldap_ctx);
    talloc_free(conn_list);
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

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_ldap_conn_list,
                                 ad_common_test_setup,
                                 ad_common_test_teardown),
        unit_test_setup_teardown(test_conn_list,
                                 ad_common_test_setup,
                                 ad_common_test_teardown),
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

    tests_set_cwd();

    return run_tests(tests);
}
