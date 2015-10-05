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
#include "tests/cmocka/common_mock_krb5.h"

#define DOMNAME     "domname"
#define SUBDOMNAME  "sub."DOMNAME
#define REALMNAME   DOMNAME
#define HOST_NAME   "ad."REALMNAME

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_AUTHID       "host/"HOST_NAME
#define KEYTAB_TEST_PRINC TEST_AUTHID"@"REALMNAME
#define KEYTAB_PATH       TESTS_PATH"/keytab_test.keytab"

#define ONEWAY_DOMNAME     "ONEWAY"
#define ONEWAY_HOST_NAME   "ad."ONEWAY_DOMNAME

#define ONEWAY_KEYTAB_PATH       TESTS_PATH"/oneway_test.keytab"
#define ONEWAY_AUTHID            "host/"ONEWAY_HOST_NAME
#define ONEWAY_TEST_PRINC        ONEWAY_AUTHID"@"ONEWAY_DOMNAME

static bool call_real_sasl_options;

krb5_error_code __wrap_krb5_kt_default(krb5_context context, krb5_keytab *id)
{
    return krb5_kt_resolve(context, KEYTAB_PATH, id);
}

struct ad_common_test_ctx {
    struct ad_id_ctx *ad_ctx;
    struct ad_id_ctx *subdom_ad_ctx;

    struct sss_domain_info *dom;
    struct sss_domain_info *subdom;
};

static void test_ad_create_default_options(void **state)
{
    struct ad_options *ad_options;
    const char *s;

    ad_options = ad_create_default_options(global_talloc_context);

    assert_non_null(ad_options->basic);

    /* Not too much to test here except some defaults */
    s = dp_opt_get_string(ad_options->basic, AD_DOMAIN);
    assert_null(s);

    assert_non_null(ad_options->id);
}

static int test_ad_common_setup(void **state)
{
    struct ad_common_test_ctx *test_ctx;

    test_dom_suite_setup(TESTS_PATH);

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

    test_ctx->ad_ctx = talloc_zero(test_ctx, struct ad_id_ctx);
    assert_non_null(test_ctx->ad_ctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_ad_common_teardown(void **state)
{
    int ret;
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(check_leaks_pop(global_talloc_context) == true);
    assert_true(leak_check_teardown());

    ret = rmdir(TESTS_PATH);
    assert_return_code(ret, errno);

    return 0;
}

static void test_ad_create_1way_trust_options(void **state)
{
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    const char *s;

    call_real_sasl_options = true;
    /* Make sure this is not the keytab that __wrap_krb5_kt_default uses */
    mock_keytab_with_contents(test_ctx, ONEWAY_KEYTAB_PATH, ONEWAY_TEST_PRINC);

    test_ctx->ad_ctx->ad_options = ad_create_1way_trust_options(
                                                            test_ctx->ad_ctx,
                                                            ONEWAY_DOMNAME,
                                                            ONEWAY_HOST_NAME,
                                                            ONEWAY_KEYTAB_PATH,
                                                            ONEWAY_AUTHID);
    assert_non_null(test_ctx->ad_ctx->ad_options);

    assert_int_equal(test_ctx->ad_ctx->ad_options->id->schema_type,
                     SDAP_SCHEMA_AD);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_KRB5_REALM);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_DOMAIN);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_HOSTNAME);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_HOST_NAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_KEYTAB);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_KEYTAB_PATH);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_KRB5_KEYTAB);
    assert_non_null(s);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_SASL_REALM);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_KRB5_REALM);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_SASL_AUTHID);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_AUTHID);

    talloc_free(test_ctx->ad_ctx->ad_options);

    unlink(ONEWAY_KEYTAB_PATH);
}
static void test_ad_create_2way_trust_options(void **state)
{
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    const char *s;

    call_real_sasl_options = true;
    mock_keytab_with_contents(test_ctx, KEYTAB_PATH, KEYTAB_TEST_PRINC);

    test_ctx->ad_ctx->ad_options = ad_create_2way_trust_options(
                                                            test_ctx->ad_ctx,
                                                            REALMNAME,
                                                            DOMNAME,
                                                            HOST_NAME);
    assert_non_null(test_ctx->ad_ctx->ad_options);

    assert_int_equal(test_ctx->ad_ctx->ad_options->id->schema_type,
                     SDAP_SCHEMA_AD);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_KRB5_REALM);
    assert_non_null(s);
    assert_string_equal(s, REALMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_DOMAIN);
    assert_non_null(s);
    assert_string_equal(s, DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_HOSTNAME);
    assert_non_null(s);
    assert_string_equal(s, HOST_NAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_KRB5_KEYTAB);
    assert_null(s); /* This is the system keytab */

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_SASL_REALM);
    assert_non_null(s);
    assert_string_equal(s, REALMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_KRB5_REALM);
    assert_non_null(s);
    assert_string_equal(s, REALMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_SASL_AUTHID);
    assert_non_null(s);
    assert_string_equal(s, TEST_AUTHID);

    talloc_free(test_ctx->ad_ctx->ad_options);

    unlink(KEYTAB_PATH);
}

static int
test_ldap_conn_setup(void **state)
{
    struct ad_common_test_ctx *test_ctx;
    errno_t ret;
    struct sdap_domain *sdom;
    struct ad_id_ctx *ad_ctx;
    struct ad_id_ctx *subdom_ad_ctx;
    struct sdap_id_conn_ctx *subdom_ldap_ctx;

    ret = test_ad_common_setup((void **) &test_ctx);
    assert_int_equal(ret, EOK);

    mock_keytab_with_contents(test_ctx, KEYTAB_PATH, KEYTAB_TEST_PRINC);

    ad_ctx = test_ctx->ad_ctx;

    ad_ctx->ad_options = ad_create_2way_trust_options(ad_ctx,
                                                      REALMNAME,
                                                      DOMNAME,
                                                      HOST_NAME);
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
    sdom->pvt = ad_ctx;

    subdom_ad_ctx = talloc_zero(test_ctx, struct ad_id_ctx);
    assert_non_null(subdom_ad_ctx);

    subdom_ldap_ctx = talloc_zero(subdom_ad_ctx, struct sdap_id_conn_ctx);
    assert_non_null(subdom_ldap_ctx);
    subdom_ad_ctx->ldap_ctx = subdom_ldap_ctx;

    ret = sdap_domain_add(ad_ctx->sdap_id_ctx->opts, test_ctx->subdom, &sdom);
    assert_int_equal(ret, EOK);
    sdom->pvt = subdom_ad_ctx;

    test_ctx->subdom_ad_ctx = subdom_ad_ctx;

    *state = test_ctx;
    return 0;
}

static int
test_ldap_conn_teardown(void **state)
{
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    unlink(KEYTAB_PATH);

    talloc_free(test_ctx->subdom_ad_ctx);
    talloc_free(test_ctx->ad_ctx->ad_options);
    talloc_free(test_ctx->ad_ctx->gc_ctx);
    talloc_free(test_ctx->ad_ctx->ldap_ctx);
    talloc_free(test_ctx->ad_ctx->sdap_id_ctx);

    test_ad_common_teardown((void **) &test_ctx);
    return 0;
}

errno_t
__real_sdap_set_sasl_options(struct sdap_options *id_opts,
                             char *default_primary,
                             char *default_realm,
                             const char *keytab_path);
errno_t
__wrap_sdap_set_sasl_options(struct sdap_options *id_opts,
                             char *default_primary,
                             char *default_realm,
                             const char *keytab_path)
{
    /* Pretend SASL is fine */
    if (call_real_sasl_options == true) {
        return __real_sdap_set_sasl_options(id_opts,
                                            default_primary,
                                            default_realm,
                                            keytab_path);
    }

    return EOK;
}

void test_ad_get_dom_ldap_conn(void **state)
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

void test_gc_conn_list(void **state)
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
    /* Subdomain error should not set the backend offline! */
    assert_true(conn_list[1]->ignore_mark_offline);
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
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);
}

void test_ldap_conn_list(void **state)
{
    struct sdap_id_conn_ctx **conn_list;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    conn_list = ad_ldap_conn_list(test_ctx,
                                  test_ctx->ad_ctx,
                                  test_ctx->dom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->ldap_ctx);
    assert_false(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);

    conn_list = ad_ldap_conn_list(test_ctx,
                                  test_ctx->ad_ctx,
                                  test_ctx->subdom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->subdom_ad_ctx->ldap_ctx);
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);
}

void test_user_conn_list(void **state)
{
    struct sdap_id_conn_ctx **conn_list;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    conn_list = ad_user_conn_list(test_ctx,
                                  test_ctx->ad_ctx,
                                  test_ctx->dom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->ldap_ctx);
    assert_false(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);

    conn_list = ad_user_conn_list(test_ctx,
                                  test_ctx->ad_ctx,
                                  test_ctx->subdom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->gc_ctx);
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_true(conn_list[1] == test_ctx->subdom_ad_ctx->ldap_ctx);
    /* Subdomain error should not set the backend offline! */
    assert_true(conn_list[1]->ignore_mark_offline);
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

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ad_create_default_options),
        cmocka_unit_test_setup_teardown(test_ad_create_1way_trust_options,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
        cmocka_unit_test_setup_teardown(test_ad_create_2way_trust_options,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
        cmocka_unit_test_setup_teardown(test_ad_get_dom_ldap_conn,
                                        test_ldap_conn_setup,
                                        test_ldap_conn_teardown),
        cmocka_unit_test_setup_teardown(test_gc_conn_list,
                                        test_ldap_conn_setup,
                                        test_ldap_conn_teardown),
        cmocka_unit_test_setup_teardown(test_ldap_conn_list,
                                        test_ldap_conn_setup,
                                        test_ldap_conn_teardown),
        cmocka_unit_test_setup_teardown(test_user_conn_list,
                                        test_ldap_conn_setup,
                                        test_ldap_conn_teardown),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
