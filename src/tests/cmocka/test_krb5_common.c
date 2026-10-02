/*
    SSSD

    krb5_common - Test for some krb5 utility functions

    Authors:
        Sumit Bose <sbose@redhat.com>

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
#include <stdbool.h>

#include "tests/cmocka/common_mock.h"
#include "tests/common.h"
#include "tests/cmocka/common_mock_krb5.h"

#include "src/providers/krb5/krb5_common.h"
#include "util/sss_krb5.h"

#define TEST_REALM "MY.REALM"
#define TEST_FAST_PRINC "fast_princ@" TEST_REALM
#define TEST_FAST_STR "dummy"
#define TEST_LIFE_STR "dummy-life"
#define TEST_RLIFE_STR "dummy-rlife"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_krb5_common_conf.ldb"
#define TEST_DOM_NAME "test.krb5.common"
#define TEST_ID_PROVIDER "ldap"

struct test_ctx {
    struct sss_test_ctx *tctx;
};

static int test_setup(void **state)
{
    struct test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;

    return 0;
}

static int test_teardown(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_true(check_leaks_pop(test_ctx));
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

#define NKEYS 4
#define KEYTAB_NAME "MEMORY:my_mem.keytab"
struct test_gvp_ctx {
    krb5_context kctx;
    krb5_keytab keytab;
    krb5_keytab_entry keys[NKEYS];
    krb5_principal princs[NKEYS];
};

static int test_gvp_setup(void **state)
{
    struct test_gvp_ctx *test_ctx;
    krb5_error_code kerr;
    krb5_enctype *enctypes;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_gvp_ctx);
    assert_non_null(test_ctx);

    kerr = krb5_init_context(&test_ctx->kctx);
    assert_int_equal(kerr, 0);

    kerr = krb5_parse_name(test_ctx->kctx, "CLIENT$@" TEST_DOM_NAME,
                           &test_ctx->princs[0]);
    assert_int_equal(kerr, 0);
    kerr = krb5_parse_name(test_ctx->kctx, "host/client@" TEST_DOM_NAME,
                           &test_ctx->princs[1]);
    assert_int_equal(kerr, 0);
    kerr = krb5_parse_name(test_ctx->kctx, "host/client.fqdn@" TEST_DOM_NAME,
                           &test_ctx->princs[2]);
    assert_int_equal(kerr, 0);
    kerr = krb5_parse_name(test_ctx->kctx, "client.fqdn@OTHER." TEST_DOM_NAME,
                           &test_ctx->princs[3]);
    assert_int_equal(kerr, 0);

    kerr = krb5_get_permitted_enctypes(test_ctx->kctx, &enctypes);
    assert_int_equal(kerr, 0);

    memset(&test_ctx->keys, NKEYS, NKEYS * sizeof(krb5_keytab_entry));

    /* To test get_validation_principal() only the princpals of the keys are
     * important. */
    mock_krb5_keytab_entry(&test_ctx->keys[0], test_ctx->princs[0], 12345, 1,
                           enctypes[0], "abc");
    mock_krb5_keytab_entry(&test_ctx->keys[1], test_ctx->princs[1], 12345, 1,
                           enctypes[0], "abc");
    mock_krb5_keytab_entry(&test_ctx->keys[2], test_ctx->princs[2], 12345, 1,
                           enctypes[0], "abc");
    mock_krb5_keytab_entry(&test_ctx->keys[3], test_ctx->princs[3], 12345, 1,
                           enctypes[0], "abc");

    krb5_free_enctypes(test_ctx->kctx, enctypes);

    /* MEMORY keytabs are remove from memory when the keytab is closed. To
     * make sure the keytab is available during the whole test it is opened in
     * setup and closed in teardown.
     * Another property of a MEMORY keytab is that the keys are read in the
     * reverse order they are written. */
    kerr = krb5_kt_resolve(test_ctx->kctx, KEYTAB_NAME, &test_ctx->keytab);
    assert_int_equal(kerr, 0);

    check_leaks_push(test_ctx);
    *state = test_ctx;

    return 0;
}

static int test_gvp_teardown(void **state)
{
    struct test_gvp_ctx *test_ctx = talloc_get_type(*state, struct test_gvp_ctx);
    krb5_error_code kerr;

    assert_true(check_leaks_pop(test_ctx));

    kerr = krb5_kt_close(test_ctx->kctx, test_ctx->keytab);
    assert_int_equal(kerr, 0);

    krb5_free_principal(test_ctx->kctx, test_ctx->princs[0]);
    krb5_free_principal(test_ctx->kctx, test_ctx->princs[1]);
    krb5_free_principal(test_ctx->kctx, test_ctx->princs[2]);
    krb5_free_principal(test_ctx->kctx, test_ctx->princs[3]);
    krb5_free_context(test_ctx->kctx);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

void test_set_extra_args(void **state)
{
    int ret;
    struct krb5_ctx *krb5_ctx;
    const char **krb5_child_extra_args;

    ret = set_extra_args(NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    krb5_ctx = talloc_zero(global_talloc_context, struct krb5_ctx);
    assert_non_null(krb5_ctx);

    ret = set_extra_args(global_talloc_context, krb5_ctx, NULL, NULL,
                         &krb5_child_extra_args);
    assert_int_equal(ret, EOK);
    assert_null(krb5_child_extra_args[0]);
    talloc_free(krb5_child_extra_args);

    krb5_ctx->canonicalize = true;
    ret = set_extra_args(global_talloc_context, krb5_ctx, NULL, NULL,
                         &krb5_child_extra_args);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_child_extra_args[0], "--canonicalize");
    assert_null(krb5_child_extra_args[1]);
    talloc_free(krb5_child_extra_args);

    krb5_ctx->realm = discard_const(TEST_REALM);
    ret = set_extra_args(global_talloc_context, krb5_ctx, NULL, NULL,
                         &krb5_child_extra_args);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_child_extra_args[0], "--realm=" TEST_REALM);
    assert_string_equal(krb5_child_extra_args[1], "--canonicalize");
    assert_null(krb5_child_extra_args[2]);
    talloc_free(krb5_child_extra_args);

    /* --fast-principal will be only set if FAST is used */
    krb5_ctx->fast_principal = discard_const(TEST_FAST_PRINC);
    ret = set_extra_args(global_talloc_context, krb5_ctx, NULL, NULL,
                         &krb5_child_extra_args);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_child_extra_args[0], "--realm=" TEST_REALM);
    assert_string_equal(krb5_child_extra_args[1], "--canonicalize");
    assert_null(krb5_child_extra_args[2]);
    talloc_free(krb5_child_extra_args);

    krb5_ctx->use_fast_str = discard_const(TEST_FAST_STR);
    ret = set_extra_args(global_talloc_context, krb5_ctx, NULL, NULL,
                         &krb5_child_extra_args);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_child_extra_args[0], "--realm=" TEST_REALM);
    assert_string_equal(krb5_child_extra_args[1], "--use-fast=" TEST_FAST_STR);
    assert_string_equal(krb5_child_extra_args[2],
                        "--fast-principal=" TEST_FAST_PRINC);
    assert_string_equal(krb5_child_extra_args[3], "--canonicalize");
    assert_null(krb5_child_extra_args[4]);
    talloc_free(krb5_child_extra_args);

    krb5_ctx->lifetime_str = discard_const(TEST_LIFE_STR);
    krb5_ctx->rlife_str = discard_const(TEST_RLIFE_STR);
    ret = set_extra_args(global_talloc_context, krb5_ctx, NULL, NULL,
                         &krb5_child_extra_args);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_child_extra_args[0], "--realm=" TEST_REALM);
    assert_string_equal(krb5_child_extra_args[1], "--lifetime=" TEST_LIFE_STR);
    assert_string_equal(krb5_child_extra_args[2],
                        "--renewable-lifetime=" TEST_RLIFE_STR);
    assert_string_equal(krb5_child_extra_args[3], "--use-fast=" TEST_FAST_STR);
    assert_string_equal(krb5_child_extra_args[4],
                        "--fast-principal=" TEST_FAST_PRINC);
    assert_string_equal(krb5_child_extra_args[5], "--canonicalize");
    assert_null(krb5_child_extra_args[6]);
    talloc_free(krb5_child_extra_args);

    talloc_free(krb5_ctx);
}

void test_sss_krb5_check_options(void **state)
{
    int ret;
    struct dp_option *opts;
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    struct krb5_ctx *krb5_ctx;

    ret = sss_krb5_check_options(NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_krb5_get_options(test_ctx, test_ctx->tctx->confdb,
                               "[domain/" TEST_DOM_NAME "]", &opts);
    assert_int_equal(ret, EOK);
    assert_non_null(opts);

    krb5_ctx = talloc_zero(test_ctx, struct krb5_ctx);
    assert_non_null(krb5_ctx);

    ret = sss_krb5_check_options(opts, test_ctx->tctx->dom, krb5_ctx);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_ctx->realm, TEST_DOM_NAME);

    /* check check_lifetime() indirectly */
    ret = dp_opt_set_string(opts, KRB5_LIFETIME, "123");
    assert_int_equal(ret, EOK);
    ret = sss_krb5_check_options(opts, test_ctx->tctx->dom, krb5_ctx);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_ctx->lifetime_str, "123s");

    ret = dp_opt_set_string(opts, KRB5_LIFETIME, "abc");
    assert_int_equal(ret, EOK);
    ret = sss_krb5_check_options(opts, test_ctx->tctx->dom, krb5_ctx);
    assert_int_equal(ret, EINVAL);

    ret = dp_opt_set_string(opts, KRB5_LIFETIME, "s");
    assert_int_equal(ret, EOK);
    ret = sss_krb5_check_options(opts, test_ctx->tctx->dom, krb5_ctx);
    assert_int_equal(ret, EINVAL);

    ret = dp_opt_set_string(opts, KRB5_LIFETIME, "1d");
    assert_int_equal(ret, EOK);
    ret = sss_krb5_check_options(opts, test_ctx->tctx->dom, krb5_ctx);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_ctx->lifetime_str, "1d");

    ret = dp_opt_set_string(opts, KRB5_LIFETIME, "7d 0h 0m 0s");
    assert_int_equal(ret, EOK);
    ret = sss_krb5_check_options(opts, test_ctx->tctx->dom, krb5_ctx);
    assert_int_equal(ret, EOK);
    assert_string_equal(krb5_ctx->lifetime_str, "7d 0h 0m 0s");

    /* check canonicalize */
    assert_false(krb5_ctx->canonicalize);

    ret = dp_opt_set_bool(opts, KRB5_USE_ENTERPRISE_PRINCIPAL, true);
    assert_int_equal(ret, EOK);
    ret = sss_krb5_check_options(opts, test_ctx->tctx->dom, krb5_ctx);
    assert_int_equal(ret, EOK);
    assert_true(krb5_ctx->canonicalize);

    ret = dp_opt_set_bool(opts, KRB5_USE_ENTERPRISE_PRINCIPAL, false);
    assert_int_equal(ret, EOK);
    ret = dp_opt_set_bool(opts, KRB5_CANONICALIZE, true);
    assert_int_equal(ret, EOK);
    ret = sss_krb5_check_options(opts, test_ctx->tctx->dom, krb5_ctx);
    assert_int_equal(ret, EOK);
    assert_true(krb5_ctx->canonicalize);

    ret = dp_opt_set_bool(opts, KRB5_USE_SUBDOMAIN_REALM, true);
    assert_int_equal(ret, EOK);

    talloc_free(krb5_ctx);
    talloc_free(opts);
}

void test_get_validation_principal(void **state)
{
    struct test_gvp_ctx *test_ctx = talloc_get_type(*state, struct test_gvp_ctx);
    krb5_error_code kerr;
    krb5_principal principal;

    kerr = mock_keytab(test_ctx->kctx, KEYTAB_NAME, test_ctx->keys, NKEYS);
    assert_int_equal(kerr, 0);

    kerr = get_validation_principal(test_ctx->kctx, test_ctx->keytab, KEYTAB_NAME,
                                    test_ctx->princs[0], &principal);
    assert_int_equal(kerr, 0);
    assert_true(krb5_principal_compare(test_ctx->kctx, principal, test_ctx->princs[2]) == TRUE);

    krb5_free_principal(test_ctx->kctx, principal);
}

void test_get_validation_principal_rev(void **state)
{
    struct test_gvp_ctx *test_ctx = talloc_get_type(*state, struct test_gvp_ctx);
    krb5_error_code kerr;
    krb5_principal principal;

    krb5_keytab_entry keys[NKEYS];

    memcpy(&keys[0],&test_ctx->keys[3], sizeof(krb5_keytab_entry));
    memcpy(&keys[1],&test_ctx->keys[2], sizeof(krb5_keytab_entry));
    memcpy(&keys[2],&test_ctx->keys[1], sizeof(krb5_keytab_entry));
    memcpy(&keys[3],&test_ctx->keys[0], sizeof(krb5_keytab_entry));


    kerr = mock_keytab(test_ctx->kctx, KEYTAB_NAME, keys, NKEYS);
    assert_int_equal(kerr, 0);

    kerr = get_validation_principal(test_ctx->kctx, test_ctx->keytab, KEYTAB_NAME,
                                    test_ctx->princs[0], &principal);
    assert_int_equal(kerr, 0);
    assert_true(krb5_principal_compare(test_ctx->kctx, principal, test_ctx->princs[1]) == TRUE);

    krb5_free_principal(test_ctx->kctx, principal);
}

void test_get_validation_principal_host_only(void **state)
{
    struct test_gvp_ctx *test_ctx = talloc_get_type(*state, struct test_gvp_ctx);
    krb5_error_code kerr;
    krb5_principal principal;

    krb5_keytab_entry keys[1];

    memcpy(&keys[0],&test_ctx->keys[0], sizeof(krb5_keytab_entry));

    kerr = mock_keytab(test_ctx->kctx, KEYTAB_NAME, keys, 1);
    assert_int_equal(kerr, 0);

    kerr = get_validation_principal(test_ctx->kctx, test_ctx->keytab, KEYTAB_NAME,
                                    test_ctx->princs[0], &principal);
    assert_int_equal(kerr, 0);
    assert_true(krb5_principal_compare(test_ctx->kctx, principal, test_ctx->princs[0]) == TRUE);

    krb5_free_principal(test_ctx->kctx, principal);
}

void test_get_validation_principal_remote_only(void **state)
{
    struct test_gvp_ctx *test_ctx = talloc_get_type(*state, struct test_gvp_ctx);
    krb5_error_code kerr;
    krb5_principal principal;

    krb5_keytab_entry keys[1];

    memcpy(&keys[0],&test_ctx->keys[3], sizeof(krb5_keytab_entry));

    kerr = mock_keytab(test_ctx->kctx, KEYTAB_NAME, keys, 1);
    assert_int_equal(kerr, 0);

    kerr = get_validation_principal(test_ctx->kctx, test_ctx->keytab, KEYTAB_NAME,
                                    test_ctx->princs[0], &principal);
    assert_int_equal(kerr, 0);
    assert_true(krb5_principal_compare(test_ctx->kctx, principal, test_ctx->princs[3]) == TRUE);

    krb5_free_principal(test_ctx->kctx, principal);
}

void test_get_validation_principal_remote_host(void **state)
{
    struct test_gvp_ctx *test_ctx = talloc_get_type(*state, struct test_gvp_ctx);
    krb5_error_code kerr;
    krb5_principal principal;

    krb5_keytab_entry keys[2];

    memcpy(&keys[0],&test_ctx->keys[0], sizeof(krb5_keytab_entry));
    memcpy(&keys[1],&test_ctx->keys[3], sizeof(krb5_keytab_entry));

    kerr = mock_keytab(test_ctx->kctx, KEYTAB_NAME, keys, 2);
    assert_int_equal(kerr, 0);

    kerr = get_validation_principal(test_ctx->kctx, test_ctx->keytab, KEYTAB_NAME,
                                    test_ctx->princs[0], &principal);
    assert_int_equal(kerr, 0);
    assert_true(krb5_principal_compare(test_ctx->kctx, principal, test_ctx->princs[3]) == TRUE);

    krb5_free_principal(test_ctx->kctx, principal);
}

void test_get_validation_principal_host_remote(void **state)
{
    struct test_gvp_ctx *test_ctx = talloc_get_type(*state, struct test_gvp_ctx);
    krb5_error_code kerr;
    krb5_principal principal;

    krb5_keytab_entry keys[2];

    memcpy(&keys[0],&test_ctx->keys[3], sizeof(krb5_keytab_entry));
    memcpy(&keys[1],&test_ctx->keys[0], sizeof(krb5_keytab_entry));

    kerr = mock_keytab(test_ctx->kctx, KEYTAB_NAME, keys, 2);
    assert_int_equal(kerr, 0);

    kerr = get_validation_principal(test_ctx->kctx, test_ctx->keytab, KEYTAB_NAME,
                                    test_ctx->princs[0], &principal);
    assert_int_equal(kerr, 0);
    assert_true(krb5_principal_compare(test_ctx->kctx, principal, test_ctx->princs[3]) == TRUE);

    krb5_free_principal(test_ctx->kctx, principal);
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
        cmocka_unit_test_setup_teardown(test_set_extra_args,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_krb5_check_options,
                                        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_validation_principal,
                                        test_gvp_setup, test_gvp_teardown),
        cmocka_unit_test_setup_teardown(test_get_validation_principal_rev,
                                        test_gvp_setup, test_gvp_teardown),
        cmocka_unit_test_setup_teardown(test_get_validation_principal_host_only,
                                        test_gvp_setup, test_gvp_teardown),
        cmocka_unit_test_setup_teardown(test_get_validation_principal_remote_only,
                                        test_gvp_setup, test_gvp_teardown),
        cmocka_unit_test_setup_teardown(test_get_validation_principal_remote_host,
                                        test_gvp_setup, test_gvp_teardown),
        cmocka_unit_test_setup_teardown(test_get_validation_principal_host_remote,
                                        test_gvp_setup, test_gvp_teardown),
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
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }

    return rv;
}
