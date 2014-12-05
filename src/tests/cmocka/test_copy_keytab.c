/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Tests keytab utilities

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

#include <stdio.h>
#include <popt.h>

#include "util/sss_krb5.h"
#include "providers/krb5/krb5_common.h"
#include "tests/cmocka/common_mock.h"

#define KEYTAB_TEST_PRINC "test/keytab@TEST.KEYTAB"
#define KEYTAB_PATH TEST_DIR "/keytab_test.keytab"
#define EMPTY_KEYTAB_PATH TEST_DIR "/empty_keytab_test.keytab"

struct keytab_test_ctx {
    krb5_context kctx;
    const char *keytab_file_name;
    krb5_principal principal;
};

void setup_keytab(void **state)
{
    struct keytab_test_ctx *test_ctx;
    krb5_error_code kerr;
    krb5_keytab keytab;
    krb5_keytab_entry kent;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct keytab_test_ctx);
    assert_non_null(test_ctx);

    kerr = krb5_init_context(&test_ctx->kctx);
    assert_int_equal(kerr, 0);

    test_ctx->keytab_file_name = "FILE:" KEYTAB_PATH;

    kerr = krb5_kt_resolve(test_ctx->kctx, test_ctx->keytab_file_name, &keytab);
    assert_int_equal(kerr, 0);

    kerr = krb5_parse_name(test_ctx->kctx, KEYTAB_TEST_PRINC,
                           &test_ctx->principal);
    assert_int_equal(kerr, 0);

    memset(&kent, 0, sizeof(kent));
    kent.magic = KV5M_KEYTAB_ENTRY;
    kent.principal = test_ctx->principal;
    kent.timestamp = 12345;
    kent.vno = 1;
    kent.key.magic = KV5M_KEYBLOCK;
    kent.key.enctype = 1;
    kent.key.length = 2;
    kent.key.contents = (krb5_octet *) discard_const("11");

    kerr = krb5_kt_add_entry(test_ctx->kctx, keytab, &kent);
    assert_int_equal(kerr, 0);

    kent.key.enctype = 2;
    kent.key.contents = (krb5_octet *) discard_const("12");

    kerr = krb5_kt_add_entry(test_ctx->kctx, keytab, &kent);
    assert_int_equal(kerr, 0);

    kent.vno = 2;
    kent.key.enctype = 1;
    kent.key.contents = (krb5_octet *) discard_const("21");

    kerr = krb5_kt_add_entry(test_ctx->kctx, keytab, &kent);
    assert_int_equal(kerr, 0);

    kent.key.enctype = 2;
    kent.key.contents = (krb5_octet *) discard_const("22");

    kerr = krb5_kt_add_entry(test_ctx->kctx, keytab, &kent);
    assert_int_equal(kerr, 0);

    kerr = krb5_kt_close(test_ctx->kctx, keytab);
    assert_int_equal(kerr, 0);

    check_leaks_push(test_ctx);
    *state = test_ctx;
}

void teardown_keytab(void **state)
{
    int ret;
    struct keytab_test_ctx *test_ctx = talloc_get_type(*state,
                                                        struct keytab_test_ctx);
    assert_non_null(test_ctx);

    krb5_free_principal(test_ctx->kctx, test_ctx->principal);
    krb5_free_context(test_ctx->kctx);

    ret = unlink(KEYTAB_PATH);
    assert_int_equal(ret, 0);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
}

void test_copy_keytab(void **state)
{
    krb5_error_code kerr;
    char *mem_keytab_name;
    krb5_keytab mem_keytab;
    krb5_keytab keytab;
    krb5_keytab_entry kent;
    struct keytab_test_ctx *test_ctx = talloc_get_type(*state,
                                                        struct keytab_test_ctx);
    assert_non_null(test_ctx);

    kerr = copy_keytab_into_memory(test_ctx, test_ctx->kctx,
                                   test_ctx->keytab_file_name,
                                   &mem_keytab_name, &mem_keytab);
    assert_int_equal(kerr, 0);
    assert_non_null(mem_keytab_name);

    kerr = krb5_kt_resolve(test_ctx->kctx, mem_keytab_name, &keytab);
    assert_int_equal(kerr, 0);

    kerr = krb5_kt_get_entry(test_ctx->kctx, keytab, test_ctx->principal, 9, 9,
                             &kent);
    assert_int_not_equal(kerr, 0);

    kerr = krb5_kt_get_entry(test_ctx->kctx, keytab, test_ctx->principal, 1, 1,
                             &kent);
    assert_int_equal(kerr, 0);
    krb5_free_keytab_entry_contents(test_ctx->kctx, &kent);

    kerr = krb5_kt_get_entry(test_ctx->kctx, keytab, test_ctx->principal, 1, 2,
                             &kent);
    assert_int_equal(kerr, 0);
    krb5_free_keytab_entry_contents(test_ctx->kctx, &kent);

    kerr = krb5_kt_get_entry(test_ctx->kctx, keytab, test_ctx->principal, 2, 1,
                             &kent);
    assert_int_equal(kerr, 0);
    krb5_free_keytab_entry_contents(test_ctx->kctx, &kent);

    kerr = krb5_kt_get_entry(test_ctx->kctx, keytab, test_ctx->principal, 2, 2,
                             &kent);
    assert_int_equal(kerr, 0);
    krb5_free_keytab_entry_contents(test_ctx->kctx, &kent);

    talloc_free(mem_keytab_name);

    kerr = krb5_kt_close(test_ctx->kctx, keytab);
    assert_int_equal(kerr, 0);

    kerr = krb5_kt_close(test_ctx->kctx, mem_keytab);
    assert_int_equal(kerr, 0);
}

void test_sss_krb5_kt_have_content(void **state)
{
    krb5_error_code kerr;
    krb5_keytab keytab;
    struct keytab_test_ctx *test_ctx = talloc_get_type(*state,
                                                        struct keytab_test_ctx);
    assert_non_null(test_ctx);

    kerr = krb5_kt_resolve(test_ctx->kctx, test_ctx->keytab_file_name, &keytab);
    assert_int_equal(kerr, 0);

    kerr = sss_krb5_kt_have_content(test_ctx->kctx, keytab);
    assert_int_equal(kerr, 0);

    kerr = krb5_kt_close(test_ctx->kctx, keytab);
    assert_int_equal(kerr, 0);

    kerr = krb5_kt_resolve(test_ctx->kctx, "FILE:" EMPTY_KEYTAB_PATH, &keytab);
    assert_int_equal(kerr, 0);

    kerr = sss_krb5_kt_have_content(test_ctx->kctx, keytab);
    assert_int_equal(kerr, KRB5_KT_NOTFOUND);

    kerr = krb5_kt_close(test_ctx->kctx, keytab);
    assert_int_equal(kerr, 0);

    /* no need to remove EMPTY_KEYTAB_PATH because krb5_kt_close() does not
     * create empty keytab files */
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_copy_keytab,
                                 setup_keytab, teardown_keytab),
        unit_test_setup_teardown(test_sss_krb5_kt_have_content,
                                 setup_keytab, teardown_keytab),
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

    rv = run_tests(tests);

    return rv;
}
