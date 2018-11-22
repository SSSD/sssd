/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Tests ccache utilities

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
#include "providers/krb5/krb5_ccache.h"
#include "tests/cmocka/common_mock.h"

#define CCACHE_TEST_CLIENT_PRINC "test/client@TEST.CCACHE"
#define CCACHE_TEST_SERVER_PRINC "test/server@TEST.CCACHE"
#define CCACHE_PATH TEST_DIR "/ccache_test.ccache"

struct ccache_test_ctx {
    krb5_context kctx;
    const char *ccache_file_name;
    krb5_principal client_principal;
    krb5_principal server_principal;
};

static int setup_ccache(void **state)
{
    struct ccache_test_ctx *test_ctx;
    krb5_error_code kerr;
    krb5_ccache ccache;
    krb5_creds test_creds;
    static krb5_address addr;
    int add=0x12345;
    krb5_authdata *a;

    static krb5_address *addrs[] = {
        &addr,
        NULL,
    };

    assert_true(leak_check_setup());


    test_ctx = talloc_zero(global_talloc_context, struct ccache_test_ctx);
    assert_non_null(test_ctx);

    kerr = krb5_init_context(&test_ctx->kctx);
    assert_int_equal(kerr, 0);

    addr.magic = KV5M_ADDRESS;
    addr.addrtype = ADDRTYPE_INET;
    addr.length = 4;
    addr.contents = (krb5_octet *) &add;

    memset(&test_creds, 0, sizeof(test_creds));
    test_creds.magic = KV5M_CREDS;
    kerr = krb5_parse_name(test_ctx->kctx, CCACHE_TEST_CLIENT_PRINC,
                           &test_ctx->client_principal);
    assert_int_equal(kerr, 0);
    test_creds.client = test_ctx->client_principal;
    kerr = krb5_parse_name(test_ctx->kctx, CCACHE_TEST_SERVER_PRINC,
                           &test_ctx->server_principal);
    assert_int_equal(kerr, 0);
    test_creds.server = test_ctx->server_principal;

    test_creds.keyblock.magic = KV5M_KEYBLOCK;
    test_creds.keyblock.contents = 0;
    test_creds.keyblock.enctype = 1;
    test_creds.keyblock.length = 1;
    test_creds.keyblock.contents = (unsigned char *) discard_const("1");
    test_creds.times.authtime = 1111;
    test_creds.times.starttime = 2222;
    test_creds.times.endtime = 3333;
    test_creds.times.renew_till = 4444;
    test_creds.is_skey = 0;
    test_creds.ticket_flags = 5555;
    test_creds.addresses = addrs;

    test_creds.ticket.magic = KV5M_DATA;
    test_creds.ticket.length = sizeof("Ticket");
    test_creds.ticket.data = discard_const("Ticket");

    test_creds.authdata = malloc (2 * sizeof(krb5_authdata *));
    assert_non_null(test_creds.authdata);

    a = (krb5_authdata *) malloc(sizeof(krb5_authdata));
    assert_non_null(a);

    a->magic = KV5M_AUTHDATA;
    a->ad_type = KRB5_AUTHDATA_IF_RELEVANT;
    a->contents = (krb5_octet * ) malloc(1);
    assert_non_null(a->contents);
    a->contents[0]=5;
    a->length = 1;
    test_creds.authdata[0] = a;
    test_creds.authdata[1] = NULL;


    test_ctx->ccache_file_name = "FILE:" CCACHE_PATH;

    kerr = krb5_cc_resolve(test_ctx->kctx, test_ctx->ccache_file_name,
                               &ccache);
    assert_int_equal(kerr, 0);

    kerr = krb5_cc_initialize(test_ctx->kctx, ccache, test_creds.client);
    assert_int_equal(kerr, 0);

    kerr = krb5_cc_store_cred(test_ctx->kctx, ccache, &test_creds);
    assert_int_equal(kerr, 0);

    kerr = krb5_cc_close(test_ctx->kctx, ccache);
    assert_int_equal(kerr, 0);

    check_leaks_push(test_ctx);
    *state = test_ctx;

    krb5_free_authdata(test_ctx->kctx, test_creds.authdata);
    return 0;
}

static int teardown_ccache(void **state)
{
    int ret;
    struct ccache_test_ctx *test_ctx = talloc_get_type(*state,
                                                        struct ccache_test_ctx);
    assert_non_null(test_ctx);

    krb5_free_principal(test_ctx->kctx, test_ctx->client_principal);
    krb5_free_principal(test_ctx->kctx, test_ctx->server_principal);
    krb5_free_context(test_ctx->kctx);

    ret = unlink(CCACHE_PATH);
    assert_int_equal(ret, 0);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

void test_copy_ccache(void **state)
{
    krb5_error_code kerr;
    char *mem_ccache_name;
    krb5_ccache ccache;
    krb5_creds mcreds;
    krb5_creds creds;
    krb5_principal mem_principal;
    struct ccache_test_ctx *test_ctx = talloc_get_type(*state,
                                                        struct ccache_test_ctx);
    assert_non_null(test_ctx);

    kerr = copy_ccache_into_memory(test_ctx, test_ctx->kctx,
                                   test_ctx->ccache_file_name,
                                   &mem_ccache_name);
    assert_int_equal(kerr, 0);
    assert_non_null(mem_ccache_name);

    kerr = krb5_cc_resolve(test_ctx->kctx, mem_ccache_name, &ccache);
    assert_int_equal(kerr, 0);

    talloc_free(mem_ccache_name);

    kerr = krb5_cc_get_principal(test_ctx->kctx, ccache, &mem_principal);
    assert_int_equal(kerr, 0);
    assert_non_null(mem_principal);

    assert_true(krb5_principal_compare(test_ctx->kctx, mem_principal,
                                       test_ctx->client_principal));
    krb5_free_principal(test_ctx->kctx, mem_principal);

    memset(&mcreds, 0, sizeof(mcreds));
    memset(&creds, 0, sizeof(mcreds));
    mcreds.client = test_ctx->client_principal;
    mcreds.server = test_ctx->server_principal;
    kerr = krb5_cc_retrieve_cred(test_ctx->kctx, ccache, 0, &mcreds, &creds);
    assert_int_equal(kerr, 0);
    krb5_free_cred_contents(test_ctx->kctx, &creds);

    kerr = krb5_cc_destroy(test_ctx->kctx, ccache);
    assert_int_equal(kerr, 0);
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

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_copy_ccache,
                                        setup_ccache, teardown_ccache),
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

    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
