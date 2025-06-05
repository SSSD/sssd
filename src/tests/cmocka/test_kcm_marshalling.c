/*
    Copyright (C) 2017 Red Hat

    SSSD tests: Test KCM JSON marshalling

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

#include "config.h"

#include <stdio.h>
#include <popt.h>

#include "util/util_creds.h"
#include "responder/kcm/kcmsrv_ccache.h"
#include "responder/kcm/kcmsrv_ccache_be.h"
#include "tests/cmocka/common_mock.h"

#define TEST_REALM                "TESTREALM"
#define TEST_PRINC_COMPONENT      "PRINC_NAME"

#define TEST_CREDS                "TESTCREDS"

#define TEST_UUID_STR             "5f8f296b-02be-4e86-9235-500e82354186"
#define TEST_SEC_KEY_ONEDIGIT     TEST_UUID_STR"-0"
#define TEST_SEC_KEY_MULTIDIGITS  TEST_UUID_STR"-123456"

#define TEST_SEC_KEY_NOSEP        TEST_UUID_STR"+0"

const struct kcm_ccdb_ops ccdb_mem_ops;
const struct kcm_ccdb_ops ccdb_secdb_ops;

struct kcm_marshalling_test_ctx {
    krb5_context kctx;
    krb5_principal princ;
};

static int setup_kcm_marshalling(void **state)
{
    struct kcm_marshalling_test_ctx *test_ctx;
    krb5_error_code kerr;

    test_ctx = talloc_zero(NULL, struct kcm_marshalling_test_ctx);
    assert_non_null(test_ctx);

    kerr = krb5_init_context(&test_ctx->kctx);
    assert_int_equal(kerr, 0);

    kerr = krb5_build_principal(test_ctx->kctx,
                                &test_ctx->princ,
                                sizeof(TEST_REALM)-1, TEST_REALM,
                                TEST_PRINC_COMPONENT, NULL);
    assert_int_equal(kerr, 0);

    *state = test_ctx;
    return 0;
}

static int teardown_kcm_marshalling(void **state)
{
    struct kcm_marshalling_test_ctx *test_ctx = talloc_get_type(*state,
                                        struct kcm_marshalling_test_ctx);
    assert_non_null(test_ctx);

    krb5_free_principal(test_ctx->kctx, test_ctx->princ);
    krb5_free_context(test_ctx->kctx);
    talloc_free(test_ctx);
    return 0;
}

static void assert_cc_name_equal(struct kcm_ccache *cc1,
                                 struct kcm_ccache *cc2)
{
    const char *name1, *name2;

    name1 = kcm_cc_get_name(cc1);
    name2 = kcm_cc_get_name(cc2);
    assert_string_equal(name1, name2);
}

static void assert_cc_uuid_equal(struct kcm_ccache *cc1,
                                 struct kcm_ccache *cc2)
{
    uuid_t u1, u2;
    errno_t ret;

    ret = kcm_cc_get_uuid(cc1, u1);
    assert_int_equal(ret, EOK);
    ret = kcm_cc_get_uuid(cc2, u2);
    assert_int_equal(ret, EOK);
    ret = uuid_compare(u1, u2);
    assert_int_equal(ret, 0);
}

static void assert_cc_princ_equal(struct kcm_ccache *cc1,
                                  struct kcm_ccache *cc2)
{
    krb5_principal p1;
    krb5_principal p2;
    char *name1;
    char *name2;
    krb5_error_code kerr;

    p1 = kcm_cc_get_client_principal(cc1);
    p2 = kcm_cc_get_client_principal(cc2);

    if (p1 != NULL && p2 != NULL) {
        kerr = krb5_unparse_name(NULL, p1, &name1);
        assert_int_equal(kerr, 0);
        kerr = krb5_unparse_name(NULL, p2, &name2);
        assert_int_equal(kerr, 0);

        assert_string_equal(name1, name2);
        krb5_free_unparsed_name(NULL, name1);
        krb5_free_unparsed_name(NULL, name2);
    } else {
        /* Either both principals must be NULL or both
         * non-NULL and represent the same principals
         */
        assert_null(p1);
        assert_null(p2);
    }
}

static void assert_cc_offset_equal(struct kcm_ccache *cc1,
                                   struct kcm_ccache *cc2)
{
    int32_t off1;
    int32_t off2;

    off1 = kcm_cc_get_offset(cc1);
    off2 = kcm_cc_get_offset(cc2);
    assert_int_equal(off1, off2);
}

static void assert_cc_equal(struct kcm_ccache *cc1,
                            struct kcm_ccache *cc2)
{
    assert_cc_name_equal(cc1, cc2);
    assert_cc_uuid_equal(cc1, cc2);
    assert_cc_princ_equal(cc1, cc2);
    assert_cc_offset_equal(cc1, cc2);
}

static void test_kcm_ccache_marshall_unmarshall_binary(void **state)
{
    struct kcm_marshalling_test_ctx *test_ctx = talloc_get_type(*state,
                                        struct kcm_marshalling_test_ctx);
    errno_t ret;
    struct cli_creds owner;
    struct kcm_ccache *cc;
    struct kcm_ccache *cc2;
    struct sss_iobuf *payload;
    const char *name;
    const char *key;
    uint8_t *data;
    uuid_t uuid;

    cli_creds_set_uid(&owner, getuid());
    cli_creds_set_gid(&owner, getgid());

    name = talloc_asprintf(test_ctx, "%"SPRIuid, getuid());
    assert_non_null(name);

    ret = kcm_cc_new(test_ctx,
                     test_ctx->kctx,
                     &owner,
                     name,
                     test_ctx->princ,
                     &cc);
    assert_int_equal(ret, EOK);

    ret = kcm_ccache_to_sec_input_binary(test_ctx, cc, &payload);
    assert_int_equal(ret, EOK);

    data = sss_iobuf_get_data(payload);
    assert_non_null(data);

    ret = kcm_cc_get_uuid(cc, uuid);
    assert_int_equal(ret, EOK);
    key = sec_key_create(test_ctx, name, uuid);
    assert_non_null(key);

    sss_iobuf_cursor_reset(payload);
    ret = sec_kv_to_ccache_binary(test_ctx, key, payload, &owner, &cc2);
    assert_int_equal(ret, EOK);

    assert_cc_equal(cc, cc2);

    /* This key is exactly one byte shorter than it should be */
    sss_iobuf_cursor_reset(payload);
    ret = sec_kv_to_ccache_binary(test_ctx, TEST_UUID_STR "-", payload, &owner,
                                  &cc2);
    assert_int_equal(ret, EINVAL);
}

static void test_kcm_ccache_no_princ_binary(void **state)
{
    struct kcm_marshalling_test_ctx *test_ctx = talloc_get_type(*state,
                                        struct kcm_marshalling_test_ctx);
    errno_t ret;
    struct cli_creds owner;
    const char *name;
    struct kcm_ccache *cc;
    krb5_principal princ;
    struct kcm_ccache *cc2;
    struct sss_iobuf *payload;
    const char *key;
    uint8_t *data;
    uuid_t uuid;

    cli_creds_set_uid(&owner, getuid());
    cli_creds_set_gid(&owner, getgid());

    name = talloc_asprintf(test_ctx, "%"SPRIuid, getuid());
    assert_non_null(name);

    ret = kcm_cc_new(test_ctx,
                     test_ctx->kctx,
                     &owner,
                     name,
                     NULL,
                     &cc);
    assert_int_equal(ret, EOK);

    princ = kcm_cc_get_client_principal(cc);
    assert_null(princ);

    ret = kcm_ccache_to_sec_input_binary(test_ctx, cc, &payload);
    assert_int_equal(ret, EOK);

    data = sss_iobuf_get_data(payload);
    assert_non_null(data);

    ret = kcm_cc_get_uuid(cc, uuid);
    assert_int_equal(ret, EOK);
    key = sec_key_create(test_ctx, name, uuid);
    assert_non_null(key);

    sss_iobuf_cursor_reset(payload);
    ret = sec_kv_to_ccache_binary(test_ctx, key, payload, &owner, &cc2);
    assert_int_equal(ret, EOK);

    assert_cc_equal(cc, cc2);
}

void test_sec_key_get_uuid(void **state)
{
    errno_t ret;
    uuid_t uuid;
    char str_uuid[UUID_STR_SIZE];

    uuid_clear(uuid);
    ret = sec_key_get_uuid(TEST_SEC_KEY_ONEDIGIT, uuid);
    assert_int_equal(ret, EOK);
    uuid_unparse(uuid, str_uuid);
    assert_string_equal(TEST_UUID_STR, str_uuid);

    ret = sec_key_get_uuid(TEST_SEC_KEY_NOSEP, uuid);
    assert_int_equal(ret, EINVAL);

    ret = sec_key_get_uuid(TEST_UUID_STR, uuid);
    assert_int_equal(ret, EINVAL);

    ret = sec_key_get_uuid(NULL, uuid);
    assert_int_equal(ret, EINVAL);
}

void test_sec_key_get_name(void **state)
{
    const char *name;

    name = sec_key_get_name(TEST_SEC_KEY_ONEDIGIT);
    assert_non_null(name);
    assert_string_equal(name, "0");

    name = sec_key_get_name(TEST_SEC_KEY_MULTIDIGITS);
    assert_non_null(name);
    assert_string_equal(name, "123456");

    name = sec_key_get_name(TEST_UUID_STR);
    assert_null(name);

    name = sec_key_get_name(TEST_SEC_KEY_NOSEP);
    assert_null(name);

    name = sec_key_get_name(NULL);
    assert_null(name);
}

void test_sec_key_match_name(void **state)
{
    assert_true(sec_key_match_name(TEST_SEC_KEY_ONEDIGIT, "0"));
    assert_true(sec_key_match_name(TEST_SEC_KEY_MULTIDIGITS, "123456"));

    assert_false(sec_key_match_name(TEST_SEC_KEY_MULTIDIGITS, "0"));
    assert_false(sec_key_match_name(TEST_SEC_KEY_ONEDIGIT, "123456"));

    assert_false(sec_key_match_name(TEST_UUID_STR, "0"));
    assert_false(sec_key_match_name(TEST_SEC_KEY_NOSEP, "0"));
    assert_false(sec_key_match_name(TEST_SEC_KEY_ONEDIGIT, NULL));
    assert_false(sec_key_match_name(NULL, "0"));
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
        cmocka_unit_test_setup_teardown(test_kcm_ccache_marshall_unmarshall_binary,
                                        setup_kcm_marshalling,
                                        teardown_kcm_marshalling),
        cmocka_unit_test_setup_teardown(test_kcm_ccache_no_princ_binary,
                                        setup_kcm_marshalling,
                                        teardown_kcm_marshalling),
        cmocka_unit_test(test_sec_key_get_uuid),
        cmocka_unit_test(test_sec_key_get_name),
        cmocka_unit_test(test_sec_key_match_name),
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
