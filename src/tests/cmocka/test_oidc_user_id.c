/*
    SSSD

    Unit tests for OIDC user identifier extraction, including Entra ID
    onPremisesImmutableId / AD objectGUID conversion.

    Copyright (C) 2026 the authors of SSSD

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

#include <popt.h>
#include <jansson.h>
#include <talloc.h>
#include <string.h>

#include "tests/cmocka/common_mock.h"
#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "oidc_child/oidc_child_util.h"

/* objectGUID blobs and string forms from test_string_utils.c */
static const uint8_t guid_blob_1[GUID_BIN_LENGTH] = {
    0x8d, 0x0d, 0xa8, 0xfe, 0xd5, 0xdb, 0x84, 0x4f,
    0x85, 0x74, 0x7d, 0xb0, 0x47, 0x7f, 0x96, 0x2e
};
static const char *guid_str_1 = "fea80d8d-dbd5-4f84-8574-7db0477f962e";

static const uint8_t guid_blob_2[GUID_BIN_LENGTH] = {
    0x91, 0x7e, 0x2e, 0xf8, 0x4e, 0x44, 0xfa, 0x4e,
    0xb1, 0x13, 0x08, 0x98, 0x63, 0x49, 0x6c, 0xc6
};
static const char *guid_str_2 = "f82e7e91-444e-4efa-b113-089863496cc6";

static void test_default_uses_id(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    const char *id;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    userinfo = json_pack("{s:s, s:s}",
                         "id", "cloud-generated-uuid",
                         "userPrincipalName", "user@example.com");
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo, NULL, "userinfo");
    assert_non_null(id);
    assert_string_equal(id, "cloud-generated-uuid");

    json_decref(userinfo);
    talloc_free(mem_ctx);
}

static void test_configured_plain_attr(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    const char *id;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    userinfo = json_pack("{s:s, s:s}",
                         "id", "cloud-id",
                         "sub", "subject-value");
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo, "sub", "userinfo");
    assert_non_null(id);
    assert_string_equal(id, "subject-value");

    json_decref(userinfo);
    talloc_free(mem_ctx);
}

static void test_onprem_immutable_id_decode(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    char *b64;
    const char *id;
    char expected[GUID_STR_BUF_SIZE];
    errno_t ret;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    ret = guid_blob_to_string_buf(guid_blob_1, expected, sizeof(expected));
    assert_int_equal(ret, EOK);
    assert_string_equal(expected, guid_str_1);

    b64 = sss_base64_encode(mem_ctx, guid_blob_1, GUID_BIN_LENGTH);
    assert_non_null(b64);

    userinfo = json_pack("{s:s, s:s}",
                         "id", "should-not-be-used",
                         "onPremisesImmutableId", b64);
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo,
                             "onPremisesImmutableId", "userinfo");
    assert_non_null(id);
    assert_string_equal(id, guid_str_1);

    json_decref(userinfo);
    talloc_free(mem_ctx);
}

static void test_onprem_immutable_id_second_vector(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    char *b64;
    const char *id;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    b64 = sss_base64_encode(mem_ctx, guid_blob_2, GUID_BIN_LENGTH);
    assert_non_null(b64);

    userinfo = json_pack("{s:s}", "onPremisesImmutableId", b64);
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo,
                             "onPremisesImmutableId", "userinfo");
    assert_non_null(id);
    assert_string_equal(id, guid_str_2);

    json_decref(userinfo);
    talloc_free(mem_ctx);
}

static void test_onprem_missing_falls_back_to_id(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    const char *id;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    userinfo = json_pack("{s:s}", "id", "entra-cloud-only-id");
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo,
                             "onPremisesImmutableId", "userinfo");
    assert_non_null(id);
    assert_string_equal(id, "entra-cloud-only-id");

    json_decref(userinfo);
    talloc_free(mem_ctx);
}

static void test_onprem_null_falls_back_to_id(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    const char *id;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    userinfo = json_pack("{s:n, s:s}",
                         "onPremisesImmutableId",
                         "id", "fallback-id");
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo,
                             "onPremisesImmutableId", "userinfo");
    assert_non_null(id);
    assert_string_equal(id, "fallback-id");

    json_decref(userinfo);
    talloc_free(mem_ctx);
}

static void test_onprem_invalid_b64_falls_back(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    const char *id;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    userinfo = json_pack("{s:s, s:s}",
                         "onPremisesImmutableId", "not-valid-base64!!!",
                         "id", "fallback-after-bad-b64");
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo,
                             "onPremisesImmutableId", "userinfo");
    assert_non_null(id);
    assert_string_equal(id, "fallback-after-bad-b64");

    json_decref(userinfo);
    talloc_free(mem_ctx);
}

static void test_onprem_wrong_length_falls_back(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    char *b64;
    const char *id;
    const unsigned char short_blob[] = { 0x01, 0x02, 0x03, 0x04 };

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    b64 = sss_base64_encode(mem_ctx, short_blob, sizeof(short_blob));
    assert_non_null(b64);

    userinfo = json_pack("{s:s, s:s}",
                         "onPremisesImmutableId", b64,
                         "id", "fallback-wrong-len");
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo,
                             "onPremisesImmutableId", "userinfo");
    assert_non_null(id);
    assert_string_equal(id, "fallback-wrong-len");

    json_decref(userinfo);
    talloc_free(mem_ctx);
}

static void test_missing_all_returns_null(void **state)
{
    TALLOC_CTX *mem_ctx;
    json_t *userinfo;
    const char *id;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    userinfo = json_pack("{s:s}", "userPrincipalName", "user@example.com");
    assert_non_null(userinfo);

    id = get_user_identifier(mem_ctx, userinfo, NULL, "userinfo");
    assert_null(id);

    json_decref(userinfo);
    talloc_free(mem_ctx);
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
        cmocka_unit_test(test_default_uses_id),
        cmocka_unit_test(test_configured_plain_attr),
        cmocka_unit_test(test_onprem_immutable_id_decode),
        cmocka_unit_test(test_onprem_immutable_id_second_vector),
        cmocka_unit_test(test_onprem_missing_falls_back_to_id),
        cmocka_unit_test(test_onprem_null_falls_back_to_id),
        cmocka_unit_test(test_onprem_invalid_b64_falls_back),
        cmocka_unit_test(test_onprem_wrong_length_falls_back),
        cmocka_unit_test(test_missing_all_returns_null),
    };

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

    tests_set_cwd();

    return cmocka_run_group_tests(tests, NULL, NULL);
}
