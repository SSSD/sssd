/*
    SSSD

    Unit test for sss_pam_data

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2024 Red Hat

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

#include "tests/cmocka/common_mock.h"

#include "util/sss_pam_data.h"

#define PASSKEY_PIN "1234"
#define OAUTH2_URI  "short.url.com/tmp\0"
#define OAUTH2_CODE "1234-5678"
#define OAUTH2_STR  OAUTH2_URI OAUTH2_CODE
#define CCACHE_NAME "KRB5CCNAME=KCM:"

#define SC1_CERT_USER       "cert_user1\0"
#define SC1_TOKEN_NAME      "token_name1\0"
#define SC1_MODULE_NAME     "module_name1\0"
#define SC1_KEY_ID          "key_id1\0"
#define SC1_LABEL           "label1\0"
#define SC1_PROMPT_STR      "prompt1\0"
#define SC1_PAM_CERT_USER   "pam_cert_user1"
#define SC1_STR             SC1_CERT_USER SC1_TOKEN_NAME SC1_MODULE_NAME SC1_KEY_ID \
                            SC1_LABEL SC1_PROMPT_STR SC1_PAM_CERT_USER
#define SC2_CERT_USER       "cert_user2\0"
#define SC2_TOKEN_NAME      "token_name2\0"
#define SC2_MODULE_NAME     "module_name2\0"
#define SC2_KEY_ID          "key_id2\0"
#define SC2_LABEL           "label2\0"
#define SC2_PROMPT_STR      "prompt2\0"
#define SC2_PAM_CERT_USER   "pam_cert_user2"
#define SC2_STR             SC2_CERT_USER SC2_TOKEN_NAME SC2_MODULE_NAME SC2_KEY_ID \
                            SC2_LABEL SC2_PROMPT_STR SC2_PAM_CERT_USER
#define SC3_CERT_USER       "cert_user3\0"
#define SC3_TOKEN_NAME      "token_name3\0"
#define SC3_MODULE_NAME     "module_name3\0"
#define SC3_KEY_ID          "key_id3\0"
#define SC3_LABEL           "label3\0"
#define SC3_PROMPT_STR      "prompt3\0"
#define SC3_PAM_CERT_USER   "pam_cert_user3"
#define SC3_STR             SC3_CERT_USER SC3_TOKEN_NAME SC3_MODULE_NAME SC3_KEY_ID \
                            SC3_LABEL SC3_PROMPT_STR SC3_PAM_CERT_USER


/***********************
 * TEST
 **********************/
void test_pam_get_response_data_not_found(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    uint8_t *buf = NULL;
    int32_t len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->resp_list = NULL;
    pam_add_response(pd, SSS_PAM_PASSKEY_INFO, 5, discard_const(PASSKEY_PIN));

    ret = pam_get_response_data(test_ctx, pd, SSS_PAM_OAUTH2_INFO, &buf, &len);
    assert_int_equal(ret, ENOENT);

    talloc_free(test_ctx);
}

void test_pam_get_response_data_one_element(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    uint8_t *buf = NULL;
    int32_t len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->resp_list = NULL;
    pam_add_response(pd, SSS_PAM_PASSKEY_INFO, 5, discard_const(PASSKEY_PIN));

    ret = pam_get_response_data(test_ctx, pd, SSS_PAM_PASSKEY_INFO, &buf, &len);
    assert_int_equal(ret, EOK);
    assert_int_equal(len, strlen(PASSKEY_PIN) + 1);
    assert_string_equal((const char*) buf, PASSKEY_PIN);

    talloc_free(test_ctx);
}

void test_pam_get_response_data_three_elements(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    uint8_t *buf = NULL;
    int32_t len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->resp_list = NULL;
    pam_add_response(pd, SSS_PAM_PASSKEY_INFO, 5, discard_const(PASSKEY_PIN));
    len = strlen(OAUTH2_URI)+1+strlen(OAUTH2_CODE)+1;
    pam_add_response(pd, SSS_PAM_OAUTH2_INFO, len, discard_const(OAUTH2_STR));
    len = strlen(CCACHE_NAME) + 1;
    pam_add_response(pd, SSS_PAM_ENV_ITEM, len, discard_const(CCACHE_NAME));

    ret = pam_get_response_data(test_ctx, pd, SSS_PAM_ENV_ITEM, &buf, &len);
    assert_int_equal(ret, EOK);
    assert_int_equal(len, strlen(CCACHE_NAME) + 1);
    assert_string_equal((const char*) buf, CCACHE_NAME);

    ret = pam_get_response_data(test_ctx, pd, SSS_PAM_OAUTH2_INFO, &buf, &len);
    assert_int_equal(ret, EOK);
    assert_int_equal(len, strlen(OAUTH2_URI)+1+strlen(OAUTH2_CODE)+1);
    assert_string_equal((const char*) buf, OAUTH2_URI);
    assert_string_equal((const char*) buf+strlen(OAUTH2_URI)+1, OAUTH2_CODE);

    ret = pam_get_response_data(test_ctx, pd, SSS_PAM_PASSKEY_INFO, &buf, &len);
    assert_int_equal(ret, EOK);
    assert_int_equal(len, strlen(PASSKEY_PIN) + 1);
    assert_string_equal((const char*) buf, PASSKEY_PIN);

    talloc_free(test_ctx);
}

void test_pam_get_response_data_three_same_elements(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    uint8_t **buf = NULL;
    int32_t *expected_len = NULL;
    int32_t *result_len = NULL;
    int num;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc(test_ctx, struct pam_data);
    assert_non_null(pd);
    expected_len = talloc_array(test_ctx, int32_t, 3);
    assert_non_null(expected_len);
    pd->resp_list = NULL;
    expected_len[0] = strlen(SC1_CERT_USER)+1+strlen(SC1_TOKEN_NAME)+1+
        strlen(SC1_MODULE_NAME)+1+strlen(SC1_KEY_ID)+1+strlen(SC1_LABEL)+1+
        strlen(SC1_PROMPT_STR)+1+strlen(SC1_PAM_CERT_USER)+1;
    pam_add_response(pd, SSS_PAM_CERT_INFO, expected_len[0], discard_const(SC1_STR));
    expected_len[1] = strlen(SC2_CERT_USER)+1+strlen(SC2_TOKEN_NAME)+1+
        strlen(SC2_MODULE_NAME)+1+strlen(SC2_KEY_ID)+1+strlen(SC2_LABEL)+1+
        strlen(SC2_PROMPT_STR)+1+strlen(SC2_PAM_CERT_USER)+1;
    pam_add_response(pd, SSS_PAM_CERT_INFO, expected_len[1], discard_const(SC2_STR));
    expected_len[2] = strlen(SC3_CERT_USER)+1+strlen(SC3_TOKEN_NAME)+1+
        strlen(SC3_MODULE_NAME)+1+strlen(SC3_KEY_ID)+1+strlen(SC3_LABEL)+1+
        strlen(SC3_PROMPT_STR)+1+strlen(SC3_PAM_CERT_USER)+1;
    pam_add_response(pd, SSS_PAM_CERT_INFO, expected_len[2], discard_const(SC3_STR));

    ret = pam_get_response_data_all_same_type(test_ctx, pd, SSS_PAM_CERT_INFO,
                                              &buf, &result_len, &num);
    assert_int_equal(ret, EOK);
    assert_int_equal(num, 3);
    assert_int_equal(result_len[0], expected_len[0]);
    assert_string_equal((const char*) buf[0], SC3_STR);
    assert_int_equal(result_len[1], expected_len[1]);
    assert_string_equal((const char*) buf[1], SC2_STR);
    assert_int_equal(result_len[2], expected_len[2]);
    assert_string_equal((const char*) buf[2], SC1_STR);

    talloc_free(test_ctx);
}

static void test_parse_supp_valgrind_args(void)
{
    /*
     * The objective of this function is to filter the unit-test functions
     * that trigger a valgrind memory leak and suppress them to avoid false
     * positives.
     */
    DEBUG_CLI_INIT(debug_level);
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
        cmocka_unit_test(test_pam_get_response_data_not_found),
        cmocka_unit_test(test_pam_get_response_data_one_element),
        cmocka_unit_test(test_pam_get_response_data_three_elements),
        cmocka_unit_test(test_pam_get_response_data_three_same_elements),
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

    test_parse_supp_valgrind_args();

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();

    return cmocka_run_group_tests(tests, NULL, NULL);
}
