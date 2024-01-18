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
