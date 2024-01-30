/*
    SSSD

    Unit test for pamsrv_json

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

#include <jansson.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"

#include "src/responder/pam/pamsrv_json.h"

#define PASSWORD_PROMPT "Password"
#define OAUTH2_URI      "short.url.com/tmp\0"
#define OAUTH2_URI_COMP "\0"
#define OAUTH2_CODE     "1234-5678"
#define OAUTH2_STR      OAUTH2_URI OAUTH2_URI_COMP OAUTH2_CODE

#define BASIC_PASSWORD              "\"password\": {" \
                                    "\"name\": \"Password\", \"role\": \"password\", " \
                                    "\"prompt\": \"Password\"}"
#define BASIC_OAUTH2                "\"eidp\": {" \
                                    "\"name\": \"Web Login\", \"role\": \"eidp\", " \
                                    "\"init_prompt\": \"Log In\", " \
                                    "\"link_prompt\": \"Log in online with another device\", " \
                                    "\"uri\": \"short.url.com/tmp\", \"code\": \"1234-5678\", " \
                                    "\"timeout\": 300}"
#define MECHANISMS_PASSWORD         "{" BASIC_PASSWORD "}"
#define MECHANISMS_OAUTH2           "{" BASIC_OAUTH2 "}"
#define PRIORITY_ALL                "[\"eidp\", \"password\"]"
#define AUTH_SELECTION_PASSWORD     "{\"auth-selection\": {\"mechanisms\": " \
                                    MECHANISMS_PASSWORD ", " \
                                    "\"priority\": [\"password\"]}}"
#define AUTH_SELECTION_OAUTH2       "{\"auth-selection\": {\"mechanisms\": " \
                                    MECHANISMS_OAUTH2 ", " \
                                    "\"priority\": [\"eidp\"]}}"
#define AUTH_SELECTION_ALL          "{\"auth-selection\": {\"mechanisms\": {" \
                                    BASIC_PASSWORD ", " \
                                    BASIC_OAUTH2 "}, " \
                                    "\"priority\": " PRIORITY_ALL "}}"

#define PASSWORD_CONTENT            "{\"password\": \"ThePassword\"}"
#define AUTH_MECH_REPLY_PASSWORD    "{\"auth-selection\": {" \
                                    "\"status\": \"Ok\", \"password\": " \
                                    PASSWORD_CONTENT "}}"
#define AUTH_MECH_REPLY_OAUTH2      "{\"auth-selection\": {" \
                                    "\"status\": \"Ok\", \"eidp\": {}}}"
#define AUTH_MECH_ERRONEOUS         "{\"auth-selection\": {" \
                                    "\"status\": \"Ok\", \"lololo\": {}}}"


/***********************
 * WRAPPERS
 **********************/
int __real_json_array_append_new(json_t *array, json_t *value);

int
__wrap_json_array_append_new(json_t *array, json_t *value)
{
    int fail;
    int ret;

    fail = mock();

    if(fail) {
        ret = -1;
    } else {
        ret = __real_json_array_append_new(array, value);
    }

    return ret;
}

int
__wrap_confdb_get_string(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                         const char *section, const char *attribute,
                         const char *defstr, char **result)
{
    int ret;

    ret = mock();
    *result = (char *) mock();

    return ret;
}

/***********************
 * TEST
 **********************/
void test_json_format_mechanisms_password(void **state)
{
    json_t *mechs = NULL;
    char *string;
    int ret;

    ret = json_format_mechanisms(true, PASSWORD_PROMPT, false, NULL, NULL,
                                 &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_PASSWORD);
    json_decref(mechs);
    free(string);
}

void test_json_format_mechanisms_oauth2(void **state)
{
    json_t *mechs = NULL;
    char *string;
    int ret;

    ret = json_format_mechanisms(false, NULL, true, OAUTH2_URI, OAUTH2_CODE,
                                 &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_OAUTH2);
    json_decref(mechs);
    free(string);
}

void test_json_format_priority_all(void **state)
{
    json_t *priority = NULL;
    char *string;
    int ret;

    will_return(__wrap_json_array_append_new, false);
    will_return(__wrap_json_array_append_new, false);
    ret = json_format_priority(true, true, &priority);
    assert_int_equal(ret, EOK);

    string = json_dumps(priority, 0);
    assert_string_equal(string, PRIORITY_ALL);
    json_decref(priority);
    free(string);
}

void test_json_format_auth_selection_password(void **state)
{
    TALLOC_CTX *test_ctx;
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, true, PASSWORD_PROMPT,
                                     false, NULL, NULL, &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_PASSWORD);
}

void test_json_format_auth_selection_oauth2(void **state)
{
    TALLOC_CTX *test_ctx;
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, false, NULL,
                                     true, OAUTH2_URI, OAUTH2_CODE,
                                     &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_OAUTH2);
}

void test_json_format_auth_selection_all(void **state)
{
    TALLOC_CTX *test_ctx;
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    will_return(__wrap_json_array_append_new, false);
    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, true, PASSWORD_PROMPT,
                                     true, OAUTH2_URI, OAUTH2_CODE,
                                     &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_ALL);
}

void test_json_format_auth_selection_failure(void **state)
{
    TALLOC_CTX *test_ctx;
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    will_return(__wrap_json_array_append_new, true);
    ret = json_format_auth_selection(test_ctx, true, PASSWORD_PROMPT,
                                     true, OAUTH2_URI, OAUTH2_CODE,
                                     &json_msg);
    assert_int_equal(ret, ENOMEM);
    assert_null(json_msg);
}

void test_generate_json_message_integration(void **state)
{
    TALLOC_CTX *test_ctx;
    struct pam_data *pd = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);

    pd->resp_list = talloc(pd, struct response_data);
    pd->resp_list->type = SSS_PAM_OAUTH2_INFO;
    pd->resp_list->len = strlen(OAUTH2_URI)+1+strlen(OAUTH2_URI_COMP)+1+strlen(OAUTH2_CODE)+1;
    pd->resp_list->data = discard_const(OAUTH2_STR);
    pd->resp_list->next = NULL;

    will_return(__wrap_confdb_get_string, EOK);
    will_return(__wrap_confdb_get_string, PASSWORD_PROMPT);
    will_return(__wrap_json_array_append_new, false);
    will_return(__wrap_json_array_append_new, false);
    ret = generate_json_auth_message(NULL, pd);
    assert_int_equal(ret, EOK);
    assert_string_equal((char*) pd->resp_list->data, AUTH_SELECTION_ALL);

    talloc_free(test_ctx);
}

void test_json_unpack_password_ok(void **state)
{
    json_t *jroot = NULL;
    char *password = NULL;
    json_error_t jret;
    int ret;

    jroot = json_loads(PASSWORD_CONTENT, 0, &jret);
    assert_non_null(jroot);

    ret = json_unpack_password(jroot, &password);
    assert_int_equal(ret, EOK);
    assert_string_equal(password, "ThePassword");
    json_decref(jroot);
}

void test_json_unpack_auth_reply_password(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    const char *password = NULL;
    size_t len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->authtok = sss_authtok_new(pd);
    assert_non_null(pd->authtok);
    pd->json_auth_selected = discard_const(AUTH_MECH_REPLY_PASSWORD);

    ret = json_unpack_auth_reply(pd);
    assert_int_equal(ret, EOK);
    assert_int_equal(sss_authtok_get_type(pd->authtok), SSS_AUTHTOK_TYPE_PASSWORD);
    sss_authtok_get_password(pd->authtok, &password, &len);
    assert_string_equal(password, "ThePassword");

    talloc_free(test_ctx);
}

void test_json_unpack_auth_reply_oauth2(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->authtok = sss_authtok_new(pd);
    assert_non_null(pd->authtok);
    pd->json_auth_selected = discard_const(AUTH_MECH_REPLY_OAUTH2);

    ret = json_unpack_auth_reply(pd);
    assert_int_equal(ret, EOK);

    talloc_free(test_ctx);
}

void test_json_unpack_auth_reply_failure(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->json_auth_selected = discard_const(AUTH_MECH_ERRONEOUS);

    ret = json_unpack_auth_reply(pd);
    assert_int_equal(ret, EINVAL);
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
        cmocka_unit_test(test_json_format_mechanisms_password),
        cmocka_unit_test(test_json_format_mechanisms_oauth2),
        cmocka_unit_test(test_json_format_priority_all),
        cmocka_unit_test(test_json_format_auth_selection_password),
        cmocka_unit_test(test_json_format_auth_selection_oauth2),
        cmocka_unit_test(test_json_format_auth_selection_all),
        cmocka_unit_test(test_json_format_auth_selection_failure),
        cmocka_unit_test(test_generate_json_message_integration),
        cmocka_unit_test(test_json_unpack_password_ok),
        cmocka_unit_test(test_json_unpack_auth_reply_password),
        cmocka_unit_test(test_json_unpack_auth_reply_oauth2),
        cmocka_unit_test(test_json_unpack_auth_reply_failure),
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
