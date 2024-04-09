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
#define SC_NAME         "smartcard ID1"
#define SC_PROMPT       "Enter PIN:"

//TODO: change and make it more beautiful
#define SC_CERT_USER    "1cert_user\0"
#define SC_TOKEN_NAME   "2token_name\0"
#define SC_MODULE_NAME  "3module_name\0"
#define SC_KEY_ID       "4key_id\0"
#define SC_LABEL        "5label\0"
#define SC_PROMPT_STR   "6prompt\0"
#define SC_PAM_CERT_USER "7pam_cert_user"
#define SC_STR          SC_CERT_USER SC_TOKEN_NAME SC_MODULE_NAME SC_KEY_ID SC_LABEL SC_PROMPT_STR SC_PAM_CERT_USER

#define BASIC_PASSWORD              "\"password\": {" \
                                    "\"name\": \"Password\", \"role\": \"password\", " \
                                    "\"prompt\": \"Password\"}"
#define BASIC_OAUTH2                "\"eidp\": {" \
                                    "\"name\": \"Web Login\", \"role\": \"eidp\", " \
                                    "\"init_prompt\": \"Log In\", " \
                                    "\"link_prompt\": \"Log in online with another device\", " \
                                    "\"uri\": \"short.url.com/tmp\", \"code\": \"1234-5678\", " \
                                    "\"timeout\": 300}"
                                    //TODO: change "smartcard ID1"?
#define BASIC_SC                    "\"smartcard ID1\": {" \
                                    "\"name\": \"smartcard ID1\", \"role\": \"smartcard\", " \
                                    "\"prompt\": \"Enter PIN:\"}"
#define MECHANISMS_PASSWORD         "{" BASIC_PASSWORD "}"
#define MECHANISMS_OAUTH2           "{" BASIC_OAUTH2 "}"
#define MECHANISMS_SC               "{" BASIC_SC "}"
                                    //TODO: change SC_NAME?
#define PRIORITY_ALL                "[\"eidp\", \"" SC_NAME "\", \"password\"]"
#define AUTH_SELECTION_PASSWORD     "{\"auth-selection\": {\"mechanisms\": " \
                                    MECHANISMS_PASSWORD ", " \
                                    "\"priority\": [\"password\"]}}"
#define AUTH_SELECTION_OAUTH2       "{\"auth-selection\": {\"mechanisms\": " \
                                    MECHANISMS_OAUTH2 ", " \
                                    "\"priority\": [\"eidp\"]}}"
#define AUTH_SELECTION_SC           "{\"auth-selection\": {\"mechanisms\": " \
                                    MECHANISMS_SC ", " \
                                    "\"priority\": [\"smartcard ID1\"]}}"
#define AUTH_SELECTION_ALL          "{\"auth-selection\": {\"mechanisms\": {" \
                                    BASIC_PASSWORD ", " \
                                    BASIC_OAUTH2 ", " \
                                    BASIC_SC "}, " \
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
                                 false, NULL, NULL,
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
                                 false, NULL, NULL,
                                 &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_OAUTH2);
    json_decref(mechs);
    free(string);
}

void test_json_format_mechanisms_sc(void **state)
{
    json_t *mechs = NULL;
    char *string;
    int ret;

    ret = json_format_mechanisms(false, NULL, false, NULL, NULL,
                                 true, SC_NAME, SC_PROMPT,
                                 &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_SC);
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
    will_return(__wrap_json_array_append_new, false);
    ret = json_format_priority(true, true, true, SC_NAME, &priority);
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
                                     false, NULL, NULL,
                                     false, NULL, NULL,
                                     &json_msg);
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
                                     false, NULL, NULL,
                                     &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_OAUTH2);
}

void test_json_format_auth_selection_sc(void **state)
{
    TALLOC_CTX *test_ctx;
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, false, NULL,
                                     false, NULL, NULL,
                                     true, SC_NAME, SC_PROMPT,
                                     &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_SC);
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
    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, true, PASSWORD_PROMPT,
                                     true, OAUTH2_URI, OAUTH2_CODE,
                                     true, SC_NAME, SC_PROMPT,
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
                                     true, SC_NAME, SC_PROMPT,
                                     &json_msg);
    assert_int_equal(ret, ENOMEM);
    assert_null(json_msg);
}

void test_generate_json_message_integration(void **state)
{
    TALLOC_CTX *test_ctx;
    struct pam_data *pd = NULL;
    int len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);

    len = strlen(OAUTH2_URI)+1+strlen(OAUTH2_URI_COMP)+1+strlen(OAUTH2_CODE)+1;
    ret = pam_add_response(pd, SSS_PAM_OAUTH2_INFO, len,
                           discard_const(OAUTH2_STR));
    assert_int_equal(ret, EOK);
    len = strlen(SC_CERT_USER)+1+strlen(SC_TOKEN_NAME)+1+
          strlen(SC_MODULE_NAME)+1+strlen(SC_KEY_ID)+1+strlen(SC_LABEL)+1+
          strlen(SC_PROMPT_STR)+1+strlen(SC_PAM_CERT_USER)+1;
    ret = pam_add_response(pd, SSS_PAM_CERT_INFO, len, discard_const(SC_STR));
    assert_int_equal(ret, EOK);

    will_return(__wrap_confdb_get_string, EOK);
    will_return(__wrap_confdb_get_string, PASSWORD_PROMPT);
    will_return(__wrap_json_array_append_new, false);
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

void test_is_pam_json_enabled_service_in_list(void **state)
{
    const char *json_services[] = {"sshd", "su", "gdm-switchable-auth", NULL};
    bool result;

    result = is_pam_json_enabled(json_services,
                                 discard_const("gdm-switchable-auth"));
    assert_int_equal(result, true);
}

void test_is_pam_json_enabled_service_not_in_list(void **state)
{
    const char *json_services[] = {"sshd", "su", "gdm-switchable-auth", NULL};
    bool result;

    result = is_pam_json_enabled(json_services,
                                 discard_const("sudo"));
    assert_int_equal(result, false);
}

void test_is_pam_json_enabled_null_list(void **state)
{
    bool result;

    result = is_pam_json_enabled(NULL,
                                 discard_const("sudo"));
    assert_int_equal(result, false);
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
        cmocka_unit_test(test_json_format_mechanisms_sc),
        cmocka_unit_test(test_json_format_priority_all),
        cmocka_unit_test(test_json_format_auth_selection_password),
        cmocka_unit_test(test_json_format_auth_selection_oauth2),
        cmocka_unit_test(test_json_format_auth_selection_sc),
        cmocka_unit_test(test_json_format_auth_selection_all),
        cmocka_unit_test(test_json_format_auth_selection_failure),
        cmocka_unit_test(test_generate_json_message_integration),
        cmocka_unit_test(test_json_unpack_password_ok),
        cmocka_unit_test(test_json_unpack_auth_reply_password),
        cmocka_unit_test(test_json_unpack_auth_reply_oauth2),
        cmocka_unit_test(test_json_unpack_auth_reply_failure),
        cmocka_unit_test(test_is_pam_json_enabled_service_in_list),
        cmocka_unit_test(test_is_pam_json_enabled_service_not_in_list),
        cmocka_unit_test(test_is_pam_json_enabled_null_list),
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
