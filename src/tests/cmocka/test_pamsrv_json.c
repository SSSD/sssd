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

#include "src/responder/pam/pamsrv.h"
#include "src/responder/pam/pamsrv_json.h"

#define OAUTH2_URI          "short.url.com/tmp\0"
#define OAUTH2_URI_COMP     "\0"
#define OAUTH2_CODE         "1234-5678"
#define OAUTH2_STR          OAUTH2_URI OAUTH2_URI_COMP OAUTH2_CODE
#define PASSKEY_CRYPTO_CHAL "6uDMvRKj3W5xJV3HaQjZrtXMNmUUAjRGklFG2MIhN5s="

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

#define BASIC_PASSWORD              "\"password\": {" \
                                    "\"name\": \"Password\", \"role\": \"password\", " \
                                    "\"prompt\": \"Password\"}"
#define BASIC_OAUTH2                "\"eidp\": {" \
                                    "\"name\": \"Web Login\", \"role\": \"eidp\", " \
                                    "\"initPrompt\": \"" OAUTH2_INIT_PROMPT "\", " \
                                    "\"linkPrompt\": \"" OAUTH2_LINK_PROMPT "\", " \
                                    "\"uri\": \"short.url.com/tmp\", \"code\": \"1234-5678\", " \
                                    "\"timeout\": 300}"
#define BASIC_SC                    "\"smartcard\": {" \
                                    "\"name\": \"Smartcard\", \"role\": \"smartcard\", " \
                                    "\"certificates\": [{" \
                                    "\"tokenName\": \"token_name1\", " \
                                    "\"certInstruction\": \"prompt1\", " \
                                    "\"pinPrompt\": \"" SC_PIN_PROMPT "\", " \
                                    "\"moduleName\": \"module_name1\", " \
                                    "\"keyId\": \"key_id1\", " \
                                    "\"label\": \"label1\"}]}"
#define MULTIPLE_SC                 "\"smartcard\": {" \
                                    "\"name\": \"Smartcard\", \"role\": \"smartcard\", " \
                                    "\"certificates\": [{" \
                                    "\"tokenName\": \"token_name1\", " \
                                    "\"certInstruction\": \"prompt1\", " \
                                    "\"pinPrompt\": \"" SC_PIN_PROMPT "\", " \
                                    "\"moduleName\": \"module_name1\", " \
                                    "\"keyId\": \"key_id1\", " \
                                    "\"label\": \"label1\"}, {" \
                                    "\"tokenName\": \"token_name2\", " \
                                    "\"certInstruction\": \"prompt2\", " \
                                    "\"pinPrompt\": \"" SC_PIN_PROMPT "\", " \
                                    "\"moduleName\": \"module_name2\", " \
                                    "\"keyId\": \"key_id2\", " \
                                    "\"label\": \"label2\"}]}"
#define BASIC_PASSKEY               "\"passkey\": {" \
                                    "\"name\": \"Passkey\", \"role\": \"passkey\", " \
                                    "\"initInstruction\": \"" PASSKEY_INIT_PROMPT "\", " \
                                    "\"keyConnected\": true, " \
                                    "\"pinRequest\": true, \"pinAttempts\": 8, " \
                                    "\"pinPrompt\": \"" PASSKEY_PIN_PROMPT "\", " \
                                    "\"touchInstruction\": \"" PASSKEY_TOUCH_PROMPT "\", " \
                                    "\"kerberos\": false, " \
                                    "\"cryptoChallenge\": \"\"}"
#define MECHANISMS_PASSWORD         "{" BASIC_PASSWORD "}"
#define MECHANISMS_OAUTH2           "{" BASIC_OAUTH2 "}"
#define MECHANISMS_SC1              "{" BASIC_SC "}"
#define MECHANISMS_SC2              "{" MULTIPLE_SC "}"
#define MECHANISMS_PASSKEY          "{" BASIC_PASSKEY "}"
#define PRIORITY_ALL                "[\"smartcard\", \"passkey\", \"eidp\", \"password\"]"
#define AUTH_SELECTION_PASSWORD     "{\"authSelection\": {\"mechanisms\": " \
                                    MECHANISMS_PASSWORD ", " \
                                    "\"priority\": [\"password\"]}}"
#define AUTH_SELECTION_OAUTH2       "{\"authSelection\": {\"mechanisms\": " \
                                    MECHANISMS_OAUTH2 ", " \
                                    "\"priority\": [\"eidp\"]}}"
#define AUTH_SELECTION_SC           "{\"authSelection\": {\"mechanisms\": " \
                                    MECHANISMS_SC2 ", " \
                                    "\"priority\": [\"smartcard\"]}}"
#define AUTH_SELECTION_PASSKEY      "{\"authSelection\": {\"mechanisms\": " \
                                    MECHANISMS_PASSKEY ", " \
                                    "\"priority\": [\"passkey\"]}}"
#define AUTH_SELECTION_ALL          "{\"authSelection\": {\"mechanisms\": {" \
                                    BASIC_PASSWORD ", " \
                                    BASIC_OAUTH2 ", " \
                                    MULTIPLE_SC ", " \
                                    BASIC_PASSKEY "}, " \
                                    "\"priority\": " PRIORITY_ALL "}}"

#define PASSWORD_CONTENT            "{\"password\": \"ThePassword\"}"
#define SMARTCARD_CONTENT           "{\"pin\": \"ThePIN\", \"tokenName\": \"token_name1\", " \
                                    "\"moduleName\": \"module_name1\", \"keyId\": \"key_id1\", " \
                                    "\"label\": \"label1\"}"
#define PASSKEY_CONTENT             "{\"pin\": \"ThePIN\", \"kerberos\": true, " \
                                    "\"cryptoChallenge\": \"" PASSKEY_CRYPTO_CHAL "\"}"
#define AUTH_MECH_REPLY_PASSWORD    "{\"authSelection\": {" \
                                    "\"status\": \"Ok\", \"password\": " \
                                    PASSWORD_CONTENT "}}"
#define AUTH_MECH_REPLY_OAUTH2      "{\"authSelection\": {" \
                                    "\"status\": \"Ok\", \"eidp\": {}}}"
#define AUTH_MECH_REPLY_SMARTCARD   "{\"authSelection\": {" \
                                    "\"status\": \"Ok\", \"smartcard:1\": " \
                                    SMARTCARD_CONTENT "}}"
#define AUTH_MECH_REPLY_PASSKEY     "{\"authSelection\": {" \
                                    "\"status\": \"Ok\", \"passkey\": " \
                                    PASSKEY_CONTENT "}}"
#define AUTH_MECH_ERRONEOUS         "{\"authSelection\": {" \
                                    "\"status\": \"Ok\", \"lololo\": {}}}"

struct cert_auth_info {
    char *cert_user;
    char *cert;
    char *token_name;
    char *module_name;
    char *key_id;
    char *label;
    char *prompt_str;
    char *pam_cert_user;
    char *choice_list_id;
    struct cert_auth_info *prev;
    struct cert_auth_info *next;
};

/***********************
 * SETUP AND TEARDOWN
 **********************/
static int setup(void **state)
{
    struct auth_data *auth_data = NULL;

    assert_true(leak_check_setup());

    auth_data = talloc_zero(global_talloc_context, struct auth_data);
    assert_non_null(auth_data);
    auth_data->pswd = talloc_zero(auth_data, struct password_data);
    assert_non_null(auth_data->pswd);
    auth_data->oauth2 = talloc_zero(auth_data, struct oauth2_data);
    assert_non_null(auth_data->oauth2);
    auth_data->sc = talloc_zero(auth_data, struct sc_data);
    assert_non_null(auth_data->sc);
    auth_data->sc->names = talloc_array(auth_data->sc, char *, 3);
    assert_non_null(auth_data->sc->names);
    auth_data->sc->cert_instructions = talloc_array(auth_data->sc, char *, 3);
    assert_non_null(auth_data->sc->cert_instructions);
    auth_data->sc->module_names = talloc_array(auth_data->sc, char *, 3);
    assert_non_null(auth_data->sc->module_names);
    auth_data->sc->key_ids = talloc_array(auth_data->sc, char *, 3);
    assert_non_null(auth_data->sc->key_ids);
    auth_data->sc->labels = talloc_array(auth_data->sc, char *, 3);
    assert_non_null(auth_data->sc->labels);
    auth_data->passkey = talloc_zero(auth_data, struct passkey_data);
    assert_non_null(auth_data->passkey);

    auth_data->pswd->enabled = false;
    auth_data->oauth2->enabled = false;
    auth_data->sc->enabled = false;
    auth_data->passkey->enabled = false;

    check_leaks_push(auth_data);
    *state = (void *)auth_data;
    return 0;
}

static int teardown(void **state)
{
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);

    assert_non_null(auth_data);
    assert_true(check_leaks_pop(auth_data));
    talloc_free(auth_data);
    assert_true(leak_check_teardown());

    return 0;
}

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

/***********************
 * TEST
 **********************/
void test_get_cert_list(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct cert_auth_info *cert_list = NULL;
    struct cert_auth_info *item = NULL;
    struct pam_data *pd = NULL;
    const char *expected_token_name[] = {SC1_TOKEN_NAME, SC2_TOKEN_NAME};
    const char *expected_module_name[] = {SC1_MODULE_NAME, SC2_MODULE_NAME};
    const char *expected_key_id[] = {SC1_KEY_ID, SC2_KEY_ID};
    const char *expected_label[] = {SC1_LABEL, SC2_LABEL};
    const char *expected_prompt_str[] = {SC1_PROMPT_STR, SC2_PROMPT_STR};
    int i = 0;
    int len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);

    len = strlen(SC1_CERT_USER)+1+strlen(SC1_TOKEN_NAME)+1+
          strlen(SC1_MODULE_NAME)+1+strlen(SC1_KEY_ID)+1+strlen(SC1_LABEL)+1+
          strlen(SC1_PROMPT_STR)+1+strlen(SC1_PAM_CERT_USER)+1;
    ret = pam_add_response(pd, SSS_PAM_CERT_INFO, len, discard_const(SC1_STR));
    assert_int_equal(ret, EOK);
    len = strlen(SC2_CERT_USER)+1+strlen(SC2_TOKEN_NAME)+1+
          strlen(SC2_MODULE_NAME)+1+strlen(SC2_KEY_ID)+1+strlen(SC2_LABEL)+1+
          strlen(SC2_PROMPT_STR)+1+strlen(SC2_PAM_CERT_USER)+1;
    ret = pam_add_response(pd, SSS_PAM_CERT_INFO, len, discard_const(SC2_STR));
    assert_int_equal(ret, EOK);

    ret = get_cert_list(test_ctx, pd, &cert_list);
    assert_int_equal(ret, EOK);
    DLIST_FOR_EACH(item, cert_list) {
        assert_string_equal(expected_token_name[i], item->token_name);
        assert_string_equal(expected_module_name[i], item->module_name);
        assert_string_equal(expected_key_id[i], item->key_id);
        assert_string_equal(expected_label[i], item->label);
        assert_string_equal(expected_prompt_str[i], item->prompt_str);
        i++;
    }

    talloc_free(test_ctx);
}

void test_get_cert_data(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    struct cert_auth_info *cert_list = NULL;
    struct cert_auth_info *cai = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    cai = talloc_zero(test_ctx, struct cert_auth_info);
    assert_non_null(cai);
    cai->token_name = discard_const(SC1_TOKEN_NAME);
    cai->module_name = discard_const(SC1_MODULE_NAME);
    cai->key_id = discard_const(SC1_KEY_ID);
    cai->label = discard_const(SC1_LABEL);
    cai->prompt_str = discard_const(SC1_PROMPT_STR);
    DLIST_ADD(cert_list, cai);
    cai = talloc_zero(test_ctx, struct cert_auth_info);
    assert_non_null(cai);
    cai->token_name = discard_const(SC2_TOKEN_NAME);
    cai->module_name = discard_const(SC2_MODULE_NAME);
    cai->key_id = discard_const(SC2_KEY_ID);
    cai->label = discard_const(SC2_LABEL);
    cai->prompt_str = discard_const(SC2_PROMPT_STR);
    DLIST_ADD(cert_list, cai);

    ret = get_cert_data(test_ctx, cert_list, auth_data);
    assert_int_equal(ret, EOK);
    assert_string_equal(auth_data->sc->names[0], SC2_TOKEN_NAME);
    assert_string_equal(auth_data->sc->module_names[0], SC2_MODULE_NAME);
    assert_string_equal(auth_data->sc->key_ids[0], SC2_KEY_ID);
    assert_string_equal(auth_data->sc->labels[0], SC2_LABEL);
    assert_string_equal(auth_data->sc->cert_instructions[0], SC2_PROMPT_STR);
    assert_string_equal(auth_data->sc->names[1], SC1_TOKEN_NAME);
    assert_string_equal(auth_data->sc->module_names[1], SC1_MODULE_NAME);
    assert_string_equal(auth_data->sc->key_ids[1], SC1_KEY_ID);
    assert_string_equal(auth_data->sc->labels[1], SC1_LABEL);
    assert_string_equal(auth_data->sc->cert_instructions[1], SC1_PROMPT_STR);

    talloc_free(test_ctx);
}

void test_json_format_mechanisms_password(void **state)
{
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    json_t *mechs = NULL;
    char *string;
    int ret;

    auth_data->pswd->enabled = true;
    auth_data->pswd->prompt = discard_const(PASSWORD_PROMPT);

    ret = json_format_mechanisms(auth_data, &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_PASSWORD);

    json_decref(mechs);
    free(string);
}

void test_json_format_mechanisms_oauth2(void **state)
{
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    json_t *mechs = NULL;
    char *string;
    int ret;

    auth_data->oauth2->enabled = true;
    auth_data->oauth2->uri = discard_const(OAUTH2_URI);
    auth_data->oauth2->code = discard_const(OAUTH2_CODE);
    auth_data->oauth2->init_prompt = discard_const(OAUTH2_INIT_PROMPT);
    auth_data->oauth2->link_prompt = discard_const(OAUTH2_LINK_PROMPT);

    ret = json_format_mechanisms(auth_data, &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_OAUTH2);

    json_decref(mechs);
    free(string);
}

void test_json_format_mechanisms_sc1(void **state)
{
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    json_t *mechs = NULL;
    char *string;
    int ret;

    auth_data->sc->enabled = true;
    auth_data->sc->names[0] = talloc_strdup(auth_data->sc->names, SC1_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[0]);
    auth_data->sc->cert_instructions[0] = talloc_strdup(auth_data->sc->cert_instructions, SC1_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[0]);
    auth_data->sc->module_names[0] = talloc_strdup(auth_data->sc->module_names, SC1_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[0]);
    auth_data->sc->key_ids[0] = talloc_strdup(auth_data->sc->key_ids, SC1_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[0]);
    auth_data->sc->labels[0] = talloc_strdup(auth_data->sc->labels, SC1_LABEL);
    assert_non_null(auth_data->sc->labels[0]);
    auth_data->sc->names[1] = NULL;
    auth_data->sc->pin_prompt = discard_const(SC_PIN_PROMPT);

    will_return(__wrap_json_array_append_new, false);

    ret = json_format_mechanisms(auth_data, &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_SC1);

    json_decref(mechs);
    free(string);
    talloc_free(auth_data->sc->names[0]);
    talloc_free(auth_data->sc->cert_instructions[0]);
    talloc_free(auth_data->sc->module_names[0]);
    talloc_free(auth_data->sc->key_ids[0]);
    talloc_free(auth_data->sc->labels[0]);
}

void test_json_format_mechanisms_sc2(void **state)
{
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    json_t *mechs = NULL;
    char *string;
    int ret;

    auth_data->sc->enabled = true;
    auth_data->sc->names[0] = talloc_strdup(auth_data->sc->names, SC1_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[0]);
    auth_data->sc->cert_instructions[0] = talloc_strdup(auth_data->sc->cert_instructions, SC1_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[0]);
    auth_data->sc->module_names[0] = talloc_strdup(auth_data->sc->module_names, SC1_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[0]);
    auth_data->sc->key_ids[0] = talloc_strdup(auth_data->sc->key_ids, SC1_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[0]);
    auth_data->sc->labels[0] = talloc_strdup(auth_data->sc->labels, SC1_LABEL);
    assert_non_null(auth_data->sc->labels[0]);
    auth_data->sc->names[1] = talloc_strdup(auth_data->sc->names, SC2_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[1]);
    auth_data->sc->cert_instructions[1] = talloc_strdup(auth_data->sc->cert_instructions, SC2_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[1]);
    auth_data->sc->module_names[1] = talloc_strdup(auth_data->sc->module_names, SC2_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[1]);
    auth_data->sc->key_ids[1] = talloc_strdup(auth_data->sc->key_ids, SC2_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[1]);
    auth_data->sc->labels[1] = talloc_strdup(auth_data->sc->labels, SC2_LABEL);
    assert_non_null(auth_data->sc->labels[1]);
    auth_data->sc->names[2] = NULL;
    auth_data->sc->pin_prompt = discard_const(SC_PIN_PROMPT);

    will_return(__wrap_json_array_append_new, false);
    will_return(__wrap_json_array_append_new, false);

    ret = json_format_mechanisms(auth_data, &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_SC2);

    json_decref(mechs);
    free(string);
    talloc_free(auth_data->sc->names[0]);
    talloc_free(auth_data->sc->cert_instructions[0]);
    talloc_free(auth_data->sc->module_names[0]);
    talloc_free(auth_data->sc->key_ids[0]);
    talloc_free(auth_data->sc->labels[0]);
    talloc_free(auth_data->sc->names[1]);
    talloc_free(auth_data->sc->cert_instructions[1]);
    talloc_free(auth_data->sc->module_names[1]);
    talloc_free(auth_data->sc->key_ids[1]);
    talloc_free(auth_data->sc->labels[1]);
}

void test_json_format_mechanisms_passkey(void **state)
{
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    json_t *mechs = NULL;
    char *string;
    int ret;

    auth_data->passkey->enabled = true;
    auth_data->passkey->init_prompt = discard_const(PASSKEY_INIT_PROMPT);
    auth_data->passkey->key_connected = true;
    auth_data->passkey->pin_request = true;
    auth_data->passkey->pin_attempts = 8;
    auth_data->passkey->pin_prompt = discard_const(PASSKEY_PIN_PROMPT);
    auth_data->passkey->touch_prompt = discard_const(PASSKEY_TOUCH_PROMPT);
    auth_data->passkey->kerberos = false;
    auth_data->passkey->crypto_challenge = discard_const("");

    ret = json_format_mechanisms(auth_data, &mechs);
    assert_int_equal(ret, EOK);

    string = json_dumps(mechs, 0);
    assert_string_equal(string, MECHANISMS_PASSKEY);

    json_decref(mechs);
    free(string);
}

void test_json_format_priority_all(void **state)
{
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    json_t *priority = NULL;
    char *string;
    int ret;

    auth_data->pswd->enabled = true;
    auth_data->oauth2->enabled = true;
    auth_data->sc->enabled = true;
    auth_data->sc->names[0] = talloc_strdup(auth_data->sc->names, SC1_LABEL);
    assert_non_null(auth_data->sc->names[0]);
    auth_data->sc->names[1] = talloc_strdup(auth_data->sc->names, SC2_LABEL);
    assert_non_null(auth_data->sc->names[1]);
    auth_data->sc->names[2] = NULL;
    auth_data->passkey->enabled = true;

    will_return_count(__wrap_json_array_append_new, false, 4);
    ret = json_format_priority(auth_data, &priority);
    assert_int_equal(ret, EOK);

    string = json_dumps(priority, 0);
    assert_string_equal(string, PRIORITY_ALL);

    json_decref(priority);
    free(string);
    talloc_free(auth_data->sc->names[0]);
    talloc_free(auth_data->sc->names[1]);
}

void test_json_format_auth_selection_password(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    auth_data->pswd->enabled = true;
    auth_data->pswd->prompt = discard_const(PASSWORD_PROMPT);

    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, auth_data, &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_PASSWORD);

    talloc_free(test_ctx);
}

void test_json_format_auth_selection_oauth2(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    auth_data->oauth2->enabled = true;
    auth_data->oauth2->uri = discard_const(OAUTH2_URI);
    auth_data->oauth2->code = discard_const(OAUTH2_CODE);
    auth_data->oauth2->init_prompt = discard_const(OAUTH2_INIT_PROMPT);
    auth_data->oauth2->link_prompt = discard_const(OAUTH2_LINK_PROMPT);

    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, auth_data, &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_OAUTH2);

    talloc_free(test_ctx);
}

void test_json_format_auth_selection_sc(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    auth_data->sc->enabled = true;
    auth_data->sc->names[0] = talloc_strdup(auth_data->sc->names, SC1_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[0]);
    auth_data->sc->cert_instructions[0] = talloc_strdup(auth_data->sc->cert_instructions, SC1_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[0]);
    auth_data->sc->module_names[0] = talloc_strdup(auth_data->sc->module_names, SC1_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[0]);
    auth_data->sc->key_ids[0] = talloc_strdup(auth_data->sc->key_ids, SC1_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[0]);
    auth_data->sc->labels[0] = talloc_strdup(auth_data->sc->labels, SC1_LABEL);
    assert_non_null(auth_data->sc->labels[0]);
    auth_data->sc->names[1] = talloc_strdup(auth_data->sc->names, SC2_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[1]);
    auth_data->sc->cert_instructions[1] = talloc_strdup(auth_data->sc->cert_instructions, SC2_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[1]);
    auth_data->sc->module_names[1] = talloc_strdup(auth_data->sc->module_names, SC2_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[1]);
    auth_data->sc->key_ids[1] = talloc_strdup(auth_data->sc->key_ids, SC2_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[1]);
    auth_data->sc->labels[1] = talloc_strdup(auth_data->sc->labels, SC2_LABEL);
    assert_non_null(auth_data->sc->labels[1]);
    auth_data->sc->names[2] = NULL;
    auth_data->sc->pin_prompt = discard_const(SC_PIN_PROMPT);

    will_return(__wrap_json_array_append_new, false);
    will_return(__wrap_json_array_append_new, false);
    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, auth_data, &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_SC);

    talloc_free(auth_data->sc->names[0]);
    talloc_free(auth_data->sc->cert_instructions[0]);
    talloc_free(auth_data->sc->module_names[0]);
    talloc_free(auth_data->sc->key_ids[0]);
    talloc_free(auth_data->sc->labels[0]);
    talloc_free(auth_data->sc->names[1]);
    talloc_free(auth_data->sc->cert_instructions[1]);
    talloc_free(auth_data->sc->module_names[1]);
    talloc_free(auth_data->sc->key_ids[1]);
    talloc_free(auth_data->sc->labels[1]);
    talloc_free(test_ctx);
}

void test_json_format_auth_selection_passkey(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    auth_data->passkey->enabled = true;
    auth_data->passkey->init_prompt = discard_const(PASSKEY_INIT_PROMPT);
    auth_data->passkey->key_connected = true;
    auth_data->passkey->pin_request = true;
    auth_data->passkey->pin_attempts = 8;
    auth_data->passkey->pin_prompt = discard_const(PASSKEY_PIN_PROMPT);
    auth_data->passkey->touch_prompt = discard_const(PASSKEY_TOUCH_PROMPT);
    auth_data->passkey->kerberos = false;
    auth_data->passkey->crypto_challenge = discard_const("");

    will_return(__wrap_json_array_append_new, false);
    ret = json_format_auth_selection(test_ctx, auth_data, &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_PASSKEY);

    talloc_free(test_ctx);
}

void test_json_format_auth_selection_all(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    auth_data->pswd->enabled = true;
    auth_data->pswd->prompt = discard_const(PASSWORD_PROMPT);
    auth_data->oauth2->enabled = true;
    auth_data->oauth2->uri = discard_const(OAUTH2_URI);
    auth_data->oauth2->code = discard_const(OAUTH2_CODE);
    auth_data->oauth2->init_prompt = discard_const(OAUTH2_INIT_PROMPT);
    auth_data->oauth2->link_prompt = discard_const(OAUTH2_LINK_PROMPT);
    auth_data->sc->enabled = true;
    auth_data->sc->names[0] = talloc_strdup(auth_data->sc->names, SC1_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[0]);
    auth_data->sc->cert_instructions[0] = talloc_strdup(auth_data->sc->cert_instructions, SC1_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[0]);
    auth_data->sc->module_names[0] = talloc_strdup(auth_data->sc->module_names, SC1_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[0]);
    auth_data->sc->key_ids[0] = talloc_strdup(auth_data->sc->key_ids, SC1_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[0]);
    auth_data->sc->labels[0] = talloc_strdup(auth_data->sc->labels, SC1_LABEL);
    assert_non_null(auth_data->sc->labels[0]);
    auth_data->sc->names[1] = talloc_strdup(auth_data->sc->names, SC2_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[1]);
    auth_data->sc->cert_instructions[1] = talloc_strdup(auth_data->sc->cert_instructions, SC2_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[1]);
    auth_data->sc->module_names[1] = talloc_strdup(auth_data->sc->module_names, SC2_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[1]);
    auth_data->sc->key_ids[1] = talloc_strdup(auth_data->sc->key_ids, SC2_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[1]);
    auth_data->sc->labels[1] = talloc_strdup(auth_data->sc->labels, SC2_LABEL);
    assert_non_null(auth_data->sc->labels[1]);
    auth_data->sc->names[2] = NULL;
    auth_data->sc->pin_prompt = discard_const(SC_PIN_PROMPT);
    auth_data->passkey->enabled = true;
    auth_data->passkey->init_prompt = discard_const(PASSKEY_INIT_PROMPT);
    auth_data->passkey->key_connected = true;
    auth_data->passkey->pin_request = true;
    auth_data->passkey->pin_attempts = 8;
    auth_data->passkey->pin_prompt = discard_const(PASSKEY_PIN_PROMPT);
    auth_data->passkey->touch_prompt = discard_const(PASSKEY_TOUCH_PROMPT);
    auth_data->passkey->kerberos = false;
    auth_data->passkey->crypto_challenge = discard_const("");

    will_return_count(__wrap_json_array_append_new, false, 6);
    ret = json_format_auth_selection(test_ctx, auth_data, &json_msg);
    assert_int_equal(ret, EOK);
    assert_string_equal(json_msg, AUTH_SELECTION_ALL);

    talloc_free(auth_data->sc->names[0]);
    talloc_free(auth_data->sc->cert_instructions[0]);
    talloc_free(auth_data->sc->module_names[0]);
    talloc_free(auth_data->sc->key_ids[0]);
    talloc_free(auth_data->sc->labels[0]);
    talloc_free(auth_data->sc->names[1]);
    talloc_free(auth_data->sc->cert_instructions[1]);
    talloc_free(auth_data->sc->module_names[1]);
    talloc_free(auth_data->sc->key_ids[1]);
    talloc_free(auth_data->sc->labels[1]);
    talloc_free(test_ctx);
}

void test_json_format_auth_selection_failure(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct auth_data *auth_data = talloc_get_type_abort(*state, struct auth_data);
    char *json_msg = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    auth_data->pswd->enabled = true;
    auth_data->pswd->prompt = discard_const(PASSWORD_PROMPT);
    auth_data->oauth2->enabled = true;
    auth_data->oauth2->uri = discard_const(OAUTH2_URI);
    auth_data->oauth2->code = discard_const(OAUTH2_CODE);
    auth_data->oauth2->init_prompt = discard_const(OAUTH2_INIT_PROMPT);
    auth_data->oauth2->link_prompt = discard_const(OAUTH2_LINK_PROMPT);
    auth_data->sc->enabled = true;
    auth_data->sc->names[0] = talloc_strdup(auth_data->sc->names, SC1_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[0]);
    auth_data->sc->cert_instructions[0] = talloc_strdup(auth_data->sc->cert_instructions, SC1_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[0]);
    auth_data->sc->module_names[0] = talloc_strdup(auth_data->sc->module_names, SC1_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[0]);
    auth_data->sc->key_ids[0] = talloc_strdup(auth_data->sc->key_ids, SC1_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[0]);
    auth_data->sc->labels[0] = talloc_strdup(auth_data->sc->labels, SC1_LABEL);
    assert_non_null(auth_data->sc->labels[0]);
    auth_data->sc->names[1] = talloc_strdup(auth_data->sc->names, SC2_TOKEN_NAME);
    assert_non_null(auth_data->sc->names[1]);
    auth_data->sc->cert_instructions[1] = talloc_strdup(auth_data->sc->cert_instructions, SC2_PROMPT_STR);
    assert_non_null(auth_data->sc->cert_instructions[1]);
    auth_data->sc->module_names[1] = talloc_strdup(auth_data->sc->module_names, SC2_MODULE_NAME);
    assert_non_null(auth_data->sc->module_names[1]);
    auth_data->sc->key_ids[1] = talloc_strdup(auth_data->sc->key_ids, SC2_KEY_ID);
    assert_non_null(auth_data->sc->key_ids[1]);
    auth_data->sc->labels[1] = talloc_strdup(auth_data->sc->labels, SC2_LABEL);
    assert_non_null(auth_data->sc->labels[1]);
    auth_data->sc->names[2] = NULL;
    auth_data->sc->pin_prompt = discard_const(SC_PIN_PROMPT);

    will_return(__wrap_json_array_append_new, true);
    ret = json_format_auth_selection(test_ctx, auth_data, &json_msg);
    assert_int_equal(ret, ENOMEM);
    assert_null(json_msg);

    talloc_free(auth_data->sc->names[0]);
    talloc_free(auth_data->sc->cert_instructions[0]);
    talloc_free(auth_data->sc->module_names[0]);
    talloc_free(auth_data->sc->key_ids[0]);
    talloc_free(auth_data->sc->labels[0]);
    talloc_free(auth_data->sc->names[1]);
    talloc_free(auth_data->sc->cert_instructions[1]);
    talloc_free(auth_data->sc->module_names[1]);
    talloc_free(auth_data->sc->key_ids[1]);
    talloc_free(auth_data->sc->labels[1]);
    talloc_free(test_ctx);
}

void test_generate_json_message_integration(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    struct prompt_config **pc_list = NULL;
    const char *prompt_pin = "true";
    int len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);

    ret = pam_add_response(pd, SSS_PASSWORD_PROMPTING, 0, NULL);
    assert_int_equal(ret, EOK);
    len = strlen(OAUTH2_URI)+1+strlen(OAUTH2_URI_COMP)+1+strlen(OAUTH2_CODE)+1;
    ret = pam_add_response(pd, SSS_PAM_OAUTH2_INFO, len,
                           discard_const(OAUTH2_STR));
    assert_int_equal(ret, EOK);
    len = strlen(SC1_CERT_USER)+1+strlen(SC1_TOKEN_NAME)+1+
          strlen(SC1_MODULE_NAME)+1+strlen(SC1_KEY_ID)+1+strlen(SC1_LABEL)+1+
          strlen(SC1_PROMPT_STR)+1+strlen(SC1_PAM_CERT_USER)+1;
    ret = pam_add_response(pd, SSS_PAM_CERT_INFO, len, discard_const(SC1_STR));
    assert_int_equal(ret, EOK);
    len = strlen(SC2_CERT_USER)+1+strlen(SC2_TOKEN_NAME)+1+
          strlen(SC2_MODULE_NAME)+1+strlen(SC2_KEY_ID)+1+strlen(SC2_LABEL)+1+
          strlen(SC2_PROMPT_STR)+1+strlen(SC2_PAM_CERT_USER)+1;
    ret = pam_add_response(pd, SSS_PAM_CERT_INFO, len, discard_const(SC2_STR));
    assert_int_equal(ret, EOK);
    ret = pam_add_response(pd, SSS_CERT_AUTH_PROMPTING, 0, NULL);
    assert_int_equal(ret, EOK);
    len = strlen(prompt_pin)+1;
    ret = pam_add_response(pd, SSS_PAM_PASSKEY_INFO, len,
                           discard_const(prompt_pin));

    will_return_count(__wrap_json_array_append_new, false, 6);
    ret = generate_json_auth_message(NULL, pc_list, pd);
    assert_int_equal(ret, EOK);
    assert_string_equal((char*) pd->resp_list->data, AUTH_SELECTION_ALL);

    pc_list_free(pc_list);
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

void test_json_unpack_smartcard_ok(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    json_t *jroot = NULL;
    const char *pin = NULL;
    struct cert_auth_info *cai = NULL;
    json_error_t jret;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    jroot = json_loads(SMARTCARD_CONTENT, 0, &jret);
    assert_non_null(jroot);

    ret = json_unpack_smartcard(test_ctx, jroot, &pin, &cai);
    assert_int_equal(ret, EOK);
    assert_string_equal(pin, "ThePIN");
    assert_string_equal(cai->token_name, "token_name1");
    assert_string_equal(cai->module_name, "module_name1");
    assert_string_equal(cai->key_id, "key_id1");
    assert_string_equal(cai->label, "label1");
    json_decref(jroot);

    talloc_free(test_ctx);
}

void test_json_unpack_passkey_ok(void **state)
{
    json_t *jroot = NULL;
    const char *pin = NULL;
    char *crypto_challenge = NULL;
    bool kerberos = false;
    json_error_t jret;
    int ret;

    jroot = json_loads(PASSKEY_CONTENT, 0, &jret);
    assert_non_null(jroot);

    ret = json_unpack_passkey(jroot, &pin, &kerberos, &crypto_challenge);
    assert_int_equal(ret, EOK);
    assert_string_equal(pin, "ThePIN");
    assert_int_equal(kerberos, true);
    assert_string_equal(crypto_challenge, PASSKEY_CRYPTO_CHAL);
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
    const char *code = NULL;
    size_t len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->authtok = sss_authtok_new(pd);
    assert_non_null(pd->authtok);
    pd->json_auth_msg = discard_const(AUTH_SELECTION_OAUTH2);
    pd->json_auth_selected = discard_const(AUTH_MECH_REPLY_OAUTH2);

    ret = json_unpack_auth_reply(pd);
    assert_int_equal(ret, EOK);
    assert_int_equal(sss_authtok_get_type(pd->authtok), SSS_AUTHTOK_TYPE_OAUTH2);
    sss_authtok_get_oauth2(pd->authtok, &code, &len);
    assert_string_equal(code, OAUTH2_CODE);

    talloc_free(test_ctx);
}

void test_json_unpack_auth_reply_sc1(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    const char *pin = NULL;
    const char *token_name = NULL;
    const char *module_name = NULL;
    const char *key_id = NULL;
    const char *label = NULL;
    size_t pin_len, token_name_len, module_name_len, key_id_len, label_len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->authtok = sss_authtok_new(pd);
    assert_non_null(pd->authtok);
    pd->json_auth_selected = discard_const(AUTH_MECH_REPLY_SMARTCARD);

    ret = json_unpack_auth_reply(pd);
    assert_int_equal(ret, EOK);
    assert_int_equal(sss_authtok_get_type(pd->authtok), SSS_AUTHTOK_TYPE_SC_PIN);
    ret = sss_authtok_get_sc(pd->authtok, &pin, &pin_len,
                             &token_name, &token_name_len,
                             &module_name, &module_name_len,
                             &key_id, &key_id_len,
                             &label, &label_len);
    assert_int_equal(ret, EOK);
    assert_string_equal(pin, "ThePIN");
    assert_string_equal(token_name, SC1_TOKEN_NAME);
    assert_string_equal(module_name, SC1_MODULE_NAME);
    assert_string_equal(key_id, SC1_KEY_ID);
    assert_string_equal(label, SC1_LABEL);

    talloc_free(test_ctx);
}

void test_json_unpack_auth_reply_sc2(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    const char *pin = NULL;
    const char *token_name = NULL;
    const char *module_name = NULL;
    const char *key_id = NULL;
    const char *label = NULL;
    size_t pin_len, token_name_len, module_name_len, key_id_len, label_len;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->authtok = sss_authtok_new(pd);
    assert_non_null(pd->authtok);
    pd->json_auth_selected = discard_const(AUTH_MECH_REPLY_SMARTCARD);

    ret = json_unpack_auth_reply(pd);
    assert_int_equal(ret, EOK);
    assert_int_equal(sss_authtok_get_type(pd->authtok), SSS_AUTHTOK_TYPE_SC_PIN);
    ret = sss_authtok_get_sc(pd->authtok, &pin, &pin_len,
                             &token_name, &token_name_len,
                             &module_name, &module_name_len,
                             &key_id, &key_id_len,
                             &label, &label_len);
    assert_int_equal(ret, EOK);
    assert_string_equal(pin, "ThePIN");
    assert_string_equal(token_name, SC1_TOKEN_NAME);
    assert_string_equal(module_name, SC1_MODULE_NAME);
    assert_string_equal(key_id, SC1_KEY_ID);
    assert_string_equal(label, SC1_LABEL);

    talloc_free(test_ctx);
}

void test_json_unpack_auth_reply_passkey(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct pam_data *pd = NULL;
    const char *pin = NULL;
    size_t len = 0;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(pd);
    pd->authtok = sss_authtok_new(pd);
    assert_non_null(pd->authtok);
    pd->json_auth_msg = discard_const(AUTH_SELECTION_PASSKEY);
    pd->json_auth_selected = discard_const(AUTH_MECH_REPLY_PASSKEY);

    ret = json_unpack_auth_reply(pd);
    assert_int_equal(ret, EOK);
    assert_int_equal(sss_authtok_get_type(pd->authtok), SSS_AUTHTOK_TYPE_PASSKEY_KRB);
    sss_authtok_get_passkey_pin(pd->authtok, &pin, &len);
    assert_string_equal(pin, "ThePIN");

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

    talloc_free(test_ctx);
}

void test_json_unpack_oauth2_code(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    char *oauth2_code = NULL;
    int ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    ret = json_unpack_oauth2_code(test_ctx, discard_const(AUTH_SELECTION_ALL),
                                  &oauth2_code);
    assert_int_equal(ret, EOK);
    assert_string_equal(oauth2_code, OAUTH2_CODE);

    talloc_free(test_ctx);
}

void test_is_pam_json_enabled_service_in_list(void **state)
{
    char *json_services[] = {discard_const("sshd"), discard_const("su"),
                             discard_const("gdm-switchable-auth"), NULL};
    bool result;

    result = is_pam_json_enabled(json_services,
                                 discard_const("gdm-switchable-auth"));
    assert_int_equal(result, true);
}

void test_is_pam_json_enabled_service_not_in_list(void **state)
{
    char *json_services[] = {discard_const("sshd"), discard_const("su"),
                             discard_const("gdm-switchable-auth"), NULL};
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
        cmocka_unit_test(test_get_cert_list),
        cmocka_unit_test_setup_teardown(test_get_cert_data, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_mechanisms_password, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_mechanisms_oauth2, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_mechanisms_sc1, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_mechanisms_sc2, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_mechanisms_passkey, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_priority_all, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_auth_selection_password, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_auth_selection_oauth2, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_auth_selection_sc, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_auth_selection_passkey, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_auth_selection_all, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_format_auth_selection_failure, setup, teardown),
#ifdef BUILD_PASSKEY
        cmocka_unit_test(test_generate_json_message_integration),
#endif
        cmocka_unit_test(test_json_unpack_password_ok),
        cmocka_unit_test(test_json_unpack_smartcard_ok),
        cmocka_unit_test(test_json_unpack_passkey_ok),
        cmocka_unit_test(test_json_unpack_auth_reply_password),
        cmocka_unit_test(test_json_unpack_auth_reply_oauth2),
        cmocka_unit_test(test_json_unpack_auth_reply_sc1),
        cmocka_unit_test(test_json_unpack_auth_reply_sc2),
        cmocka_unit_test(test_json_unpack_auth_reply_passkey),
        cmocka_unit_test(test_json_unpack_auth_reply_failure),
        cmocka_unit_test(test_json_unpack_oauth2_code),
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
