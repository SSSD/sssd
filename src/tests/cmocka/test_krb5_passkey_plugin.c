/*
    Copyright (C) 2023 Red Hat

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

#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "krb5_plugin/passkey/passkey.h"

void test_sss_passkey_message_encode__null(void **state)
{
    char *str;

    str = sss_passkey_message_encode(NULL);
    assert_null(str);
}

void test_sss_passkey_message_encode__invalid(void **state)
{
    struct sss_passkey_message message = {0};
    char *str;

    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    message.phase = SSS_PASSKEY_PHASE_REPLY;
    str = sss_passkey_message_encode(&message);
    assert_null(str);
}

void test_sss_passkey_message_encode__init(void **state)
{
    struct sss_passkey_message message = {0};
    char *str;

    message.phase = SSS_PASSKEY_PHASE_INIT;
    str = sss_passkey_message_encode(&message);
    assert_non_null(str);
    assert_string_equal(str, "passkey {\"phase\":0}");
    free(str);

    message.phase = SSS_PASSKEY_PHASE_INIT;
    message.state = discard_const("abcd");
    str = sss_passkey_message_encode(&message);
    assert_null(str);
}

void test_sss_passkey_message_encode__challenge(void **state)
{
    struct sss_passkey_message message = {0};
    struct sss_passkey_challenge challenge = {0};
    const char *id_list[] = {"a", "b", NULL};
    char *str;

    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    message.state = NULL;
    message.data.challenge = NULL;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    message.state = discard_const("abcd");
    message.data.challenge = NULL;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    challenge.domain = discard_const("domain");
    challenge.credential_id_list = discard_const(id_list);
    challenge.user_verification = 1;
    challenge.cryptographic_challenge = discard_const("crypto-challenge");
    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    message.state = NULL;
    message.data.challenge = &challenge;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    challenge.domain = NULL;
    challenge.credential_id_list = NULL;
    challenge.user_verification = 0;
    challenge.cryptographic_challenge = NULL;
    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    message.state = NULL;
    message.data.challenge = &challenge;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    challenge.domain = NULL;
    challenge.credential_id_list = discard_const(id_list);
    challenge.user_verification = 1;
    challenge.cryptographic_challenge = discard_const("crypto-challenge");
    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    message.state = discard_const("abcd");
    message.data.challenge = &challenge;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    challenge.domain = discard_const("domain");
    challenge.credential_id_list = NULL;
    challenge.user_verification = 1;
    challenge.cryptographic_challenge = discard_const("crypto-challenge");
    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    message.state = discard_const("abcd");
    message.data.challenge = &challenge;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    challenge.domain = discard_const("domain");
    challenge.credential_id_list = discard_const(id_list);
    challenge.user_verification = 1;
    challenge.cryptographic_challenge = NULL;
    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    message.state = discard_const("abcd");
    message.data.challenge = &challenge;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    challenge.domain = discard_const("domain");
    challenge.credential_id_list = discard_const(id_list);
    challenge.user_verification = 1;
    challenge.cryptographic_challenge = discard_const("crypto-challenge");
    message.phase = SSS_PASSKEY_PHASE_CHALLENGE;
    message.state = discard_const("abcd");
    message.data.challenge = &challenge;
    str = sss_passkey_message_encode(&message);
    assert_non_null(str);
    assert_string_equal(str, "passkey {\"phase\":1,\"state\":\"abcd\",\"data\":{\"domain\":\"domain\",\"credential_id_list\":[\"a\",\"b\"],\"user_verification\":1,\"cryptographic_challenge\":\"crypto-challenge\"}}");
    free(str);
}

void test_sss_passkey_message_encode__reply(void **state)
{
    struct sss_passkey_message message = {0};
    struct sss_passkey_reply reply = {0};
    char *str;

    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = NULL;
    message.data.reply = NULL;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = discard_const("abcd");
    message.data.reply = NULL;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = NULL;
    message.data.reply = &reply;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    reply.credential_id = discard_const("id");
    reply.cryptographic_challenge = discard_const("crypto-challenge");
    reply.authenticator_data = discard_const("auth-data");
    reply.assertion_signature = discard_const("assertion-sig");
    reply.user_id = NULL;
    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = NULL;
    message.data.reply = &reply;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    reply.credential_id = NULL;
    reply.cryptographic_challenge = discard_const("crypto-challenge");
    reply.authenticator_data = discard_const("auth-data");
    reply.assertion_signature = discard_const("assertion-sig");
    reply.user_id = NULL;
    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = discard_const("abcd");
    message.data.reply = &reply;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    reply.credential_id = discard_const("id");
    reply.cryptographic_challenge = NULL;
    reply.authenticator_data = discard_const("auth-data");
    reply.assertion_signature = discard_const("assertion-sig");
    reply.user_id = NULL;
    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = discard_const("abcd");
    message.data.reply = &reply;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    reply.credential_id = discard_const("id");
    reply.cryptographic_challenge = discard_const("crypto-challenge");
    reply.authenticator_data = NULL;
    reply.assertion_signature = discard_const("assertion-sig");
    reply.user_id = NULL;
    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = discard_const("abcd");
    message.data.reply = &reply;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    reply.credential_id = discard_const("id");
    reply.cryptographic_challenge = discard_const("crypto-challenge");
    reply.authenticator_data = discard_const("auth-data");
    reply.assertion_signature = NULL;
    reply.user_id = NULL;
    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = discard_const("abcd");
    message.data.reply = &reply;
    str = sss_passkey_message_encode(&message);
    assert_null(str);

    reply.credential_id = discard_const("id");
    reply.cryptographic_challenge = discard_const("crypto-challenge");
    reply.authenticator_data = discard_const("auth-data");
    reply.assertion_signature = discard_const("assertion-sig");
    reply.user_id = NULL;
    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = discard_const("abcd");
    message.data.reply = &reply;
    str = sss_passkey_message_encode(&message);
    assert_non_null(str);
    assert_string_equal(str, "passkey {\"phase\":2,\"state\":\"abcd\",\"data\":{\"credential_id\":\"id\",\"cryptographic_challenge\":\"crypto-challenge\",\"authenticator_data\":\"auth-data\",\"assertion_signature\":\"assertion-sig\"}}");
    free(str);

    reply.credential_id = discard_const("id");
    reply.cryptographic_challenge = discard_const("crypto-challenge");
    reply.authenticator_data = discard_const("auth-data");
    reply.assertion_signature = discard_const("assertion-sig");
    reply.user_id = discard_const("user-id");
    message.phase = SSS_PASSKEY_PHASE_REPLY;
    message.state = discard_const("abcd");
    message.data.reply = &reply;
    str = sss_passkey_message_encode(&message);
    assert_non_null(str);
    assert_string_equal(str, "passkey {\"phase\":2,\"state\":\"abcd\",\"data\":{\"credential_id\":\"id\",\"cryptographic_challenge\":\"crypto-challenge\",\"authenticator_data\":\"auth-data\",\"assertion_signature\":\"assertion-sig\",\"user_id\":\"user-id\"}}");
    free(str);
}

void test_sss_passkey_message_decode__null(void **state)
{
    struct sss_passkey_message *message;

    message = sss_passkey_message_decode(NULL);
    assert_null(message);
}

void test_sss_passkey_message_decode__invalid(void **state)
{
    struct sss_passkey_message *message;
    const char *str;

    str = "";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "oauth2";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":10}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":1, \"state\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":1, \"state\":\"abcd\", \"data\":{\"test\":\"test\"}}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":2, \"state\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":2, \"state\":\"abcd\", \"data\":{\"test\":\"test\"}}";
    message = sss_passkey_message_decode(str);
    assert_null(message);
}

void test_sss_passkey_message_decode__init(void **state)
{
    struct sss_passkey_message *message;
    const char *str;

    str = "passkey {\"phase\":0,\"state\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":0,\"data\":{\"test\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":0,\"state\":\"abcd\",\"data\":{\"test\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":0}";
    message = sss_passkey_message_decode(str);
    assert_non_null(message);
    assert_int_equal(message->phase, SSS_PASSKEY_PHASE_INIT);
    assert_null(message->state);
    assert_null(message->data.ptr);
    sss_passkey_message_free(message);
}

void test_sss_passkey_message_decode__challenge(void **state)
{
    struct sss_passkey_message *message;
    const char *str;

    str = "passkey {\"phase\":1}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":1,\"state\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":1,\"data\":{\"test\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":1,\"state\":\"abcd\",\"data\":{\"domain\":\"domain\",\"credential_id_list\":[\"a\",\"b\"],\"user_verification\":1,\"cryptographic_challenge\":\"crypto-challenge\"}}";
    message = sss_passkey_message_decode(str);
    assert_non_null(message);
    assert_int_equal(message->phase, SSS_PASSKEY_PHASE_CHALLENGE);
    assert_non_null(message->state);
    assert_string_equal(message->state, "abcd");
    assert_non_null(message->data.challenge);
    assert_non_null(message->data.challenge->domain);
    assert_string_equal(message->data.challenge->domain, "domain");
    assert_non_null(message->data.challenge->credential_id_list);
    assert_string_equal(message->data.challenge->credential_id_list[0], "a");
    assert_string_equal(message->data.challenge->credential_id_list[1], "b");
    assert_null(message->data.challenge->credential_id_list[2]);
    assert_int_equal(message->data.challenge->user_verification, 1);
    assert_non_null(message->data.challenge->cryptographic_challenge);
    assert_string_equal(message->data.challenge->cryptographic_challenge, "crypto-challenge");
    sss_passkey_message_free(message);
}

void test_sss_passkey_message_decode__reply(void **state)
{
    struct sss_passkey_message *message;
    const char *str;

    str = "passkey {\"phase\":2}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":2,\"state\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":2,\"data\":{\"test\":\"abcd\"}";
    message = sss_passkey_message_decode(str);
    assert_null(message);

    str = "passkey {\"phase\":2,\"state\":\"abcd\",\"data\":{\"credential_id\":\"id\",\"cryptographic_challenge\":\"crypto-challenge\",\"authenticator_data\":\"auth-data\",\"assertion_signature\":\"assertion-sig\"}}";
    message = sss_passkey_message_decode(str);
    assert_non_null(message);
    assert_int_equal(message->phase, SSS_PASSKEY_PHASE_REPLY);
    assert_non_null(message->state);
    assert_string_equal(message->state, "abcd");
    assert_non_null(message->data.reply);
    assert_non_null(message->data.reply->credential_id);
    assert_string_equal(message->data.reply->credential_id, "id");
    assert_non_null(message->data.reply->cryptographic_challenge);
    assert_string_equal(message->data.reply->cryptographic_challenge, "crypto-challenge");
    assert_non_null(message->data.reply->authenticator_data);
    assert_string_equal(message->data.reply->authenticator_data, "auth-data");
    assert_non_null(message->data.reply->assertion_signature);
    assert_string_equal(message->data.reply->assertion_signature, "assertion-sig");
    sss_passkey_message_free(message);
}

void test_sss_passkey_config_init__invalid(void **state)
{
    struct sss_passkey_config *passkeycfg;
    krb5_error_code ret;

    ret = sss_passkey_config_init("not-json", &passkeycfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_passkey_config_init("", &passkeycfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_passkey_config_init("[]", &passkeycfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_passkey_config_init("[{\"indicators\": \"test\"}]", &passkeycfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_passkey_config_init("{\"indicators\": \"test\"}", &passkeycfg);
    assert_int_equal(ret, EINVAL);
}

void test_sss_passkey_config_init__ok(void **state)
{
    struct sss_passkey_config *passkeycfg;
    krb5_error_code ret;

    ret = sss_passkey_config_init("[{}]", &passkeycfg);
    assert_int_equal(ret, 0);
    assert_non_null(passkeycfg);
    assert_null(passkeycfg->indicators);
    sss_passkey_config_free(passkeycfg);

    ret = sss_passkey_config_init("[{\"indicators\": [\"i1\"]}]", &passkeycfg);
    assert_int_equal(ret, 0);
    assert_non_null(passkeycfg);
    assert_non_null(passkeycfg->indicators);
    assert_non_null(passkeycfg->indicators[0]);
    assert_null(passkeycfg->indicators[1]);
    assert_string_equal(passkeycfg->indicators[0], "i1");
    sss_passkey_config_free(passkeycfg);

    ret = sss_passkey_config_init("[{\"indicators\": [\"i1\", \"i2\"]}]", &passkeycfg);
    assert_int_equal(ret, 0);
    assert_non_null(passkeycfg);
    assert_non_null(passkeycfg->indicators);
    assert_non_null(passkeycfg->indicators[0]);
    assert_non_null(passkeycfg->indicators[1]);
    assert_null(passkeycfg->indicators[2]);
    assert_string_equal(passkeycfg->indicators[0], "i1");
    assert_string_equal(passkeycfg->indicators[1], "i2");
    sss_passkey_config_free(passkeycfg);
}

int main(int argc, const char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sss_passkey_message_encode__null),
        cmocka_unit_test(test_sss_passkey_message_encode__invalid),
        cmocka_unit_test(test_sss_passkey_message_encode__init),
        cmocka_unit_test(test_sss_passkey_message_encode__challenge),
        cmocka_unit_test(test_sss_passkey_message_encode__reply),
        cmocka_unit_test(test_sss_passkey_message_decode__null),
        cmocka_unit_test(test_sss_passkey_message_decode__invalid),
        cmocka_unit_test(test_sss_passkey_message_decode__init),
        cmocka_unit_test(test_sss_passkey_message_decode__challenge),
        cmocka_unit_test(test_sss_passkey_message_decode__reply),
        cmocka_unit_test(test_sss_passkey_config_init__invalid),
        cmocka_unit_test(test_sss_passkey_config_init__ok),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
