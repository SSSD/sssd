/*
    Copyright (C) 2020 Red Hat

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
#include "krb5_plugin/idp/idp.h"

void test_sss_idp_oauth2_encode_challenge__null(void **state)
{
    struct sss_idp_oauth2 data = {0};
    char *str;

    str = sss_idp_oauth2_encode_challenge(NULL);
    assert_null(str);

    str = sss_idp_oauth2_encode_challenge(&data);
    assert_null(str);
}

void test_sss_idp_oauth2_encode_challenge__ok(void **state)
{
    struct sss_idp_oauth2 data = {0};
    char *str;

    /* Empty required data. */
    data.verification_uri = NULL;
    data.user_code = NULL;
    str = sss_idp_oauth2_encode_challenge(&data);
    assert_null(str);

    data.verification_uri = discard_const("https://visit.me");
    data.user_code = NULL;
    str = sss_idp_oauth2_encode_challenge(&data);
    assert_null(str);

    data.verification_uri = NULL;
    data.user_code = discard_const("123456");
    str = sss_idp_oauth2_encode_challenge(&data);
    assert_null(str);

    /* Empty optional data. */
    data.verification_uri = discard_const("https://visit.me");
    data.verification_uri_complete = NULL;
    data.user_code = discard_const("123456");
    str = sss_idp_oauth2_encode_challenge(&data);
    assert_non_null(str);
    assert_string_equal(str, "oauth2 {\"verification_uri\":\"https://visit.me\",\"user_code\":\"123456\"}");
    free(str);

    /* Full format. */
    data.verification_uri = discard_const("https://visit.me");
    data.verification_uri_complete = discard_const("https://visit.me?code=123456");
    data.user_code = discard_const("123456");
    str = sss_idp_oauth2_encode_challenge(&data);
    assert_non_null(str);
    assert_string_equal(str, "oauth2 {\"verification_uri\":\"https://visit.me\",\"verification_uri_complete\":\"https://visit.me?code=123456\",\"user_code\":\"123456\"}");
    free(str);
}

void test_sss_idp_oauth2_decode_challenge__invalid(void **state)
{
    struct sss_idp_oauth2 *data;

    data = sss_idp_oauth2_decode_challenge("not-json");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("{}");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("[]");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("[{}]");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("{\"verification_uri\": \"test\", \"user_code\": \"test\"}");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("oauth2 ");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("oauth2 {}");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("oauth2 []");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("oauth2 [{}]");
    assert_null(data);
}

void test_sss_idp_oauth2_decode_challenge__ok(void **state)
{
    struct sss_idp_oauth2 *data;

    /* Empty required data. */
    data = sss_idp_oauth2_decode_challenge("oauth2 {\"verification_uri_complete\": \"https://visit.me?code=123456\",\"user_code\": \"123456\"}");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("oauth2 {\"verification_uri\": \"https://visit.me\",\"verification_uri_complete\": \"https://visit.me?code=123456\"}");
    assert_null(data);

    data = sss_idp_oauth2_decode_challenge("oauth2 {\"verification_uri_complete\": \"https://visit.me?code=123456\"}");
    assert_null(data);

    /* Empty optional data. */
    data = sss_idp_oauth2_decode_challenge("oauth2 {\"verification_uri\": \"https://visit.me\",\"user_code\": \"123456\"}");
    assert_non_null(data);
    assert_string_equal(data->verification_uri, "https://visit.me");
    assert_null(data->verification_uri_complete);
    assert_string_equal(data->user_code, "123456");
    sss_idp_oauth2_free(data);

    /* Full format. */
    data = sss_idp_oauth2_decode_challenge("oauth2 {\"verification_uri\": \"https://visit.me\",\"verification_uri_complete\": \"https://visit.me?code=123456\",\"user_code\": \"123456\"}");
    assert_non_null(data);
    assert_string_equal(data->verification_uri, "https://visit.me");
    assert_string_equal(data->verification_uri_complete, "https://visit.me?code=123456");
    assert_string_equal(data->user_code, "123456");
    sss_idp_oauth2_free(data);
}

void test_sss_idp_oauth2_decode_challenge__v2(void **state)
{
    struct sss_idp_oauth2 *data;
    char *str;

    /* DARC: page delivery with a confirmation code. */
    data = sss_idp_oauth2_decode_challenge("oauth2 {\"v\":2,\"delivery\":\"page\",\"verification_uri\":\"https://id.example.com/device\",\"user_code\":\"WDJB-MJHT\",\"confirmation\":{\"length\":6,\"charset\":\"numeric\"},\"expires_in\":600}");
    assert_non_null(data);
    assert_int_equal(data->version, 2);
    assert_string_equal(data->delivery, "page");
    assert_string_equal(data->user_code, "WDJB-MJHT");
    assert_int_equal(data->confirmation_length, 6);
    assert_string_equal(data->confirmation_charset, "numeric");
    assert_int_equal(data->expires_in, 600);
    assert_true(sss_idp_oauth2_needs_confirmation(data));

    /* Round trip. */
    str = sss_idp_oauth2_encode_challenge(data);
    assert_non_null(str);
    assert_string_equal(str, "oauth2 {\"v\":2,\"delivery\":\"page\",\"verification_uri\":\"https://id.example.com/device\",\"user_code\":\"WDJB-MJHT\",\"confirmation\":{\"length\":6,\"charset\":\"numeric\"},\"expires_in\":600}");
    free(str);
    sss_idp_oauth2_free(data);

    /* Version 2 without confirmation (policy "off"): behaves like v1. */
    data = sss_idp_oauth2_decode_challenge("oauth2 {\"v\":2,\"delivery\":\"page\",\"verification_uri\":\"https://id.example.com/device\",\"user_code\":\"WDJB-MJHT\"}");
    assert_non_null(data);
    assert_false(sss_idp_oauth2_needs_confirmation(data));
    sss_idp_oauth2_free(data);

    /* Authenticator delivery needs no URI, but needs a code. */
    data = sss_idp_oauth2_decode_challenge("oauth2 {\"v\":2,\"delivery\":\"authenticator\",\"confirmation\":{\"length\":6}}");
    assert_non_null(data);
    assert_null(data->verification_uri);
    assert_true(sss_idp_oauth2_needs_confirmation(data));
    sss_idp_oauth2_free(data);

    data = sss_idp_oauth2_decode_challenge("oauth2 {\"v\":2,\"delivery\":\"authenticator\"}");
    assert_null(data);

    /* A v1 payload never asks for a code. */
    data = sss_idp_oauth2_decode_challenge("oauth2 {\"verification_uri\":\"https://visit.me\",\"user_code\":\"123456\",\"confirmation\":{\"length\":6}}");
    assert_non_null(data);
    assert_int_equal(data->version, 1);
    assert_false(sss_idp_oauth2_needs_confirmation(data));
    sss_idp_oauth2_free(data);

    /* Unreasonable lengths are rejected. */
    data = sss_idp_oauth2_decode_challenge("oauth2 {\"v\":2,\"verification_uri\":\"https://x\",\"user_code\":\"A\",\"confirmation\":{\"length\":1000}}");
    assert_null(data);
}

void test_sss_idp_oauth2_confirm_padata(void **state)
{
    krb5_pa_data *padata;
    krb5_pa_data empty = {0};
    char *code;

    padata = sss_idp_oauth2_encode_confirm_padata(" 481 207 ");
    assert_non_null(padata);
    assert_int_equal(padata->pa_type, SSSD_IDP_OAUTH2_PADATA);
    assert_string_equal((char *)padata->contents, "oauth2-confirm 481207");
    assert_int_equal(padata->length, strlen("oauth2-confirm 481207") + 1);

    code = sss_idp_oauth2_decode_confirm_padata(padata);
    assert_non_null(code);
    assert_string_equal(code, "481207");
    free(code);
    free(padata->contents);
    free(padata);

    /* Nothing typed, or garbage. */
    assert_null(sss_idp_oauth2_encode_confirm_padata(""));
    assert_null(sss_idp_oauth2_encode_confirm_padata(" - "));
    assert_null(sss_idp_oauth2_encode_confirm_padata("48\x01" "1207"));
    assert_null(sss_idp_oauth2_encode_confirm_padata("123456789012345678901234567890123"));

    /* Version 1 empty PA-152 is not a confirmation. */
    empty.pa_type = SSSD_IDP_OAUTH2_PADATA;
    assert_null(sss_idp_oauth2_decode_confirm_padata(&empty));

    /* Wrong prefix, missing terminator. */
    padata = sss_idp_oauth2_encode_confirm_padata("123456");
    assert_non_null(padata);
    memcpy(padata->contents, "oauth2-nope", strlen("oauth2-nope"));
    assert_null(sss_idp_oauth2_decode_confirm_padata(padata));
    padata->length--;
    assert_null(sss_idp_oauth2_decode_confirm_padata(padata));
    free(padata->contents);
    free(padata);
}

void test_sss_idp_oauth2_accept_indicators(void **state)
{
    char **ind;

    ind = sss_idp_oauth2_decode_accept_indicators("oauth2 {\"v\":2,\"indicators\":[\"idp-confirmed\",\"otp\",\"idp-mfa\",7]}");
    assert_non_null(ind);
    assert_string_equal(ind[0], "idp-confirmed");
    assert_string_equal(ind[1], "idp-mfa");
    assert_null(ind[2]);
    free(ind[0]);
    free(ind[1]);
    free(ind);

    /* Only idp-* names may be added by the RADIUS server. */
    assert_null(sss_idp_oauth2_decode_accept_indicators("oauth2 {\"indicators\":[\"hardened\"]}"));
    assert_null(sss_idp_oauth2_decode_accept_indicators("oauth2 {}"));
    assert_null(sss_idp_oauth2_decode_accept_indicators("not oauth2"));
    assert_null(sss_idp_oauth2_decode_accept_indicators(NULL));
}

void test_sss_idp_config_init__invalid(void **state)
{
    struct sss_idp_config *idpcfg;
    krb5_error_code ret;

    ret = sss_idp_config_init("not-json", &idpcfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_idp_config_init("", &idpcfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_idp_config_init("{}", &idpcfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_idp_config_init("[]", &idpcfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_idp_config_init("[{}]", &idpcfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_idp_config_init("[{\"indicators\": [\"test\"]}]", &idpcfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_idp_config_init("[{\"type\": \"oauth2\", \"indicators\": \"test\"}]", &idpcfg);
    assert_int_equal(ret, EINVAL);
}

void test_sss_idp_config_init__unsupported_type(void **state)
{
    struct sss_idp_config *idpcfg;
    krb5_error_code ret;

    ret = sss_idp_config_init("{\"type\": null}", &idpcfg);
    assert_int_equal(ret, EINVAL);

    ret = sss_idp_config_init("{\"type\": \"notsup\"}", &idpcfg);
    assert_int_equal(ret, EINVAL);
}

void test_sss_idp_config_init__oauth2(void **state)
{
    struct sss_idp_config *idpcfg;
    krb5_error_code ret;

    ret = sss_idp_config_init("[{\"type\": \"oauth2\"}]", &idpcfg);
    assert_int_equal(ret, 0);
    assert_non_null(idpcfg);
    assert_string_equal(idpcfg->type, "oauth2");
    assert_null(idpcfg->indicators);
    sss_idp_config_free(idpcfg);

    ret = sss_idp_config_init("[{\"type\": \"oauth2\", \"indicators\": [\"i1\"]}]", &idpcfg);
    assert_int_equal(ret, 0);
    assert_non_null(idpcfg);
    assert_string_equal(idpcfg->type, "oauth2");
    assert_non_null(idpcfg->indicators);
    assert_non_null(idpcfg->indicators[0]);
    assert_null(idpcfg->indicators[1]);
    assert_string_equal(idpcfg->indicators[0], "i1");
    sss_idp_config_free(idpcfg);

    ret = sss_idp_config_init("[{\"type\": \"oauth2\", \"indicators\": [\"i1\", \"i2\"]}]", &idpcfg);
    assert_int_equal(ret, 0);
    assert_non_null(idpcfg);
    assert_string_equal(idpcfg->type, "oauth2");
    assert_non_null(idpcfg->indicators);
    assert_non_null(idpcfg->indicators[0]);
    assert_non_null(idpcfg->indicators[1]);
    assert_null(idpcfg->indicators[2]);
    assert_string_equal(idpcfg->indicators[0], "i1");
    assert_string_equal(idpcfg->indicators[1], "i2");
    sss_idp_config_free(idpcfg);
}

int main(int argc, const char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sss_idp_oauth2_encode_challenge__null),
        cmocka_unit_test(test_sss_idp_oauth2_encode_challenge__ok),
        cmocka_unit_test(test_sss_idp_oauth2_decode_challenge__invalid),
        cmocka_unit_test(test_sss_idp_oauth2_decode_challenge__ok),
        cmocka_unit_test(test_sss_idp_oauth2_decode_challenge__v2),
        cmocka_unit_test(test_sss_idp_oauth2_confirm_padata),
        cmocka_unit_test(test_sss_idp_oauth2_accept_indicators),
        cmocka_unit_test(test_sss_idp_config_init__invalid),
        cmocka_unit_test(test_sss_idp_config_init__unsupported_type),
        cmocka_unit_test(test_sss_idp_config_init__oauth2),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
