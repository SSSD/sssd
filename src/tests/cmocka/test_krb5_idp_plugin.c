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
        cmocka_unit_test(test_sss_idp_config_init__invalid),
        cmocka_unit_test(test_sss_idp_config_init__unsupported_type),
        cmocka_unit_test(test_sss_idp_config_init__oauth2),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
