/*
    SSSD

    prompt config - Utilities tests

    Authors:
        Sumit bose <sbose@redhat.com>

    Copyright (C) 2019 Red Hat

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

#include <string.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"

#include "sss_client/sss_cli.h"

void test_pc_list_add_password(void **state)
{
    int ret;
    struct prompt_config **pc_list = NULL;

    ret = pc_list_add_password(&pc_list, "Hello");
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);
    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_PASSWORD, pc_get_type(pc_list[0]));
    assert_string_equal("Hello", pc_get_password_prompt(pc_list[0]));
    assert_null(pc_list[1]);

    ret = pc_list_add_password(&pc_list, "Hello2");
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);
    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_PASSWORD, pc_get_type(pc_list[0]));
    assert_string_equal("Hello", pc_get_password_prompt(pc_list[0]));
    assert_non_null(pc_list[1]);
    assert_int_equal(PC_TYPE_PASSWORD, pc_get_type(pc_list[1]));
    assert_string_equal("Hello2", pc_get_password_prompt(pc_list[1]));
    assert_null(pc_list[2]);

    pc_list_free(pc_list);
}

void test_pc_list_add_2fa_single(void **state)
{
    int ret;
    struct prompt_config **pc_list = NULL;

    ret = pc_list_add_2fa_single(&pc_list, "Hello");
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);
    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_2FA_SINGLE, pc_get_type(pc_list[0]));
    assert_string_equal("Hello", pc_get_2fa_single_prompt(pc_list[0]));
    assert_null(pc_list[1]);

    ret = pc_list_add_2fa_single(&pc_list, "Hello2");
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);
    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_2FA_SINGLE, pc_get_type(pc_list[0]));
    assert_string_equal("Hello", pc_get_2fa_single_prompt(pc_list[0]));
    assert_non_null(pc_list[1]);
    assert_int_equal(PC_TYPE_2FA_SINGLE, pc_get_type(pc_list[1]));
    assert_string_equal("Hello2", pc_get_2fa_single_prompt(pc_list[1]));
    assert_null(pc_list[2]);

    pc_list_free(pc_list);
}

void test_pc_list_add_2fa(void **state)
{
    int ret;
    struct prompt_config **pc_list = NULL;

    ret = pc_list_add_2fa(&pc_list, "Hello", "Good Bye");
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);
    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_2FA, pc_get_type(pc_list[0]));
    assert_string_equal("Hello", pc_get_2fa_1st_prompt(pc_list[0]));
    assert_string_equal("Good Bye", pc_get_2fa_2nd_prompt(pc_list[0]));
    assert_null(pc_list[1]);

    pc_list_free(pc_list);
}

void test_pc_list_add_eidp(void **state)
{
    int ret;
    struct prompt_config **pc_list = NULL;

    ret = pc_list_add_eidp(&pc_list, "init", "link");
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);
    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_EIDP, pc_get_type(pc_list[0]));
    assert_string_equal("init", pc_get_eidp_init_prompt(pc_list[0]));
    assert_string_equal("link", pc_get_eidp_link_prompt(pc_list[0]));
    assert_null(pc_list[1]);

    pc_list_free(pc_list);
}

void test_pc_list_add_smartcard(void **state)
{
    int ret;
    struct prompt_config **pc_list = NULL;

    ret = pc_list_add_smartcard(&pc_list, "init", "PIN");
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);
    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_SMARTCARD, pc_get_type(pc_list[0]));
    assert_string_equal("init", pc_get_smartcard_init_prompt(pc_list[0]));
    assert_string_equal("PIN", pc_get_smartcard_pin_prompt(pc_list[0]));
    assert_null(pc_list[1]);

    pc_list_free(pc_list);
}

void test_pc_list_add_oauth2(void **state)
{
    int ret;
    struct prompt_config **pc_list = NULL;

    ret = pc_list_add_oauth2(&pc_list, "inter");
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);
    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_OAUTH2, pc_get_type(pc_list[0]));
    assert_string_equal("inter", pc_get_oauth2_inter_prompt(pc_list[0]));
    assert_null(pc_list[1]);

    pc_list_free(pc_list);
}

void test_pam_get_response_prompt_config(void **state)
{
    int ret;
    struct prompt_config **pc_list = NULL;
    int len;
    uint8_t *data;

    ret = pc_list_add_password(&pc_list, "password");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_2fa(&pc_list, "first", "second");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_2fa_single(&pc_list, "single");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_eidp(&pc_list, "init", "link");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_smartcard(&pc_list, "init", "PIN");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_oauth2(&pc_list, "inter");
    assert_int_equal(ret, EOK);

    ret = pam_get_response_prompt_config(pc_list, &len, &data);
    pc_list_free(pc_list);
    assert_int_equal(ret, EOK);
    assert_int_equal(len, 109);

#if __BYTE_ORDER == __LITTLE_ENDIAN
    assert_memory_equal(data, "\6\0\0\0\1\0\0\0\10\0\0\0" "password\2\0\0\0\5\0\0\0"
                        "first\6\0\0\0" "second\3\0\0\0\6\0\0\0" "single\6\0\0\0\4\0\0\0"
                        "init\4\0\0\0" "link\5\0\0\0\4\0\0\0"
                        "init\3\0\0\0" "PIN\7\0\0\0\5\0\0\0"
                        "inter", len);
#else
    assert_memory_equal(data, "\0\0\0\6\0\0\0\1\0\0\0\10" "password\0\0\0\2\0\0\0\5"
                        "first\0\0\0\6" "second\0\0\0\3\0\0\0\6" "single\0\0\0\6\0\0\0\4"
                        "init\0\0\0\4" "link\0\0\0\5\0\0\0\4"
                        "init\0\0\0\3" "PIN\0\0\0\7\0\0\0\5"
                        "inter", len);
#endif

    free(data);
}

void test_pc_list_from_response(void **state)
{
    int ret;
    struct prompt_config **pc_list = NULL;
    int len;
    uint8_t *data;

    ret = pc_list_add_password(&pc_list, "password");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_2fa(&pc_list, "first", "second");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_2fa_single(&pc_list, "single");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_eidp(&pc_list, "init", "link");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_smartcard(&pc_list, "init", "PIN");
    assert_int_equal(ret, EOK);

    ret = pc_list_add_oauth2(&pc_list, "inter");
    assert_int_equal(ret, EOK);

    ret = pam_get_response_prompt_config(pc_list, &len, &data);
    pc_list_free(pc_list);
    assert_int_equal(ret, EOK);
    assert_int_equal(len, 109);

    pc_list = NULL;

    ret = pc_list_from_response(len, data, &pc_list);
    free(data);
    assert_int_equal(ret, EOK);
    assert_non_null(pc_list);

    assert_non_null(pc_list[0]);
    assert_int_equal(PC_TYPE_PASSWORD, pc_get_type(pc_list[0]));
    assert_string_equal("password", pc_get_password_prompt(pc_list[0]));

    assert_non_null(pc_list[1]);
    assert_int_equal(PC_TYPE_2FA, pc_get_type(pc_list[1]));
    assert_string_equal("first", pc_get_2fa_1st_prompt(pc_list[1]));
    assert_string_equal("second", pc_get_2fa_2nd_prompt(pc_list[1]));

    assert_non_null(pc_list[2]);
    assert_int_equal(PC_TYPE_2FA_SINGLE, pc_get_type(pc_list[2]));
    assert_string_equal("single", pc_get_2fa_single_prompt(pc_list[2]));

    assert_non_null(pc_list[3]);
    assert_int_equal(PC_TYPE_EIDP, pc_get_type(pc_list[3]));
    assert_string_equal("init", pc_get_eidp_init_prompt(pc_list[3]));
    assert_string_equal("link", pc_get_eidp_link_prompt(pc_list[3]));

    assert_non_null(pc_list[4]);
    assert_int_equal(PC_TYPE_SMARTCARD, pc_get_type(pc_list[4]));
    assert_string_equal("init", pc_get_smartcard_init_prompt(pc_list[4]));
    assert_string_equal("PIN", pc_get_smartcard_pin_prompt(pc_list[4]));

    assert_non_null(pc_list[5]);
    assert_int_equal(PC_TYPE_OAUTH2, pc_get_type(pc_list[5]));
    assert_string_equal("inter", pc_get_oauth2_inter_prompt(pc_list[5]));

    assert_null(pc_list[6]);

    pc_list_free(pc_list);
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
        cmocka_unit_test(test_pc_list_add_password),
        cmocka_unit_test(test_pc_list_add_2fa_single),
        cmocka_unit_test(test_pc_list_add_2fa),
        cmocka_unit_test(test_pc_list_add_eidp),
        cmocka_unit_test(test_pc_list_add_smartcard),
        cmocka_unit_test(test_pc_list_add_oauth2),
        cmocka_unit_test(test_pam_get_response_prompt_config),
        cmocka_unit_test(test_pc_list_from_response),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
