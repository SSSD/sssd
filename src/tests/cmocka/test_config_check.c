/*
    Authors:
        Michal Zidek <mzidek@redhat.com>

    Copyright (C) 2017 Red Hat

    Config file validators test

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
#include <talloc.h>
#include <ini_configobj.h>

#include "util/sss_ini.h"
#include "tests/cmocka/common_mock.h"

#define RULES_PATH ABS_SRC_DIR"/src/config/cfg_rules.ini"

struct sss_ini {
    char **error_list;
    struct ref_array *ra_success_list;
    struct ref_array *ra_error_list;
    struct ini_cfgobj *sssd_config;
    struct value_obj *obj;
    const struct stat *cstat;
    struct ini_cfgfile *file;
    bool main_config_exists;
};

void config_check_test_common(const char *cfg_string,
                              size_t num_errors_expected,
                              const char **errors_expected)
{
    struct sss_ini *init_data;
    size_t num_errors;
    char **strs;
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    init_data = sss_ini_new(tmp_ctx);

    ret = sss_ini_open(init_data, NULL, cfg_string);
    assert_int_equal(ret, EOK);

    ret = ini_config_create(&(init_data->sssd_config));
    assert_int_equal(ret, EOK);

    ret = ini_config_parse(init_data->file,
                           INI_STOP_ON_ANY,
                           INI_MV1S_OVERWRITE,
                           INI_PARSE_NOWRAP,
                           init_data->sssd_config);
    assert_int_equal(ret, EOK);

    ret = sss_ini_call_validators_strs(tmp_ctx, init_data,
                                       RULES_PATH,
                                       &strs, &num_errors);
    assert_int_equal(ret, EOK);

    /* Output from validators */
    for (int i = 0; i < num_errors; i++) {
        /* Keep this printf loop for faster debugging */
        printf("%s\n", strs[i]);
    }
    assert_int_equal(num_errors, num_errors_expected);

    for (int i = 0; i < num_errors && i <= num_errors_expected; i++) {
        assert_string_equal(strs[i], errors_expected[i]);
    }

    /* Check if the number of errors is the same */
    assert_int_equal(num_errors_expected, num_errors);

    talloc_free(tmp_ctx);
}

void config_check_test_bad_section_name(void **state)
{
    char cfg_str[] = "[sssssssssssssd]";
    const char *expected_errors[] = {
        "[rule/allowed_sections]: Section [sssssssssssssd] is not allowed. "
        "Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_chars_in_section_name(void **state)
{
    char cfg_str[] = "[domain/LD@P]\n"
                     "id_provider = ldap\n";
    const char *expected_errors[] = {
        "[rule/allowed_sections]: Section [domain/LD@P] is not allowed. "
        "Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_too_many_subdomains(void **state)
{
    char cfg_str[] = "[domain/ad.test/b.test/c.test]";
    const char *expected_errors[] = {
        "[rule/allowed_sections]: Section [domain/ad.test/b.test/c.test] is not allowed. "
        "Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_sssd_option_name(void **state)
{
    char cfg_str[] = "[sssd]\n"
                     "debug_leTYPOvel = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_sssd_options]: Attribute 'debug_leTYPOvel' is not "
        "allowed in section 'sssd'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_pam_option_name(void **state)
{
    char cfg_str[] = "[pam]\n"
                     "debug_leTYPOvel = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_pam_options]: Attribute 'debug_leTYPOvel' is not "
        "allowed in section 'pam'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_nss_option_name(void **state)
{
    char cfg_str[] = "[nss]\n"
                     "debug_leTYPOvel = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_nss_options]: Attribute 'debug_leTYPOvel' is not "
        "allowed in section 'nss'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_pac_option_name(void **state)
{
    char cfg_str[] = "[pac]\n"
                     "debug_leTYPOvel = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_pac_options]: Attribute 'debug_leTYPOvel' is not "
        "allowed in section 'pac'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_ifp_option_name(void **state)
{
    char cfg_str[] = "[ifp]\n"
                     "debug_leTYPOvel = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_ifp_options]: Attribute 'debug_leTYPOvel' is not "
        "allowed in section 'ifp'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_domain_option_name(void **state)
{
    char cfg_str[] = "[domain/A.test]\n"
                     "debug_leTYPOvel = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_subdomain_options]: Attribute 'debug_leTYPOvel' is not "
        "allowed in section 'domain/A.test'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_appdomain_option_name(void **state)
{
    char cfg_str[] = "[application/myapp]\n"
                     "debug_leTYPOvel = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_domain_options]: Attribute 'debug_leTYPOvel' is not "
        "allowed in section 'application/myapp'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_subdom_option_name(void **state)
{
    char cfg_str[] = "[domain/A.test/B.A.test]\n"
                     "debug_leTYPOvel = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_subdomain_options]: Attribute 'debug_leTYPOvel' is not "
        "allowed in section 'domain/A.test/B.A.test'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_bad_certmap_option_name(void **state)
{
    char cfg_str[] = "[certmap/files/testuser]\n"
                     "debug_level = 10\n";
    const char *expected_errors[] = {
        "[rule/allowed_certmap_options]: Attribute 'debug_level' is not "
        "allowed in section 'certmap/files/testuser'. Check for typos.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_good_sections(void **state)
{
    char cfg_str[] = "[sssd]\n"
                     "[pam]\n"
                     "[nss]\n"
                     "[domain/testdom.test]\n"
                     "id_provider = proxy\n"
                     "[domain/testdom.test/testsubdom.testdom.test]\n"
                     "[application/myapp]\n"
                     "[ssh]\n"
                     "[ifp]\n"
                     "[pac]\n"
                     "[certmap/files/testuser]\n";
    const char *expected_errors[] = { NULL };

    config_check_test_common(cfg_str, 0, expected_errors);
}

void config_check_test_missing_id_provider(void **state)
{
    char cfg_str[] = "[domain/A.test]\n";
    const char *expected_errors[] = {
        "[rule/sssd_checks]: Attribute 'id_provider' is missing in "
        "section 'domain/A.test'.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_inherit_from_in_normal_dom(void **state)
{
    char cfg_str[] = "[domain/A.test]\n"
                     "id_provider = proxy\n"
                     "inherit_from = domain\n";
    const char *expected_errors[] = {
        "[rule/sssd_checks]: Attribute 'inherit_from' is not allowed in "
        "section 'domain/A.test'.",
    };

    config_check_test_common(cfg_str, 1, expected_errors);
}

void config_check_test_inherit_from_in_app_dom(void **state)
{
    char cfg_str[] = "[application/A.test]\n"
                     "inherit_from = domain\n";
    const char *expected_errors[] = { NULL };

    config_check_test_common(cfg_str, 0, expected_errors);
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
        cmocka_unit_test(config_check_test_bad_section_name),
        cmocka_unit_test(config_check_test_bad_chars_in_section_name),
        cmocka_unit_test(config_check_test_too_many_subdomains),
        cmocka_unit_test(config_check_test_bad_sssd_option_name),
        cmocka_unit_test(config_check_test_bad_pam_option_name),
        cmocka_unit_test(config_check_test_bad_nss_option_name),
        cmocka_unit_test(config_check_test_bad_pac_option_name),
        cmocka_unit_test(config_check_test_bad_ifp_option_name),
        cmocka_unit_test(config_check_test_bad_appdomain_option_name),
        cmocka_unit_test(config_check_test_bad_subdom_option_name),
        cmocka_unit_test(config_check_test_bad_certmap_option_name),
        cmocka_unit_test(config_check_test_good_sections),
        cmocka_unit_test(config_check_test_missing_id_provider),
        cmocka_unit_test(config_check_test_inherit_from_in_normal_dom),
        cmocka_unit_test(config_check_test_inherit_from_in_app_dom),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
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

    DEBUG_CLI_INIT(debug_level);
    tests_set_cwd();
    return cmocka_run_group_tests(tests, NULL, NULL);
}
