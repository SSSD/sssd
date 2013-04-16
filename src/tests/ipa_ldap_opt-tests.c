/*
   SSSD

   Tests if IPA and LDAP backend options are in sync

   Authors:
       Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) 2010 Red Hat

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

#include <check.h>
#include <stdlib.h>
#include <talloc.h>

#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_opts.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/krb5/krb5_opts.h"
#include "providers/krb5/krb5_common.h"
#include "providers/ad/ad_opts.h"
#include "providers/dp_dyndns.h"
#include "tests/common.h"

struct test_domain {
    const char *domain;
    const char *basedn;
};

struct test_domain test_domains[] = {
    { "abc", "dc=abc"},
    { "a.b.c", "dc=a,dc=b,dc=c"},
    { "A.B.C", "dc=a,dc=b,dc=c"},
    { NULL, NULL}
};

START_TEST(test_domain_to_basedn)
{
    int ret;
    int i;
    TALLOC_CTX *tmp_ctx;
    char *basedn;

    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "talloc_new failed");

    ret = domain_to_basedn(tmp_ctx, NULL, &basedn);
    fail_unless(ret == EINVAL,
                "domain_to_basedn does not fail with EINVAL if domain is NULL");

    ret = domain_to_basedn(tmp_ctx, "abc", NULL);
    fail_unless(ret == EINVAL,
                "domain_to_basedn does not fail with EINVAL if basedn is NULL");

    for(i=0; test_domains[i].domain != NULL; i++) {
        ret = domain_to_basedn(tmp_ctx, test_domains[i].domain, &basedn);
        fail_unless(ret == EOK, "domain_to_basedn failed");
        fail_unless(strcmp(basedn, test_domains[i].basedn) == 0,
                    "domain_to_basedn returned wrong basedn, "
                    "get [%s], expected [%s]", basedn, test_domains[i].basedn);
        talloc_free(basedn);
    }

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(test_compare_opts)
{
    errno_t ret;

    ret = compare_dp_options(default_basic_opts, SDAP_OPTS_BASIC,
                             ipa_def_ldap_opts);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    ret = compare_dp_options(default_krb5_opts, KRB5_OPTS,
                             ipa_def_krb5_opts);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    ret = compare_dp_options(ipa_dyndns_opts, DP_OPT_DYNDNS,
                             ad_dyndns_opts);
    fail_unless(ret == EOK, "[%s]", strerror(ret));
}
END_TEST

START_TEST(test_compare_sdap_attrs)
{
    errno_t ret;

    /* General Attributes */
    ret = compare_sdap_attr_maps(generic_attr_map, SDAP_AT_GENERAL,
                                 ipa_attr_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    /* User Attributes */
    ret = compare_sdap_attr_maps(rfc2307_user_map, SDAP_OPTS_USER,
                                 ipa_user_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    /* Group Attributes */
    ret = compare_sdap_attr_maps(rfc2307_group_map, SDAP_OPTS_GROUP,
                                 ipa_group_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    /* Service Attributes */
    ret = compare_sdap_attr_maps(service_map, SDAP_OPTS_SERVICES,
                                 ipa_service_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    /* AutoFS Attributes */
    ret = compare_sdap_attr_maps(rfc2307_autofs_mobject_map,
                                 SDAP_OPTS_AUTOFS_MAP,
                                 ipa_autofs_mobject_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    ret = compare_sdap_attr_maps(rfc2307_autofs_entry_map,
                                 SDAP_OPTS_AUTOFS_ENTRY,
                                 ipa_autofs_entry_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));
}
END_TEST

START_TEST(test_compare_2307_with_2307bis)
{
    errno_t ret;

    /* User Attributes */
    ret = compare_sdap_attr_maps(rfc2307_user_map, SDAP_OPTS_USER,
                                 rfc2307bis_user_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    /* Group Attributes */
    ret = compare_sdap_attr_maps(rfc2307_group_map, SDAP_OPTS_GROUP,
                                 rfc2307bis_group_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    /* AutoFS Attributes */
    ret = compare_sdap_attr_maps(rfc2307_autofs_mobject_map,
                                 SDAP_OPTS_AUTOFS_MAP,
                                 rfc2307bis_autofs_mobject_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));

    ret = compare_sdap_attr_maps(rfc2307_autofs_entry_map,
                                 SDAP_OPTS_AUTOFS_ENTRY,
                                 rfc2307bis_autofs_entry_map);
    fail_unless(ret == EOK, "[%s]", strerror(ret));
}
END_TEST

Suite *ipa_ldap_opt_suite (void)
{
    Suite *s = suite_create ("ipa_ldap_opt");

    TCase *tc_ipa_ldap_opt = tcase_create ("ipa_ldap_opt");

    tcase_add_test (tc_ipa_ldap_opt, test_compare_opts);
    tcase_add_test (tc_ipa_ldap_opt, test_compare_sdap_attrs);
    tcase_add_test (tc_ipa_ldap_opt, test_compare_2307_with_2307bis);
    suite_add_tcase (s, tc_ipa_ldap_opt);

    TCase *tc_ipa_utils = tcase_create ("ipa_utils");
    tcase_add_test (tc_ipa_utils, test_domain_to_basedn);
    suite_add_tcase (s, tc_ipa_utils);

    return s;
}

int main(void)
{
    int number_failed;

    tests_set_cwd();

    Suite *s = ipa_ldap_opt_suite ();
    SRunner *sr = srunner_create (s);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
