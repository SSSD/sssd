/*
   SSSD

   Tests if AD and LDAP backend options are in sync

   Authors:
       Jakub Hrozek <jhrozek@redhat.com>
       Stephen Gallagher <sgallagh@redhat.com>

   Copyright (C) 2012 Red Hat

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

#include "providers/ad/ad_common.h"
#include "providers/ad/ad_opts.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/krb5/krb5_opts.h"
#include "providers/krb5/krb5_common.h"
#include "tests/common.h"

START_TEST(test_compare_opts)
{
    errno_t ret;

    ret = compare_dp_options(default_basic_opts, SDAP_OPTS_BASIC,
                             ad_def_ldap_opts);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = compare_dp_options(default_krb5_opts, KRB5_OPTS,
                             ad_def_krb5_opts);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
}
END_TEST

START_TEST(test_compare_sdap_attrs)
{
    errno_t ret;

    /* General Attributes */
    ret = compare_sdap_attr_maps(generic_attr_map, SDAP_AT_GENERAL,
                                 ad_2008r2_attr_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* User Attributes */
    ret = compare_sdap_attr_maps(rfc2307_user_map, SDAP_OPTS_USER,
                                 ad_2008r2_user_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* Group Attributes */
    ret = compare_sdap_attr_maps(rfc2307_group_map, SDAP_OPTS_GROUP,
                                 ad_2008r2_group_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* Netgroup Attributes */
    ret = compare_sdap_attr_maps(netgroup_map, SDAP_OPTS_NETGROUP,
                                 ad_netgroup_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* Service Attributes */
    ret = compare_sdap_attr_maps(service_map, SDAP_OPTS_SERVICES,
                                 ad_service_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
}
END_TEST

Suite *ad_ldap_opt_suite (void)
{
    Suite *s = suite_create ("ad_ldap_opt");

    TCase *tc_ad_ldap_opt = tcase_create ("ad_ldap_opt");

    tcase_add_test (tc_ad_ldap_opt, test_compare_opts);
    tcase_add_test (tc_ad_ldap_opt, test_compare_sdap_attrs);
    suite_add_tcase (s, tc_ad_ldap_opt);

    return s;
}

int main(void)
{
    int number_failed;

    tests_set_cwd();

    Suite *s = ad_ldap_opt_suite ();
    SRunner *sr = srunner_create (s);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
